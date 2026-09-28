//! Backend-agnostic run engine.
//!
//! The engine owns the domain state machine of runs and attempts. It is driven by
//! idempotent [`Engine::reconcile`] calls (from the Kubernetes controller, or from a loop in
//! tests/local mode) and by runnerd reports arriving through the [`ingest`] API.
//!
//! ```text
//! ACPRun (stable)            attempts (disposable)
//!   RunCreated
//!   Pending ──plan──▶ Attempt 1 [claude]  Pending ▶ Starting ▶ Running ▶ Failed/TimedOut
//!   Running ──plan──▶ Attempt 2 [claude]  ...                          ▶ Failed
//!           ──plan──▶ Attempt 3 [codex]   (fallback: new session + ResumeCapsule) ▶ Succeeded
//!   Succeeded (artifact = attempt 3 patch)  RunCompleted
//! ```
//!
//! Supervision (per reconcile, per active attempt) uses two independent signals — runnerd
//! heartbeats (the runtime works) and agent progress (agent-sourced events; the provider
//! agent moves) — distinguishing:
//! * running normally — fresh heartbeat, fresh agent progress;
//! * no progress — the controller answers runnerd's next heartbeat with a cancel directive;
//!   runnerd cancels the agent over IPC and reports; if the attempt is still active after
//!   the grace window, the controller finalizes it and terminates the sandbox;
//! * process crashed — runnerd reports `ProcessCrashed` (agent) or the sandbox exits
//!   without a report (runnerd);
//! * sandbox disappeared — backend reports `Missing` -> `SandboxLost`;
//! * hard timeout — runnerd enforces it; the engine backstops it and Kubernetes
//!   `activeDeadlineSeconds` backstops the engine.

pub mod backend;
pub mod bundles;
pub mod capsule;
pub mod codex_refresh;
pub mod compat;
pub mod creds;
pub mod environment;
pub mod harness;
pub mod ingest;
pub mod local_container;
pub mod metrics;

use acp_runner_core::attempt_spec::{
    AttemptOutput, AttemptSpec, CredentialEnvLayout, CredentialFileLayout, CredentialLayout, DriverSpec,
};
use acp_runner_core::credentials::{CredentialMetadata, Provider};
use acp_runner_core::events::{EventEnvelope, EventKind, EventSource, ProgressData};
use acp_runner_core::failure::{FailureReason, RetryDisposition};
use acp_runner_core::plan::{FinishedAttempt, NextAttempt, plan_next};
use acp_runner_core::spec::{RunSpec, RunnerClassSpec};
use acp_runner_core::{AttemptPhase, RunPhase, WIRE_VERSION};
use acp_runner_journal::{ArtifactStore, AttemptRow, Journal, LeaseRequest, NewAttempt, NewRun, RunRow, StartAttempt};
use backend::{BackendError, RunKey, SandboxBackend, SandboxObservation, SandboxRef, SandboxRequest, sandbox_name};
use base64::Engine as _;
use creds::CredentialStore;
use metrics::Metrics;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

pub type Result<T> = anyhow::Result<T>;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Unique id of this controller instance (pod name).
    pub controller_id: String,
    /// URL runnerd uses to reach the ingest API.
    pub ingest_url: String,
    /// Attempt supervision lease; another instance takes over after it expires.
    pub supervision_lease: Duration,
    pub active_requeue: Duration,
    pub waiting_requeue: Duration,
    pub record_raw_payloads: bool,
    /// Runner classes with persistent subscription credentials must use
    /// `egress.mode: proxy`. Disable only for local development.
    pub require_egress_proxy_for_credentials: bool,
    /// V2: exact image strings (`repo@sha256:<hex>`) allowed for credentialed
    /// runner classes. Empty denies all credentialed images (fail closed).
    pub allowed_images: Vec<String>,
    /// V2: service accounts credentialed runner classes may use.
    pub allowed_service_accounts: Vec<String>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            controller_id: "acp-runner-controller".into(),
            ingest_url: "http://127.0.0.1:8081".into(),
            supervision_lease: Duration::from_secs(45),
            active_requeue: Duration::from_secs(5),
            waiting_requeue: Duration::from_secs(15),
            record_raw_payloads: true,
            require_egress_proxy_for_credentials: true,
            allowed_images: vec![],
            allowed_service_accounts: vec![
                acp_runner_core::spec::DEFAULT_AGENT_SERVICE_ACCOUNT.to_string(),
            ],
        }
    }
}

pub struct Engine {
    pub journal: Journal,
    pub backend: Arc<dyn SandboxBackend>,
    pub creds: Arc<dyn CredentialStore>,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub metrics: Arc<Metrics>,
    pub cfg: EngineConfig,
}

/// Input for one reconcile: the orchestrator-facing resource, resolved.
#[derive(Debug, Clone)]
pub struct RunInput {
    pub key: RunKey,
    pub spec: RunSpec,
    pub cancel: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttemptView {
    pub id: Uuid,
    pub ordinal: i32,
    pub runner_class: String,
    pub driver: String,
    pub phase: AttemptPhase,
    pub sandbox: Option<SandboxRef>,
    pub credential_profile: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_heartbeat_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_progress_at: Option<chrono::DateTime<chrono::Utc>>,
    pub failure: Option<FailureReason>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactView {
    pub id: Uuid,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub changed_paths: usize,
    pub base_revision: String,
    pub storage: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunView {
    pub run_id: Uuid,
    pub phase: RunPhase,
    pub attempt_count: i32,
    pub current: Option<AttemptView>,
    pub failure: Option<FailureReason>,
    pub artifact: Option<ArtifactView>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub waiting_reason: Option<String>,
    #[serde(skip)]
    pub requeue_after: Option<Duration>,
}

pub fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn secs_since(now: chrono::DateTime<chrono::Utc>, t: chrono::DateTime<chrono::Utc>) -> u64 {
    (now - t).num_seconds().max(0) as u64
}

/// Record metrics for an attempt that just reached a terminal phase.
pub fn record_attempt_finished(m: &Metrics, a: &AttemptRow, phase: AttemptPhase, reason: Option<&FailureReason>) {
    let secs = (chrono::Utc::now() - a.created_at).num_milliseconds() as f64 / 1000.0;
    m.attempt_finished(
        &a.driver,
        phase.as_str(),
        reason.map(|r| r.code()),
        reason.map(|r| r.is_timeout()).unwrap_or(false),
        secs,
    );
}

impl Engine {
    async fn controller_event(&self, run_id: Uuid, attempt_id: Option<Uuid>, kind: EventKind, data: serde_json::Value) {
        let ev = EventEnvelope::new(kind, EventSource::Controller, data);
        if let Err(e) = self.journal.append_event(run_id, attempt_id, &ev).await {
            tracing::error!(%run_id, error = %e, "journaling controller event failed");
        }
    }

    /// Idempotent reconcile of one run.
    pub async fn reconcile(&self, input: &RunInput) -> Result<RunView> {
        let (run, created) = self
            .journal
            .ensure_run(&NewRun {
                id: Uuid::now_v7(),
                k8s_namespace: input.key.namespace.clone(),
                k8s_name: input.key.name.clone(),
                k8s_uid: input.key.uid.clone(),
                task_id: input.spec.task_id.clone(),
                spec: serde_json::to_value(&input.spec)?,
            })
            .await?;
        if created {
            self.metrics.run("created");
            tracing::info!(run_id = %run.id, run = %input.key.name, task_id = %input.spec.task_id, "run created");
        }
        let Some(lock) = self.journal.try_lock_run(run.id).await? else {
            let mut v = self.view(run.id).await?;
            v.requeue_after = Some(Duration::from_secs(2));
            return Ok(v);
        };
        let res = self.reconcile_locked(run.id, input).await;
        lock.release().await?;
        let requeue = res?;
        let mut v = self.view(run.id).await?;
        v.requeue_after = if v.phase.is_terminal() { None } else { Some(requeue) };
        Ok(v)
    }

    /// Cancel (e.g. the ACPRun is being deleted). Idempotent; unknown runs are ignored.
    pub async fn cancel(&self, key: &RunKey, detail: &str) -> Result<()> {
        let Some(run) = self.journal.run_by_uid(&key.uid).await? else { return Ok(()) };
        for _ in 0..50 {
            if let Some(lock) = self.journal.try_lock_run(run.id).await? {
                let run = self.journal.get_run(run.id).await?;
                let r = if run.phase().is_terminal() {
                    self.cleanup_terminal(&run).await
                } else {
                    self.cancel_locked(&run, detail).await
                };
                lock.release().await?;
                return r;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        anyhow::bail!("could not lock run {} for cancellation", run.id)
    }

    async fn reconcile_locked(&self, run_id: Uuid, input: &RunInput) -> Result<Duration> {
        let run = self.journal.get_run(run_id).await?;
        if run.phase().is_terminal() {
            self.cleanup_terminal(&run).await?;
            return Ok(Duration::ZERO);
        }
        // The spec is snapshotted at creation: later edits do not affect an in-flight run.
        let spec: RunSpec = serde_json::from_value(run.spec.clone())?;
        if let Err(e) = spec.validate() {
            self.fail_run(&run, FailureReason::Unsupported { detail: format!("invalid run spec: {e}") }).await?;
            return Ok(Duration::ZERO);
        }
        // A persistent subscription credential is readable by the CLI (and therefore by
        // anything the agent runs); the run is only allowed when the only way out of the
        // pod is the allowlisting egress proxy.
        let violations = spec.credential_egress_violations();
        if self.cfg.require_egress_proxy_for_credentials && !violations.is_empty() {
            let detail = format!(
                "runner class(es) {violations:?} use persistent subscription credentials but egress.mode is not \
                 proxy; set egress.mode: proxy with an allowlisting egress proxy (development only: \
                 ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS=true)"
            );
            self.fail_run(&run, FailureReason::Unsupported { detail }).await?;
            return Ok(Duration::ZERO);
        }
        // V2 trust boundary (admission, before any lease): a credentialed
        // class runs only on an operator-allowlisted digest-pinned image with
        // an allowlisted service account. Namespace users cannot steer a
        // granted credential into a self-chosen image this way.
        for class in &spec.runner_classes {
            if class.credentials.provider.is_none() {
                continue;
            }
            if let Err(e) = acp_runner_core::spec::validate_credentialed_image(&class.image, &self.cfg.allowed_images)
            {
                let detail = format!("runner class {}: {e}", class.name);
                self.fail_run(&run, FailureReason::Unsupported { detail }).await?;
                return Ok(Duration::ZERO);
            }
            if let Err(e) = acp_runner_core::spec::resolve_service_account(
                class.service_account_name.as_deref(),
                &self.cfg.allowed_service_accounts,
            ) {
                let detail = format!("runner class {}: {e}", class.name);
                self.fail_run(&run, FailureReason::Unsupported { detail }).await?;
                return Ok(Duration::ZERO);
            }
        }
        if input.cancel {
            self.cancel_locked(&run, "cancel requested (spec.cancel=true)").await?;
            return Ok(Duration::ZERO);
        }
        let attempts = self.journal.attempts_for_run(run.id).await?;
        if let Some(a) = attempts.last()
            && a.phase().is_active()
        {
            let requeue = self.supervise(&run, &spec, a).await?;
            let a = self.journal.get_attempt(a.id).await?;
            if a.phase().is_active() {
                return Ok(requeue);
            }
        }
        let attempts = self.journal.attempts_for_run(run.id).await?;
        if let Some(last) = attempts.last() {
            self.attempt_cleanup(last).await?;
            if last.phase() == AttemptPhase::Succeeded {
                self.journal.set_run_phase(run.id, RunPhase::Succeeded, None, last.artifact_id).await?;
                self.controller_event(
                    run.id,
                    None,
                    EventKind::RunCompleted,
                    json!({"attempts": attempts.len(), "attemptId": last.id, "runnerClass": last.runner_class,
                           "driver": last.driver, "artifactId": last.artifact_id}),
                )
                .await;
                self.metrics.run("succeeded");
                tracing::info!(run_id = %run.id, attempt_id = %last.id, driver = %last.driver, "run succeeded");
                return Ok(Duration::ZERO);
            }
        }
        let history: Vec<FinishedAttempt> = attempts
            .iter()
            .map(|a| FinishedAttempt {
                class_index: a.class_index as usize,
                disposition: a.failure().map(|f| f.disposition()).unwrap_or(RetryDisposition::RetrySame),
            })
            .collect();
        match plan_next(spec.runner_classes.len(), &spec.retry, &history) {
            None => {
                let reason = attempts
                    .last()
                    .and_then(|a| a.failure())
                    .unwrap_or_else(|| FailureReason::internal("no attempt could be planned"));
                self.fail_run(&run, reason).await?;
                Ok(Duration::ZERO)
            }
            Some(next) => self.start_attempt(&run, &spec, &attempts, next).await,
        }
    }

    async fn fail_run(&self, run: &RunRow, reason: FailureReason) -> Result<()> {
        self.journal.set_run_phase(run.id, RunPhase::Failed, Some(&reason), None).await?;
        let n = self.journal.attempts_for_run(run.id).await?.len();
        self.controller_event(run.id, None, EventKind::RunFailed, json!({"reason": reason, "attempts": n})).await;
        self.metrics.run("failed");
        tracing::warn!(run_id = %run.id, reason = %reason, "run failed");
        Ok(())
    }

    async fn cancel_locked(&self, run: &RunRow, detail: &str) -> Result<()> {
        let reason = FailureReason::Cancelled { detail: detail.to_string() };
        for a in self.journal.attempts_for_run(run.id).await? {
            if a.phase().is_active()
                && self
                    .journal
                    .transition_attempt(a.id, &AttemptPhase::ACTIVE, AttemptPhase::Cancelled, Some(&reason), None)
                    .await?
            {
                self.controller_event(run.id, Some(a.id), EventKind::AttemptFailed, json!({"reason": reason})).await;
                record_attempt_finished(&self.metrics, &a, AttemptPhase::Cancelled, Some(&reason));
            }
            self.attempt_cleanup(&self.journal.get_attempt(a.id).await?).await?;
        }
        self.journal.set_run_phase(run.id, RunPhase::Cancelled, Some(&reason), None).await?;
        self.controller_event(run.id, None, EventKind::RunFailed, json!({"reason": reason})).await;
        self.metrics.run("cancelled");
        Ok(())
    }

    async fn cleanup_terminal(&self, run: &RunRow) -> Result<()> {
        for a in self.journal.attempts_for_run(run.id).await? {
            if a.phase().is_active() {
                let reason = FailureReason::Cancelled { detail: "run already finished".into() };
                self.journal
                    .transition_attempt(a.id, &AttemptPhase::ACTIVE, AttemptPhase::Cancelled, Some(&reason), None)
                    .await?;
            }
            if a.sandbox_released_at.is_none()
                || self.journal.lease_for_attempt(a.id).await?.is_some_and(|l| l.released_at.is_none())
            {
                self.attempt_cleanup(&self.journal.get_attempt(a.id).await?).await?;
            }
        }
        Ok(())
    }

    /// Idempotent side effects of a finished attempt: sandbox terminated, lease released,
    /// credential profile flagged when the provider rejected it.
    async fn attempt_cleanup(&self, a: &AttemptRow) -> Result<()> {
        if let Some(sref) = &a.sandbox_ref
            && a.sandbox_released_at.is_none()
        {
            let sref: SandboxRef = serde_json::from_value(sref.clone())?;
            let grace = serde_json::from_value::<AttemptSpec>(a.spec.clone())
                .map(|s| Duration::from_secs(s.timeouts.grace_seconds))
                .unwrap_or(Duration::from_secs(20));
            match self.backend.terminate(&sref, grace).await {
                Ok(()) => self.journal.mark_sandbox_released(a.id).await?,
                Err(e) => tracing::warn!(attempt_id = %a.id, error = %e, "sandbox termination failed; will retry"),
            }
        }
        // 1c: the credential lease is released only after the backend has
        // confirmed the sandbox is gone (or the attempt never had one). A
        // live sandbox keeps its exclusive credential un-lendable even if the
        // controller was down past the lease window (see V10 fencing).
        let sandbox_gone =
            a.sandbox_ref.is_none() || self.journal.get_attempt(a.id).await?.sandbox_released_at.is_some();
        if sandbox_gone && self.journal.release_lease(a.id).await? {
            tracing::debug!(attempt_id = %a.id, "credential lease released");
        }
        if let (Some(profile), Some(reason)) = (&a.credential_profile, a.failure()) {
            let status = match reason {
                FailureReason::AuthEnrollmentRequired { .. } => Some("needs_reauth"),
                FailureReason::AuthPolicyViolation { .. } => Some("disabled"),
                _ => None,
            };
            if let Some(status) = status
                && let Some(p) = self.journal.get_profile(profile).await?
                && p.status == "active"
            {
                self.journal.set_profile_status(profile, status, Some(&reason.message())).await?;
                tracing::warn!(profile, status, "credential profile flagged");
            }
        }
        Ok(())
    }

    async fn supervise(&self, run: &RunRow, spec: &RunSpec, a: &AttemptRow) -> Result<Duration> {
        match self.journal.renew_supervision_lease(a.id, &self.cfg.controller_id, self.cfg.supervision_lease).await? {
            Ok(Some(prev)) => {
                tracing::warn!(attempt_id = %a.id, previous = %prev, "took over stale attempt supervision lease");
                self.controller_event(
                    run.id,
                    Some(a.id),
                    EventKind::Progress,
                    serde_json::to_value(ProgressData::new(
                        "supervision_takeover",
                        format!("controller {} took over from stale controller {prev}", self.cfg.controller_id),
                    ))?,
                )
                .await;
            }
            Ok(None) => {}
            Err(owner) => {
                tracing::debug!(attempt_id = %a.id, %owner, "attempt supervised by another live controller");
                return Ok(self.cfg.supervision_lease / 2);
            }
        }
        let class = spec
            .runner_classes
            .get(a.class_index as usize)
            .ok_or_else(|| anyhow::anyhow!("attempt refers to unknown class index {}", a.class_index))?;
        let t = spec.effective_timeouts(class);
        if a.sandbox_ref.is_none() {
            // Pending attempt without sandbox (fresh, or the controller crashed before creating it).
            self.create_sandbox(run, spec, a, None).await?;
            return Ok(self.cfg.active_requeue);
        }
        let sref: SandboxRef = serde_json::from_value(a.sandbox_ref.clone().expect("checked"))?;
        let obs = match self.backend.observe(&sref).await {
            Ok(o) => o,
            Err(BackendError::Transient(e)) => {
                tracing::warn!(attempt_id = %a.id, error = %e, "observing sandbox failed");
                return Ok(self.cfg.active_requeue);
            }
            Err(BackendError::Permanent(e)) => {
                SandboxObservation::Exited { exit_code: None, reason: Some("BackendError".into()), message: Some(e) }
            }
        };
        // runnerd may have reported the terminal state meanwhile
        let a = self.journal.get_attempt(a.id).await?;
        if !a.phase().is_active() {
            return Ok(Duration::ZERO);
        }
        let now = self.journal.db_now().await?;
        let created = a.sandbox_created_at.unwrap_or(a.created_at);
        let since_created = secs_since(now, created);
        let hard_backstop = t.hard_seconds + t.startup_seconds + 2 * t.grace_seconds + 30;
        let verdict: Option<(AttemptPhase, FailureReason)> = if since_created > hard_backstop {
            Some((AttemptPhase::TimedOut, FailureReason::HardTimeout { seconds: t.hard_seconds }))
        } else {
            match obs {
                SandboxObservation::Missing => Some((
                    AttemptPhase::Failed,
                    FailureReason::SandboxLost { detail: format!("{} {} no longer exists", sref.backend, sref.name) },
                )),
                SandboxObservation::Exited { exit_code: None, reason, message } => Some((
                    AttemptPhase::Failed,
                    FailureReason::SandboxFailed {
                        detail: format!("{}: {}", reason.unwrap_or_default(), message.unwrap_or_default()),
                    },
                )),
                SandboxObservation::Exited { exit_code: Some(code), reason, message } => Some((
                    AttemptPhase::Failed,
                    FailureReason::ProcessCrashed {
                        exit_code: Some(code),
                        signal: None,
                        detail: format!(
                            "runnerd exited without reporting a result ({}{})",
                            reason.unwrap_or_else(|| "exit".into()),
                            message.map(|m| format!(": {m}")).unwrap_or_default()
                        ),
                    },
                )),
                SandboxObservation::Pending { .. } | SandboxObservation::Running => match a.last_heartbeat_at {
                    // signal 1: runnerd heartbeat = the runtime works
                    None if since_created > t.startup_seconds => {
                        Some((AttemptPhase::Failed, FailureReason::StartTimeout { seconds: t.startup_seconds }))
                    }
                    Some(hb) if secs_since(now, hb) > t.heartbeat_timeout_seconds() => Some((
                        AttemptPhase::Failed,
                        FailureReason::HeartbeatLost { seconds_since_last: secs_since(now, hb) },
                    )),
                    // signal 2: agent progress = the provider agent moves
                    _ => match (a.cancel_requested_at, a.last_progress_at.or(a.started_at)) {
                        // runnerd got the cancel directive but the attempt is still active:
                        // finalize here; attempt_cleanup then terminates the whole sandbox,
                        // so the agent never has to stop itself correctly.
                        (Some(req), _) if secs_since(now, req) > 2 * t.grace_seconds + 2 * t.heartbeat_seconds + 30 => {
                            let reason = a
                                .cancel_request()
                                .unwrap_or(FailureReason::NoProgressTimeout { seconds: t.no_progress_seconds });
                            Some((
                                if reason.is_timeout() { AttemptPhase::TimedOut } else { AttemptPhase::Failed },
                                reason,
                            ))
                        }
                        (None, Some(p)) if secs_since(now, p) > t.no_progress_seconds => {
                            let reason = FailureReason::NoProgressTimeout { seconds: t.no_progress_seconds };
                            if self.journal.request_attempt_cancel(a.id, &reason).await? {
                                tracing::warn!(attempt_id = %a.id, "no agent progress; cancel directive issued");
                                self.controller_event(
                                    run.id,
                                    Some(a.id),
                                    EventKind::Progress,
                                    serde_json::to_value(
                                        ProgressData::new(
                                            "no_progress_detected",
                                            "no agent progress; asking runnerd to cancel the agent",
                                        )
                                        .with_detail(
                                            json!({"secondsSinceAgentProgress": secs_since(now, p),
                                                                "noProgressSeconds": t.no_progress_seconds,
                                                                "directive": "cancel"}),
                                        ),
                                    )?,
                                )
                                .await;
                            }
                            None
                        }
                        _ => None,
                    },
                },
            }
        };
        if let Some((phase, reason)) = verdict {
            if self.journal.transition_attempt(a.id, &AttemptPhase::ACTIVE, phase, Some(&reason), None).await? {
                let kind =
                    if phase == AttemptPhase::TimedOut { EventKind::AttemptTimedOut } else { EventKind::AttemptFailed };
                self.controller_event(run.id, Some(a.id), kind, json!({"reason": reason, "detectedBy": "controller"}))
                    .await;
                record_attempt_finished(&self.metrics, &a, phase, Some(&reason));
                tracing::warn!(run_id = %run.id, attempt_id = %a.id, driver = %a.driver, reason = %reason, "attempt failed (controller)");
            }
            return Ok(Duration::ZERO);
        }
        Ok(self.cfg.active_requeue)
    }

    /// Whether the leased profile may write back (V1c): Codex `chatgpt` mode only.
    async fn profile_supports_writeback(&self, profile: &str) -> Result<bool> {
        Ok(self
            .journal
            .get_profile(profile)
            .await?
            .and_then(|p| serde_json::from_value::<CredentialMetadata>(p.metadata).ok())
            .is_some_and(|md| md.auth_kind == "chatgpt"))
    }

    /// Merge per-run overrides into a copy of the class driver config (V9.3):
    /// env keys replace class keys, run files append after class files.
    fn merged_driver_config(
        class: &RunnerClassSpec,
        overrides: &acp_runner_core::spec::RunOverrides,
    ) -> Result<serde_json::Value> {
        if overrides.is_empty() {
            return Ok(class.driver_config.clone());
        }
        let mut cfg = class.driver_config.clone();
        if cfg.is_null() {
            cfg = serde_json::json!({});
        }
        let obj = cfg.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!("runner class {}: cannot apply overrides to a non-object driver config", class.name)
        })?;
        if !overrides.env.is_empty() {
            let env = obj.entry("env".to_string()).or_insert_with(|| serde_json::json!({}));
            let map = env.as_object_mut().ok_or_else(|| {
                anyhow::anyhow!("runner class {}: driver config `env` is not an object", class.name)
            })?;
            for (k, v) in &overrides.env {
                map.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }
        if !overrides.files.is_empty() {
            let files = obj.entry("files".to_string()).or_insert_with(|| serde_json::json!([]));
            let arr = files.as_array_mut().ok_or_else(|| {
                anyhow::anyhow!("runner class {}: driver config `files` is not an array", class.name)
            })?;
            for f in &overrides.files {
                arr.push(serde_json::json!({"target": f.target, "content": f.content, "mode": f.mode}));
            }
        }
        Ok(cfg)
    }

    fn credential_layout(class: &RunnerClassSpec, provider: Provider, profile: &str) -> CredentialLayout {
        // V9: the files provider has no static file list — the bundle keys
        // are filenames and the class `fileTargets` give their HOME targets.
        // Never write-back: static secrets have no refresh to hand back.
        if provider == Provider::Files {
            return CredentialLayout {
                provider: provider.as_str().to_string(),
                profile: profile.to_string(),
                files: class
                    .credentials
                    .file_targets
                    .iter()
                    .map(|(k, t)| CredentialFileLayout {
                        key: k.clone(),
                        target: t.clone(),
                        mode: 0o600,
                        writeback: false,
                    })
                    .collect(),
                env: vec![],
            };
        }
        let spec = provider.spec();
        CredentialLayout {
            provider: provider.as_str().to_string(),
            profile: profile.to_string(),
            files: spec
                .files
                .iter()
                .map(|f| CredentialFileLayout {
                    key: f.key.to_string(),
                    target: class
                        .credentials
                        .file_targets
                        .get(f.key)
                        .cloned()
                        .unwrap_or_else(|| f.default_target.to_string()),
                    mode: f.mode,
                    writeback: f.writeback,
                })
                .collect(),
            env: spec
                .env
                .iter()
                .map(|e| CredentialEnvLayout { key: e.key.to_string(), env_name: e.env_name.to_string() })
                .collect(),
        }
    }

    async fn start_attempt(
        &self,
        run: &RunRow,
        spec: &RunSpec,
        previous: &[AttemptRow],
        next: NextAttempt,
    ) -> Result<Duration> {
        let class = &spec.runner_classes[next.class_index];
        let attempt_id = Uuid::now_v7();
        // V9.3: per-run launch additions, before any sandbox exists.
        if !spec.overrides.is_empty() {
            if class.driver != "acp" {
                let reason = FailureReason::Unsupported {
                    detail: format!(
                        "runner overrides are only supported for the acp driver (class {} uses {})",
                        class.name, class.driver
                    ),
                };
                return self.record_unstartable_attempt(run, class, next, attempt_id, reason).await;
            }
            if !class.allow_run_overrides {
                let reason = FailureReason::Unsupported {
                    detail: format!(
                        "runner class {} does not allow run overrides (allowRunOverrides)", class.name
                    ),
                };
                return self.record_unstartable_attempt(run, class, next, attempt_id, reason).await;
            }
        }
        let token = new_token();
        let t = spec.effective_timeouts(class);
        let provider = match class.credentials.provider.as_deref().map(str::parse::<Provider>) {
            None => None,
            Some(Ok(p)) => Some(p),
            Some(Err(e)) => {
                let reason = FailureReason::Unsupported { detail: format!("runner class {}: {e}", class.name) };
                return self.record_unstartable_attempt(run, class, next, attempt_id, reason).await;
            }
        };
        let (capsule, previous_patch) = if previous.is_empty() {
            (None, None)
        } else {
            let built = capsule::build(self, run, spec, previous).await?;
            (Some(built.capsule), built.previous_patch)
        };
        let apply_patch_b64 = match (&capsule, previous_patch) {
            (Some(c), Some(bytes)) if c.previous_artifact.as_ref().is_some_and(|a| a.applied_to_workspace) => {
                Some(base64::engine::general_purpose::STANDARD.encode(bytes))
            }
            _ => None,
        };
        let prompt = capsule.as_ref().map(|c| c.render_prompt()).unwrap_or_else(|| spec.prompt.clone());
        let mut attempt_spec = AttemptSpec {
            wire_version: WIRE_VERSION,
            run_id: run.id,
            attempt_id,
            task_id: spec.task_id.clone(),
            ordinal: next.ordinal,
            class_attempt: next.class_attempt,
            runner_class: class.name.clone(),
            driver: DriverSpec { name: class.driver.clone(), config: Self::merged_driver_config(class, &spec.overrides)? },
            repository: spec.repository.clone(),
            prompt,
            capsule,
            apply_patch_b64,
            output: AttemptOutput {
                kind: spec.output.kind,
                require_changes: spec.output.require_changes,
                max_patch_bytes: spec.effective_max_patch_bytes(class),
                allowed_paths: class.workspace.allowed_paths.clone(),
                allow_submodules: spec.output.allow_submodules,
            },
            timeouts: t,
            permissions: class.permissions,
            egress: class.egress.clone(),
            credentials: None,
            record_raw_payloads: self.cfg.record_raw_payloads,
            env: class.env.clone(),
            session: Default::default(),
            bootstrap: Default::default(),
        };
        let lease = provider.map(|p| LeaseRequest {
            provider: p.as_str().to_string(),
            candidates: class.credentials.profiles.clone(),
            holder: self.cfg.controller_id.clone(),
            // V10c: the lease spans the sandbox's hard deadline (same bound as
            // the pod's activeDeadlineSeconds); heartbeat only extends it
            // optimistically, capped at the deadline.
            ttl: t.hard_deadline(),
        });
        // Layout depends on the profile that will be leased; the store decides at lease time.
        // All candidates share the provider layout, so we fill the profile in afterwards.
        if let Some(p) = provider {
            attempt_spec.credentials = Some(Self::credential_layout(class, p, "<leased>"));
        }
        let new = NewAttempt {
            id: attempt_id,
            run_id: run.id,
            ordinal: next.ordinal as i32,
            class_index: next.class_index as i32,
            class_attempt: next.class_attempt as i32,
            runner_class: class.name.clone(),
            driver: class.driver.clone(),
            spec: serde_json::to_value(&attempt_spec)?,
            ingest_token_hash: token_hash(&token),
            lease_owner: self.cfg.controller_id.clone(),
            lease_ttl: self.cfg.supervision_lease,
        };
        match self.journal.start_attempt(&new, lease.as_ref()).await? {
            StartAttempt::Started { attempt, lease } => {
                // V10c fencing: never share an exclusive profile with a live
                // sandbox — terminate lapsed zombies first, fail closed.
                if let Some(l) = &lease
                    && let Err(e) = backend::fence_exclusive_lease(
                        &self.journal,
                        self.backend.as_ref(),
                        &l.profile_name,
                        attempt.id,
                    )
                    .await
                {
                    let reason =
                        FailureReason::CredentialUnavailable { detail: format!("credential fencing: {e}") };
                    let _ = self.journal.release_lease(attempt.id).await;
                    self.journal
                        .transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&reason), None)
                        .await?;
                    self.controller_event(run.id, Some(attempt.id), EventKind::AttemptFailed, json!({"reason": reason}))
                        .await;
                    record_attempt_finished(&self.metrics, &attempt, AttemptPhase::Failed, Some(&reason));
                    tracing::warn!(run_id = %run.id, attempt_id = %attempt.id, error = %e, "credential fencing refused the lease");
                    return Ok(self.cfg.active_requeue);
                }
                let mut attempt = *attempt;
                if let (Some(p), Some(l)) = (provider, &lease) {
                    let mut layout = Self::credential_layout(class, p, &l.profile_name);
                    // 1c: only the `chatgpt` mode writes back. PAT /
                    // agentIdentity layouts carry writeback=false so runnerd
                    // never even offers the file for write-back.
                    if p == Provider::Codex && !self.profile_supports_writeback(&l.profile_name).await? {
                        for f in &mut layout.files {
                            f.writeback = false;
                        }
                    }
                    attempt_spec.credentials = Some(layout);
                    let v = serde_json::to_value(&attempt_spec)?;
                    sqlx_update_spec(&self.journal, attempt.id, &v).await?;
                    attempt.spec = v;
                }
                let prev_class = previous.last().map(|p| p.runner_class.clone());
                self.controller_event(
                    run.id,
                    Some(attempt.id),
                    EventKind::AttemptStarted,
                    json!({"ordinal": next.ordinal, "classAttempt": next.class_attempt, "runnerClass": class.name,
                           "driver": class.driver, "fallback": next.is_fallback, "previousRunnerClass": prev_class,
                           "credentialProfile": lease.as_ref().map(|l| l.profile_name.clone()),
                           "hasResumeCapsule": attempt_spec.capsule.is_some()}),
                )
                .await;
                self.metrics.attempt_started(&class.driver, &class.name);
                if next.is_fallback {
                    let from = previous.last().map(|p| p.driver.as_str()).unwrap_or("");
                    self.metrics.fallback(from, &class.driver);
                }
                tracing::info!(run_id = %run.id, attempt_id = %attempt.id, driver = %class.driver, runner_class = %class.name,
                    ordinal = next.ordinal, fallback = next.is_fallback, "attempt started");
                self.create_sandbox(run, spec, &attempt, Some(token)).await?;
                Ok(self.cfg.active_requeue)
            }
            StartAttempt::NoCredentialAvailable { detail } => {
                let msg = format!("waiting for a credential lease on runner class {}: {detail}", class.name);
                if run.waiting_reason.as_deref() != Some(msg.as_str()) {
                    self.journal.set_run_waiting(run.id, Some(&msg)).await?;
                    self.controller_event(
                        run.id,
                        None,
                        EventKind::Progress,
                        serde_json::to_value(ProgressData::new("waiting_for_credential", msg))?,
                    )
                    .await;
                }
                Ok(self.cfg.waiting_requeue)
            }
            StartAttempt::CredentialUnusable { detail } => {
                let reason =
                    FailureReason::CredentialUnavailable { detail: format!("runner class {}: {detail}", class.name) };
                self.record_unstartable_attempt(run, class, next, attempt_id, reason).await
            }
        }
    }

    /// Journal an attempt that could not even be started (so the planner can move on).
    async fn record_unstartable_attempt(
        &self,
        run: &RunRow,
        class: &RunnerClassSpec,
        next: NextAttempt,
        attempt_id: Uuid,
        reason: FailureReason,
    ) -> Result<Duration> {
        let new = NewAttempt {
            id: attempt_id,
            run_id: run.id,
            ordinal: next.ordinal as i32,
            class_index: next.class_index as i32,
            class_attempt: next.class_attempt as i32,
            runner_class: class.name.clone(),
            driver: class.driver.clone(),
            spec: json!({}),
            ingest_token_hash: token_hash(&new_token()),
            lease_owner: self.cfg.controller_id.clone(),
            lease_ttl: self.cfg.supervision_lease,
        };
        if let StartAttempt::Started { attempt, .. } = self.journal.start_attempt(&new, None).await? {
            self.controller_event(
                run.id,
                Some(attempt.id),
                EventKind::AttemptStarted,
                json!({"ordinal": next.ordinal, "runnerClass": class.name, "driver": class.driver, "fallback": next.is_fallback}),
            )
            .await;
            self.journal
                .transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&reason), None)
                .await?;
            self.controller_event(run.id, Some(attempt.id), EventKind::AttemptFailed, json!({"reason": reason})).await;
            record_attempt_finished(&self.metrics, &attempt, AttemptPhase::Failed, Some(&reason));
            tracing::warn!(run_id = %run.id, runner_class = %class.name, reason = %reason, "attempt could not start");
        }
        Ok(Duration::ZERO)
    }

    async fn create_sandbox(&self, run: &RunRow, spec: &RunSpec, a: &AttemptRow, token: Option<String>) -> Result<()> {
        let token = match token {
            Some(t) => t,
            None => {
                let t = new_token();
                self.journal.set_attempt_token(a.id, &token_hash(&t)).await?;
                t
            }
        };
        let class = &spec.runner_classes[a.class_index as usize];
        let mut credential_files = BTreeMap::new();
        if let Some(profile) = &a.credential_profile {
            match self.creds.load(profile).await {
                Ok((_sp, bundle)) => credential_files = bundle,
                Err(e) => {
                    let reason =
                        FailureReason::CredentialUnavailable { detail: format!("loading profile {profile}: {e}") };
                    if self
                        .journal
                        .transition_attempt(a.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&reason), None)
                        .await?
                    {
                        self.controller_event(run.id, Some(a.id), EventKind::AttemptFailed, json!({"reason": reason}))
                            .await;
                        record_attempt_finished(&self.metrics, a, AttemptPhase::Failed, Some(&reason));
                    }
                    return Ok(());
                }
            }
        }
        let req = SandboxRequest {
            run_key: RunKey {
                namespace: run.k8s_namespace.clone(),
                name: run.k8s_name.clone(),
                uid: run.k8s_uid.clone(),
            },
            run_id: run.id,
            attempt_id: a.id,
            ordinal: a.ordinal as u32,
            name: sandbox_name(&run.k8s_name, a.ordinal as u32, a.id),
            class: class.clone(),
            ingest_url: self.cfg.ingest_url.clone(),
            token,
            credential_files,
            runner_secret_files: Default::default(),
            timeouts: spec.effective_timeouts(class),
        };
        match self.backend.create(&req).await {
            Ok(sref) => {
                self.journal.set_attempt_sandbox(a.id, &serde_json::to_value(&sref)?).await?;
                tracing::info!(attempt_id = %a.id, backend = %sref.backend, sandbox = %sref.name, "sandbox created");
            }
            Err(BackendError::Transient(e)) => {
                tracing::warn!(attempt_id = %a.id, error = %e, "sandbox creation failed; will retry");
            }
            Err(BackendError::Permanent(e)) => {
                let reason = FailureReason::SandboxFailed { detail: e };
                if self
                    .journal
                    .transition_attempt(a.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&reason), None)
                    .await?
                {
                    self.controller_event(run.id, Some(a.id), EventKind::AttemptFailed, json!({"reason": reason}))
                        .await;
                    record_attempt_finished(&self.metrics, a, AttemptPhase::Failed, Some(&reason));
                }
            }
        }
        Ok(())
    }

    pub async fn view(&self, run_id: Uuid) -> Result<RunView> {
        let run = self.journal.get_run(run_id).await?;
        let attempts = self.journal.attempts_for_run(run_id).await?;
        let current = attempts.last().map(|a| AttemptView {
            id: a.id,
            ordinal: a.ordinal,
            runner_class: a.runner_class.clone(),
            driver: a.driver.clone(),
            phase: a.phase(),
            sandbox: a.sandbox_ref.clone().and_then(|v| serde_json::from_value(v).ok()),
            credential_profile: a.credential_profile.clone(),
            started_at: a.started_at,
            last_heartbeat_at: a.last_heartbeat_at,
            last_progress_at: a.last_progress_at,
            failure: a.failure(),
        });
        let artifact = match run.artifact_id {
            Some(id) => self.artifacts.get_meta(id).await.ok().map(|m| ArtifactView {
                id: m.id,
                kind: m.kind,
                sha256: m.sha256,
                size_bytes: m.size_bytes,
                changed_paths: m.changed_paths.as_array().map(|a| a.len()).unwrap_or(0),
                base_revision: m.base_revision,
                storage: m.storage,
            }),
            None => None,
        };
        Ok(RunView {
            run_id,
            phase: run.phase(),
            attempt_count: attempts.len() as i32,
            current,
            failure: run.failure(),
            artifact,
            started_at: run.started_at,
            finished_at: run.finished_at,
            waiting_reason: run.waiting_reason.clone(),
            requeue_after: None,
        })
    }

    /// Refresh gauges from the database (cheap; call periodically).
    pub async fn refresh_gauges(&self) -> Result<()> {
        let counts = self.journal.active_attempt_counts().await?;
        self.metrics.set_active(&counts, &["fake", "codex", "claude"]);
        Ok(())
    }
}

async fn sqlx_update_spec(j: &Journal, id: Uuid, spec: &serde_json::Value) -> Result<()> {
    j.update_attempt_spec(id, spec).await?;
    Ok(())
}
