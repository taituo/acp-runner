//! Ingest API used by runnerd inside the sandbox.
//!
//! Authentication: `Authorization: Bearer <per-attempt token>`. Only the SHA-256 of the
//! token is stored. A token is valid only while its attempt is active and only for that
//! attempt; it cannot read other attempts, runs or credentials. Everything a runner submits
//! is treated as untrusted input: kinds are restricted, payloads are re-redacted, artifact
//! sizes and hashes are verified, credential write-backs are validated against the enrolled
//! profile (same provider, same account, no API keys).
//!
//! | method | path                     | purpose                                  |
//! |--------|--------------------------|------------------------------------------|
//! | GET    | /v1/attempt              | fetch the AttemptSpec                    |
//! | POST   | /v1/attempt/events       | append normalized events (idempotent)    |
//! | POST   | /v1/attempt/heartbeat    | liveness; reply may carry a directive    |
//! | POST   | /v1/attempt/artifact     | upload the patch artifact                |
//! | POST   | /v1/attempt/credential   | hand back a refreshed credential file    |
//! | GET    | /v1/attempt/overlay/{id} | environment bootstrap: overlay patch     |
//! | GET    | /v1/attempt/bundle/{d}   | environment bootstrap: bundle by digest  |
//! | GET    | /v1/attempt/harness/{d}  | environment bootstrap: harness artifact  |
//!
//! Bootstrap downloads are authorized per item: only what the attempt's own spec pins can
//! be fetched with its token (runnerd verifies digests again before using anything).

use crate::backend::RunKey;
use crate::codex_refresh::{CodexRefresher, RefreshError, RefreshedTokens};
use crate::creds::CredentialStore;
use crate::metrics::Metrics;
use crate::{record_attempt_finished, token_hash};
use acp_runner_core::credentials::{CredentialMetadata, Provider, fingerprint};
use acp_runner_core::events::{
    AttemptTerminalData, ChangedPath, EventEnvelope, EventKind, EventSource, HeartbeatReply, RunnerDirective,
};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::redact::Redactor;
use acp_runner_core::{AttemptPhase, AttemptSpec, WIRE_VERSION};
use acp_runner_journal::{ArtifactStore, AttemptRow, Journal, JournalError, NewArtifact};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

pub const WIRE_HEADER: &str = "x-acp-runner-wire-version";
pub const MAX_BODY_BYTES: usize = 96 * 1024 * 1024;
const MAX_EVENTS_PER_BATCH: usize = 1000;

pub struct IngestState {
    pub journal: Journal,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub creds: Arc<dyn CredentialStore>,
    pub metrics: Arc<Metrics>,
    /// Triggers an immediate reconcile of the run after terminal reports.
    pub notify: Option<UnboundedSender<RunKey>>,
    pub heartbeat_journal_every: Duration,
    /// Redeliver a directive delivered over this long ago without an ack
    /// (runnerd died mid-directive). Acks arrive on the next heartbeat, so
    /// this must comfortably exceed the heartbeat interval.
    pub directive_redelivery_after: Duration,
    /// Serves pinned harness artifacts to environment bootstraps.
    pub harnesses: Option<Arc<dyn crate::harness::HarnessProvider>>,
    /// Each heartbeat extends the attempt's credential lease to at least now + this window.
    pub lease_heartbeat_window: Duration,
    /// Verifying Codex OAuth refresh (V1a): inject [`CodexRefresher`]. `None`
    /// disables ChatGPT write-back — without a verifier the controller cannot
    /// re-bind the account. Production injects the HTTPS refresher; tests
    /// inject scripted fakes.
    pub codex_refresher: Option<Arc<dyn CodexRefresher>>,
    redactor: Redactor,
}

impl IngestState {
    pub fn new(
        journal: Journal,
        artifacts: Arc<dyn ArtifactStore>,
        creds: Arc<dyn CredentialStore>,
        metrics: Arc<Metrics>,
        notify: Option<UnboundedSender<RunKey>>,
    ) -> Self {
        IngestState {
            journal,
            artifacts,
            creds,
            metrics,
            notify,
            heartbeat_journal_every: Duration::from_secs(60),
            directive_redelivery_after: Duration::from_secs(30),
            harnesses: None,
            lease_heartbeat_window: Duration::from_secs(15 * 60),
            // ChatGPT write-back stays disabled until a refresher is injected
            // (controller prod wiring, or a test fake).
            codex_refresher: None,
            redactor: Redactor::new(),
        }
    }

    pub fn with_harnesses(mut self, h: Arc<dyn crate::harness::HarnessProvider>) -> Self {
        self.harnesses = Some(h);
        self
    }

    /// Queue a provider operation for the environment backed by `attempt_id`
    /// in the durable directive table (V5a: survives restarts, shared across
    /// controller replicas). Returns the row id.
    pub async fn push_env_directive(
        &self,
        attempt_id: Uuid,
        directive: acp_runner_core::events::RunnerDirective,
    ) -> Result<Uuid, JournalError> {
        self.journal.push_env_directive(attempt_id, &directive).await
    }
}

pub fn router(state: Arc<IngestState>) -> Router {
    Router::new()
        .route("/v1/attempt", get(get_spec))
        .route("/v1/attempt/events", post(post_events))
        .route("/v1/attempt/heartbeat", post(post_heartbeat))
        .route("/v1/attempt/artifact", post(post_artifact))
        .route("/v1/attempt/credential", post(post_credential))
        .route("/v1/attempt/overlay/{id}", get(get_overlay))
        .route("/v1/attempt/bundle/{digest}", get(get_bundle))
        .route("/v1/attempt/harness/{digest}", get(get_harness))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl From<JournalError> for ApiError {
    fn from(e: JournalError) -> Self {
        tracing::error!(error = %e, "ingest journal error");
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "journal unavailable".into())
    }
}

type ApiResult<T> = Result<T, ApiError>;

async fn authenticate(st: &IngestState, headers: &HeaderMap, allow_pending: bool) -> ApiResult<AttemptRow> {
    if let Some(v) = headers.get(WIRE_HEADER).and_then(|v| v.to_str().ok())
        && v != WIRE_VERSION.to_string()
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("wire version {v} unsupported (controller speaks {WIRE_VERSION})"),
        ));
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    if token.len() < 32 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid token".into()));
    }
    let a = st
        .journal
        .attempt_by_token_hash(&token_hash(token))
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "unknown token".into()))?;
    let ok = match a.phase() {
        AttemptPhase::Starting | AttemptPhase::Running => true,
        AttemptPhase::Pending => allow_pending,
        _ => false,
    };
    if !ok {
        return Err(ApiError(StatusCode::CONFLICT, format!("attempt is {}", a.phase)));
    }
    Ok(a)
}

async fn get_spec(State(st): State<Arc<IngestState>>, headers: HeaderMap) -> ApiResult<Json<serde_json::Value>> {
    let a = authenticate(&st, &headers, true).await?;
    Ok(Json(a.spec))
}

fn attempt_spec(a: &AttemptRow) -> ApiResult<AttemptSpec> {
    serde_json::from_value(a.spec.clone()).map_err(|_| ApiError(StatusCode::CONFLICT, "attempt spec unreadable".into()))
}

async fn get_overlay(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if !spec.bootstrap.overlays.iter().any(|o| o.artifact_id == id) {
        return Err(ApiError(StatusCode::FORBIDDEN, "overlay is not part of this attempt".into()));
    }
    let bytes = st.artifacts.get_content(id).await?; // verifies the stored sha256
    Ok(([(axum::http::header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn get_bundle(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if !spec.bootstrap.bundles.iter().any(|b| b.digest == digest) {
        return Err(ApiError(StatusCode::FORBIDDEN, "bundle is not part of this attempt".into()));
    }
    let b = st
        .journal
        .get_bundle(&digest)
        .await?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "bundle not stored".into()))?;
    Ok(Json(b).into_response())
}

async fn get_harness(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    axum::extract::Path(digest): axum::extract::Path<String>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    let spec = attempt_spec(&a)?;
    if spec.bootstrap.harness.as_ref().map(|h| h.digest.as_str()) != Some(digest.as_str()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "harness is not part of this attempt".into()));
    }
    let Some(hp) = st.harnesses.clone() else {
        return Err(ApiError(StatusCode::NOT_FOUND, "no harness provider configured".into()));
    };
    let path = hp.open(&digest).await.map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    let file = tokio::fs::File::open(&path).await.map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let body = axum::body::Body::from_stream(tokio_util_stream(file));
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (axum::http::header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

/// Stream a file in chunks (no extra dependency on tokio-util).
fn tokio_util_stream(
    mut file: tokio::fs::File,
) -> impl futures::Stream<Item = Result<Vec<u8>, std::io::Error>> + Send + 'static {
    futures::stream::poll_fn(move |cx| {
        use tokio::io::AsyncRead;
        let mut buf = vec![0u8; 256 * 1024];
        let mut rb = tokio::io::ReadBuf::new(&mut buf);
        match std::pin::Pin::new(&mut file).poll_read(cx, &mut rb) {
            std::task::Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    std::task::Poll::Ready(None)
                } else {
                    buf.truncate(n);
                    std::task::Poll::Ready(Some(Ok(buf)))
                }
            }
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
}

#[derive(Deserialize)]
struct EventBatch {
    events: Vec<EventEnvelope>,
}

#[derive(Serialize)]
struct Accepted {
    accepted: usize,
}

fn run_key_of(journal_run: &acp_runner_journal::RunRow) -> RunKey {
    RunKey {
        namespace: journal_run.k8s_namespace.clone(),
        name: journal_run.k8s_name.clone(),
        uid: journal_run.k8s_uid.clone(),
    }
}

async fn post_events(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(mut batch): Json<EventBatch>,
) -> ApiResult<Json<Accepted>> {
    let a = authenticate(&st, &headers, true).await?;
    if batch.events.len() > MAX_EVENTS_PER_BATCH {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "too many events in batch".into()));
    }
    for ev in &mut batch.events {
        if !ev.kind.runner_may_emit() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("runner may not emit {}", ev.kind)));
        }
        // Defense in depth: runnerd never forwards these from agentd, and the ingest refuses
        // them as well — an agent claim can never become a terminal state, artifact or
        // heartbeat.
        if matches!(ev.source, EventSource::Agent | EventSource::Driver) && !ev.kind.agent_may_emit() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("agent-sourced {} is not accepted", ev.kind)));
        }
        // Reserved Progress categories are runnerd's trust domain (V3b). runnerd
        // renames them to `agent.<category>` itself; a batch that still carries a
        // reserved category with an agent source is forged or stale and rejected.
        if matches!(ev.source, EventSource::Agent | EventSource::Driver)
            && ev.kind == EventKind::Progress
            && ev
                .data
                .get("category")
                .and_then(|c| c.as_str())
                .is_some_and(acp_runner_core::events::is_reserved_agent_category)
        {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "agent-sourced reserved progress category is not accepted".into(),
            ));
        }
        if ev.seq.is_none() {
            return Err(ApiError(StatusCode::BAD_REQUEST, "events must carry seq".into()));
        }
        if ev.source == EventSource::Controller {
            ev.source = EventSource::Runnerd;
        }
        st.redactor.redact_json(&mut ev.data);
        if let Some(raw) = ev.raw.as_mut() {
            st.redactor.redact_json(raw);
        }
    }
    let accepted = st.journal.append_events(a.run_id, Some(a.id), &batch.events).await?;
    // Agent progress (second liveness signal, next to runnerd heartbeats): only events that
    // come from the agent, plus runnerd's report that the agent started / got its input.
    if batch.events.iter().any(|e| {
        (matches!(e.source, EventSource::Agent | EventSource::Driver) && e.kind.counts_as_progress())
            || matches!(e.kind, EventKind::AgentStarted | EventKind::InputSent)
    }) {
        st.journal.touch_progress(a.id, chrono::Utc::now()).await?;
    }
    if let Some(ev) = batch.events.iter().find(|e| e.kind == EventKind::AgentStarted) {
        st.journal
            .transition_attempt(
                a.id,
                &[AttemptPhase::Pending, AttemptPhase::Starting],
                AttemptPhase::Running,
                None,
                None,
            )
            .await?;
        let s = |k: &str| ev.data.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let version = [s("cliVersion"), s("adapterVersion")].into_iter().flatten().collect::<Vec<_>>().join(" / ");
        if !version.is_empty() {
            st.journal.set_attempt_details(a.id, Some(&version), None, None).await?;
        }
    }
    if let Some(rev) = batch.events.iter().find_map(|e| {
        (e.source == EventSource::Runnerd
            && e.kind == EventKind::Progress
            && e.data.get("category").and_then(|c| c.as_str()) == Some("workspace_ready"))
        .then(|| e.data.pointer("/detail/baseRevision").and_then(|r| r.as_str()).map(str::to_string))
        .flatten()
    }) && acp_runner_core::spec::is_safe_revision(&rev)
    {
        st.journal.set_attempt_details(a.id, None, Some(&rev), None).await?;
    }
    if let Some(term) = batch.events.iter().find(|e| e.kind.is_attempt_terminal()) {
        let data: AttemptTerminalData = serde_json::from_value(term.data.clone()).unwrap_or(AttemptTerminalData {
            reason: Some(FailureReason::internal("unparseable terminal event")),
            stop_reason: None,
            summary: None,
            artifact_id: None,
        });
        let mut phase = match term.kind {
            EventKind::AttemptCompleted => AttemptPhase::Succeeded,
            EventKind::AttemptTimedOut => AttemptPhase::TimedOut,
            _ => match &data.reason {
                Some(FailureReason::Cancelled { .. }) => AttemptPhase::Cancelled,
                _ => AttemptPhase::Failed,
            },
        };
        let mut reason = match (phase, data.reason.clone()) {
            (AttemptPhase::Succeeded, _) => None,
            (_, Some(r)) => Some(r),
            (_, None) => Some(FailureReason::internal("runner reported failure without reason")),
        };
        // V3a: the terminal artifact must belong to this attempt. A foreign
        // artifactId fails the attempt with ProtocolError and is never attached.
        let mut artifact_id = data.artifact_id;
        if let Some(id) = artifact_id {
            let owned = match st.artifacts.get_meta(id).await {
                Ok(meta) => meta.attempt_id == a.id && meta.run_id == a.run_id,
                Err(_) => false,
            };
            if !owned {
                tracing::warn!(attempt_id = %a.id, artifact_id = %id, "terminal artifact does not belong to this attempt");
                artifact_id = None;
                phase = AttemptPhase::Failed;
                reason = Some(FailureReason::ProtocolError {
                    detail: format!("terminal artifact {id} does not belong to this attempt"),
                });
            }
        }
        let outcome = json!({"stopReason": data.stop_reason, "summary": data.summary});
        if st.journal.transition_attempt(a.id, &AttemptPhase::ACTIVE, phase, reason.as_ref(), Some(&outcome)).await? {
            if let Some(id) = artifact_id {
                st.journal.set_attempt_details(a.id, None, None, Some(id)).await?;
            }
            record_attempt_finished(&st.metrics, &a, phase, reason.as_ref());
            tracing::info!(run_id = %a.run_id, attempt_id = %a.id, driver = %a.driver, phase = %phase,
                reason = ?reason.as_ref().map(|r| r.code()), "attempt reported terminal state");
            if let Some(n) = &st.notify
                && let Ok(run) = st.journal.get_run(a.run_id).await
            {
                let _ = n.send(run_key_of(&run));
            }
        }
    }
    Ok(Json(Accepted { accepted }))
}

async fn post_heartbeat(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(mut hb): Json<serde_json::Value>,
) -> ApiResult<Response> {
    let a = authenticate(&st, &headers, true).await?;
    st.journal.touch_heartbeat(a.id).await?;
    // A live sandbox keeps its credential lease alive (environment leases span the whole
    // lifetime; a dead sandbox's lease lapses after the window). V10c: the
    // extension never passes the sandbox's hard deadline (lease acquired at
    // ~sandbox creation + hard_deadline); heartbeats past it stop extending.
    let cap = st
        .journal
        .lease_for_attempt(a.id)
        .await?
        .and_then(|l| {
            serde_json::from_value::<acp_runner_core::attempt_spec::AttemptSpec>(a.spec.clone())
                .ok()
                .and_then(|s| chrono::Duration::from_std(s.timeouts.hard_deadline()).ok())
                .map(|d| l.acquired_at + d)
        });
    st.journal.extend_lease(a.id, st.lease_heartbeat_window, cap).await?;
    let lease_expires_at =
        st.journal.lease_for_attempt(a.id).await?.filter(|l| l.released_at.is_none()).map(|l| l.expires_at.timestamp());
    // Explicit directive acks ride on the heartbeat (V5a).
    for id in hb.get("ackedDirectives").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|v| {
        v.as_str().and_then(|s| s.parse::<Uuid>().ok())
    }) {
        st.journal.ack_env_directive(id).await?;
    }
    if st.journal.claim_heartbeat_journal(a.id, st.heartbeat_journal_every).await? {
        st.redactor.redact_json(&mut hb);
        let ev = EventEnvelope::new(EventKind::Heartbeat, EventSource::Runnerd, hb);
        st.journal.append_event(a.run_id, Some(a.id), &ev).await?;
    }
    // Cancel first: a queued snapshot must not delay a cancellation (V5a).
    // Controller decisions travel back on the heartbeat (runnerd has no inbound port).
    if let Some(reason) = a.cancel_request() {
        return Ok(Json(HeartbeatReply {
            directive: Some(RunnerDirective::Cancel { reason }),
            directive_id: None,
            lease_expires_at,
        })
        .into_response());
    }
    if let Some((id, d)) = st.journal.next_env_directive(a.id, st.directive_redelivery_after).await? {
        return Ok(Json(HeartbeatReply { directive: Some(d), directive_id: Some(id), lease_expires_at }).into_response());
    }
    // V10c: attempts holding a credential lease learn its expiry on every
    // heartbeat (quiet ones too); anything else keeps the empty 204.
    if let Some(exp) = lease_expires_at {
        return Ok(Json(HeartbeatReply { directive: None, directive_id: None, lease_expires_at: Some(exp) })
            .into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactUpload {
    kind: String,
    base_revision: String,
    sha256: String,
    changed_paths: Vec<ChangedPath>,
    driver: String,
    #[serde(default)]
    driver_version: Option<String>,
    patch_b64: String,
}

async fn post_artifact(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(up): Json<ArtifactUpload>,
) -> ApiResult<Json<serde_json::Value>> {
    let a = authenticate(&st, &headers, false).await?;
    const KINDS: &[&str] = &["patch", "partial_patch", "snapshot", "final", "partial_final"];
    if !KINDS.contains(&up.kind.as_str()) {
        return Err(ApiError(StatusCode::BAD_REQUEST, format!("unknown artifact kind {:?}", up.kind)));
    }
    if !acp_runner_core::spec::is_safe_revision(&up.base_revision) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid base revision".into()));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(up.patch_b64.as_bytes())
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "patch is not base64".into()))?;
    let limit = serde_json::from_value::<AttemptSpec>(a.spec.clone())
        .map(|s| s.output.max_patch_bytes)
        .unwrap_or(acp_runner_core::spec::DEFAULT_MAX_PATCH_BYTES);
    if bytes.len() as u64 > limit {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, limit.to_string()));
    }
    for p in &up.changed_paths {
        if acp_runner_core::paths::validate_relative_path(&p.path).is_err() {
            return Err(ApiError(StatusCode::BAD_REQUEST, format!("invalid changed path {:?}", p.path)));
        }
    }
    // Lineage is derived server-side from trusted records, never from the upload.
    let environment_id = st.journal.environment_by_attempt(a.id).await?.map(|e| e.id);
    let lineage =
        serde_json::from_value::<AttemptSpec>(a.spec.clone()).map(|s| s.bootstrap.lineage).unwrap_or_default();
    let meta = NewArtifact {
        environment_id,
        parent_artifact_id: lineage.parent_artifact_id,
        parent_environment_id: lineage.parent_environment_id,
        run_id: a.run_id,
        attempt_id: a.id,
        kind: up.kind,
        base_revision: up.base_revision.clone(),
        sha256: up.sha256,
        changed_paths: up.changed_paths,
        driver: if up.driver == a.driver { up.driver } else { a.driver.clone() },
        driver_version: up.driver_version.clone(),
    };
    let stored = match st.artifacts.put(&meta, &bytes).await {
        Ok(s) => s,
        Err(JournalError::TooLarge { limit, .. }) => {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, limit.to_string()));
        }
        Err(JournalError::Invalid(m)) => return Err(ApiError(StatusCode::BAD_REQUEST, m)),
        Err(e) => return Err(e.into()),
    };
    st.journal.set_attempt_details(a.id, up.driver_version.as_deref(), Some(&up.base_revision), None).await?;
    Ok(Json(json!({"artifactId": stored.id, "storage": stored.storage})))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialWriteback {
    key: String,
    content_b64: String,
}

/// Terminal attempts may still hand back credentials for a short window after
/// finishing (finding 10): a cancel racing the final write-back must not lose
/// refreshed tokens, but the lease must still be unreleased (see
/// [`Engine::attempt_cleanup` ordering]).
async fn authenticate_for_credential(st: &IngestState, headers: &HeaderMap) -> ApiResult<AttemptRow> {
    if let Ok(a) = authenticate(st, headers, false).await {
        return Ok(a);
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))?;
    let a = st
        .journal
        .attempt_by_token_hash(&token_hash(token))
        .await?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "unknown token".into()))?;
    let terminal = matches!(
        a.phase(),
        AttemptPhase::Succeeded | AttemptPhase::Failed | AttemptPhase::TimedOut | AttemptPhase::Cancelled
    );
    let recent = a
        .finished_at
        .is_some_and(|f| chrono::Utc::now() - f < chrono::Duration::minutes(10));
    if terminal && recent {
        Ok(a)
    } else {
        Err(ApiError(StatusCode::CONFLICT, format!("attempt is {}", a.phase())))
    }
}

async fn post_credential(
    State(st): State<Arc<IngestState>>,
    headers: HeaderMap,
    Json(wb): Json<CredentialWriteback>,
) -> ApiResult<StatusCode> {
    // Authenticate first so rejections carry the attempt id; the id is the
    // only agent-supplied value ever logged here.
    let a = authenticate_for_credential(&st, &headers).await?;
    let attempt_id = a.id;
    let reject = |reason: &str, m: String| {
        st.metrics.writeback("rejected", reason);
        tracing::warn!(attempt_id = %attempt_id, reason = %m, "credential write-back rejected");
        ApiError(StatusCode::UNPROCESSABLE_ENTITY, m)
    };
    let Some(profile) = a.credential_profile.clone() else {
        return Err(reject("no-lease", "attempt holds no credential".into()));
    };
    // Lock lease AND profile rows before reading anything: enrollment facts
    // below come from the locked row and cannot change mid-flight (no lost
    // update against a concurrent sync_profiles/admin write). A missing
    // profile surfaces here as lease-lost (nothing to write back to).
    let Some(guard) = st.journal.begin_writeback(a.id, &profile).await? else {
        return Err(reject("lease-lost", "attempt no longer holds the credential lease".into()));
    };
    let provider: Provider = guard
        .profile
        .provider
        .parse()
        .map_err(|e: acp_runner_core::credentials::CredentialError| reject("unknown-provider", e.to_string()))?;
    let enrolled: CredentialMetadata = serde_json::from_value(guard.profile.metadata.clone())
        .map_err(|e| reject("bad-enrollment", format!("stored metadata unreadable: {e}")))?;
    // 1c: write-back exists only for the `chatgpt` mode. PAT / agentIdentity
    // profiles never refresh through the sandbox.
    if provider != Provider::Codex || enrolled.auth_kind != "chatgpt" {
        return Err(reject("mode-not-writable", format!("write-back is disabled for {}:{}", provider, enrolled.auth_kind)));
    }
    if !provider.spec().files.iter().any(|f| f.key == wb.key && f.writeback) {
        return Err(reject("key-not-writable", format!("key {:?} is not write-back enabled", wb.key)));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(wb.content_b64.as_bytes())
        .map_err(|_| reject("bad-encoding", "content is not base64".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(reject("too-large", "credential file too large".into()));
    }
    // 1a: trust nothing agent-written except the refresh token itself. The
    // stored file is built controller-side from the provider response.
    let submitted: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| reject("bad-content", "content is not JSON".into()))?;
    let submitted_rt = submitted
        .get("tokens")
        .and_then(|t| t.get("refresh_token"))
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
        .ok_or_else(|| reject("no-refresh-token", "submitted file has no tokens.refresh_token".into()))?;
    let Some(refresher) = st.codex_refresher.clone() else {
        return Err(reject("refresh-unconfigured", "codex refresh verifier is not configured".into()));
    };
    // The guard above already holds both row locks; the refresh happens under
    // them so neither a lease release nor a profile sync can interleave.
    let refreshed: RefreshedTokens = match refresher.refresh(submitted_rt).await {
        Ok(r) => r,
        Err(RefreshError::Permanent { reason }) => {
            return Err(reject("refresh-rejected", format!("provider refused the refresh: {reason}")));
        }
        Err(RefreshError::Transient { reason }) => {
            st.metrics.writeback("rejected", "refresh-unavailable");
            tracing::warn!(attempt_id = %attempt_id, reason = %reason, "credential write-back refresh unavailable");
            return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("token endpoint unavailable: {reason}")));
        }
    };
    // Account binding is enforced here, against the enrolled profile: the
    // provider-response account must equal the enrolled account. Plaintext
    // `tokens.account_id` from the submitted file is never consulted.
    let verified_fp = fingerprint(refreshed.account_id.as_bytes());
    match &enrolled.account_fingerprint {
        Some(e) if *e == verified_fp => {}
        _ => {
            return Err(reject(
                "account-mismatch",
                "provider account does not match the enrolled profile".into(),
            ));
        }
    }
    let new_bytes = serde_json::to_vec(&serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {
            "id_token": refreshed.id_token,
            "access_token": refreshed.access_token,
            "refresh_token": refreshed.refresh_token.as_deref().unwrap_or(submitted_rt),
            "account_id": refreshed.account_id,
        },
        "last_refresh": chrono::Utc::now().to_rfc3339(),
    }))
    .map_err(|_| reject("internal", "failed to encode refreshed credential".into()))?;
    // Structural sanity of the controller-built file; the account fingerprint
    // is then pinned to the provider-response value regardless of what the
    // validator derives from the (controller-written) plaintext.
    let mut md = acp_runner_core::credentials::validate_codex_auth_json(&new_bytes)
        .map_err(|e| reject("internal", format!("built credential invalid: {e}")))?;
    md.account_fingerprint = Some(verified_fp);
    // Store-side compare-and-swap against the locked enrollment baseline: if
    // an admin re-enrolled concurrently, the store no longer holds what we
    // authorized against, and the write is refused instead of clobbering the
    // newer enrollment. (The guard's DB row lock separately serializes
    // profile syncs; the K8s replace adds resourceVersion CAS past the GET.)
    let expected_fp = enrolled.material_fingerprint.as_str();
    if expected_fp.is_empty() {
        return Err(reject("no-baseline", "enrolled profile has no material fingerprint".into()));
    }
    match st.creds.update_file(&profile, &wb.key, &new_bytes, &md, expected_fp).await {
        Ok(()) => {}
        Err(crate::creds::CredStoreError::Conflict(detail)) => {
            st.metrics.writeback("rejected", "store-conflict");
            tracing::warn!(attempt_id = %attempt_id, reason = %detail, "credential write-back store conflict");
            return Err(ApiError(StatusCode::CONFLICT, detail));
        }
        Err(e) => return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("credential store: {e}"))),
    }
    guard
        .commit_metadata(&profile, &serde_json::to_value(&md).unwrap_or_default(), &fingerprint(&new_bytes))
        .await?;
    st.metrics.writeback("accepted", "ok");
    tracing::info!(attempt_id = %attempt_id, profile = %profile, "verified credential written back");
    Ok(StatusCode::NO_CONTENT)
}
