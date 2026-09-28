//! The trusted attempt supervisor.
//!
//! runnerd never runs the provider CLI itself. It prepares everything the agent needs,
//! hands a sanitized launch description to agentd over the local socket, and keeps every
//! authoritative decision on its own side of the trust boundary:
//!
//! | concern                     | owner   | how                                                   |
//! |-----------------------------|---------|-------------------------------------------------------|
//! | attempt token, ingest       | runnerd | read from the attempt Secret; never shared            |
//! | workspace at exact revision | runnerd | shallow fetch + checkout, private git dir snapshot    |
//! | credential materialization  | runnerd | whitelisted copies into the synthetic HOME            |
//! | conversation, tool calls    | agentd  | journaled with `source = agent` (untrusted claims)     |
//! | liveness                    | runnerd | heartbeats; agent progress tracked separately         |
//! | hard / no-progress timeouts | runnerd | `Cancel` over IPC, then the sandbox is terminated     |
//! | patch artifact              | runnerd | computed from the working tree vs. the private repo   |
//! | terminal attempt state      | runnerd | decided here; agentd's `Exit` is only an input        |
//! | credential write-back       | runnerd | read without following links, validated by controller |

use crate::agent_link::{AgentConn, AgentListener, AgentdLaunch, reap_spawned};
use crate::home::{PreparedHome, changed_writeback_files, prepare_home};
use crate::posture;
use crate::sink::{ArtifactUpload, EventSink, SinkError};
use acp_runner_core::events::{
    AgentOutputData, AgentStartedData, ArtifactCreatedData, AttemptTerminalData, EventEnvelope, EventKind, EventSource,
    HeartbeatData, InputSentData, ProgressData, RunnerDirective, truncate_utf8,
};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::redact::Redactor;
use acp_runner_core::spec::OutputKind;
use acp_runner_core::{AttemptPhase, AttemptSpec};
use acp_runner_ipc::{
    AgentEvent, AgentExit, AgentLaunchSpec, AgentOutcome, AgentPosture, AgentTimeouts, FromAgent, PROTOCOL_VERSION,
    StagedCredentialEnv, ToAgent, agent_may_claim,
};
use acp_runner_workspace::{CollectOptions, GitWorkspace, WorkspaceError, collect_patch, prepare_with_env};
use base64::Engine as _;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use uuid::Uuid;

const MAX_RAW_BYTES: usize = 32 * 1024;
const OUTPUT_FLUSH_BYTES: usize = 8 * 1024;
const OUTPUT_FLUSH_AFTER: Duration = Duration::from_millis(750);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(600);

/// How agentd sees the shared directories (identical paths unless a local isolation layer
/// remaps them).
#[derive(Debug, Clone)]
pub struct AgentView {
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    /// Materialized harness artifact (read-only for the agent; `/opt/harness`).
    pub harness: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RunnerDirs {
    /// Git working tree, shared with the agent (`/workspace`, the volume root).
    pub workspace: PathBuf,
    /// Synthetic HOME, shared with the agent (`/home/agent`).
    pub home: PathBuf,
    /// Shared run directory holding the agentd socket (`/run/acp-runner`).
    pub run_dir: PathBuf,
    /// runnerd-private state: authoritative git directory, scratch (`/var/lib/acp-runner`).
    pub state: PathBuf,
    /// runnerd's own tmp.
    pub tmp: PathBuf,
    /// Read-only per-attempt secret mount (`/var/run/acp-runner/attempt`).
    pub secret_dir: Option<PathBuf>,
    /// Harness artifact root, written by runnerd only (`/opt/harness`).
    pub harness: PathBuf,
    pub agent: AgentView,
}

impl RunnerDirs {
    /// Local layout below `base` (development, tests). The agent sees the same paths.
    pub fn under(base: &Path, secret_dir: Option<PathBuf>) -> RunnerDirs {
        RunnerDirs {
            workspace: base.join("workspace"),
            home: base.join("home"),
            run_dir: base.join("run"),
            state: base.join("state"),
            tmp: base.join("tmp"),
            secret_dir,
            harness: base.join("harness"),
            agent: AgentView {
                workspace: base.join("workspace"),
                home: base.join("home"),
                tmp: base.join("agent-tmp"),
                harness: base.join("harness"),
            },
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SupervisorOptions {
    /// Fail the attempt if the sandbox posture is violated (set by Kubernetes backends).
    pub strict_posture: bool,
    /// Skip the driver probe (version/auth detection).
    pub skip_probe: bool,
    /// PATH for agent processes.
    pub agent_path_env: Option<String>,
    pub extra_ca_file: Option<String>,
    /// Additional literal secrets to redact (e.g. the ingest token).
    pub extra_secrets: Vec<String>,
    pub agentd: AgentdLaunch,
    /// The controller supervises agent progress (pod mode) and answers heartbeats with a
    /// cancel directive; runnerd's own no-progress watchdog is then only a backstop.
    pub controller_watchdog: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptResult {
    pub phase: AttemptPhase,
    pub reason: Option<FailureReason>,
    pub stop_reason: Option<String>,
    pub summary: Option<String>,
    pub artifact_id: Option<Uuid>,
    pub base_revision: Option<String>,
    pub changed_paths: usize,
    pub driver_version: Option<String>,
}

/// Wraps the sink with redaction, output coalescing and agent-progress tracking.
struct Emitter<'a> {
    sink: &'a mut dyn EventSink,
    redactor: Redactor,
    record_raw: bool,
    out_buf: Option<(String, String, Instant)>,
    /// Last message from the agent that proves progress (not `Status`).
    last_agent_progress: Instant,
    last_message: String,
    stage: &'static str,
    agent_pid: Option<u32>,
    agent_alive: bool,
}

impl<'a> Emitter<'a> {
    fn cap_raw(&self, raw: Option<Value>) -> Option<Value> {
        if !self.record_raw {
            return None;
        }
        let mut raw = raw?;
        self.redactor.redact_json(&mut raw);
        let len = serde_json::to_vec(&raw).map(|v| v.len()).unwrap_or(0);
        if len > MAX_RAW_BYTES { Some(json!({"truncated": true, "bytes": len})) } else { Some(raw) }
    }

    async fn emit_env(&mut self, kind: EventKind, source: EventSource, data: impl Serialize, raw: Option<Value>) {
        if kind != EventKind::AgentOutput {
            self.flush_output().await;
        }
        let mut data = serde_json::to_value(data).unwrap_or(Value::Null);
        self.redactor.redact_json(&mut data);
        let raw = self.cap_raw(raw);
        self.sink.emit(EventEnvelope::new(kind, source, data).with_raw(raw)).await;
    }

    async fn emit(&mut self, kind: EventKind, data: impl Serialize) {
        self.emit_env(kind, EventSource::Runnerd, data, None).await
    }

    async fn progress(&mut self, category: &str, message: &str, detail: Value) {
        self.emit(EventKind::Progress, ProgressData::new(category, message).with_detail(detail)).await
    }

    fn touch(&mut self) {
        self.last_agent_progress = Instant::now();
    }

    async fn output(&mut self, channel: String, text: &str) {
        let channel = if channel == "thought" { channel } else { "message".to_string() };
        if channel == "message" {
            self.last_message.push_str(text);
            if self.last_message.len() > 8192 {
                let mut c = self.last_message.len() - 4096;
                while !self.last_message.is_char_boundary(c) {
                    c += 1;
                }
                self.last_message = self.last_message[c..].to_string();
            }
        }
        match &mut self.out_buf {
            Some((ch, buf, _)) if *ch == channel => buf.push_str(text),
            _ => {
                self.flush_output().await;
                self.out_buf = Some((channel, text.to_string(), Instant::now()));
            }
        }
        let full = self.out_buf.as_ref().map(|(_, b, _)| b.len() >= OUTPUT_FLUSH_BYTES).unwrap_or(false);
        if full {
            self.flush_output().await;
        }
    }

    async fn maybe_flush_output(&mut self) {
        let due = self.out_buf.as_ref().map(|(_, _, t)| t.elapsed() >= OUTPUT_FLUSH_AFTER).unwrap_or(false);
        if due {
            self.flush_output().await;
        }
    }

    async fn flush_output(&mut self) {
        if let Some((channel, text, _)) = self.out_buf.take() {
            let (text, truncated) = truncate_utf8(&self.redactor.redact_string(&text), 16 * 1024);
            let data = AgentOutputData { channel, text, truncated };
            self.sink.emit(EventEnvelope::new(EventKind::AgentOutput, EventSource::Agent, data)).await;
        }
    }

    /// Heartbeat to the controller; returns a directive if the controller sent one.
    async fn heartbeat(&mut self) -> Option<RunnerDirective> {
        self.maybe_flush_output().await;
        let hb = HeartbeatData {
            agent_alive: self.agent_alive,
            agent_pid: self.agent_pid,
            seconds_since_progress: Some(self.last_agent_progress.elapsed().as_secs()),
            stage: self.stage.to_string(),
            // One-shot attempts never consume queued directives (only the
            // journal cancel path): nothing to ack.
            acked_directives: vec![],
        };
        match self.sink.heartbeat(&hb).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "heartbeat failed");
                None
            }
        }
    }

    /// Journal an agent event (`source = agent`).
    async fn agent_event(&mut self, ev: AgentEvent) {
        self.touch();
        match ev {
            AgentEvent::SessionStarted { data, raw } => {
                self.emit_env(EventKind::SessionStarted, EventSource::Agent, data, raw).await
            }
            AgentEvent::Output { channel, text } => self.output(channel, &text).await,
            AgentEvent::ToolCall { data, raw } => {
                self.emit_env(EventKind::ToolCall, EventSource::Agent, data, raw).await
            }
            AgentEvent::ToolResult { data, raw } => {
                self.emit_env(EventKind::ToolResult, EventSource::Agent, data, raw).await
            }
            AgentEvent::PermissionRequest { data, raw } => {
                self.emit_env(EventKind::PermissionRequest, EventSource::Agent, data, raw).await
            }
            AgentEvent::Progress { mut data, raw } => {
                // Reserved categories are runnerd's trust domain: quarantine the
                // agent claim under `agent.<category>` and leave a marker.
                if acp_runner_core::events::is_reserved_agent_category(&data.category) {
                    let original = std::mem::take(&mut data.category);
                    data.category = format!("agent.{original}");
                    self.progress(
                        "protocol_warning",
                        &format!("agent sent reserved progress category {original:?}; renamed"),
                        json!({"category": original}),
                    )
                    .await;
                }
                self.emit_env(EventKind::Progress, EventSource::Agent, data, raw).await
            }
        }
    }
}

async fn with_heartbeats<F: Future>(em: &mut Emitter<'_>, every: Duration, fut: F) -> F::Output {
    tokio::pin!(fut);
    let mut hb = tokio::time::interval(every);
    hb.tick().await;
    loop {
        tokio::select! {
            r = &mut fut => return r,
            _ = hb.tick() => {
                if let Some(d) = em.heartbeat().await {
                    tracing::warn!(directive = ?d, "controller directive received before the agent started; ignored");
                }
            }
        }
    }
}

enum LoopExit {
    Agent(AgentExit),
    /// agentd closed the link (or died) without a final report.
    Lost,
    /// agentd violated the local protocol.
    Protocol(String),
    /// runnerd's own watchdog.
    Timeout(FailureReason),
    /// Controller directive (heartbeat response).
    Directive(FailureReason),
    /// SIGTERM/SIGINT to runnerd (sandbox deletion).
    External,
}

/// agentd's view of its own container violates the split (strict mode only).
fn isolation_violations(p: &AgentPosture) -> Vec<&'static str> {
    let mut v = vec![];
    if p.attempt_secret_visible {
        v.push("the attempt Secret is mounted in the agent container");
    }
    if p.ingest_env_present {
        v.push("runnerd configuration (ACP_RUNNER_*) is present in the agent environment");
    }
    if p.service_account_token_present {
        v.push("a service-account token is mounted in the agent container");
    }
    if p.runnerd_process_visible {
        v.push("runnerd is visible from the agent container (shared PID namespace)");
    }
    v
}

/// Run one attempt end-to-end. Never panics on agent misbehaviour; always reports a
/// terminal event through `sink` (best effort) and returns the result.
pub async fn run_attempt(
    spec: AttemptSpec,
    dirs: RunnerDirs,
    sink: &mut dyn EventSink,
    opts: SupervisorOptions,
    mut external_cancel: watch::Receiver<bool>,
) -> AttemptResult {
    let mut redactor = Redactor::new();
    for s in &opts.extra_secrets {
        redactor.add_secret(s);
    }
    let mut em = Emitter {
        sink,
        redactor,
        record_raw: spec.record_raw_payloads,
        out_buf: None,
        last_agent_progress: Instant::now(),
        last_message: String::new(),
        stage: "preparing",
        agent_pid: None,
        agent_alive: false,
    };
    let mut result = AttemptResult {
        phase: AttemptPhase::Failed,
        reason: None,
        stop_reason: None,
        summary: None,
        artifact_id: None,
        base_revision: None,
        changed_paths: 0,
        driver_version: None,
    };
    let started = Instant::now();
    let hb_every = Duration::from_secs(spec.timeouts.heartbeat_seconds.max(1));
    let grace = Duration::from_secs(spec.timeouts.grace_seconds);
    let startup = Duration::from_secs(spec.timeouts.startup_seconds.max(30));
    em.heartbeat().await;

    // ---- posture -----------------------------------------------------------------------
    for d in [&dirs.workspace, &dirs.home, &dirs.run_dir, &dirs.state, &dirs.tmp] {
        let _ = std::fs::create_dir_all(d);
    }
    let p = posture::check(&dirs.workspace, &dirs.home);
    let violations = p.violations();
    em.progress(
        "sandbox_posture",
        if violations.is_empty() { "ok" } else { "violations" },
        json!({"posture": p, "violations": violations, "strict": opts.strict_posture}),
    )
    .await;
    if opts.strict_posture && !violations.is_empty() {
        let reason =
            FailureReason::SandboxFailed { detail: format!("sandbox posture violated: {}", violations.join("; ")) };
        return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
    }

    // ---- agentd link (bound early so agentd can connect while we prepare) --------------
    let mut listener = match AgentListener::bind(&dirs.run_dir) {
        Ok(l) => l,
        Err(e) => {
            let reason = FailureReason::Internal { detail: format!("binding the agentd socket: {e}") };
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
        }
    };
    if let AgentdLaunch::Spawn { program, env } = &opts.agentd {
        let mut env = env.clone();
        env.push(("HOME".into(), dirs.agent.home.to_string_lossy().to_string()));
        match listener.spawn_agentd(program, &env) {
            Ok(pid) => {
                em.progress(
                    "agentd_spawned",
                    "agentd started by runnerd (local mode: same trust domain, not an isolation boundary)",
                    json!({"pid": pid}),
                )
                .await
            }
            Err(e) => {
                let reason =
                    FailureReason::Unsupported { detail: format!("cannot start agentd {}: {e}", program.display()) };
                return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
            }
        }
    }

    // ---- workspace ---------------------------------------------------------------------
    let net_env: Vec<(String, String)> = spec
        .egress
        .https_proxy
        .iter()
        .flat_map(|p| [("HTTPS_PROXY".to_string(), p.clone()), ("HTTP_PROXY".to_string(), p.clone())])
        .chain(spec.egress.no_proxy.iter().map(|n| ("NO_PROXY".to_string(), n.clone())))
        .collect();
    let prep = with_heartbeats(
        &mut em,
        hb_every,
        tokio::time::timeout(startup, prepare_with_env(&dirs.workspace, &dirs.state, &spec.repository, &net_env)),
    )
    .await;
    let ws: GitWorkspace = match prep {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            let reason = FailureReason::WorkspacePrepareFailed { detail: em.redactor.redact_string(&e.to_string()) };
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
        }
        Err(_) => {
            let reason =
                FailureReason::WorkspacePrepareFailed { detail: format!("git fetch/checkout exceeded {startup:?}") };
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
        }
    };
    result.base_revision = Some(ws.base_sha.clone());
    em.progress("workspace_ready", "workspace prepared", json!({"baseRevision": ws.base_sha, "sparse": ws.sparse}))
        .await;
    if let Some(b64) = &spec.apply_patch_b64 {
        let applied = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(bytes) => ws.apply_patch(&bytes).await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match applied {
            Ok(()) => em.progress("previous_patch_applied", "applied previous attempt's patch", Value::Null).await,
            Err(e) => {
                let reason = FailureReason::WorkspacePrepareFailed { detail: format!("applying previous patch: {e}") };
                return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await;
            }
        }
    }

    // ---- synthetic HOME + credentials --------------------------------------------------
    let prepared_home =
        match prepare_home(&dirs.home, spec.credentials.as_ref(), dirs.secret_dir.as_deref(), &mut em.redactor) {
            Ok(h) => h,
            Err(reason) => return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, None).await,
        };
    if let Some(l) = &spec.credentials {
        em.progress(
            "credentials_placed",
            "credential copies placed in the synthetic HOME",
            json!({"provider": l.provider, "profile": l.profile, "files": l.files.iter().map(|f| &f.target).collect::<Vec<_>>(),
                   "stagedEnv": l.env.iter().map(|e| &e.env_name).collect::<Vec<_>>()}),
        )
        .await;
    }
    let home = Some(&prepared_home);

    // ---- connect agentd ----------------------------------------------------------------
    em.stage = "connecting";
    let accepted = with_heartbeats(&mut em, hb_every, listener.accept(startup)).await;
    let mut conn = match accepted {
        Ok(c) => c,
        Err(e) => {
            let reason = FailureReason::SandboxFailed { detail: format!("agentd: {e}") };
            let (child, _) = listener.reject_further_connections();
            reap_spawned(child, Duration::from_millis(100)).await;
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, home).await;
        }
    };
    let (mut child, _) = listener.reject_further_connections();
    let hello = with_heartbeats(&mut em, hb_every, tokio::time::timeout(Duration::from_secs(30), conn.recv())).await;
    let posture_report = match hello {
        Ok(Some(Ok(FromAgent::Hello { protocol, agentd_version, pid, posture }))) => {
            em.progress(
                "agentd_connected",
                "agentd connected",
                json!({"pid": pid, "peer": conn.peer.map(|(p, u)| json!({"pid": p, "uid": u})),
                       "agentdVersion": agentd_version, "protocol": protocol, "agentReportedPosture": posture}),
            )
            .await;
            if protocol != PROTOCOL_VERSION {
                let reason = FailureReason::Unsupported {
                    detail: format!("agentd speaks local protocol v{protocol}, runnerd v{PROTOCOL_VERSION}"),
                };
                conn.close();
                reap_spawned(child.take(), grace).await;
                return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, home).await;
            }
            posture
        }
        other => {
            let detail = match other {
                Err(_) => "agentd sent no Hello".to_string(),
                Ok(None) => "agentd closed the connection before Hello".to_string(),
                Ok(Some(Err(e))) => format!("malformed Hello: {e}"),
                Ok(Some(Ok(_))) => "first message was not Hello".to_string(),
            };
            conn.close();
            reap_spawned(child.take(), grace).await;
            let reason = FailureReason::ProtocolError { detail: format!("agentd: {detail}") };
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, home).await;
        }
    };
    if opts.strict_posture && !opts.agentd.is_spawn() {
        let v = isolation_violations(&posture_report);
        if !v.is_empty() {
            conn.close();
            let reason = FailureReason::SandboxFailed { detail: format!("agent isolation violated: {}", v.join("; ")) };
            return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, home).await;
        }
    }

    // ---- launch ------------------------------------------------------------------------
    let launch = AgentLaunchSpec {
        attempt_id: spec.attempt_id,
        ordinal: spec.ordinal,
        driver: spec.driver.name.clone(),
        driver_config: spec.driver.config.clone(),
        prompt: Some(spec.prompt.clone()),
        raw_acp: false,
        workdir: None,
        bootstrap: vec![],
        path_prepend: vec![],
        workspace: dirs.agent.workspace.clone(),
        home: dirs.agent.home.clone(),
        tmp: dirs.agent.tmp.clone(),
        env: spec.env.clone(),
        credential_env: prepared_home
            .staged_env
            .iter()
            .map(|s| StagedCredentialEnv { env_name: s.env_name.clone(), path: dirs.agent.home.join(&s.rel) })
            .collect(),
        permissions: spec.permissions,
        egress: spec.egress.clone(),
        record_raw: spec.record_raw_payloads,
        timeouts: AgentTimeouts {
            startup_seconds: spec.timeouts.startup_seconds,
            grace_seconds: spec.timeouts.grace_seconds,
            status_seconds: spec.timeouts.heartbeat_seconds.max(1),
        },
        skip_probe: opts.skip_probe,
        path_env: opts.agent_path_env.clone(),
        extra_ca_file: opts.extra_ca_file.clone(),
    };
    if let Err(e) = conn.send(&ToAgent::Launch { spec: Box::new(launch) }).await {
        conn.close();
        reap_spawned(child.take(), grace).await;
        let reason =
            FailureReason::ProcessCrashed { exit_code: None, signal: None, detail: format!("agentd link: {e}") };
        return finish(&mut em, result, AttemptPhase::Failed, Some(reason), &dirs, home).await;
    }
    em.stage = "starting";
    em.touch();

    // ---- supervise ---------------------------------------------------------------------
    let hard = Duration::from_secs(spec.timeouts.hard_seconds);
    let np = spec.timeouts.no_progress_seconds;
    let no_progress = if opts.controller_watchdog {
        Duration::from_secs(np + spec.timeouts.grace_seconds + 2 * hb_every.as_secs())
    } else {
        Duration::from_secs(np)
    };
    let mut probe_versions: (Option<String>, Option<String>) = (None, None);
    let mut hb = tokio::time::interval(hb_every);
    hb.tick().await;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let exit = loop {
        tokio::select! {
            m = conn.recv() => match m {
                None => break LoopExit::Lost,
                Some(Err(e)) => break LoopExit::Protocol(e),
                Some(Ok(msg)) => match msg {
                    FromAgent::Hello { .. } => break LoopExit::Protocol("duplicate Hello".into()),
                    FromAgent::Probe { report, executable, cli_version, adapter_version } => {
                        em.touch();
                        probe_versions = (cli_version.clone(), adapter_version.clone());
                        result.driver_version = join_versions(&cli_version, &adapter_version);
                        em.emit_env(
                            EventKind::Progress,
                            EventSource::Agent,
                            ProgressData::new("driver_probe", "probe completed")
                                .with_detail(json!({"report": report, "executable": executable})),
                            None,
                        )
                        .await;
                    }
                    FromAgent::Started { program, pid } => {
                        em.touch();
                        em.agent_pid = pid;
                        em.agent_alive = true;
                        let program = truncate_utf8(&program, 128).0;
                        em.emit(EventKind::AgentStarted, AgentStartedData {
                            driver: spec.driver.name.clone(),
                            program,
                            pid,
                            cli_version: probe_versions.0.clone(),
                            adapter_version: probe_versions.1.clone(),
                        }).await;
                    }
                    FromAgent::InputSent { .. } => {
                        em.touch();
                        em.stage = "running";
                        em.emit(EventKind::InputSent, InputSentData {
                            bytes: spec.prompt.len(),
                            sha256: hex::encode(Sha256::digest(spec.prompt.as_bytes())),
                            preview: truncate_utf8(&spec.prompt, 200).0,
                            has_resume_capsule: spec.capsule.is_some(),
                        }).await;
                    }
                    FromAgent::Event { event } => em.agent_event(event).await,
                    FromAgent::Status { agent_alive, agent_pid } => {
                        em.agent_alive = agent_alive;
                        if agent_pid.is_some() {
                            em.agent_pid = agent_pid;
                        }
                    }
                    FromAgent::Ready | FromAgent::BootstrapDone { .. } => {} // environment mode only
                    FromAgent::Exit { exit } => break LoopExit::Agent(exit),
                },
            },
            _ = hb.tick() => {
                if let Some(RunnerDirective::Cancel { reason }) = em.heartbeat().await {
                    break LoopExit::Directive(reason);
                }
            }
            _ = tick.tick() => {
                em.maybe_flush_output().await;
                if started.elapsed() >= hard {
                    break LoopExit::Timeout(FailureReason::HardTimeout { seconds: hard.as_secs() });
                }
                if em.last_agent_progress.elapsed() >= no_progress {
                    break LoopExit::Timeout(FailureReason::NoProgressTimeout { seconds: np });
                }
            }
            changed = external_cancel.changed() => {
                if changed.is_err() || *external_cancel.borrow() {
                    break LoopExit::External;
                }
            }
        }
    };

    // ---- decide ------------------------------------------------------------------------
    em.stage = "finalizing";
    let (phase, reason, stop_reason, summary) = match exit {
        LoopExit::Agent(x) => interpret_exit(&mut em, &spec, x),
        LoopExit::Lost => {
            let (code, signal) = child_exit(&mut child).await;
            let reason = FailureReason::ProcessCrashed {
                exit_code: code,
                signal,
                detail: "agentd disconnected without reporting a result".into(),
            };
            (AttemptPhase::Failed, Some(reason), None, None)
        }
        LoopExit::Protocol(detail) => {
            em.progress("agentd_protocol_violation", &detail, Value::Null).await;
            let reason = FailureReason::ProtocolError { detail: format!("agentd: {detail}") };
            (AttemptPhase::Failed, Some(reason), None, None)
        }
        LoopExit::Timeout(reason) | LoopExit::Directive(reason) => {
            em.stage = "cancelling";
            em.progress("timeout", &reason.message(), json!({"code": reason.code()})).await;
            stop_agent(&mut em, &mut conn, &reason.message(), grace, hb_every).await;
            let phase = if reason.is_timeout() {
                AttemptPhase::TimedOut
            } else if matches!(reason, FailureReason::Cancelled { .. }) {
                AttemptPhase::Cancelled
            } else {
                AttemptPhase::Failed
            };
            (phase, Some(reason), None, None)
        }
        LoopExit::External => {
            em.stage = "cancelling";
            stop_agent(&mut em, &mut conn, "sandbox is being terminated", grace, hb_every).await;
            let reason = FailureReason::Cancelled { detail: "runnerd received SIGTERM".into() };
            (AttemptPhase::Cancelled, Some(reason), None, None)
        }
    };
    let rejected = conn.rejected_connections();
    conn.close();
    reap_spawned(child.take(), Duration::from_secs(2)).await;
    if rejected > 0 {
        em.progress(
            "agentd_extra_connections_rejected",
            "additional connections to the runnerd socket were refused",
            json!({"count": rejected}),
        )
        .await;
    }
    em.agent_alive = false;
    result.stop_reason = stop_reason;
    let summary = summary.or_else(|| {
        let m = em.last_message.trim().to_string();
        (!m.is_empty()).then_some(m)
    });
    result.summary = summary.map(|s| em.redactor.redact_string(&truncate_utf8(&s, 2000).0));

    // ---- artifact (computed by runnerd from the working tree) -------------------------
    let mut phase = phase;
    let mut reason = reason;
    if spec.output.kind == OutputKind::Patch {
        let copts = CollectOptions {
            max_bytes: spec.output.max_patch_bytes,
            allowed_paths: spec.output.allowed_paths.clone(),
            reject_symlink_escape: true,
            exclude_paths: vec![],
            allow_submodules: spec.output.allow_submodules,
        };
        let collected =
            with_heartbeats(&mut em, hb_every, tokio::time::timeout(COLLECT_TIMEOUT, collect_patch(&ws, &copts)))
                .await
                .unwrap_or_else(|_| {
                    Err(WorkspaceError::Policy(format!("patch collection exceeded {COLLECT_TIMEOUT:?}")))
                });
        let driver_version = result.driver_version.clone();
        match (phase, collected) {
            (AttemptPhase::Succeeded, Ok(p)) if p.is_empty() && spec.output.require_changes => {
                phase = AttemptPhase::Failed;
                reason = Some(FailureReason::NoChanges);
            }
            (AttemptPhase::Succeeded, Ok(p)) if p.is_empty() => {}
            (AttemptPhase::Succeeded, Ok(p)) => {
                result.changed_paths = p.changed_paths.len();
                match upload(&mut em, "patch", &p, &spec.driver.name, driver_version).await {
                    Ok(id) => result.artifact_id = Some(id),
                    Err(r) => {
                        phase = AttemptPhase::Failed;
                        reason = Some(r);
                    }
                }
            }
            (AttemptPhase::Succeeded, Err(e)) => {
                phase = AttemptPhase::Failed;
                reason = Some(match e {
                    WorkspaceError::TooLarge { size_bytes, limit_bytes } => {
                        FailureReason::ArtifactTooLarge { size_bytes, limit_bytes }
                    }
                    WorkspaceError::Policy(m) => FailureReason::WorkspacePolicyViolation { detail: m },
                    other => FailureReason::Internal { detail: format!("collecting patch: {other}") },
                });
            }
            (_, Ok(p)) if !p.is_empty() => {
                // Failed attempt: keep the partial patch as a diagnostic / resume input.
                result.changed_paths = p.changed_paths.len();
                if let Ok(id) = upload(&mut em, "partial_patch", &p, &spec.driver.name, driver_version).await {
                    result.artifact_id = Some(id);
                }
            }
            (_, Err(e)) => em.progress("partial_patch_unavailable", &e.to_string(), Value::Null).await,
            _ => {}
        }
    }
    finish(&mut em, result, phase, reason, &dirs, home).await
}

fn join_versions(cli: &Option<String>, adapter: &Option<String>) -> Option<String> {
    let v: Vec<String> = [cli, adapter].iter().filter_map(|x| x.as_ref().map(|s| truncate_utf8(s, 64).0)).collect();
    (!v.is_empty()).then(|| v.join(" / "))
}

async fn child_exit(child: &mut Option<tokio::process::Child>) -> (Option<i32>, Option<i32>) {
    use std::os::unix::process::ExitStatusExt;
    let Some(c) = child.as_mut() else { return (None, None) };
    match tokio::time::timeout(Duration::from_secs(2), c.wait()).await {
        Ok(Ok(st)) => (st.code(), st.signal()),
        _ => (None, None),
    }
}

/// Turn agentd's final report into the attempt outcome. agentd's claims are bounded: it
/// cannot claim failures that runnerd/the controller own, and success still requires the
/// runnerd-computed patch to satisfy the output expectation.
fn interpret_exit(
    em: &mut Emitter<'_>,
    spec: &AttemptSpec,
    x: AgentExit,
) -> (AttemptPhase, Option<FailureReason>, Option<String>, Option<String>) {
    let stderr = em.redactor.redact_string(&truncate_utf8(x.stderr_tail.trim(), 2000).0);
    match x.outcome {
        AgentOutcome::TurnEnded { success: true, stop_reason, summary, .. } => {
            (AttemptPhase::Succeeded, None, Some(stop_reason), summary)
        }
        AgentOutcome::TurnEnded { success: false, stop_reason, detail, summary } => {
            let reason = FailureReason::AgentStopped {
                stop_reason: stop_reason.clone(),
                detail: em.redactor.redact_string(&detail),
            };
            (AttemptPhase::Failed, Some(reason), Some(stop_reason), summary)
        }
        AgentOutcome::Failed { reason } if agent_may_claim(&reason) => {
            let reason = match reason {
                FailureReason::AuthEnrollmentRequired { detail, .. } => {
                    FailureReason::AuthEnrollmentRequired { provider: spec.driver.name.clone(), detail }
                }
                FailureReason::ProcessCrashed { exit_code, signal, detail }
                    if !stderr.is_empty() && !detail.contains("stderr:") =>
                {
                    FailureReason::ProcessCrashed { exit_code, signal, detail: format!("{detail} | stderr: {stderr}") }
                }
                r => r,
            };
            (AttemptPhase::Failed, Some(reason), None, None)
        }
        AgentOutcome::Failed { reason } => {
            let reason = FailureReason::ProtocolError {
                detail: format!("agentd claimed the runner-owned failure {}; ignored", reason.code()),
            };
            (AttemptPhase::Failed, Some(reason), None, None)
        }
        AgentOutcome::Crashed { detail } => {
            let reason = FailureReason::ProcessCrashed {
                exit_code: x.exit_code,
                signal: x.signal,
                detail: format!("{} | stderr: {stderr}", truncate_utf8(&detail, 500).0),
            };
            (AttemptPhase::Failed, Some(reason), None, None)
        }
        AgentOutcome::Cancelled { stop_reason, .. } => {
            let reason = FailureReason::AgentStopped {
                stop_reason: stop_reason.clone().unwrap_or_else(|| "cancelled".into()),
                detail: "the agent reported a cancellation runnerd did not request".into(),
            };
            (AttemptPhase::Failed, Some(reason), stop_reason, None)
        }
    }
}

/// Ask agentd to cancel and wait for its final report (the CLI gets `grace` to end its
/// turn, then agentd needs up to `grace` to terminate it). If agentd does not report in
/// time it is considered unresponsive: in Kubernetes the controller terminates the whole
/// sandbox after the terminal report, so the agent never has to stop itself correctly.
async fn stop_agent(em: &mut Emitter<'_>, conn: &mut AgentConn, why: &str, grace: Duration, hb_every: Duration) {
    if conn.send(&ToAgent::Cancel { reason: why.to_string() }).await.is_err() {
        em.progress("agent_unreachable", "agentd link already closed", Value::Null).await;
        return;
    }
    let wait = grace * 2 + Duration::from_secs(5);
    let deadline = tokio::time::Instant::now() + wait;
    let mut hb = tokio::time::interval(hb_every);
    hb.tick().await;
    loop {
        tokio::select! {
            m = conn.recv() => match m {
                Some(Ok(FromAgent::Exit { exit })) => {
                    let ack = matches!(exit.outcome, AgentOutcome::Cancelled { acknowledged: true, .. });
                    em.progress("agent_stopped", "agentd confirmed the stop",
                        json!({"acknowledged": ack, "exitCode": exit.exit_code, "signal": exit.signal})).await;
                    return;
                }
                Some(Ok(FromAgent::Event { event })) => em.agent_event(event).await,
                Some(Ok(FromAgent::Status { agent_alive, .. })) => em.agent_alive = agent_alive,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    em.progress("agent_stopped", "agentd closed the link", Value::Null).await;
                    return;
                }
            },
            _ = hb.tick() => { let _ = em.heartbeat().await; }
            _ = tokio::time::sleep_until(deadline) => {
                em.progress(
                    "agent_unresponsive",
                    "agentd did not confirm the cancellation in time; the sandbox will be terminated",
                    json!({"waitedSeconds": wait.as_secs()}),
                ).await;
                return;
            }
        }
    }
}

async fn upload(
    em: &mut Emitter<'_>,
    kind: &str,
    p: &acp_runner_workspace::PatchArtifact,
    driver: &str,
    driver_version: Option<String>,
) -> Result<Uuid, FailureReason> {
    let art = ArtifactUpload {
        kind: kind.to_string(),
        base_revision: p.base_sha.clone(),
        sha256: p.sha256.clone(),
        changed_paths: p.changed_paths.clone(),
        driver: driver.to_string(),
        driver_version,
        patch_b64: base64::engine::general_purpose::STANDARD.encode(&p.patch),
    };
    em.flush_output().await;
    match em.sink.upload_artifact(&art).await {
        Ok(acc) => {
            em.emit(
                EventKind::ArtifactCreated,
                ArtifactCreatedData {
                    artifact_id: acc.artifact_id,
                    kind: kind.to_string(),
                    base_revision: p.base_sha.clone(),
                    sha256: p.sha256.clone(),
                    size_bytes: p.size_bytes(),
                    changed_paths: p.changed_paths.clone(),
                    storage: acc.storage,
                },
            )
            .await;
            Ok(acc.artifact_id)
        }
        Err(SinkError::Rejected { status: 413, body }) => Err(FailureReason::ArtifactTooLarge {
            size_bytes: p.size_bytes(),
            limit_bytes: body.trim().parse().unwrap_or(0),
        }),
        Err(e) => Err(FailureReason::Internal { detail: format!("artifact upload failed: {e}") }),
    }
}

async fn finish(
    em: &mut Emitter<'_>,
    mut result: AttemptResult,
    phase: AttemptPhase,
    reason: Option<FailureReason>,
    dirs: &RunnerDirs,
    home: Option<&PreparedHome>,
) -> AttemptResult {
    em.flush_output().await;
    // Hand refreshed credential files back (validated by the controller).
    if let Some(h) = home {
        for (key, bytes) in changed_writeback_files(&dirs.home, h) {
            // The refreshed values are new secrets: redact them from now on (V8.1).
            if let Ok(s) = std::str::from_utf8(&bytes) {
                em.redactor.add_secret(s);
            }
            match em.sink.writeback(&key, &bytes).await {
                Ok(()) => {
                    em.progress("credential_writeback", &format!("refreshed {key} handed back"), Value::Null).await
                }
                Err(e) => em.progress("credential_writeback_failed", &format!("{key}: {e}"), Value::Null).await,
            }
        }
    }
    let reason = reason.map(|r| redact_reason(&em.redactor, r));
    result.phase = phase;
    result.reason = reason.clone();
    let kind = match phase {
        AttemptPhase::Succeeded => EventKind::AttemptCompleted,
        AttemptPhase::TimedOut => EventKind::AttemptTimedOut,
        _ => EventKind::AttemptFailed,
    };
    em.emit(
        kind,
        AttemptTerminalData {
            reason,
            stop_reason: result.stop_reason.clone(),
            summary: result.summary.clone(),
            artifact_id: result.artifact_id,
        },
    )
    .await;
    if let Err(e) = em.sink.flush().await {
        tracing::error!(error = %e, "final event flush failed");
    }
    result
}

fn redact_reason(r: &Redactor, reason: FailureReason) -> FailureReason {
    let mut v = serde_json::to_value(&reason).unwrap_or(Value::Null);
    r.redact_json(&mut v);
    serde_json::from_value(v).unwrap_or(reason)
}
