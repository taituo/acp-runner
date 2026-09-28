//! Local protocol between the trusted attempt supervisor (`runnerd`) and the untrusted
//! agent executor (`agentd`).
//!
//! ```text
//! runnerd (TRUSTED)                         agentd (UNTRUSTED trust domain)
//!   attempt token, credential lease,          provider CLI (Codex / Claude / fake),
//!   workspace prepare, journal, heartbeat,    synthetic HOME, disposable workspace
//!   patch collection, credential write-back
//!            │   control: Unix socket /run/acp-runner/agentd.sock
//!            │   frame = u32 big-endian length + JSON
//!            ▼
//!   ToAgent:   Launch, Proceed, Cancel, Finish
//!   FromAgent: Hello, BootstrapDone, Probe, Started, InputSent, Ready, Event, Status, Exit
//!
//!            │   data (environment mode only): Unix socket /run/acp-runner/acp-data.sock
//!            ▼   raw ACP JSON-RPC bytes between the caller (via the gateway) and the harness
//! ```
//!
//! Design rules:
//!
//! * The **control** link is deliberately tiny and is not ACP. In one-shot attempts ACP
//!   stays between agentd (the ACP client) and the CLI.
//! * In environment mode the caller is the ACP client: agentd starts the harness as an ACP
//!   stdio agent and copies bytes between its stdio and the **data** socket; runnerd's
//!   gateway authenticates the caller and relays the same bytes unmodified. Neither side
//!   invents ACP semantics on that path.
//! * Nothing secret flows runnerd -> agentd except what the CLI must have anyway, and that
//!   is staged as files in the synthetic HOME, never inside a frame. The [`AgentLaunchSpec`]
//!   carries no controller URL, no attempt token, no repository URL and no run id.
//! * Everything agentd sends is an *untrusted claim*. runnerd journals agent events with
//!   `source = agent`, computes the patch itself, and decides the terminal state itself.
//!   There is structurally no message by which agentd could submit `AttemptCompleted`,
//!   `ArtifactCreated` or a heartbeat.
//! * Frames are bounded ([`MAX_FRAME_BYTES`]); unknown message types are protocol errors.

use acp_runner_core::events::{
    EventKind, PermissionRequestData, ProgressData, SessionStartedData, ToolCallData, ToolResultData,
};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::{EgressPolicy, PermissionPolicy};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// Version of this local protocol. runnerd and agentd ship in the same image; a mismatch
/// means a broken image and fails the attempt.
pub const PROTOCOL_VERSION: u32 = 1;
/// Upper bound for one frame. Agent events are size-capped before they are framed.
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;
/// Socket file name inside the shared run directory (`/run/acp-runner`).
pub const SOCKET_FILE: &str = "agentd.sock";
/// Environment-mode data socket (raw ACP bytes, harness <-> gateway), same directory.
pub const DATA_SOCKET_FILE: &str = "acp-data.sock";
/// Directory (relative to the synthetic HOME) where runnerd stages credentials that a CLI
/// receives via environment variable. agentd reads and deletes them before starting the CLI.
pub const STAGED_CREDENTIALS_DIR: &str = ".acp-credentials";

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_BYTES} byte limit")]
    TooLarge(u32),
    #[error("malformed message: {0}")]
    Malformed(String),
}

/// Write one frame.
pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(|e| IpcError::Malformed(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| IpcError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one frame. `Ok(None)` on a clean end of stream (peer closed between frames).
pub async fn read_frame<R, T>(r: &mut R) -> Result<Option<T>, IpcError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len);
    if len > MAX_FRAME_BYTES {
        return Err(IpcError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map(Some).map_err(|e| IpcError::Malformed(e.to_string()))
}

// ---- runnerd -> agentd -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ToAgent {
    /// Start the provider CLI for this attempt. Sent exactly once, after the workspace and
    /// the synthetic HOME are ready.
    Launch { spec: Box<AgentLaunchSpec> },
    /// After `BootstrapDone`: runnerd has recorded the workspace state; start the harness.
    Proceed,
    /// One-shot: stop the turn gracefully, then terminate. Environment mode: terminate the
    /// harness (provider cancel). Turn-level cancel in environment mode is plain ACP
    /// `session/cancel` from the caller on the data path.
    Cancel { reason: String },
    /// Environment mode: end the session — terminate the harness, then report `Exit`.
    Finish,
}

/// Sanitized launch description. Contains nothing agentd must not know.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentLaunchSpec {
    /// Attempt id (not secret; used e.g. as Claude Code `--session-id`).
    pub attempt_id: Uuid,
    pub ordinal: u32,
    pub driver: String,
    #[serde(default)]
    pub driver_config: Value,
    /// One-shot prompt (task + rendered resume capsule). `None` in environment mode, where
    /// the caller drives ACP itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Environment mode: start the harness as an ACP stdio agent, connect its stdio to the
    /// data socket ([`DATA_SOCKET_FILE`], next to the control socket) and report `Ready`;
    /// agentd is not the ACP client.
    #[serde(default)]
    pub raw_acp: bool,
    /// Paths as agentd sees them. `workspace` is the working-tree root.
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    /// Harness working directory (validated by runnerd; below `workspace`). Default:
    /// `workspace`. Probe, bootstrap commands (unless they set `cwd`), the harness process
    /// and its tools start here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
    /// Untrusted setup commands: `execve(command, argv, env)` before the harness starts.
    /// agentd reports `BootstrapDone` afterwards and waits for `Proceed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap: Vec<acp_runner_core::environment::BootstrapExec>,
    /// Directories prepended to the agent PATH (materialized harness artifact).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_prepend: Vec<PathBuf>,
    /// Non-secret runner class environment.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Credentials the CLI receives via environment variable, staged as files by runnerd.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_env: Vec<StagedCredentialEnv>,
    pub permissions: PermissionPolicy,
    #[serde(default)]
    pub egress: EgressPolicy,
    pub record_raw: bool,
    pub timeouts: AgentTimeouts,
    #[serde(default)]
    pub skip_probe: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_ca_file: Option<String>,
}

/// `env_name` is set for the CLI process only, from the file at `path` (agentd's view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StagedCredentialEnv {
    pub env_name: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentTimeouts {
    /// Bound for CLI start + protocol handshake.
    pub startup_seconds: u64,
    /// Grace period between a graceful cancel and forced termination of the CLI.
    pub grace_seconds: u64,
    /// Interval of `Status` messages.
    pub status_seconds: u64,
}

// ---- agentd -> runnerd -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum FromAgent {
    Hello {
        protocol: u32,
        agentd_version: String,
        pid: u32,
        #[serde(default)]
        posture: AgentPosture,
    },
    /// All `bootstrap` commands succeeded; agentd waits for `Proceed` before the harness
    /// starts (so runnerd can attribute the setup's workspace changes).
    BootstrapDone {
        steps: u32,
    },
    /// Result of the driver probe (executable, versions, auth state). Never contains
    /// credential values (the report is produced from CLI status output).
    Probe {
        report: Value,
        #[serde(default)]
        executable: Option<String>,
        #[serde(default)]
        cli_version: Option<String>,
        #[serde(default)]
        adapter_version: Option<String>,
    },
    /// The CLI process was started.
    Started {
        program: String,
        #[serde(default)]
        pid: Option<u32>,
    },
    /// The prompt was delivered to the CLI.
    InputSent {
        bytes: usize,
    },
    /// Environment mode: the harness runs and its stdio is connected to the data socket.
    Ready,
    Event {
        event: AgentEvent,
    },
    /// Local liveness of the CLI. Not a heartbeat: only runnerd heartbeats to the controller.
    Status {
        agent_alive: bool,
        #[serde(default)]
        agent_pid: Option<u32>,
    },
    /// Final report. agentd has stopped the CLI when it sends this.
    Exit {
        exit: AgentExit,
    },
}

/// agentd's self-check of its own container, sent in `Hello`. Evidence only (agentd is
/// untrusted); runnerd journals it and, in strict mode, refuses to launch when agentd
/// reports that it can see the attempt secret or the ingest configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPosture {
    pub uid: u32,
    pub attempt_secret_visible: bool,
    pub ingest_env_present: bool,
    pub service_account_token_present: bool,
    /// Another process named `runnerd` is visible in `/proc` (shared PID namespace).
    pub runnerd_process_visible: bool,
}

/// Normalized agent output. These are the only event kinds agentd can produce.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum AgentEvent {
    SessionStarted {
        data: SessionStartedData,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<Value>,
    },
    Output {
        /// `message` or `thought`.
        channel: String,
        text: String,
    },
    ToolCall {
        data: ToolCallData,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<Value>,
    },
    ToolResult {
        data: ToolResultData,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<Value>,
    },
    PermissionRequest {
        data: PermissionRequestData,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<Value>,
    },
    Progress {
        data: ProgressData,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        raw: Option<Value>,
    },
}

impl AgentEvent {
    pub fn event_kind(&self) -> EventKind {
        match self {
            AgentEvent::SessionStarted { .. } => EventKind::SessionStarted,
            AgentEvent::Output { .. } => EventKind::AgentOutput,
            AgentEvent::ToolCall { .. } => EventKind::ToolCall,
            AgentEvent::ToolResult { .. } => EventKind::ToolResult,
            AgentEvent::PermissionRequest { .. } => EventKind::PermissionRequest,
            AgentEvent::Progress { .. } => EventKind::Progress,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentExit {
    pub outcome: AgentOutcome,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    /// Last bytes of the CLI's stderr (unredacted: runnerd redacts).
    #[serde(default)]
    pub stderr_tail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "camelCase", deny_unknown_fields)]
pub enum AgentOutcome {
    /// The prompt turn ended (success = the agent reports normal completion).
    TurnEnded {
        success: bool,
        stop_reason: String,
        #[serde(default)]
        detail: String,
        #[serde(default)]
        summary: Option<String>,
    },
    /// The driver detected a condition that fails the attempt (auth, protocol, ...).
    Failed { reason: FailureReason },
    /// The CLI exited unexpectedly.
    Crashed { detail: String },
    /// Stopped after `Cancel`. `acknowledged` = the CLI ended its turn within the grace
    /// period (otherwise it was terminated by signal).
    Cancelled {
        acknowledged: bool,
        #[serde(default)]
        stop_reason: Option<String>,
    },
}

/// Failure codes agentd may *claim*. Everything else (timeouts, artifact, workspace,
/// sandbox, credential lease, cancellation) is decided by runnerd or the controller.
pub fn agent_may_claim(reason: &FailureReason) -> bool {
    matches!(
        reason,
        FailureReason::AuthEnrollmentRequired { .. }
            | FailureReason::AuthPolicyViolation { .. }
            | FailureReason::Unsupported { .. }
            | FailureReason::ProtocolError { .. }
            | FailureReason::ProcessCrashed { .. }
            | FailureReason::AgentStopped { .. }
            | FailureReason::BootstrapFailed { .. }
            | FailureReason::Internal { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn launch() -> AgentLaunchSpec {
        AgentLaunchSpec {
            attempt_id: Uuid::nil(),
            ordinal: 1,
            driver: "fake".into(),
            driver_config: serde_json::json!({"scenario": "fix"}),
            prompt: Some("fix it".into()),
            raw_acp: false,
            workspace: "/workspace".into(),
            home: "/home/agent".into(),
            tmp: "/tmp".into(),
            workdir: Some("/workspace/app".into()),
            bootstrap: vec![],
            path_prepend: vec![],
            env: BTreeMap::new(),
            credential_env: vec![StagedCredentialEnv {
                env_name: "CLAUDE_CODE_OAUTH_TOKEN".into(),
                path: "/home/agent/.acp-credentials/oauth-token".into(),
            }],
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            record_raw: true,
            timeouts: AgentTimeouts { startup_seconds: 30, grace_seconds: 5, status_seconds: 2 },
            skip_probe: false,
            path_env: None,
            extra_ca_file: None,
        }
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let (mut a, mut b) = duplex(1 << 16);
        let msg = ToAgent::Launch { spec: Box::new(launch()) };
        write_frame(&mut a, &msg).await.unwrap();
        let ev = FromAgent::Event { event: AgentEvent::Output { channel: "message".into(), text: "hello ä".into() } };
        write_frame(&mut a, &ev).await.unwrap();
        drop(a);
        let got: ToAgent = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got, msg);
        let got: FromAgent = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got, ev);
        assert!(read_frame::<_, FromAgent>(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_and_unknown_frames_are_rejected() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            let _ = a.write_all(&(MAX_FRAME_BYTES + 1).to_be_bytes()).await;
        });
        assert!(matches!(read_frame::<_, FromAgent>(&mut b).await, Err(IpcError::TooLarge(_))));
        // An agent cannot invent message types such as a terminal attempt report.
        for forged in [
            r#"{"type":"attemptCompleted","artifactId":"00000000-0000-0000-0000-000000000000"}"#,
            r#"{"type":"heartbeat","agentAlive":true}"#,
            r#"{"type":"event","event":{"kind":"artifactCreated","data":{}}}"#,
            r#"{"type":"event","event":{"kind":"output","channel":"message","text":"x","source":"runnerd"}}"#,
        ] {
            let (mut a, mut b) = duplex(1024);
            let body = forged.as_bytes();
            a.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
            a.write_all(body).await.unwrap();
            let r = read_frame::<_, FromAgent>(&mut b).await;
            assert!(matches!(r, Err(IpcError::Malformed(_))), "{forged} -> {r:?}");
        }
    }

    #[test]
    fn launch_spec_carries_no_controller_identity() {
        let v = serde_json::to_value(launch()).unwrap();
        let keys: Vec<String> = v.as_object().unwrap().keys().map(|k| k.to_ascii_lowercase()).collect();
        for k in &keys {
            for forbidden in ["ingest", "token", "runid", "repository", "secret", "url"] {
                assert!(!k.contains(forbidden), "launch spec has field {k}");
            }
        }
    }

    #[test]
    fn agent_cannot_claim_controller_owned_failures() {
        assert!(agent_may_claim(&FailureReason::AuthEnrollmentRequired { provider: "x".into(), detail: "y".into() }));
        assert!(!agent_may_claim(&FailureReason::NoChanges));
        assert!(!agent_may_claim(&FailureReason::HardTimeout { seconds: 1 }));
        assert!(!agent_may_claim(&FailureReason::Cancelled { detail: String::new() }));
        assert!(!agent_may_claim(&FailureReason::ArtifactTooLarge { size_bytes: 1, limit_bytes: 1 }));
    }
}

// ---- caller <-> gateway (environment mode) ----------------------------------------------

/// Constants of the caller-facing gateway (HTTP/1.1 upgrade, then raw ACP). See
/// `docs/v3-provider-bootstrap.md`.
pub mod gateway {
    /// Upgrade path.
    pub const ACP_PATH: &str = "/v1/acp";
    /// `Upgrade:` token for the raw newline-delimited JSON-RPC stream (ACP's stdio framing).
    pub const RAW_UPGRADE: &str = "acp-ndjson";
    /// Response header: environment id the connection is bound to.
    pub const HDR_ENVIRONMENT: &str = "x-acp-environment";
    /// Response header: the harness working directory to pass as `cwd` in `session/new`.
    pub const HDR_WORKDIR: &str = "x-acp-workdir";
    /// Response header: the environment phase at attach time.
    pub const HDR_PHASE: &str = "x-acp-phase";
    /// Maximum size of one ACP message relayed by the gateway.
    pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
}
