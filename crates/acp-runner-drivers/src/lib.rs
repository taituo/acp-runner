//! Agent drivers.
//!
//! A driver knows how one coding-agent CLI is prepared, started, spoken to, cancelled and
//! probed. Drivers run only inside **agentd**, the untrusted executor; agentd forwards
//! normalized [`DriverEvent`]s to runnerd over the local socket. runnerd, the engine and the
//! controller never link driver code.
//!
//! Registered drivers:
//!
//! | name     | protocol              | process                                              |
//! |----------|-----------------------|------------------------------------------------------|
//! | `fake`   | ACP v1 (stdio)        | `fake-acp-agent` (deterministic, CI)                 |
//! | `codex`  | ACP v1 (stdio)        | `codex-acp` (pinned `@agentclientprotocol/codex-acp`) which drives the pinned Codex CLI app-server |
//! | `claude` | Claude Code stream-json | the unmodified `claude` binary in `-p` mode (no Agent SDK adapter) |
//!
//! Environment mode (raw ACP dataplane): the caller is the ACP client, so every harness must
//! be startable as an ACP stdio agent ([`AgentDriver::acp_spawn`]). ACP harnesses (fake,
//! Codex via codex-acp) are used as-is; Claude Code is wrapped by the small in-tree ACP
//! bridge ([`claude_acp`], `agentd claude-acp-bridge`) that drives the unmodified `claude`
//! binary per turn (`--session-id` / `--resume`), so the provider only ever sees a normal
//! ACP agent.
//!
//! Adding a driver: implement [`AgentDriver`] in a new module and add it to [`driver_for`].
//! The controller, CRDs and journal need no change (driver name + opaque config).

pub mod acp_driver;
pub mod claude;
pub mod claude_acp;
pub mod codex;
pub mod env;
pub mod process;

use acp_runner_core::events::{PermissionRequestData, ProgressData, ToolCallData, ToolResultData};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::{EgressPolicy, PermissionPolicy};
use acp_runner_workspace::{CollectOptions, GitWorkspace, PatchArtifact, WorkspaceError, collect_patch};
use async_trait::async_trait;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

pub use process::ExitInfo;

/// Everything a driver needs about the attempt it runs in. Built by agentd from runnerd's
/// sanitized launch description.
#[derive(Debug, Clone)]
pub struct DriverContext {
    pub attempt_id: Uuid,
    pub ordinal: u32,
    /// Agent working directory (the git working tree).
    pub workspace: PathBuf,
    /// Synthetic, per-attempt HOME.
    pub home: PathBuf,
    /// Bounded tmpfs for the agent.
    pub tmp: PathBuf,
    /// Opaque driver configuration from the runner class.
    pub config: serde_json::Value,
    /// Non-secret environment from the runner class.
    pub class_env: BTreeMap<String, String>,
    /// Leased credential variables (whitelisted by the provider spec), for the CLI process
    /// only. Secret.
    pub credential_env: Vec<(String, String)>,
    pub permissions: PermissionPolicy,
    pub egress: EgressPolicy,
    pub record_raw: bool,
    /// PATH for agent processes (defaults to the image layout).
    pub path_env: Option<String>,
    /// Extra CA bundle for TLS-intercepting egress proxies.
    pub extra_ca_file: Option<String>,
    /// Executable hosting in-tree ACP bridges (`agentd`), for harnesses that are not ACP
    /// agents themselves.
    pub bridge_exe: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum AuthState {
    /// Usable login state detected (method is a non-secret description).
    Ready {
        method: String,
    },
    /// No usable login: a human must enroll/re-enroll the profile.
    EnrollmentRequired {
        detail: String,
    },
    /// Login state exists but violates policy (API key billing).
    PolicyViolation {
        detail: String,
    },
    /// Driver needs no credentials.
    NotRequired,
    Unknown {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReport {
    pub driver: String,
    pub executable: Option<String>,
    pub cli_version: Option<String>,
    pub adapter_version: Option<String>,
    pub auth: AuthState,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub provider_session_id: Option<String>,
    pub protocol: String,
    pub agent_name: Option<String>,
    pub agent_version: Option<String>,
    pub model: Option<String>,
    pub capabilities: serde_json::Value,
}

/// Normalized driver output. `raw` carries the provider message when raw recording is on.
#[derive(Debug, Clone, PartialEq)]
pub enum DriverEvent {
    SessionStarted {
        info: SessionInfo,
        raw: Option<serde_json::Value>,
    },
    AgentOutput {
        channel: &'static str,
        text: String,
        raw: Option<serde_json::Value>,
    },
    ToolCall {
        data: ToolCallData,
        raw: Option<serde_json::Value>,
    },
    ToolResult {
        data: ToolResultData,
        raw: Option<serde_json::Value>,
    },
    PermissionRequest {
        data: PermissionRequestData,
        raw: Option<serde_json::Value>,
    },
    Progress {
        data: ProgressData,
        raw: Option<serde_json::Value>,
    },
    /// The prompt turn ended. `success` means the agent reports normal completion.
    TurnEnded {
        stop_reason: String,
        success: bool,
        detail: String,
        summary: Option<String>,
        raw: Option<serde_json::Value>,
    },
    /// The driver detected a condition that must fail the attempt (auth policy, ...).
    Failure {
        reason: FailureReason,
    },
    /// The agent process exited.
    Exited {
        exit: ExitInfo,
        stderr_tail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessHealth {
    pub pid: Option<u32>,
    pub alive: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("executable not installed: {0}")]
    NotInstalled(String),
    #[error("failed to spawn agent: {0}")]
    Spawn(String),
    #[error("{0}")]
    Auth(FailureReason),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("agent process exited during startup: {0}")]
    StartupExit(String),
    #[error("i/o error: {0}")]
    Io(String),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("timed out: {0}")]
    Timeout(String),
}

impl DriverError {
    pub fn to_failure(&self, driver: &str) -> FailureReason {
        match self {
            DriverError::NotInstalled(d) => FailureReason::Unsupported { detail: format!("{driver}: {d}") },
            DriverError::Spawn(d) => FailureReason::ProcessCrashed { exit_code: None, signal: None, detail: d.clone() },
            DriverError::Auth(r) => r.clone(),
            DriverError::Protocol(d) => FailureReason::ProtocolError { detail: d.clone() },
            DriverError::StartupExit(d) => {
                FailureReason::ProcessCrashed { exit_code: None, signal: None, detail: d.clone() }
            }
            DriverError::Io(d) => FailureReason::Internal { detail: d.clone() },
            DriverError::Config(d) => FailureReason::Unsupported { detail: d.clone() },
            DriverError::Unsupported(d) => FailureReason::Unsupported { detail: d.clone() },
            DriverError::Timeout(d) => FailureReason::ProtocolError { detail: format!("timeout: {d}") },
        }
    }
}

/// Static description + factory of a driver.
#[async_trait]
pub trait AgentDriver: Send + Sync {
    /// Registry name (`fake`, `codex`, `claude`).
    fn name(&self) -> &'static str;
    /// Wire protocol spoken with the process (`acp/1`, `claude-stream-json`).
    fn protocol(&self) -> &'static str;
    /// Detect executable, version and authentication state without exposing secrets and
    /// without making model requests.
    async fn probe(&self, ctx: &DriverContext) -> Result<ProbeReport, DriverError>;
    /// Lay out driver-owned configuration inside the synthetic HOME (credential files were
    /// already placed by runnerd according to the provider whitelist; env credentials were
    /// staged by runnerd and moved into `credential_env` by agentd).
    async fn prepare(&self, ctx: &DriverContext) -> Result<(), DriverError>;
    /// Start the agent process.
    async fn spawn(&self, ctx: &DriverContext) -> Result<Box<dyn AgentProcess>, DriverError>;
    /// Environment mode: how to start this harness as an ACP stdio agent whose stdio the
    /// caller drives directly (raw ACP dataplane).
    fn acp_spawn(&self, ctx: &DriverContext) -> Result<process::SpawnSpec, DriverError>;
    /// Collect the output artifact. Default: binary git patch of the workspace.
    async fn collect_artifact(
        &self,
        ws: &GitWorkspace,
        opts: &CollectOptions,
    ) -> Result<PatchArtifact, WorkspaceError> {
        collect_patch(ws, opts).await
    }
}

/// A running agent process.
#[async_trait]
pub trait AgentProcess: Send {
    /// Protocol handshake / session creation.
    async fn initialize_session(&mut self) -> Result<SessionInfo, DriverError>;
    /// Start the (single) prompt turn.
    async fn send_prompt(&mut self, text: &str) -> Result<(), DriverError>;
    /// Next normalized event; `None` after the process exited and output was drained.
    async fn next_event(&mut self) -> Option<DriverEvent>;
    /// Graceful cancellation of the current turn (ACP `session/cancel`, SIGINT for Claude).
    async fn cancel(&mut self) -> Result<(), DriverError>;
    fn health(&self) -> ProcessHealth;
    /// Terminate: SIGTERM to the process group, wait `grace`, SIGKILL.
    async fn shutdown(&mut self, grace: Duration) -> ExitInfo;
    /// Last bytes of stderr (unredacted — callers must redact).
    fn stderr_tail(&self) -> String;
}

/// Driver registry.
pub fn driver_for(name: &str) -> Result<Box<dyn AgentDriver>, DriverError> {
    match name {
        "fake" => Ok(Box::new(acp_driver::AcpDriver::fake())),
        "acp" => Ok(Box::new(acp_driver::AcpDriver::generic())),
        "codex" => Ok(Box::new(codex::CodexDriver)),
        "claude" => Ok(Box::new(claude::ClaudeDriver)),
        other => Err(DriverError::Unsupported(format!("unknown driver {other:?} (known: fake, acp, codex, claude)"))),
    }
}

pub const KNOWN_DRIVERS: &[&str] = &["fake", "acp", "codex", "claude"];

/// Run a short command and capture (stdout, stderr, exit code) with a timeout.
pub(crate) async fn run_capture(
    program: &str,
    args: &[&str],
    env: &[(String, String)],
    cwd: &std::path::Path,
    timeout: Duration,
) -> Result<(String, String, Option<i32>), DriverError> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| DriverError::Timeout(format!("{program} {}", args.join(" "))))?
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DriverError::NotInstalled(program.to_string())
            } else {
                DriverError::Io(e.to_string())
            }
        })?;
    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    ))
}

/// Config helpers for opaque driver JSON.
pub(crate) fn cfg_str(cfg: &serde_json::Value, key: &str) -> Option<String> {
    cfg.get(key).and_then(|v| v.as_str()).map(str::to_string).filter(|s| !s.is_empty())
}

pub(crate) fn cfg_str_list(cfg: &serde_json::Value, key: &str) -> Vec<String> {
    cfg.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

pub(crate) fn cfg_env(cfg: &serde_json::Value, key: &str) -> Vec<(String, String)> {
    cfg.get(key)
        .and_then(|v| v.as_object())
        .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn ctx() -> DriverContext {
        DriverContext {
            attempt_id: Uuid::nil(),
            ordinal: 1,
            workspace: std::env::temp_dir(),
            home: std::env::temp_dir().join("acp-home"),
            tmp: std::env::temp_dir(),
            config: serde_json::json!({}),
            class_env: BTreeMap::new(),
            credential_env: vec![],
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            record_raw: true,
            path_env: None,
            extra_ca_file: None,
            bridge_exe: None,
        }
    }

    #[test]
    fn registry_knows_exactly_the_supported_drivers() {
        for d in KNOWN_DRIVERS {
            assert_eq!(driver_for(d).unwrap().name(), *d);
        }
        assert!(driver_for("gemini").is_err());
    }

    #[tokio::test]
    async fn generic_acp_driver_requires_a_command() {
        // V9.1: no default to guess — probe/prepare fail without `command`.
        let d = driver_for("acp").unwrap();
        assert!(matches!(d.probe(&ctx()).await, Err(DriverError::Config(_))));
        let mut c = ctx();
        c.config = serde_json::json!({"command": "/bin/true"});
        assert!(d.probe(&c).await.is_ok());
    }

    #[tokio::test]
    async fn launch_cwd_is_workspace_relative_and_validated() {
        // V9.2: optional `cwd` joins the workspace; traversal is refused.
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("docs")).unwrap();
        let d = driver_for("acp").unwrap();
        let mut c = ctx();
        c.workspace = t.path().to_path_buf();
        c.config = serde_json::json!({"command": "/bin/true", "cwd": "docs"});
        assert!(d.probe(&c).await.is_ok());
        c.config = serde_json::json!({"command": "/bin/true", "cwd": "../evil"});
        assert!(matches!(d.probe(&c).await, Err(DriverError::Config(_))));
        c.config = serde_json::json!({"command": "/bin/true", "cwd": "/abs"});
        assert!(matches!(d.probe(&c).await, Err(DriverError::Config(_))));
    }
}
