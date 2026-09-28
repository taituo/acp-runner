//! Generic ACP (stdio) agent process, used by the `fake` and `acp` drivers.

use crate::process::{ExitInfo, ManagedChild, SpawnSpec};
use crate::{
    AgentDriver, AgentProcess, AuthState, DriverContext, DriverError, DriverEvent, ProbeReport, ProcessHealth,
    SessionInfo, cfg_env, cfg_str, cfg_str_list, env,
};
use acp_runner_acp::client::{self, InitializeResult};
use acp_runner_acp::normalize::{self, SessionUpdate};
use acp_runner_acp::{AcpError, Connection, Incoming, codes, methods};
use acp_runner_core::events::{PermissionRequestData, ProgressData, ToolCallData, ToolResultData, truncate_utf8};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::PermissionMode;
use async_trait::async_trait;
use nix::sys::signal::Signal;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

const INIT_TIMEOUT: Duration = Duration::from_secs(90);
const SUMMARY_BYTES: usize = 2000;

/// Launch description for an ACP agent process.
#[derive(Debug, Clone)]
pub struct AcpLaunch {
    /// Driver / provider name used in failure messages.
    pub driver: &'static str,
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Harness working directory (V9 `launch.cwd`, workspace-relative).
    pub cwd: std::path::PathBuf,
}

/// The deterministic fake ACP driver (and the base for other ACP drivers).
pub struct AcpDriver {
    pub name: &'static str,
    pub default_command: Option<&'static str>,
}

impl AcpDriver {
    pub fn fake() -> Self {
        AcpDriver { name: "fake", default_command: Some("fake-acp-agent") }
    }

    /// The generic `acp` driver (V9): any stdio ACP CLI via a pure launch
    /// spec. `command` is mandatory — there is no default to guess.
    pub fn generic() -> Self {
        AcpDriver { name: "acp", default_command: None }
    }

    fn launch(&self, ctx: &DriverContext) -> Result<AcpLaunch, DriverError> {
        let program = match cfg_str(&ctx.config, "command").or_else(|| self.default_command.map(str::to_string)) {
            Some(p) if !p.trim().is_empty() => p,
            _ => return Err(DriverError::Config("driver acp requires a launch `command`".into())),
        };
        // V9 `launch.cwd`: workspace-relative, validated like any workdir
        // (no `..`, no absolute paths, no `.git`).
        let cwd = match cfg_str(&ctx.config, "cwd") {
            None => ctx.workspace.clone(),
            Some(c) => acp_runner_core::environment::normalize_workdir(&c)
                .map(|rel| ctx.workspace.join(rel))
                .map_err(|e| DriverError::Config(format!("launch `cwd`: {e}")))?,
        };
        let args = cfg_str_list(&ctx.config, "args");
        let mut driver_env = cfg_env(&ctx.config, "env");
        if let Some(s) = cfg_str(&ctx.config, "scenario") {
            driver_env.push(("FAKE_ACP_SCENARIO".into(), s));
        }
        driver_env.push(("FAKE_ACP_ATTEMPT_ORDINAL".into(), ctx.ordinal.to_string()));
        Ok(AcpLaunch { driver: self.name, program, args, env: env::compose(ctx, &driver_env)?, cwd })
    }
}

#[async_trait]
impl AgentDriver for AcpDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn protocol(&self) -> &'static str {
        "acp/1"
    }

    async fn probe(&self, ctx: &DriverContext) -> Result<ProbeReport, DriverError> {
        let launch = self.launch(ctx)?;
        let (out, _err, code) =
            crate::run_capture(&launch.program, &["--version"], &launch.env, &ctx.workspace, Duration::from_secs(20))
                .await?;
        Ok(ProbeReport {
            driver: self.name.to_string(),
            executable: Some(launch.program),
            cli_version: (code == Some(0)).then(|| out.trim().to_string()),
            adapter_version: None,
            auth: AuthState::NotRequired,
            notes: vec![],
        })
    }

    async fn prepare(&self, ctx: &DriverContext) -> Result<(), DriverError> {
        place_launch_files(ctx)
    }

    async fn spawn(&self, ctx: &DriverContext) -> Result<Box<dyn AgentProcess>, DriverError> {
        let launch = self.launch(ctx)?;
        Ok(Box::new(AcpProcess::spawn(ctx, launch)?))
    }

    fn acp_spawn(&self, ctx: &DriverContext) -> Result<SpawnSpec, DriverError> {
        let l = self.launch(ctx)?;
        Ok(SpawnSpec { program: l.program, args: l.args, env: l.env, cwd: l.cwd,
 secure_cwd: None })
    }
}

/// Write `launch.files` entries into the synthetic HOME (V9): trusted
/// class/run configuration the harness reads at startup. Placement never
/// follows symlinks — an earlier bootstrap step may have planted them, so
/// they are unlinked, not followed, before the file is created.
fn place_launch_files(ctx: &DriverContext) -> Result<(), DriverError> {
    let files = ctx.config.get("files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for f in &files {
        let target = f.get("target").and_then(|v| v.as_str()).ok_or_else(|| {
            DriverError::Config("launch.files entries need a `target` relative to the HOME".into())
        })?;
        let content = f.get("content").and_then(|v| v.as_str()).ok_or_else(|| {
            DriverError::Config(format!("launch.files entry {target:?} needs string `content`"))
        })?;
        let mode = f.get("mode").and_then(|v| v.as_u64()).unwrap_or(0o600) as u32 & 0o777;
        acp_runner_core::paths::replace_beneath(&ctx.home, target, content.as_bytes(), mode)
            .map_err(|e| DriverError::Config(format!("launch.files entry {target:?}: {e}")))?;
    }
    Ok(())
}

pub struct AcpProcess {
    driver: &'static str,
    child: ManagedChild,
    conn: Connection,
    incoming: mpsc::Receiver<Incoming>,
    incoming_closed: bool,
    exit_rx: watch::Receiver<Option<ExitInfo>>,
    exit_seen: Option<ExitInfo>,
    session_id: Option<String>,
    prompt_rx: Option<oneshot::Receiver<Result<Value, AcpError>>>,
    queue: VecDeque<DriverEvent>,
    finished: bool,
    allow_permissions: bool,
    record_raw: bool,
    last_message: String,
    workspace: std::path::PathBuf,
    pub init: Option<InitializeResult>,
}

impl AcpProcess {
    pub fn spawn(ctx: &DriverContext, launch: AcpLaunch) -> Result<AcpProcess, DriverError> {
        let spec =
            SpawnSpec { program: launch.program, args: launch.args, env: launch.env, cwd: launch.cwd,
 secure_cwd: None };
        let mut child = ManagedChild::spawn(&spec)?;
        let stdin = child.take_stdin().ok_or_else(|| DriverError::Spawn("no stdin".into()))?;
        let stdout = child.take_stdout().ok_or_else(|| DriverError::Spawn("no stdout".into()))?;
        let (conn, incoming) = Connection::spawn(stdout, stdin);
        let exit_rx = child.exit_watch();
        Ok(AcpProcess {
            driver: launch.driver,
            child,
            conn,
            incoming,
            incoming_closed: false,
            exit_rx,
            exit_seen: None,
            session_id: None,
            prompt_rx: None,
            queue: VecDeque::new(),
            finished: false,
            allow_permissions: ctx.permissions.mode == PermissionMode::AllowAll,
            record_raw: ctx.record_raw,
            last_message: String::new(),
            workspace: ctx.workspace.clone(),
            init: None,
        })
    }

    fn raw(&self, v: &Value) -> Option<Value> {
        self.record_raw.then(|| v.clone())
    }

    async fn startup_error(&self, e: AcpError, stage: &str) -> DriverError {
        match e {
            AcpError::Rpc { code, ref message, .. } if code == codes::AUTH_REQUIRED => {
                let methods: Vec<String> = self
                    .init
                    .as_ref()
                    .map(|i| i.auth_methods.iter().map(|m| m.id.clone()).collect())
                    .unwrap_or_default();
                DriverError::Auth(FailureReason::AuthEnrollmentRequired {
                    provider: self.driver.to_string(),
                    detail: format!(
                        "{stage}: {message}; the agent offers auth methods {methods:?} but acp-runner never authenticates \
                         interactively — enroll a credential profile with `acp-runnerctl auth enroll`"
                    ),
                })
            }
            AcpError::UnsupportedProtocolVersion { agent, client } => {
                DriverError::Unsupported(format!("{stage}: agent speaks ACP v{agent}, runner supports v{client}"))
            }
            AcpError::Closed => {
                // give the exit status a moment to arrive
                let exit = self.child.wait_timeout(Duration::from_secs(2)).await;
                DriverError::StartupExit(format!("{stage}: agent closed stdout (exit {exit:?})"))
            }
            other => DriverError::Protocol(format!("{stage}: {other}")),
        }
    }

    async fn handle_incoming(&mut self, msg: Incoming) {
        match msg {
            Incoming::Notification { method, params } => self.handle_notification(&method, params),
            Incoming::Request { id, method, params } => self.handle_request(id, &method, params).await,
            Incoming::Invalid { line, error } => self.queue.push_back(DriverEvent::Progress {
                data: ProgressData::new("protocol_warning", format!("ignored non-JSON-RPC output: {error}"))
                    .with_detail(json!({"line": truncate_utf8(&line, 256).0})),
                raw: None,
            }),
        }
    }

    fn handle_notification(&mut self, method: &str, params: Value) {
        let raw = self.raw(&params);
        if method == methods::SESSION_UPDATE {
            match normalize::decode(&params) {
                SessionUpdate::AgentMessageChunk { text } => {
                    self.last_message.push_str(&text);
                    if self.last_message.len() > SUMMARY_BYTES * 2 {
                        let start = self.last_message.len() - SUMMARY_BYTES;
                        let mut s = start;
                        while !self.last_message.is_char_boundary(s) {
                            s += 1;
                        }
                        self.last_message = self.last_message[s..].to_string();
                    }
                    self.queue.push_back(DriverEvent::AgentOutput { channel: "message", text, raw });
                }
                SessionUpdate::AgentThoughtChunk { text } => {
                    self.queue.push_back(DriverEvent::AgentOutput { channel: "thought", text, raw })
                }
                SessionUpdate::UserMessageChunk { .. } => {}
                SessionUpdate::ToolCall { id, title, kind, status, raw_input } => {
                    self.last_message.clear();
                    self.queue.push_back(DriverEvent::ToolCall {
                        data: ToolCallData { tool_call_id: id, title, kind, status, input: raw_input },
                        raw,
                    })
                }
                SessionUpdate::ToolCallUpdate { id, status, title, text } => {
                    let terminal = matches!(status.as_deref(), Some("completed") | Some("failed"));
                    if terminal {
                        let is_error = status.as_deref() == Some("failed");
                        self.queue.push_back(DriverEvent::ToolResult {
                            data: ToolResultData {
                                tool_call_id: id,
                                status: status.unwrap_or_default(),
                                output: text.map(|t| truncate_utf8(&t, 4000).0),
                                is_error,
                            },
                            raw,
                        });
                    } else {
                        self.queue.push_back(DriverEvent::Progress {
                            data: ProgressData::new(
                                "tool_call_update",
                                format!("{} {}", title.unwrap_or_default(), status.unwrap_or_default())
                                    .trim()
                                    .to_string(),
                            )
                            .with_detail(json!({"toolCallId": id})),
                            raw,
                        });
                    }
                }
                SessionUpdate::Plan { entries } => self.queue.push_back(DriverEvent::Progress {
                    data: ProgressData::new("plan", "plan updated").with_detail(json!({"entries": entries})),
                    raw,
                }),
                SessionUpdate::Other { kind } => self.queue.push_back(DriverEvent::Progress {
                    data: ProgressData::new(if kind.is_empty() { "session_update".to_string() } else { kind }, ""),
                    raw,
                }),
            }
        } else if method == "_auth/status_update" {
            // codex-acp extension: surface API-key auth as a policy violation.
            let kind = params.pointer("/authStatus/kind").and_then(|k| k.as_str()).unwrap_or("");
            if kind == "api_key" {
                self.queue.push_back(DriverEvent::Failure {
                    reason: FailureReason::AuthPolicyViolation {
                        detail: format!(
                            "{} reports API-key authentication; acp-runner forbids API-key billing",
                            self.driver
                        ),
                    },
                });
            }
            self.queue.push_back(DriverEvent::Progress {
                data: ProgressData::new("auth_status", kind.to_string()),
                raw: None,
            });
        } else {
            self.queue
                .push_back(DriverEvent::Progress { data: ProgressData::new("notification", method.to_string()), raw });
        }
    }

    async fn handle_request(&mut self, id: Value, method: &str, params: Value) {
        let raw = self.raw(&params);
        if method == methods::SESSION_REQUEST_PERMISSION {
            let title =
                params.pointer("/toolCall/title").and_then(|t| t.as_str()).unwrap_or("permission request").to_string();
            let tool_call_id = params.pointer("/toolCall/toolCallId").and_then(|t| t.as_str()).map(str::to_string);
            let choice = client::choose_permission_option(&params, self.allow_permissions);
            let (response, decision) = match &choice {
                Some(opt) => {
                    (client::permission_selected(opt), if self.allow_permissions { "allowed" } else { "denied" })
                }
                None => (client::permission_cancelled(), "cancelled"),
            };
            let _ = self.conn.respond(id, response).await;
            self.queue.push_back(DriverEvent::PermissionRequest {
                data: PermissionRequestData { tool_call_id, title, decision: decision.to_string(), option_id: choice },
                raw,
            });
        } else {
            // We advertise no fs/terminal capabilities; refuse everything else.
            let _ = self
                .conn
                .respond_error(id, codes::METHOD_NOT_FOUND, &format!("acp-runner client does not implement {method}"))
                .await;
            self.queue.push_back(DriverEvent::Progress {
                data: ProgressData::new("unsupported_client_method", method.to_string()),
                raw,
            });
        }
    }

    fn turn_ended(&mut self, res: Result<Value, AcpError>) {
        match res {
            Ok(v) => {
                let stop = client::stop_reason(&v);
                let success = stop == "end_turn";
                let summary = (!self.last_message.trim().is_empty())
                    .then(|| truncate_utf8(self.last_message.trim(), SUMMARY_BYTES).0);
                self.queue.push_back(DriverEvent::TurnEnded {
                    detail: format!("stopReason={stop}"),
                    stop_reason: stop,
                    success,
                    summary,
                    raw: self.raw(&v),
                });
            }
            Err(AcpError::Closed) => {} // process exit is reported separately
            Err(e) => self.queue.push_back(DriverEvent::TurnEnded {
                stop_reason: "error".into(),
                success: false,
                detail: e.to_string(),
                summary: None,
                raw: None,
            }),
        }
    }
}

#[async_trait]
impl AgentProcess for AcpProcess {
    async fn initialize_session(&mut self) -> Result<SessionInfo, DriverError> {
        let init = match tokio::time::timeout(
            INIT_TIMEOUT,
            client::initialize(&self.conn, "acp-runner", env!("CARGO_PKG_VERSION")),
        )
        .await
        {
            Ok(Ok(i)) => i,
            Ok(Err(e)) => return Err(self.startup_error(e, "initialize").await),
            Err(_) => return Err(DriverError::Timeout("ACP initialize".into())),
        };
        if init.auth_status_kind().as_deref() == Some("api_key") {
            return Err(DriverError::Auth(FailureReason::AuthPolicyViolation {
                detail: format!("{} is configured for API-key authentication", self.driver),
            }));
        }
        self.init = Some(init);
        let session = match tokio::time::timeout(INIT_TIMEOUT, client::new_session(&self.conn, &self.workspace)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(self.startup_error(e, "session/new").await),
            Err(_) => return Err(DriverError::Timeout("ACP session/new".into())),
        };
        self.session_id = Some(session.session_id.clone());
        let init = self.init.as_ref().expect("set above");
        let info = SessionInfo {
            provider_session_id: Some(session.session_id),
            protocol: format!("acp/{}", init.protocol_version),
            agent_name: init.agent_info.name.clone(),
            agent_version: init.agent_info.version.clone(),
            model: session.raw.pointer("/models/currentModelId").and_then(|m| m.as_str()).map(str::to_string),
            capabilities: init.agent_capabilities.clone(),
        };
        let raw = self.record_raw.then(|| json!({"initialize": init.raw, "session/new": session.raw}));
        self.queue.push_back(DriverEvent::SessionStarted { info: info.clone(), raw });
        Ok(info)
    }

    async fn send_prompt(&mut self, text: &str) -> Result<(), DriverError> {
        let sid = self.session_id.clone().ok_or_else(|| DriverError::Protocol("send_prompt before session".into()))?;
        let (tx, rx) = oneshot::channel();
        let conn = self.conn.clone();
        let params = client::prompt_params(&sid, text);
        tokio::spawn(async move {
            let r = conn.request(methods::SESSION_PROMPT, params).await;
            let _ = tx.send(r);
        });
        self.prompt_rx = Some(rx);
        Ok(())
    }

    async fn next_event(&mut self) -> Option<DriverEvent> {
        enum Sel {
            Msg(Option<Incoming>),
            Prompt(Result<Value, AcpError>),
            Exit,
            Drained,
        }
        loop {
            if let Some(ev) = self.queue.pop_front() {
                return Some(ev);
            }
            if self.finished {
                return None;
            }
            if self.exit_seen.is_none() {
                let v = *self.exit_rx.borrow();
                if v.is_some() {
                    self.exit_seen = v;
                }
            }
            if let Some(exit) = self.exit_seen
                && self.incoming_closed
            {
                self.finished = true;
                return Some(DriverEvent::Exited { exit, stderr_tail: self.child.stderr_tail() });
            }
            let incoming_closed = self.incoming_closed;
            let has_prompt = self.prompt_rx.is_some();
            let exit_known = self.exit_seen.is_some();
            let sel = {
                let incoming = &mut self.incoming;
                let prompt_rx = &mut self.prompt_rx;
                let exit_rx = &mut self.exit_rx;
                tokio::select! {
                    biased;
                    m = incoming.recv(), if !incoming_closed => Sel::Msg(m),
                    r = async { prompt_rx.as_mut().expect("guarded").await }, if has_prompt => {
                        Sel::Prompt(r.unwrap_or(Err(AcpError::Closed)))
                    }
                    _ = exit_rx.changed(), if !exit_known => Sel::Exit,
                    // A grandchild may hold stdout open after the agent exited; stop waiting.
                    _ = tokio::time::sleep(Duration::from_secs(3)), if exit_known => Sel::Drained,
                }
            };
            match sel {
                Sel::Msg(Some(m)) => self.handle_incoming(m).await,
                Sel::Msg(None) => self.incoming_closed = true,
                Sel::Prompt(r) => {
                    self.prompt_rx = None;
                    self.turn_ended(r);
                }
                Sel::Exit => {
                    let v = *self.exit_rx.borrow();
                    self.exit_seen = Some(v.unwrap_or_default());
                }
                Sel::Drained => self.incoming_closed = true,
            }
        }
    }

    async fn cancel(&mut self) -> Result<(), DriverError> {
        if let Some(sid) = &self.session_id {
            self.conn
                .notify(methods::SESSION_CANCEL, client::cancel_params(sid))
                .await
                .map_err(|e| DriverError::Io(e.to_string()))?;
        } else {
            self.child.signal(Signal::SIGTERM);
        }
        Ok(())
    }

    fn health(&self) -> ProcessHealth {
        ProcessHealth { pid: Some(self.child.pid), alive: self.child.is_alive() }
    }

    async fn shutdown(&mut self, grace: Duration) -> ExitInfo {
        self.conn.close_input().await;
        if let Some(i) = self.child.wait_timeout(Duration::from_millis(200)).await {
            self.child.signal_group(Signal::SIGKILL);
            return i;
        }
        self.child.terminate(grace).await
    }

    fn stderr_tail(&self) -> String {
        self.child.stderr_tail()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ctx;
    use std::os::unix::fs::PermissionsExt;

    fn ctx_with(config: serde_json::Value, home: std::path::PathBuf) -> DriverContext {
        let mut c = ctx();
        c.config = config;
        c.home = home;
        c
    }

    #[test]
    fn launch_files_land_in_home_without_following_links() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        // a planted symlink at the target is replaced, not followed
        let victim = t.path().join("victim.txt");
        std::fs::write(&victim, "victim").unwrap();
        std::fs::create_dir_all(home.join(".config/opencode")).unwrap();
        std::os::unix::fs::symlink(&victim, home.join(".config/opencode/opencode.json")).unwrap();
        let ctx = ctx_with(
            serde_json::json!({"files": [{"target": ".config/opencode/opencode.json", "content": "{\"model\":\"x\"}"}]}),
            home.clone(),
        );
        place_launch_files(&ctx).unwrap();
        assert_eq!(std::fs::read_to_string(home.join(".config/opencode/opencode.json")).unwrap(), "{\"model\":\"x\"}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim");
        assert_eq!(
            std::fs::metadata(home.join(".config/opencode/opencode.json")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // traversal and missing content are refused
        let bad = ctx_with(serde_json::json!({"files": [{"target": "../x", "content": "y"}]}), home.clone());
        assert!(place_launch_files(&bad).is_err());
        let bad = ctx_with(serde_json::json!({"files": [{"target": "x"}]}), home);
        assert!(place_launch_files(&bad).is_err());
    }
}
