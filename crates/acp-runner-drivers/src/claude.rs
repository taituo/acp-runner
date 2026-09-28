//! Anthropic Claude Code driver — native CLI, **not** an Agent-SDK-based ACP adapter.
//!
//! Why not `@agentclientprotocol/claude-agent-acp`? That adapter is built on the Claude
//! Agent SDK. We run the unmodified `claude` binary directly in its documented
//! non-interactive mode and normalize its `stream-json` output ourselves, which keeps the
//! subscription login path (`claude setup-token` -> `CLAUDE_CODE_OAUTH_TOKEN`) and avoids
//! an extra adapter layer. (As of 2026-09 Anthropic's help center states that Agent SDK,
//! `claude -p` and third-party app usage all still draw from subscription limits; a
//! separate credit pool announced for 2026-06-15 was paused. See README.)
//!
//! Invocation (flags verified against `claude --help` of 2.1.274):
//!
//! ```text
//! claude -p --input-format stream-json --output-format stream-json --verbose \
//!   --session-id <attempt uuid> --permission-mode <mode> --permission-prompts none \
//!   --setting-sources user --strict-mcp-config --no-session-persistence [--model ..] \
//!   [--allowedTools ..] [--disallowedTools ..]
//! ```
//!
//! * `--bare` is NOT used: bare mode ignores `CLAUDE_CODE_OAUTH_TOKEN` (API key only).
//! * `--setting-sources user` + `--strict-mcp-config` keep repository `.claude/settings.json`
//!   hooks and `.mcp.json` servers of the (untrusted) checked-out repo from running.
//! * `--permission-prompts none` (>= 2.1.259): nothing waits for a human; unapproved actions
//!   are denied and reported as `permission_denied` system messages.
//! * Cancellation: SIGINT ends the turn ("To end the turn instead, send SIGINT"); SIGTERM
//!   exits with 143 leaving the turn unfinished — used as the forced step.
//! * Guard: the `system/init` message carries `apiKeySource`; anything other than `none`
//!   means an API key is in use and the attempt fails with `AuthPolicyViolation`.
//! * Auto-update is disabled via `DISABLE_AUTOUPDATER=1` and `DISABLE_UPDATES=1`.

use crate::process::{ExitInfo, ManagedChild, SpawnSpec};
use crate::{
    AgentDriver, AgentProcess, AuthState, DriverContext, DriverError, DriverEvent, ProbeReport, ProcessHealth,
    SessionInfo, cfg_env, cfg_str, cfg_str_list, env,
};
use acp_runner_core::events::{PermissionRequestData, ProgressData, ToolCallData, ToolResultData, truncate_utf8};
use acp_runner_core::failure::FailureReason;
use async_trait::async_trait;
use nix::sys::signal::Signal;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdin;
use tokio::sync::{mpsc, watch};

pub struct ClaudeDriver;

pub const DEFAULT_PERMISSION_MODE: &str = "acceptEdits";
pub const DEFAULT_ALLOWED_TOOLS: &[&str] =
    &["Bash", "Read", "Edit", "Write", "Glob", "Grep", "NotebookEdit", "TodoWrite"];
const PERMISSION_MODES: &[&str] = &["acceptEdits", "auto", "dontAsk", "plan", "manual", "default", "bypassPermissions"];

impl ClaudeDriver {
    fn command(ctx: &DriverContext) -> String {
        cfg_str(&ctx.config, "command").unwrap_or_else(|| "claude".into())
    }

    /// One-shot invocation: [`Self::base_args`] + our session id + no persistence.
    pub fn args(ctx: &DriverContext) -> Result<Vec<String>, DriverError> {
        let mut a = Self::base_args(ctx)?;
        a.extend(["--session-id".to_string(), ctx.attempt_id.to_string(), "--no-session-persistence".to_string()]);
        Ok(a)
    }

    /// Headless stream-json invocation without session selection (the ACP bridge adds
    /// `--session-id <id>` for the first turn and `--resume <id>` for later turns).
    pub fn base_args(ctx: &DriverContext) -> Result<Vec<String>, DriverError> {
        let mode = cfg_str(&ctx.config, "permissionMode").unwrap_or_else(|| DEFAULT_PERMISSION_MODE.into());
        if !PERMISSION_MODES.contains(&mode.as_str()) {
            return Err(DriverError::Config(format!("claude permissionMode {mode:?} not in {PERMISSION_MODES:?}")));
        }
        let mut a = cfg_str_list(&ctx.config, "commandArgs");
        a.extend(
            ["-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose"].map(str::to_string),
        );
        a.extend(["--permission-mode".to_string(), mode]);
        a.extend(["--permission-prompts".to_string(), "none".to_string()]);
        a.extend([
            "--setting-sources".to_string(),
            cfg_str(&ctx.config, "settingSources").unwrap_or_else(|| "user".into()),
        ]);
        a.push("--strict-mcp-config".into());
        if let Some(m) = cfg_str(&ctx.config, "model") {
            a.extend(["--model".to_string(), m]);
        }
        let allowed = match ctx.config.get("allowedTools") {
            Some(_) => cfg_str_list(&ctx.config, "allowedTools"),
            None => DEFAULT_ALLOWED_TOOLS.iter().map(|s| s.to_string()).collect(),
        };
        if !allowed.is_empty() {
            a.extend(["--allowedTools".to_string(), allowed.join(",")]);
        }
        let disallowed = cfg_str_list(&ctx.config, "disallowedTools");
        if !disallowed.is_empty() {
            a.extend(["--disallowedTools".to_string(), disallowed.join(",")]);
        }
        if let Some(s) = cfg_str(&ctx.config, "appendSystemPrompt") {
            a.extend(["--append-system-prompt".to_string(), s]);
        }
        for extra in cfg_str_list(&ctx.config, "extraArgs") {
            if extra == "--bare" || extra.starts_with("--bare=") {
                return Err(DriverError::Config(
                    "--bare ignores CLAUDE_CODE_OAUTH_TOKEN (API-key only); refusing".into(),
                ));
            }
            if ["--session-id", "--resume", "-r", "--continue", "-c"].contains(&extra.as_str()) {
                return Err(DriverError::Config(format!("{extra} is managed by acp-runner")));
            }
            a.push(extra);
        }
        Ok(a)
    }

    fn driver_env(ctx: &DriverContext) -> Vec<(String, String)> {
        let mut e = vec![
            ("CLAUDE_CONFIG_DIR".to_string(), ctx.home.join(".claude").to_string_lossy().to_string()),
            ("DISABLE_AUTOUPDATER".to_string(), "1".to_string()),
            ("DISABLE_UPDATES".to_string(), "1".to_string()),
            ("DISABLE_INSTALLATION_CHECKS".to_string(), "1".to_string()),
        ];
        if ctx.config.get("disableNonessentialTraffic").and_then(|v| v.as_bool()).unwrap_or(true) {
            e.push(("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".into(), "1".into()));
        }
        e.extend(cfg_env(&ctx.config, "env"));
        e
    }
}

#[async_trait]
impl AgentDriver for ClaudeDriver {
    fn name(&self) -> &'static str {
        "claude"
    }

    fn protocol(&self) -> &'static str {
        "claude-stream-json"
    }

    async fn probe(&self, ctx: &DriverContext) -> Result<ProbeReport, DriverError> {
        let envv = env::compose(ctx, &Self::driver_env(ctx))?;
        let cmd = Self::command(ctx);
        let prefix = cfg_str_list(&ctx.config, "commandArgs");
        let with_prefix = |rest: &[&str]| -> Vec<String> {
            prefix.iter().cloned().chain(rest.iter().map(|s| s.to_string())).collect()
        };
        let mut notes = vec![];
        let v_args = with_prefix(&["--version"]);
        let v_refs: Vec<&str> = v_args.iter().map(String::as_str).collect();
        let (out, _, code) = crate::run_capture(&cmd, &v_refs, &envv, &ctx.workspace, Duration::from_secs(30)).await?;
        let cli_version = (code == Some(0)).then(|| out.split_whitespace().next().unwrap_or("").to_string());
        let s_args = with_prefix(&["auth", "status", "--json"]);
        let s_refs: Vec<&str> = s_args.iter().map(String::as_str).collect();
        let auth = match crate::run_capture(&cmd, &s_refs, &envv, &ctx.workspace, Duration::from_secs(30)).await {
            Ok((out, _, _)) => classify_auth_status(&out),
            Err(e) => AuthState::Unknown { detail: e.to_string() },
        };
        if std::path::Path::new("/etc/claude-code").exists() {
            notes.push(
                "managed settings directory /etc/claude-code exists in the image; it could configure apiKeyHelper — \
                 the runtime apiKeySource guard will abort such attempts"
                    .into(),
            );
        }
        if cfg_str(&ctx.config, "permissionMode").as_deref() == Some("bypassPermissions") {
            notes.push(
                "bypassPermissions is documented as recommended only for sandboxes without internet access".into(),
            );
        }
        Ok(ProbeReport {
            driver: "claude".into(),
            executable: crate::codex::resolve_in_path(&cmd, ctx.path_env.as_deref())
                .map(|p| p.to_string_lossy().to_string()),
            cli_version,
            adapter_version: None,
            auth,
            notes,
        })
    }

    async fn prepare(&self, ctx: &DriverContext) -> Result<(), DriverError> {
        let dir = ctx.home.join(".claude");
        tokio::fs::create_dir_all(&dir).await.map_err(|e| DriverError::Io(e.to_string()))?;
        Ok(())
    }

    async fn spawn(&self, ctx: &DriverContext) -> Result<Box<dyn AgentProcess>, DriverError> {
        let spec = SpawnSpec {
            program: Self::command(ctx),
            args: Self::args(ctx)?,
            env: env::compose(ctx, &Self::driver_env(ctx))?,
            cwd: ctx.workspace.clone(),
 secure_cwd: None };
        let mut child = ManagedChild::spawn(&spec)?;
        let stdin = child.take_stdin();
        let stdout = child.take_stdout().ok_or_else(|| DriverError::Spawn("no stdout".into()))?;
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let parsed =
                    serde_json::from_str::<Value>(&line).map_err(|e| (truncate_utf8(&line, 256).0, e.to_string()));
                if tx.send(parsed).await.is_err() {
                    break;
                }
            }
        });
        let exit_rx = child.exit_watch();
        Ok(Box::new(ClaudeProcess {
            child,
            stdin,
            lines: rx,
            lines_closed: false,
            exit_rx,
            exit_seen: None,
            queue: VecDeque::new(),
            finished: false,
            record_raw: ctx.record_raw,
            session_id: ctx.attempt_id.to_string(),
            mapper: StreamMapper::default(),
        }))
    }

    /// Environment mode: the in-tree ACP bridge (`agentd claude-acp-bridge`) wrapping the
    /// unmodified `claude` binary. The bridge inherits this (already composed, credential
    /// carrying) environment and passes it to each `claude` turn process.
    fn acp_spawn(&self, ctx: &DriverContext) -> Result<SpawnSpec, DriverError> {
        let bridge = ctx.bridge_exe.clone().ok_or_else(|| {
            DriverError::Unsupported("claude needs the ACP bridge (agentd) for environment mode".into())
        })?;
        let cfg = crate::claude_acp::BridgeConfig { command: Self::command(ctx), args: Self::base_args(ctx)? };
        let mut envv = env::compose(ctx, &Self::driver_env(ctx))?;
        envv.push((
            crate::claude_acp::CONFIG_ENV.to_string(),
            serde_json::to_string(&cfg).map_err(|e| DriverError::Config(e.to_string()))?,
        ));
        Ok(SpawnSpec {
            program: bridge.to_string_lossy().to_string(),
            args: vec!["claude-acp-bridge".into()],
            env: envv,
            cwd: ctx.workspace.clone(),
 secure_cwd: None })
    }
}

/// Classify `claude auth status --json`.
pub fn classify_auth_status(out: &str) -> AuthState {
    let v: Value = match serde_json::from_str(out.trim()) {
        Ok(v) => v,
        Err(_) => return AuthState::Unknown { detail: "unparseable `claude auth status --json` output".into() },
    };
    let provider = v.get("apiProvider").and_then(|p| p.as_str()).unwrap_or("firstParty");
    if provider != "firstParty" {
        return AuthState::PolicyViolation {
            detail: format!("apiProvider={provider} (cloud provider credentials are not allowed)"),
        };
    }
    if !v.get("loggedIn").and_then(|l| l.as_bool()).unwrap_or(false) {
        return AuthState::EnrollmentRequired { detail: "claude reports loggedIn=false".into() };
    }
    let method = v.get("authMethod").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let lower = method.to_ascii_lowercase();
    if lower.contains("api_key") || lower.contains("apikey") || lower.contains("api-key") || lower.contains("helper") {
        return AuthState::PolicyViolation { detail: format!("authMethod={method}") };
    }
    if lower == "oauth_token" || lower.contains("claude") || lower.contains("oauth") || lower.contains("subscription") {
        return AuthState::Ready { method };
    }
    AuthState::Unknown { detail: format!("unrecognized authMethod {method:?}") }
}

/// Stateful mapping of stream-json messages to driver events.
#[derive(Debug, Default)]
pub struct StreamMapper {
    auth_error_seen: bool,
    last_text: String,
}

const AUTH_ERRORS: &[&str] = &["authentication_failed", "oauth_org_not_allowed"];

impl StreamMapper {
    pub fn map(&mut self, msg: &Value, record_raw: bool) -> Vec<DriverEvent> {
        let raw = || record_raw.then(|| msg.clone());
        let mut out = vec![];
        let ty = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let subtype = msg.get("subtype").and_then(|t| t.as_str()).unwrap_or("");
        match (ty, subtype) {
            ("system", "init") => {
                let key_source = msg.get("apiKeySource").and_then(|k| k.as_str()).unwrap_or("none");
                if key_source != "none" {
                    out.push(DriverEvent::Failure {
                        reason: FailureReason::AuthPolicyViolation {
                            detail: format!(
                                "Claude Code reports apiKeySource={key_source}; API-key billing is forbidden"
                            ),
                        },
                    });
                }
                let s = |k: &str| msg.get(k).and_then(|x| x.as_str()).map(str::to_string);
                out.push(DriverEvent::SessionStarted {
                    info: SessionInfo {
                        provider_session_id: s("session_id"),
                        protocol: "claude-stream-json".into(),
                        agent_name: Some("claude-code".into()),
                        agent_version: s("claude_code_version"),
                        model: s("model"),
                        capabilities: json!({
                            "permissionMode": msg.get("permissionMode"),
                            "tools": msg.get("tools").and_then(|t| t.as_array()).map(|a| a.len()),
                            "capabilities": msg.get("capabilities"),
                            "apiKeySource": key_source,
                        }),
                    },
                    raw: raw(),
                });
            }
            ("system", "api_retry") => {
                let err = msg.get("error").and_then(|e| e.as_str()).unwrap_or("unknown").to_string();
                if AUTH_ERRORS.contains(&err.as_str()) {
                    self.auth_error_seen = true;
                }
                out.push(DriverEvent::Progress {
                    data: ProgressData::new("api_retry", err).with_detail(json!({
                        "attempt": msg.get("attempt"),
                        "maxRetries": msg.get("max_retries"),
                        "status": msg.get("error_status"),
                    })),
                    raw: raw(),
                });
            }
            ("system", "permission_denied") => out.push(DriverEvent::PermissionRequest {
                data: PermissionRequestData {
                    tool_call_id: msg.get("tool_use_id").and_then(|t| t.as_str()).map(str::to_string),
                    title: msg
                        .get("tool_name")
                        .and_then(|t| t.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| "tool".into()),
                    decision: "denied".into(),
                    option_id: None,
                },
                raw: raw(),
            }),
            ("system", other) => {
                out.push(DriverEvent::Progress { data: ProgressData::new(format!("system/{other}"), ""), raw: raw() })
            }
            ("assistant", _) => {
                let blocks = msg.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                let nested = msg.get("parent_tool_use_id").map(|p| !p.is_null()).unwrap_or(false);
                for b in &blocks {
                    match b.get("type").and_then(|t| t.as_str()) {
                        Some("text") => {
                            let text = b.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
                            if !nested {
                                self.last_text = text.clone();
                            }
                            out.push(DriverEvent::AgentOutput { channel: "message", text, raw: raw() });
                        }
                        Some("thinking") => out.push(DriverEvent::AgentOutput {
                            channel: "thought",
                            text: b.get("thinking").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                            raw: None,
                        }),
                        Some("tool_use") => out.push(DriverEvent::ToolCall {
                            data: ToolCallData {
                                tool_call_id: b.get("id").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                                title: b.get("name").and_then(|t| t.as_str()).unwrap_or("tool").to_string(),
                                kind: Some(tool_kind(b.get("name").and_then(|t| t.as_str()).unwrap_or(""))),
                                status: Some("in_progress".into()),
                                input: b.get("input").cloned(),
                            },
                            raw: raw(),
                        }),
                        _ => {}
                    }
                }
            }
            ("user", _) => {
                let blocks = msg.pointer("/message/content").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                for b in &blocks {
                    if b.get("type").and_then(|t| t.as_str()) == Some("tool_result") {
                        let is_error = b.get("is_error").and_then(|e| e.as_bool()).unwrap_or(false);
                        let text = match b.get("content") {
                            Some(Value::String(s)) => s.clone(),
                            Some(Value::Array(a)) => a
                                .iter()
                                .filter_map(|x| x.get("text").and_then(|t| t.as_str()))
                                .collect::<Vec<_>>()
                                .join("\n"),
                            _ => String::new(),
                        };
                        out.push(DriverEvent::ToolResult {
                            data: ToolResultData {
                                tool_call_id: b.get("tool_use_id").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                                status: if is_error { "failed".into() } else { "completed".into() },
                                output: Some(truncate_utf8(&text, 4000).0),
                                is_error,
                            },
                            raw: raw(),
                        });
                    }
                }
            }
            ("result", sub) => {
                let is_error = msg.get("is_error").and_then(|e| e.as_bool()).unwrap_or(sub != "success");
                let result_text = msg.get("result").and_then(|r| r.as_str()).unwrap_or("").to_string();
                let success = sub == "success" && !is_error;
                if !success {
                    let lower = result_text.to_ascii_lowercase();
                    let looks_auth = self.auth_error_seen
                        || lower.contains("/login")
                        || lower.contains("oauth token")
                        || lower.contains("invalid api key")
                        || lower.contains("authentication_error")
                        || lower.contains("login expired");
                    if looks_auth {
                        out.push(DriverEvent::Failure {
                            reason: FailureReason::AuthEnrollmentRequired {
                                provider: "claude".into(),
                                detail: format!(
                                    "Claude Code reported an authentication failure ({}); re-run `claude setup-token` and re-enroll the profile",
                                    truncate_utf8(&result_text, 200).0
                                ),
                            },
                        });
                    }
                }
                let summary =
                    if !result_text.is_empty() { Some(result_text.clone()) } else { Some(self.last_text.clone()) }
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| truncate_utf8(&s, 2000).0);
                out.push(DriverEvent::TurnEnded {
                    stop_reason: if success { "end_turn".into() } else { sub.to_string() },
                    success,
                    detail: format!(
                        "subtype={sub} is_error={is_error} num_turns={} duration_ms={}",
                        msg.get("num_turns").map(|v| v.to_string()).unwrap_or_default(),
                        msg.get("duration_ms").map(|v| v.to_string()).unwrap_or_default()
                    ),
                    summary,
                    raw: raw(),
                });
            }
            ("rate_limit_event", _) => {
                let info = msg.get("rate_limit_info").cloned().unwrap_or(Value::Null);
                out.push(DriverEvent::Progress {
                    data: ProgressData::new(
                        "rate_limit",
                        info.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    )
                    .with_detail(json!({
                        "rateLimitType": info.get("rateLimitType"),
                        "utilization": info.get("utilization"),
                        "resetsAt": info.get("resetsAt"),
                    })),
                    raw: raw(),
                });
            }
            ("stream_event", _) => {}
            (other, _) => out.push(DriverEvent::Progress {
                data: ProgressData::new(if other.is_empty() { "unknown".to_string() } else { other.to_string() }, ""),
                raw: raw(),
            }),
        }
        out
    }
}

fn tool_kind(name: &str) -> String {
    match name {
        "Read" | "NotebookRead" => "read",
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => "edit",
        "Bash" | "BashOutput" | "KillShell" => "execute",
        "Glob" | "Grep" | "LS" => "search",
        "WebFetch" | "WebSearch" => "fetch",
        "TodoWrite" => "think",
        _ => "other",
    }
    .to_string()
}

pub struct ClaudeProcess {
    child: ManagedChild,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<Result<Value, (String, String)>>,
    lines_closed: bool,
    exit_rx: watch::Receiver<Option<ExitInfo>>,
    exit_seen: Option<ExitInfo>,
    queue: VecDeque<DriverEvent>,
    finished: bool,
    record_raw: bool,
    session_id: String,
    mapper: StreamMapper,
}

#[async_trait]
impl AgentProcess for ClaudeProcess {
    async fn initialize_session(&mut self) -> Result<SessionInfo, DriverError> {
        // Claude Code emits `system/init` once the first user message arrives; the
        // SessionStarted event is produced from it. The session id is ours (--session-id).
        if let Some(e) = self.child.wait_timeout(Duration::from_millis(300)).await {
            return Err(DriverError::StartupExit(format!(
                "claude exited immediately ({e:?}): {}",
                truncate_utf8(&self.child.stderr_tail(), 500).0
            )));
        }
        Ok(SessionInfo {
            provider_session_id: Some(self.session_id.clone()),
            protocol: "claude-stream-json".into(),
            agent_name: Some("claude-code".into()),
            agent_version: None,
            model: None,
            capabilities: Value::Null,
        })
    }

    async fn send_prompt(&mut self, text: &str) -> Result<(), DriverError> {
        let mut stdin = self.stdin.take().ok_or_else(|| DriverError::Protocol("prompt already sent".into()))?;
        let msg = json!({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}});
        let mut line = serde_json::to_vec(&msg).map_err(|e| DriverError::Io(e.to_string()))?;
        line.push(b'\n');
        stdin.write_all(&line).await.map_err(|e| DriverError::Io(e.to_string()))?;
        stdin.flush().await.map_err(|e| DriverError::Io(e.to_string()))?;
        // Single-turn attempt: end input so Claude Code exits after the result.
        drop(stdin);
        Ok(())
    }

    async fn next_event(&mut self) -> Option<DriverEvent> {
        enum Sel {
            Line(Option<Result<Value, (String, String)>>),
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
                && self.lines_closed
            {
                self.finished = true;
                return Some(DriverEvent::Exited { exit, stderr_tail: self.child.stderr_tail() });
            }
            let lines_closed = self.lines_closed;
            let exit_known = self.exit_seen.is_some();
            let sel = {
                let lines = &mut self.lines;
                let exit_rx = &mut self.exit_rx;
                tokio::select! {
                    biased;
                    l = lines.recv(), if !lines_closed => Sel::Line(l),
                    _ = exit_rx.changed(), if !exit_known => Sel::Exit,
                    _ = tokio::time::sleep(Duration::from_secs(3)), if exit_known => Sel::Drained,
                }
            };
            match sel {
                Sel::Line(Some(Ok(v))) => {
                    let evs = self.mapper.map(&v, self.record_raw);
                    self.queue.extend(evs);
                }
                Sel::Line(Some(Err((line, err)))) => self.queue.push_back(DriverEvent::Progress {
                    data: ProgressData::new("protocol_warning", format!("ignored non-JSON output: {err}"))
                        .with_detail(json!({"line": line})),
                    raw: None,
                }),
                Sel::Line(None) | Sel::Drained => self.lines_closed = true,
                Sel::Exit => {
                    let v = *self.exit_rx.borrow();
                    self.exit_seen = Some(v.unwrap_or_default());
                }
            }
        }
    }

    async fn cancel(&mut self) -> Result<(), DriverError> {
        self.child.signal(Signal::SIGINT);
        Ok(())
    }

    fn health(&self) -> ProcessHealth {
        ProcessHealth { pid: Some(self.child.pid), alive: self.child.is_alive() }
    }

    async fn shutdown(&mut self, grace: Duration) -> ExitInfo {
        self.stdin.take();
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

    #[test]
    fn args_are_headless_stream_json_and_never_bare() {
        let c = ctx();
        let a = ClaudeDriver::args(&c).unwrap();
        for f in ["-p", "--input-format", "--output-format", "--verbose", "--permission-prompts", "--strict-mcp-config"]
        {
            assert!(a.contains(&f.to_string()), "missing {f}");
        }
        assert!(!a.contains(&"--bare".to_string()));
        let mut c = ctx();
        c.config = json!({"extraArgs": ["--bare"]});
        assert!(ClaudeDriver::args(&c).is_err());
        c.config = json!({"permissionMode": "yolo"});
        assert!(ClaudeDriver::args(&c).is_err());
    }

    #[test]
    fn auth_status_classification() {
        let ready = r#"{"loggedIn":true,"authMethod":"oauth_token","apiProvider":"firstParty"}"#;
        assert!(matches!(classify_auth_status(ready), AuthState::Ready { .. }));
        let key = r#"{"loggedIn":true,"authMethod":"api_key","apiProvider":"firstParty"}"#;
        assert!(matches!(classify_auth_status(key), AuthState::PolicyViolation { .. }));
        let bedrock = r#"{"loggedIn":true,"authMethod":"x","apiProvider":"bedrock"}"#;
        assert!(matches!(classify_auth_status(bedrock), AuthState::PolicyViolation { .. }));
        let out = r#"{"loggedIn":false}"#;
        assert!(matches!(classify_auth_status(out), AuthState::EnrollmentRequired { .. }));
    }

    #[test]
    fn stream_mapping_of_a_recorded_session() {
        let fixture = include_str!("../tests/fixtures/claude-stream.jsonl");
        let mut m = StreamMapper::default();
        let events: Vec<DriverEvent> = fixture
            .lines()
            .filter(|l| !l.trim().is_empty())
            .flat_map(|l| m.map(&serde_json::from_str(l).unwrap(), false))
            .collect();
        let kinds: Vec<&str> = events
            .iter()
            .map(|e| match e {
                DriverEvent::SessionStarted { .. } => "session",
                DriverEvent::AgentOutput { .. } => "output",
                DriverEvent::ToolCall { .. } => "tool_call",
                DriverEvent::ToolResult { .. } => "tool_result",
                DriverEvent::PermissionRequest { .. } => "permission",
                DriverEvent::Progress { .. } => "progress",
                DriverEvent::TurnEnded { .. } => "turn_ended",
                DriverEvent::Failure { .. } => "failure",
                DriverEvent::Exited { .. } => "exited",
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["session", "output", "tool_call", "tool_result", "permission", "progress", "output", "turn_ended"]
        );
        match events.last().unwrap() {
            DriverEvent::TurnEnded { success, stop_reason, summary, .. } => {
                assert!(success);
                assert_eq!(stop_reason, "end_turn");
                assert!(summary.as_deref().unwrap().contains("Fixed"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn api_key_source_is_a_policy_violation() {
        let mut m = StreamMapper::default();
        let evs = m
            .map(&json!({"type":"system","subtype":"init","apiKeySource":"ANTHROPIC_API_KEY","session_id":"x"}), false);
        assert!(matches!(&evs[0], DriverEvent::Failure { reason: FailureReason::AuthPolicyViolation { .. } }));
    }

    #[test]
    fn auth_failure_result_requires_enrollment() {
        let mut m = StreamMapper::default();
        m.map(&json!({"type":"system","subtype":"api_retry","error":"authentication_failed","attempt":1}), false);
        let evs = m.map(&json!({"type":"result","subtype":"error_during_execution","is_error":true,"result":"Failed to authenticate"}), false);
        assert!(matches!(&evs[0], DriverEvent::Failure { reason: FailureReason::AuthEnrollmentRequired { .. } }));
        assert!(matches!(&evs[1], DriverEvent::TurnEnded { success: false, .. }));
    }
}
