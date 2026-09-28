//! A small **ACP agent that wraps the unmodified Claude Code CLI** (`agentd
//! claude-acp-bridge`). Environment mode exposes raw ACP to the caller, so every harness must
//! look like a normal ACP stdio agent; Claude Code speaks its own `-p` stream-json protocol.
//! Instead of normalizing Claude inside the provider, this bridge is the harness:
//!
//! * `initialize` / `session/new` (the bridge keeps the session id and `cwd`),
//! * `session/prompt` → one `claude -p --input-format stream-json --output-format stream-json`
//!   process per turn: `--session-id <id>` for the first turn, `--resume <id>` afterwards
//!   (multi-turn with Claude Code's own session persistence inside the synthetic HOME),
//! * stream-json → `session/update` (`agent_message_chunk`, `agent_thought_chunk`,
//!   `tool_call`, `tool_call_update`) and the prompt response (`stopReason`),
//! * `session/cancel` → SIGINT to the turn process ("end the turn"), `stopReason: cancelled`.
//!
//! It never uses the Agent SDK, never authenticates interactively and keeps the same
//! guards as the one-shot driver: `apiKeySource != none` aborts the turn with an auth policy
//! error; authentication failures map to ACP `AuthRequired` (-32000). Permission prompts are
//! off (`--permission-prompts none`, decided by the configured permission mode), so the
//! bridge never sends `session/request_permission`.

use crate::claude::StreamMapper;
use crate::process::{ManagedChild, SpawnSpec};
use crate::{DriverError, DriverEvent};
use acp_runner_core::failure::FailureReason;
use nix::sys::signal::Signal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Environment variable carrying the [`BridgeConfig`] (JSON; non-secret).
pub const CONFIG_ENV: &str = "ACP_CLAUDE_BRIDGE";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// `claude` executable.
    pub command: String,
    /// Headless stream-json arguments without session selection (see `ClaudeDriver::base_args`).
    pub args: Vec<String>,
}

type Writer = Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>;

struct Session {
    cwd: PathBuf,
    /// Claude Code created the session (saw `system/init`): later turns use `--resume`.
    started: bool,
    /// Running turn: (process id, cancelled flag).
    active: Option<(u32, Arc<AtomicBool>)>,
}

struct Bridge {
    cfg: BridgeConfig,
    env: Vec<(String, String)>,
    out: Writer,
    sessions: Mutex<HashMap<String, Session>>,
}

async fn send(out: &Writer, v: &Value) {
    let mut line = serde_json::to_vec(v).unwrap_or_default();
    line.push(b'\n');
    let mut w = out.lock().await;
    let _ = w.write_all(&line).await;
    let _ = w.flush().await;
}

fn result(id: &Value, r: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": r})
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn update(session_id: &str, u: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session_id, "update": u}})
}

/// Serve ACP on (`input`, `output`) until `input` closes.
pub async fn run_bridge<R, W>(input: R, output: W, cfg: BridgeConfig, env: Vec<(String, String)>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let bridge = Arc::new(Bridge {
        cfg,
        env,
        out: Arc::new(tokio::sync::Mutex::new(Box::new(output))),
        sessions: Mutex::new(HashMap::new()),
    });
    let mut lines = BufReader::new(input).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            send(&bridge.out, &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}))
                .await;
            continue;
        };
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let id = msg.get("id").cloned().filter(|i| !i.is_null());
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        match (method.as_str(), id) {
            ("initialize", Some(id)) => {
                send(
                    &bridge.out,
                    &result(
                        &id,
                        json!({
                            "protocolVersion": 1,
                            "agentInfo": {"name": "claude-acp-bridge", "title": "Claude Code (acp-runner bridge)",
                                          "version": env!("CARGO_PKG_VERSION")},
                            "agentCapabilities": {"loadSession": false,
                                                  "promptCapabilities": {"image": false, "audio": false, "embeddedContext": true}},
                            "authMethods": []
                        }),
                    ),
                )
                .await
            }
            ("session/new", Some(id)) => {
                let cwd = params
                    .get("cwd")
                    .and_then(|c| c.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
                if !cwd.is_absolute() {
                    send(&bridge.out, &error(&id, -32602, "cwd must be an absolute path")).await;
                    continue;
                }
                let sid = uuid::Uuid::new_v4().to_string();
                bridge.sessions.lock().expect("lock").insert(sid.clone(), Session { cwd, started: false, active: None });
                send(&bridge.out, &result(&id, json!({"sessionId": sid}))).await;
            }
            ("session/prompt", Some(id)) => {
                let sid = params.get("sessionId").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let text = prompt_text(&params);
                let cancelled = Arc::new(AtomicBool::new(false));
                // Ok((cwd, resume)) | Err(error reply)
                let claimed = {
                    let mut sessions = bridge.sessions.lock().expect("lock");
                    match sessions.get_mut(&sid) {
                        None => Err(error(&id, -32602, "unknown sessionId")),
                        Some(s) if s.active.is_some() => {
                            Err(error(&id, -32002, "a prompt turn is already running in this session"))
                        }
                        Some(s) => {
                            s.active = Some((0, cancelled.clone()));
                            Ok((s.cwd.clone(), s.started))
                        }
                    }
                };
                let (cwd, resume) = match claimed {
                    Ok(v) => v,
                    Err(reply) => {
                        send(&bridge.out, &reply).await;
                        continue;
                    }
                };
                let b = bridge.clone();
                tokio::spawn(async move {
                    let reply = b.turn(&id, &sid, &cwd, resume, &text, cancelled).await;
                    if let Some(s) = b.sessions.lock().expect("lock").get_mut(&sid) {
                        s.active = None;
                    }
                    send(&b.out, &reply).await;
                });
            }
            ("session/cancel", None) => {
                let sid = params.get("sessionId").and_then(|s| s.as_str()).unwrap_or("");
                if let Some((pid, flag)) = bridge.sessions.lock().expect("lock").get(sid).and_then(|s| s.active.clone()) {
                    flag.store(true, Ordering::SeqCst);
                    if pid > 0 {
                        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), Signal::SIGINT);
                    }
                }
            }
            (_, Some(id)) if !method.is_empty() => {
                send(&bridge.out, &error(&id, -32601, &format!("method not supported by the Claude bridge: {method}")))
                    .await
            }
            _ => {} // notifications we do not handle, and responses (we send no requests)
        }
    }
    Ok(())
}

/// Text of an ACP prompt (text blocks and embedded text resources).
fn prompt_text(params: &Value) -> String {
    let mut out = vec![];
    for b in params.get("prompt").and_then(|p| p.as_array()).into_iter().flatten() {
        match b.get("type").and_then(|t| t.as_str()) {
            Some("text") => out.push(b.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string()),
            Some("resource") => {
                if let Some(t) = b.pointer("/resource/text").and_then(|t| t.as_str()) {
                    let uri = b.pointer("/resource/uri").and_then(|u| u.as_str()).unwrap_or("resource");
                    out.push(format!("<resource uri=\"{uri}\">\n{t}\n</resource>"));
                }
            }
            Some("resource_link") => {
                if let Some(u) = b.get("uri").and_then(|u| u.as_str()) {
                    out.push(format!("(resource: {u})"));
                }
            }
            _ => {}
        }
    }
    out.join("\n")
}

impl Bridge {
    /// Run one turn; returns the JSON-RPC response for the prompt request.
    async fn turn(
        &self,
        id: &Value,
        sid: &str,
        cwd: &std::path::Path,
        resume: bool,
        text: &str,
        cancelled: Arc<AtomicBool>,
    ) -> Value {
        let mut args = self.cfg.args.clone();
        args.extend([if resume { "--resume" } else { "--session-id" }.to_string(), sid.to_string()]);
        let spec = SpawnSpec { program: self.cfg.command.clone(), args, env: self.env.clone(), cwd: cwd.to_path_buf(),
 secure_cwd: None };
        let mut child = match ManagedChild::spawn(&spec) {
            Ok(c) => c,
            Err(DriverError::NotInstalled(p)) => return error(id, -32603, &format!("claude not installed: {p}")),
            Err(e) => return error(id, -32603, &format!("starting claude: {e}")),
        };
        if let Some(s) = self.sessions.lock().expect("lock").get_mut(sid) {
            s.active = Some((child.pid, cancelled.clone()));
        }
        if cancelled.load(Ordering::SeqCst) {
            child.signal(Signal::SIGINT);
        }
        if let Some(mut stdin) = child.take_stdin() {
            let msg = json!({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}});
            let mut line = serde_json::to_vec(&msg).unwrap_or_default();
            line.push(b'\n');
            let _ = stdin.write_all(&line).await;
            let _ = stdin.flush().await;
            drop(stdin); // one user message per process: claude exits after the result
        }
        let Some(stdout) = child.take_stdout() else {
            return error(id, -32603, "claude has no stdout");
        };
        let mut mapper = StreamMapper::default();
        let mut lines = BufReader::new(stdout).lines();
        let mut ended: Option<(bool, String, String)> = None;
        let mut failure: Option<FailureReason> = None;
        let mut saw_init = false;
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            for ev in mapper.map(&v, false) {
                match ev {
                    DriverEvent::SessionStarted { .. } => saw_init = true,
                    DriverEvent::AgentOutput { channel, text, .. } => {
                        let kind = if channel == "thought" { "agent_thought_chunk" } else { "agent_message_chunk" };
                        send(&self.out, &update(sid, json!({"sessionUpdate": kind, "content": {"type": "text", "text": text}})))
                            .await;
                    }
                    DriverEvent::ToolCall { data, .. } => {
                        send(
                            &self.out,
                            &update(
                                sid,
                                json!({"sessionUpdate": "tool_call", "toolCallId": data.tool_call_id, "title": data.title,
                                       "kind": data.kind, "status": "in_progress", "rawInput": data.input}),
                            ),
                        )
                        .await
                    }
                    DriverEvent::ToolResult { data, .. } => {
                        send(
                            &self.out,
                            &update(
                                sid,
                                json!({"sessionUpdate": "tool_call_update", "toolCallId": data.tool_call_id,
                                       "status": if data.is_error { "failed" } else { "completed" },
                                       "content": [{"type": "content", "content": {"type": "text", "text": data.output.unwrap_or_default()}}]}),
                            ),
                        )
                        .await
                    }
                    DriverEvent::PermissionRequest { data, .. } => {
                        if let Some(tc) = data.tool_call_id {
                            send(
                                &self.out,
                                &update(
                                    sid,
                                    json!({"sessionUpdate": "tool_call_update", "toolCallId": tc, "status": "failed",
                                           "content": [{"type": "content", "content": {"type": "text",
                                                        "text": format!("{} denied by the permission policy", data.title)}}]}),
                                ),
                            )
                            .await
                        }
                    }
                    DriverEvent::TurnEnded { success, stop_reason, detail, .. } => {
                        ended = Some((success, stop_reason, detail))
                    }
                    DriverEvent::Failure { reason } => {
                        // auth policy (API key) or enrollment problem: stop this turn now.
                        child.signal_group(Signal::SIGTERM);
                        failure.get_or_insert(reason);
                    }
                    DriverEvent::Progress { .. } | DriverEvent::Exited { .. } => {}
                }
            }
        }
        let exit = match child.wait_timeout(Duration::from_secs(10)).await {
            Some(e) => e,
            None => child.terminate(Duration::from_secs(5)).await,
        };
        if saw_init
            && failure.is_none()
            && let Some(s) = self.sessions.lock().expect("lock").get_mut(sid)
        {
            s.started = true;
        }
        match (failure, ended) {
            (Some(FailureReason::AuthEnrollmentRequired { detail, .. }), _) => {
                error(id, -32000, &format!("Authentication required: {detail}"))
            }
            (Some(reason), _) => error(id, -32603, &reason.message()),
            (None, _) if cancelled.load(Ordering::SeqCst) => result(id, json!({"stopReason": "cancelled"})),
            (None, Some((true, _, _))) => result(id, json!({"stopReason": "end_turn"})),
            (None, Some((false, stop, _))) if stop == "error_max_turns" => {
                result(id, json!({"stopReason": "max_turn_requests"}))
            }
            (None, Some((false, stop, detail))) => error(id, -32603, &format!("claude turn failed ({stop}): {detail}")),
            (None, None) => {
                let tail = child.stderr_tail();
                let tail = acp_runner_core::events::truncate_utf8(tail.trim(), 500).0;
                error(id, -32603, &format!("claude exited without a result (exit {exit:?}): {tail}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_text_concatenates_text_and_embedded_resources() {
        let p = json!({"prompt": [
            {"type": "text", "text": "fix it"},
            {"type": "resource", "resource": {"uri": "file:///a.txt", "text": "A"}},
            {"type": "image", "data": "..."}
        ]});
        let t = prompt_text(&p);
        assert!(t.starts_with("fix it\n<resource uri=\"file:///a.txt\">"));
    }
}
