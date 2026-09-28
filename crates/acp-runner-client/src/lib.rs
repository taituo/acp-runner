//! ACP client for **AgentEnvironment gateways**.
//!
//! The gateway is authenticated once (HTTP/1.1 `Authorization: Bearer <connection ticket>`)
//! and then carries plain ACP:
//!
//! * [`Transport::Raw`]: `GET /v1/acp` with `Upgrade: acp-ndjson` → `101 Switching Protocols`,
//!   then newline-delimited JSON-RPC in both directions (ACP's own stdio framing),
//! * [`Transport::WebSocket`]: `GET /v1/acp` WebSocket upgrade, one JSON-RPC message per
//!   text frame.
//!
//! After that nothing here is acp-runner specific: [`AcpClient`] is an ordinary ACP client
//! (`initialize`, `session/new`, `session/prompt`, `session/cancel`, answering
//! `session/request_permission`). Environment lifecycle (snapshot/finish/branch/destroy) is
//! not on this path — it belongs to the provider's control plane.

use acp_runner_acp::client::{self, InitializeResult};
use acp_runner_acp::normalize::{self, SessionUpdate};
use acp_runner_acp::{AcpError, Connection, Incoming, codes, methods};
use acp_runner_ipc::gateway::{ACP_PATH, HDR_ENVIRONMENT, HDR_PHASE, HDR_WORKDIR, RAW_UPGRADE};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// HTTP upgrade to newline-delimited JSON-RPC.
    Raw,
    /// HTTP upgrade to WebSocket (one message per text frame).
    WebSocket,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connecting to the gateway: {0}")]
    Connect(String),
    /// The gateway refused the connection (401 bad ticket, 403 other environment, 409 closed...).
    #[error("gateway rejected the connection ({status}): {reason}")]
    Rejected { status: u16, reason: String },
    #[error("ACP: {0}")]
    Acp(#[from] AcpError),
    #[error("protocol: {0}")]
    Protocol(String),
}

/// What the gateway told us at attach time.
#[derive(Debug, Clone, Default)]
pub struct AttachInfo {
    pub environment_id: Option<String>,
    /// Harness working directory to use as `cwd` in `session/new`.
    pub workdir: Option<String>,
    pub phase: Option<String>,
}

/// An authenticated byte stream carrying newline-delimited ACP JSON-RPC.
pub struct Dataplane {
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub info: AttachInfo,
}

fn http_request(gateway: &str, ticket: &str, upgrade: &str) -> String {
    format!(
        "GET {ACP_PATH} HTTP/1.1\r\nHost: {gateway}\r\nConnection: Upgrade\r\nUpgrade: {upgrade}\r\n\
         Authorization: Bearer {ticket}\r\nUser-Agent: acp-runner-client/{}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    )
}

/// Read an HTTP/1.1 response head (bounded). Returns (status, headers lower-cased, reason).
async fn read_head<R: AsyncRead + Unpin>(r: &mut BufReader<R>) -> Result<(u16, BTreeMap<String, String>), ClientError> {
    let mut total = 0usize;
    let mut status = 0u16;
    let mut headers = BTreeMap::new();
    let mut first = true;
    loop {
        let mut line = Vec::new();
        let n = r.read_until(b'\n', &mut line).await.map_err(|e| ClientError::Connect(e.to_string()))?;
        if n == 0 {
            return Err(ClientError::Connect("gateway closed during the handshake".into()));
        }
        total += n;
        if total > 16 * 1024 {
            return Err(ClientError::Protocol("response head too large".into()));
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if first {
            first = false;
            status = text
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse().ok())
                .ok_or_else(|| ClientError::Protocol(format!("bad status line {text:?}")))?;
            continue;
        }
        if text.is_empty() {
            return Ok((status, headers));
        }
        if let Some((k, v)) = text.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
}

fn info_from(headers: &BTreeMap<String, String>) -> AttachInfo {
    AttachInfo {
        environment_id: headers.get(HDR_ENVIRONMENT).cloned(),
        workdir: headers.get(HDR_WORKDIR).cloned(),
        phase: headers.get(HDR_PHASE).cloned(),
    }
}

/// Open an authenticated dataplane to `gateway` (`host:port`).
pub async fn open(gateway: &str, ticket: &str, transport: Transport) -> Result<Dataplane, ClientError> {
    let stream = TcpStream::connect(gateway).await.map_err(|e| ClientError::Connect(format!("{gateway}: {e}")))?;
    let _ = stream.set_nodelay(true);
    match transport {
        Transport::Raw => {
            let mut s = BufReader::new(stream);
            s.get_mut()
                .write_all(http_request(gateway, ticket, RAW_UPGRADE).as_bytes())
                .await
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            let (status, headers) = read_head(&mut s).await?;
            if status != 101 {
                let mut body = vec![0u8; 512];
                let n = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::io::AsyncReadExt::read(&mut s, &mut body),
                )
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(0);
                return Err(ClientError::Rejected {
                    status,
                    reason: String::from_utf8_lossy(&body[..n]).trim().to_string(),
                });
            }
            let info = info_from(&headers);
            // BufReader keeps bytes that arrived right after the head.
            let (rd, wr) = tokio::io::split(s);
            Ok(Dataplane { reader: Box::new(rd), writer: Box::new(wr), info })
        }
        Transport::WebSocket => {
            let mut req = format!("ws://{gateway}{ACP_PATH}")
                .into_client_request()
                .map_err(|e| ClientError::Connect(e.to_string()))?;
            req.headers_mut().insert(
                "authorization",
                format!("Bearer {ticket}").parse().map_err(|_| ClientError::Connect("invalid ticket header".into()))?,
            );
            let (ws, resp) = match tokio_tungstenite::client_async(req, stream).await {
                Ok(v) => v,
                Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
                    let reason =
                        r.body().as_ref().map(|b| String::from_utf8_lossy(b).trim().to_string()).unwrap_or_default();
                    return Err(ClientError::Rejected { status: r.status().as_u16(), reason });
                }
                Err(e) => return Err(ClientError::Connect(e.to_string())),
            };
            let headers: BTreeMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let info = info_from(&headers);
            // Adapt frames <-> newline-delimited JSON through an in-memory pipe.
            let (ours, theirs) = tokio::io::duplex(1 << 20);
            let (mut pipe_rd, mut pipe_wr) = tokio::io::split(theirs);
            let (mut ws_tx, mut ws_rx) = ws.split();
            tokio::spawn(async move {
                while let Some(Ok(m)) = ws_rx.next().await {
                    let text = match m {
                        Message::Text(t) => t.as_str().to_string(),
                        Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                        Message::Close(_) => break,
                        _ => continue,
                    };
                    let mut line = text.into_bytes();
                    line.push(b'\n');
                    if pipe_wr.write_all(&line).await.is_err() {
                        break;
                    }
                }
                let _ = pipe_wr.shutdown().await;
            });
            tokio::spawn(async move {
                let mut lines = BufReader::new(&mut pipe_rd).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    if l.trim().is_empty() {
                        continue;
                    }
                    if ws_tx.send(Message::text(l)).await.is_err() {
                        break;
                    }
                }
                let _ = ws_tx.send(Message::Close(None)).await;
            });
            let (rd, wr) = tokio::io::split(ours);
            Ok(Dataplane { reader: Box::new(rd), writer: Box::new(wr), info })
        }
    }
}

/// How the client answers `session/request_permission`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PermissionAnswer {
    #[default]
    AllowOnce,
    Reject,
}

/// A streamed piece of a prompt turn.
#[derive(Debug, Clone, PartialEq)]
pub enum TurnUpdate {
    Message(String),
    Thought(String),
    ToolCall { id: String, title: String },
    ToolResult { id: String, status: String },
    Other(Value),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TurnOutcome {
    pub stop_reason: String,
    /// Concatenated `agent_message_chunk` text of the turn.
    pub text: String,
    pub tool_calls: usize,
    /// Raw prompt response (may carry `usage` / `_meta`).
    pub raw: Value,
}

/// A plain ACP client over a gateway dataplane.
pub struct AcpClient {
    conn: Connection,
    incoming: mpsc::Receiver<Incoming>,
    pub info: AttachInfo,
    pub permissions: PermissionAnswer,
    pub init: Option<InitializeResult>,
}

/// Cancels the running turn of a session from another task.
#[derive(Clone)]
pub struct Canceller {
    conn: Connection,
    session_id: String,
}

impl Canceller {
    pub async fn cancel(&self) -> Result<(), ClientError> {
        Ok(self.conn.notify(methods::SESSION_CANCEL, client::cancel_params(&self.session_id)).await?)
    }
}

impl AcpClient {
    /// Connect and authenticate (no ACP traffic yet).
    pub async fn connect(gateway: &str, ticket: &str, transport: Transport) -> Result<AcpClient, ClientError> {
        let dp = open(gateway, ticket, transport).await?;
        let (conn, incoming) = Connection::spawn(dp.reader, dp.writer);
        Ok(AcpClient { conn, incoming, info: dp.info, permissions: PermissionAnswer::AllowOnce, init: None })
    }

    /// `initialize` (protocol negotiation; no fs/terminal client capabilities).
    pub async fn initialize(&mut self) -> Result<&InitializeResult, ClientError> {
        let init = client::initialize(&self.conn, "acp-runner-client", env!("CARGO_PKG_VERSION")).await?;
        self.init = Some(init);
        Ok(self.init.as_ref().expect("set"))
    }

    /// `session/new` in `cwd` (defaults to the environment's workdir announced by the gateway).
    pub async fn new_session(&mut self, cwd: Option<&str>) -> Result<String, ClientError> {
        let cwd = cwd.map(str::to_string).or_else(|| self.info.workdir.clone()).unwrap_or_else(|| "/workspace".into());
        let r = client::new_session(&self.conn, std::path::Path::new(&cwd)).await?;
        Ok(r.session_id)
    }

    pub fn canceller(&self, session_id: &str) -> Canceller {
        Canceller { conn: self.conn.clone(), session_id: session_id.to_string() }
    }

    /// Send a raw JSON-RPC request (for ACP methods this client has no helper for).
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        Ok(self.conn.request(method, params).await?)
    }

    /// Run one prompt turn to completion.
    pub async fn prompt(&mut self, session_id: &str, text: &str) -> Result<TurnOutcome, ClientError> {
        self.prompt_with(session_id, text, |_| {}).await
    }

    /// Run one prompt turn, streaming updates to `on_update`.
    pub async fn prompt_with(
        &mut self,
        session_id: &str,
        text: &str,
        mut on_update: impl FnMut(TurnUpdate),
    ) -> Result<TurnOutcome, ClientError> {
        let (tx, mut rx) = oneshot::channel();
        let conn = self.conn.clone();
        let params = client::prompt_params(session_id, text);
        tokio::spawn(async move {
            let _ = tx.send(conn.request(methods::SESSION_PROMPT, params).await);
        });
        let mut out = TurnOutcome::default();
        loop {
            tokio::select! {
                biased;
                m = self.incoming.recv() => match m {
                    Some(Incoming::Notification { method, params }) if method == methods::SESSION_UPDATE => {
                        if params.get("sessionId").and_then(|s| s.as_str()).is_some_and(|s| s != session_id) {
                            continue;
                        }
                        let u = match normalize::decode(&params) {
                            SessionUpdate::AgentMessageChunk { text } => {
                                out.text.push_str(&text);
                                TurnUpdate::Message(text)
                            }
                            SessionUpdate::AgentThoughtChunk { text } => TurnUpdate::Thought(text),
                            SessionUpdate::ToolCall { id, title, .. } => {
                                out.tool_calls += 1;
                                TurnUpdate::ToolCall { id, title }
                            }
                            SessionUpdate::ToolCallUpdate { id, status: Some(status), .. }
                                if status == "completed" || status == "failed" => TurnUpdate::ToolResult { id, status },
                            _ => TurnUpdate::Other(params.get("update").cloned().unwrap_or(Value::Null)),
                        };
                        on_update(u);
                    }
                    Some(Incoming::Request { id, method, params }) => self.answer(id, &method, &params).await,
                    Some(_) => {}
                    None => return Err(ClientError::Acp(AcpError::Closed)),
                },
                r = &mut rx => {
                    let v = r.unwrap_or(Err(AcpError::Closed))?;
                    // drain updates that raced the response
                    while let Ok(m) = self.incoming.try_recv() {
                        if let Incoming::Notification { method, params } = m
                            && method == methods::SESSION_UPDATE
                            && let SessionUpdate::AgentMessageChunk { text } = normalize::decode(&params)
                        {
                            out.text.push_str(&text);
                            on_update(TurnUpdate::Message(text));
                        }
                    }
                    out.stop_reason = client::stop_reason(&v);
                    out.raw = v;
                    return Ok(out);
                }
            }
        }
    }

    async fn answer(&self, id: Value, method: &str, params: &Value) {
        if method == methods::SESSION_REQUEST_PERMISSION {
            let allow = self.permissions == PermissionAnswer::AllowOnce;
            let resp = match client::choose_permission_option(params, allow) {
                Some(o) => client::permission_selected(&o),
                None => client::permission_cancelled(),
            };
            let _ = self.conn.respond(id, resp).await;
        } else {
            let _ = self
                .conn
                .respond_error(id, codes::METHOD_NOT_FOUND, &format!("client does not implement {method}"))
                .await;
        }
    }

    /// Close our side of the connection.
    pub async fn close(self) {
        self.conn.close_input().await;
    }
}

/// Convenience: `initialize` + `session/new` in the environment workdir.
pub async fn connect_session(
    gateway: &str,
    ticket: &str,
    transport: Transport,
) -> Result<(AcpClient, String), ClientError> {
    let mut c = AcpClient::connect(gateway, ticket, transport).await?;
    c.initialize().await?;
    let sid = c.new_session(None).await?;
    Ok((c, sid))
}

/// A JSON-RPC message for tests/tools that speak to the dataplane directly.
pub fn jsonrpc_request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}
