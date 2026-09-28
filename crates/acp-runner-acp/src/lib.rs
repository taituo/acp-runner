//! Minimal, tolerant Agent Client Protocol (ACP) **client** for stdio agents.
//!
//! Scope: exactly the client side acp-runner needs inside a sandbox —
//! `initialize` (with protocol version negotiation), `session/new`, `session/prompt`,
//! `session/cancel`, incoming `session/update` notifications and
//! `session/request_permission` requests. We advertise no `fs/*` or `terminal/*` client
//! capabilities, so agents operate on the real POSIX workspace themselves.
//!
//! Why not the official `agent-client-protocol` Rust SDK? It is a good library, but its
//! 2.x API (builder/role based, typed schema with strict enums) is evolving quickly and
//! strict deserialization of new `sessionUpdate` variants would make a pinned runner
//! brittle against adapter upgrades. The runner needs a *tolerant reader* that preserves
//! raw payloads for diagnostics; the wire format (newline-delimited JSON-RPC 2.0) is small.
//! The SDK can replace [`Connection`] later without touching the driver trait.
//!
//! Protocol constants below were checked against `agent-client-protocol-schema` 1.9.1
//! (ACP v1) and against `@agentclientprotocol/codex-acp` 1.13.1.

pub mod client;
pub mod normalize;

use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

/// Latest ACP major protocol version this client implements.
pub const PROTOCOL_VERSION: u64 = 1;

/// Maximum size of a single JSON-RPC line accepted from an agent.
pub const MAX_MESSAGE_BYTES: u64 = 16 * 1024 * 1024;

pub mod methods {
    pub const INITIALIZE: &str = "initialize";
    pub const AUTHENTICATE: &str = "authenticate";
    pub const SESSION_NEW: &str = "session/new";
    pub const SESSION_PROMPT: &str = "session/prompt";
    pub const SESSION_CANCEL: &str = "session/cancel";
    pub const SESSION_UPDATE: &str = "session/update";
    pub const SESSION_REQUEST_PERMISSION: &str = "session/request_permission";
    pub const FS_READ_TEXT_FILE: &str = "fs/read_text_file";
    pub const FS_WRITE_TEXT_FILE: &str = "fs/write_text_file";
}

pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const INTERNAL_ERROR: i64 = -32603;
    /// ACP `AuthRequired`.
    pub const AUTH_REQUIRED: i64 = -32000;
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum AcpError {
    #[error("agent returned JSON-RPC error {code}: {message}")]
    Rpc { code: i64, message: String, data: Option<Value> },
    #[error("connection to agent closed")]
    Closed,
    #[error("i/o error talking to agent: {0}")]
    Io(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("agent speaks ACP protocol version {agent}, client supports {client}")]
    UnsupportedProtocolVersion { agent: u64, client: u64 },
}

impl AcpError {
    pub fn is_auth_required(&self) -> bool {
        matches!(self, AcpError::Rpc { code, .. } if *code == codes::AUTH_REQUIRED)
    }
}

/// Messages initiated by the agent.
#[derive(Debug, Clone, PartialEq)]
pub enum Incoming {
    Notification {
        method: String,
        params: Value,
    },
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// A line on stdout that is not valid JSON-RPC (agents must not do this; we tolerate
    /// and report it instead of crashing).
    Invalid {
        line: String,
        error: String,
    },
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, AcpError>>>>>;

/// A JSON-RPC 2.0 connection over newline-delimited JSON.
#[derive(Clone)]
pub struct Connection {
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    pending: Pending,
    next_id: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl Connection {
    /// Start the connection. A background task reads `reader` until EOF; agent-initiated
    /// messages are delivered on the returned channel, which closes when the agent's stdout
    /// closes.
    pub fn spawn<R, W>(reader: R, writer: W) -> (Connection, mpsc::Receiver<Incoming>)
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (tx, rx) = mpsc::channel(1024);
        let conn = Connection {
            writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let pending = conn.pending.clone();
        let closed = conn.closed.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(reader);
            loop {
                let mut buf = Vec::new();
                let res = (&mut reader).take(MAX_MESSAGE_BYTES).read_until(b'\n', &mut buf).await;
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        if buf.last() != Some(&b'\n') && n as u64 >= MAX_MESSAGE_BYTES {
                            let _ = tx
                                .send(Incoming::Invalid {
                                    line: String::new(),
                                    error: format!("message exceeds {MAX_MESSAGE_BYTES} bytes; closing"),
                                })
                                .await;
                            break;
                        }
                        let line = String::from_utf8_lossy(&buf);
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        dispatch(line, &pending, &tx).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "acp reader error");
                        break;
                    }
                }
            }
            closed.store(true, Ordering::SeqCst);
            let waiters: Vec<_> = pending.lock().expect("pending lock").drain().collect();
            for (_, w) in waiters {
                let _ = w.send(Err(AcpError::Closed));
            }
        });
        (conn, rx)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn write_message(&self, msg: &Value) -> Result<(), AcpError> {
        if self.is_closed() {
            return Err(AcpError::Closed);
        }
        let mut line = serde_json::to_vec(msg).map_err(|e| AcpError::Protocol(e.to_string()))?;
        line.push(b'\n');
        let mut w = self.writer.lock().await;
        w.write_all(&line).await.map_err(|e| AcpError::Io(e.to_string()))?;
        w.flush().await.map_err(|e| AcpError::Io(e.to_string()))
    }

    /// Send a request and wait for its response. Callers apply their own timeouts.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, AcpError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("pending lock").insert(id, tx);
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        if let Err(e) = self.write_message(&msg).await {
            self.pending.lock().expect("pending lock").remove(&id);
            return Err(e);
        }
        rx.await.unwrap_or(Err(AcpError::Closed))
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<(), AcpError> {
        self.write_message(&json!({"jsonrpc": "2.0", "method": method, "params": params})).await
    }

    pub async fn respond(&self, id: Value, result: Value) -> Result<(), AcpError> {
        self.write_message(&json!({"jsonrpc": "2.0", "id": id, "result": result})).await
    }

    pub async fn respond_error(&self, id: Value, code: i64, message: &str) -> Result<(), AcpError> {
        self.write_message(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})).await
    }

    /// Close our write side (agent sees EOF on stdin).
    pub async fn close_input(&self) {
        let mut w = self.writer.lock().await;
        let _ = w.shutdown().await;
    }
}

async fn dispatch(line: &str, pending: &Pending, tx: &mpsc::Sender<Incoming>) {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.send(Incoming::Invalid { line: line.chars().take(512).collect(), error: e.to_string() }).await;
            return;
        }
    };
    let method = v.get("method").and_then(|m| m.as_str()).map(str::to_string);
    let id = v.get("id").cloned().filter(|i| !i.is_null());
    match (method, id) {
        (Some(method), Some(id)) => {
            let params = v.get("params").cloned().unwrap_or(Value::Null);
            let _ = tx.send(Incoming::Request { id, method, params }).await;
        }
        (Some(method), None) => {
            let params = v.get("params").cloned().unwrap_or(Value::Null);
            let _ = tx.send(Incoming::Notification { method, params }).await;
        }
        (None, Some(id)) => {
            let Some(num) = id.as_u64() else {
                let _ = tx
                    .send(Incoming::Invalid {
                        line: line.chars().take(512).collect(),
                        error: "response with non-numeric id".into(),
                    })
                    .await;
                return;
            };
            let waiter = pending.lock().expect("pending lock").remove(&num);
            let Some(waiter) = waiter else {
                tracing::debug!(id = num, "response for unknown request id");
                return;
            };
            let result = if let Some(err) = v.get("error") {
                Err(AcpError::Rpc {
                    code: err.get("code").and_then(|c| c.as_i64()).unwrap_or(codes::INTERNAL_ERROR),
                    message: err.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string(),
                    data: err.get("data").cloned(),
                })
            } else {
                Ok(v.get("result").cloned().unwrap_or(Value::Null))
            };
            let _ = waiter.send(result);
        }
        (None, None) => {
            let _ = tx
                .send(Incoming::Invalid {
                    line: line.chars().take(512).collect(),
                    error: "neither request nor response".into(),
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// A scripted in-memory "agent".
    async fn scripted_agent(
        agent_side: tokio::io::DuplexStream,
        script: impl Fn(Value) -> Vec<Value> + Send + 'static,
    ) {
        let (r, mut w) = tokio::io::split(agent_side);
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let msg: Value = serde_json::from_str(&line).unwrap();
            for out in script(msg) {
                let mut s = serde_json::to_vec(&out).unwrap();
                s.push(b'\n');
                w.write_all(&s).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn request_response_and_notifications() {
        let (client_side, agent_side) = duplex(64 * 1024);
        tokio::spawn(scripted_agent(agent_side, |msg| {
            let id = msg["id"].clone();
            vec![
                json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hi"}}}}),
                json!({"jsonrpc":"2.0","id":id,"result":{"echo": msg["method"]}}),
            ]
        }));
        let (r, w) = tokio::io::split(client_side);
        let (conn, mut rx) = Connection::spawn(r, w);
        let res = conn.request("ping", json!({})).await.unwrap();
        assert_eq!(res["echo"], "ping");
        match rx.recv().await.unwrap() {
            Incoming::Notification { method, .. } => assert_eq!(method, "session/update"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_and_invalid_lines() {
        let (client_side, agent_side) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (r, mut w) = tokio::io::split(agent_side);
            let mut lines = BufReader::new(r).lines();
            let line = lines.next_line().await.unwrap().unwrap();
            let msg: Value = serde_json::from_str(&line).unwrap();
            w.write_all(b"this is not json\n").await.unwrap();
            let err =
                json!({"jsonrpc":"2.0","id":msg["id"],"error":{"code":-32000,"message":"Authentication required"}});
            w.write_all(format!("{err}\n").as_bytes()).await.unwrap();
        });
        let (r, w) = tokio::io::split(client_side);
        let (conn, mut rx) = Connection::spawn(r, w);
        let e = conn.request("session/new", json!({})).await.unwrap_err();
        assert!(e.is_auth_required());
        assert!(matches!(rx.recv().await.unwrap(), Incoming::Invalid { .. }));
    }

    #[tokio::test]
    async fn pending_requests_fail_on_close() {
        let (client_side, agent_side) = duplex(1024);
        let (r, w) = tokio::io::split(client_side);
        let (conn, _rx) = Connection::spawn(r, w);
        let h = tokio::spawn(async move { conn.request("x", json!({})).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(agent_side);
        assert_eq!(h.await.unwrap().unwrap_err(), AcpError::Closed);
    }
}
