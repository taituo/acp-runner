//! **OpenAI Responses shim over ACP.**
//!
//! ```text
//!              ┌── native ACP client
//! ACP gateway ─┼── this shim (OpenAI Responses subset)  ← not part of the environment core
//!              └── future adapters
//! ```
//!
//! The shim is just another ACP client of an AgentEnvironment gateway. It maps:
//!
//! | OpenAI Responses                         | ACP                                         |
//! |------------------------------------------|---------------------------------------------|
//! | `POST /v1/responses` `model`             | the environment (via a [`ConnectionSource`])|
//! | `input` (text / input_text parts)        | `session/prompt` text                       |
//! | no `previous_response_id`                | `session/new` (cwd = environment workdir)   |
//! | `previous_response_id`                   | same ACP session (continuation)             |
//! | `stream: true` → SSE `response.*` events | `session/update` `agent_message_chunk`      |
//! | `POST /v1/responses/{id}/cancel`         | `session/cancel`                            |
//! | `usage`                                  | prompt response `usage`, when the agent has one |
//!
//! Deliberately **not** supported in v1: client-side tools (`tools: [{type: "function"}]`).
//! The harness's own tools (Read/Edit/Bash/MCP/sub-agents) run inside the environment; a
//! request carrying client tools is refused with a clear error rather than half-emulated.

use acp_runner_client::{AcpClient, Canceller, ClientError, Transport, TurnUpdate};
use async_trait::async_trait;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Where the shim gets a gateway connection for a `model` (an environment reference).
#[async_trait]
pub trait ConnectionSource: Send + Sync {
    /// A fresh `(gateway host:port, connection ticket)` for the environment named `model`.
    async fn connect(&self, model: &str) -> anyhow::Result<(String, String)>;
    /// Models (environments) to list on `GET /v1/models`.
    async fn models(&self) -> Vec<String> {
        vec![]
    }
}

struct Conversation {
    model: String,
    session_id: String,
}

pub struct ShimState {
    source: Arc<dyn ConnectionSource>,
    transport: Transport,
    /// One ACP client per environment; turns on one environment are serialized.
    clients: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<AcpClient>>>>>,
    /// response id → conversation (for `previous_response_id`).
    conversations: Mutex<HashMap<String, Conversation>>,
    /// response id → canceller while in flight.
    running: Mutex<HashMap<String, Canceller>>,
    /// response id → final response object.
    finished: Mutex<HashMap<String, Value>>,
}

impl ShimState {
    pub fn new(source: Arc<dyn ConnectionSource>, transport: Transport) -> Arc<ShimState> {
        Arc::new(ShimState {
            source,
            transport,
            clients: Default::default(),
            conversations: Default::default(),
            running: Default::default(),
            finished: Default::default(),
        })
    }
}

pub fn router(state: Arc<ShimState>) -> Router {
    Router::new()
        .route("/v1/responses", post(create_response))
        .route("/v1/responses/{id}", get(get_response))
        .route("/v1/responses/{id}/cancel", post(cancel_response))
        .route("/v1/models", get(list_models))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state)
}

#[derive(Deserialize)]
struct CreateRequest {
    model: String,
    #[serde(default)]
    input: Value,
    #[serde(default)]
    instructions: Option<String>,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    previous_response_id: Option<String>,
    #[serde(default)]
    tools: Vec<Value>,
    #[serde(default)]
    metadata: Option<Value>,
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"error": {"message": message, "type": "invalid_request_error", "code": code, "param": null}})))
        .into_response()
}

/// Text of `input`: a string, or message items with string / `input_text` content.
fn input_text(input: &Value) -> Option<String> {
    match input {
        Value::String(s) => Some(s.clone()),
        Value::Array(items) => {
            let mut out = vec![];
            for it in items {
                match it.get("content") {
                    Some(Value::String(s)) => out.push(s.clone()),
                    Some(Value::Array(parts)) => {
                        for p in parts {
                            if matches!(p.get("type").and_then(|t| t.as_str()), Some("input_text") | Some("text"))
                                && let Some(t) = p.get("text").and_then(|t| t.as_str())
                            {
                                out.push(t.to_string());
                            }
                        }
                    }
                    _ => {
                        if it.get("type").and_then(|t| t.as_str()) == Some("input_text")
                            && let Some(t) = it.get("text").and_then(|t| t.as_str())
                        {
                            out.push(t.to_string());
                        }
                    }
                }
            }
            (!out.is_empty()).then(|| out.join("\n\n"))
        }
        _ => None,
    }
}

fn usage_of(raw: &Value) -> Value {
    let u = raw.get("usage").or_else(|| raw.pointer("/_meta/usage"));
    let Some(u) = u else { return Value::Null };
    let n = |a: &str, b: &str| u.get(a).or_else(|| u.get(b)).and_then(|v| v.as_u64());
    match (n("inputTokens", "input_tokens"), n("outputTokens", "output_tokens")) {
        (Some(i), Some(o)) => json!({"input_tokens": i, "output_tokens": o, "total_tokens": i + o}),
        _ => Value::Null,
    }
}

#[allow(clippy::too_many_arguments)]
fn response_object(
    id: &str,
    model: &str,
    created: i64,
    previous: Option<&str>,
    status: &str,
    item_id: &str,
    text: &str,
    extra: Value,
) -> Value {
    let output = if status == "in_progress" {
        json!([])
    } else {
        json!([{"type": "message", "id": item_id, "status": "completed", "role": "assistant",
                "content": [{"type": "output_text", "text": text, "annotations": []}]}])
    };
    let mut v = json!({
        "id": id, "object": "response", "created_at": created, "status": status, "model": model,
        "output": output, "previous_response_id": previous, "usage": null, "error": null,
        "incomplete_details": null, "tools": [], "parallel_tool_calls": false,
    });
    if let (Value::Object(m), Value::Object(e)) = (&mut v, extra) {
        m.extend(e);
    }
    v
}

async fn client_for(st: &ShimState, model: &str) -> Arc<tokio::sync::Mutex<Option<AcpClient>>> {
    st.clients.lock().await.entry(model.to_string()).or_default().clone()
}

async fn ensure_connected(st: &ShimState, model: &str, slot: &mut Option<AcpClient>) -> Result<(), String> {
    if slot.is_some() {
        return Ok(());
    }
    let (gateway, ticket) = st.source.connect(model).await.map_err(|e| e.to_string())?;
    let mut c = AcpClient::connect(&gateway, &ticket, st.transport).await.map_err(|e| e.to_string())?;
    c.initialize().await.map_err(|e| e.to_string())?;
    *slot = Some(c);
    Ok(())
}

async fn create_response(State(st): State<Arc<ShimState>>, Json(req): Json<CreateRequest>) -> Response {
    if req.tools.iter().any(|t| t.get("type").is_some()) {
        return error(
            StatusCode::BAD_REQUEST,
            "unsupported_tools",
            "client-side tools are not supported by this shim (v1); the environment's harness uses its own tools",
        );
    }
    let Some(mut text) = input_text(&req.input) else {
        return error(StatusCode::BAD_REQUEST, "invalid_input", "input must be text or input_text message parts");
    };
    let (session, conversation_known) = match &req.previous_response_id {
        Some(prev) => match st.conversations.lock().expect("lock").get(prev) {
            Some(c) if c.model == req.model => (Some(c.session_id.clone()), true),
            Some(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "model_mismatch",
                    "previous_response_id belongs to another model",
                );
            }
            None => return error(StatusCode::NOT_FOUND, "previous_response_not_found", "unknown previous_response_id"),
        },
        None => (None, false),
    };
    if !conversation_known && let Some(i) = &req.instructions {
        text = format!("{i}\n\n{text}");
    }
    let id = format!("resp_{}", uuid::Uuid::now_v7().simple());
    let item_id = format!("msg_{}", uuid::Uuid::now_v7().simple());
    let created = chrono::Utc::now().timestamp();
    let (tx, rx) = mpsc::channel::<Value>(256);
    let st2 = st.clone();
    let (id2, item2, model2, prev2) =
        (id.clone(), item_id.clone(), req.model.clone(), req.previous_response_id.clone());
    let meta = req.metadata.clone();
    // The turn runs in its own task so a disconnecting HTTP client does not abort it.
    let turn = tokio::spawn(async move {
        run_turn(&st2, &id2, &item2, &model2, prev2.as_deref(), session, &text, created, meta, tx).await
    });
    if req.stream {
        let stream = futures::stream::unfold(rx, |mut rx| async move {
            let v = rx.recv().await?;
            let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("message").to_string();
            Some((Ok::<Event, Infallible>(Event::default().event(ty).data(v.to_string())), rx))
        });
        return Sse::new(stream).into_response();
    }
    drop(rx);
    match turn.await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err((status, code, msg))) => error(status, &code, &msg),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
    }
}

type TurnError = (StatusCode, String, String);

#[allow(clippy::too_many_arguments)]
async fn run_turn(
    st: &Arc<ShimState>,
    id: &str,
    item_id: &str,
    model: &str,
    previous: Option<&str>,
    session: Option<String>,
    text: &str,
    created: i64,
    metadata: Option<Value>,
    tx: mpsc::Sender<Value>,
) -> Result<Value, TurnError> {
    let seq = std::sync::atomic::AtomicU64::new(0);
    let emit = |mut v: Value| {
        v["sequence_number"] = json!(seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        let _ = tx.try_send(v);
    };
    let base = |status: &str, text: &str| {
        response_object(id, model, created, previous, status, item_id, text, json!({"metadata": metadata.clone()}))
    };
    emit(json!({"type": "response.created", "response": base("in_progress", "")}));
    let slot = client_for(st, model).await;
    let mut guard = slot.lock().await;
    let fail = |status: StatusCode, code: &str, msg: String, emit: &dyn Fn(Value)| {
        let mut r = base("failed", "");
        r["error"] = json!({"code": code, "message": msg});
        emit(json!({"type": "response.failed", "response": r}));
        (status, code.to_string(), msg)
    };
    if let Err(e) = ensure_connected(st, model, &mut guard).await {
        return Err(fail(StatusCode::BAD_GATEWAY, "environment_unavailable", e, &emit));
    }
    let client = guard.as_mut().expect("connected");
    let session_id = match session {
        Some(s) => s,
        None => match client.new_session(None).await {
            Ok(s) => s,
            Err(e) => {
                *guard = None;
                return Err(fail(StatusCode::BAD_GATEWAY, "session_failed", e.to_string(), &emit));
            }
        },
    };
    st.running.lock().expect("lock").insert(id.to_string(), client.canceller(&session_id));
    emit(json!({"type": "response.in_progress", "response": base("in_progress", "")}));
    emit(json!({"type": "response.output_item.added", "output_index": 0,
                "item": {"type": "message", "id": item_id, "status": "in_progress", "role": "assistant", "content": []}}));
    emit(json!({"type": "response.content_part.added", "item_id": item_id, "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []}}));
    let outcome = client
        .prompt_with(&session_id, text, |u| {
            if let TurnUpdate::Message(delta) = u {
                emit(json!({"type": "response.output_text.delta", "item_id": item_id, "output_index": 0,
                            "content_index": 0, "delta": delta}));
            }
        })
        .await;
    st.running.lock().expect("lock").remove(id);
    let out = match outcome {
        Ok(o) => o,
        Err(e) => {
            // reconnect with a fresh ticket next time (sessions live on in the harness)
            if matches!(e, ClientError::Acp(_) | ClientError::Connect(_)) {
                *guard = None;
            }
            return Err(fail(StatusCode::BAD_GATEWAY, "turn_failed", e.to_string(), &emit));
        }
    };
    let (status, incomplete) = match out.stop_reason.as_str() {
        "end_turn" | "refusal" => ("completed", Value::Null),
        "cancelled" => ("cancelled", Value::Null),
        "max_tokens" => ("incomplete", json!({"reason": "max_output_tokens"})),
        other => ("incomplete", json!({"reason": other})),
    };
    emit(json!({"type": "response.output_text.done", "item_id": item_id, "output_index": 0, "content_index": 0,
                "text": out.text}));
    emit(json!({"type": "response.content_part.done", "item_id": item_id, "output_index": 0, "content_index": 0,
                "part": {"type": "output_text", "text": out.text, "annotations": []}}));
    let mut resp = base(status, &out.text);
    resp["usage"] = usage_of(&out.raw);
    resp["incomplete_details"] = incomplete;
    resp["metadata"] = json!({"user": metadata, "acp_stop_reason": out.stop_reason, "acp_session_id": session_id});
    emit(json!({"type": "response.output_item.done", "output_index": 0, "item": resp["output"][0].clone()}));
    let done_type = match status {
        "completed" => "response.completed",
        "incomplete" => "response.incomplete",
        _ => "response.cancelled",
    };
    emit(json!({"type": done_type, "response": resp.clone()}));
    st.conversations
        .lock()
        .expect("lock")
        .insert(id.to_string(), Conversation { model: model.to_string(), session_id: session_id.clone() });
    st.finished.lock().expect("lock").insert(id.to_string(), resp.clone());
    Ok(resp)
}

async fn get_response(State(st): State<Arc<ShimState>>, Path(id): Path<String>) -> Response {
    if let Some(v) = st.finished.lock().expect("lock").get(&id).cloned() {
        return Json(v).into_response();
    }
    if st.running.lock().expect("lock").contains_key(&id) {
        return Json(json!({"id": id, "object": "response", "status": "in_progress"})).into_response();
    }
    error(StatusCode::NOT_FOUND, "not_found", "unknown response id")
}

async fn cancel_response(State(st): State<Arc<ShimState>>, Path(id): Path<String>) -> Response {
    let c = st.running.lock().expect("lock").get(&id).cloned();
    match c {
        Some(c) => match c.cancel().await {
            Ok(()) => Json(json!({"id": id, "object": "response", "status": "cancelling"})).into_response(),
            Err(e) => error(StatusCode::BAD_GATEWAY, "cancel_failed", &e.to_string()),
        },
        None => match st.finished.lock().expect("lock").get(&id).cloned() {
            Some(v) => Json(v).into_response(),
            None => error(StatusCode::NOT_FOUND, "not_found", "unknown or finished response id"),
        },
    }
}

async fn list_models(State(st): State<Arc<ShimState>>) -> Response {
    let data: Vec<Value> = st
        .source
        .models()
        .await
        .into_iter()
        .map(|m| json!({"id": m, "object": "model", "owned_by": "acp-runner"}))
        .collect();
    Json(json!({"object": "list", "data": data})).into_response()
}

/// A [`ConnectionSource`] reading `{ "<model>": {"gateway": "...", "ticket": "..."} }` from a
/// JSON file on every connect (an operator/sidecar refreshes the short-lived tickets). The
/// shim never holds the provider's ticket key.
pub struct FileConnectionSource {
    pub path: std::path::PathBuf,
}

#[async_trait]
impl ConnectionSource for FileConnectionSource {
    async fn connect(&self, model: &str) -> anyhow::Result<(String, String)> {
        let v: Value = serde_json::from_slice(&tokio::fs::read(&self.path).await?)?;
        let e = v.get(model).ok_or_else(|| anyhow::anyhow!("unknown model {model:?}"))?;
        let s = |k: &str| e.get(k).and_then(|x| x.as_str()).map(str::to_string);
        Ok((
            s("gateway").ok_or_else(|| anyhow::anyhow!("no gateway"))?,
            s("ticket").ok_or_else(|| anyhow::anyhow!("no ticket"))?,
        ))
    }

    async fn models(&self) -> Vec<String> {
        let Ok(bytes) = tokio::fs::read(&self.path).await else { return vec![] };
        serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_forms() {
        assert_eq!(input_text(&json!("hi")).as_deref(), Some("hi"));
        let v = json!([{"role": "user", "content": [{"type": "input_text", "text": "a"}, {"type": "input_image"}]},
                       {"role": "user", "content": "b"}]);
        assert_eq!(input_text(&v).as_deref(), Some("a\n\nb"));
        assert_eq!(input_text(&json!(42)), None);
        assert_eq!(usage_of(&json!({"usage": {"inputTokens": 3, "outputTokens": 4}}))["total_tokens"], 7);
        assert!(usage_of(&json!({"stopReason": "end_turn"})).is_null());
    }
}
