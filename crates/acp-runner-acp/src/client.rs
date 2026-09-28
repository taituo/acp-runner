//! Typed helpers for the ACP v1 client flow used by acp-runner.

use crate::{AcpError, Connection, PROTOCOL_VERSION, methods};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct AgentInfo {
    pub name: Option<String>,
    pub title: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthMethod {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InitializeResult {
    pub protocol_version: u64,
    pub agent_info: AgentInfo,
    pub agent_capabilities: Value,
    pub auth_methods: Vec<AuthMethod>,
    pub raw: Value,
}

impl InitializeResult {
    /// codex-acp reports account state in `agentCapabilities._meta.authStatus.kind`
    /// (`account`, `api_key`, `none`, ...). Other agents may not; returns `None` then.
    pub fn auth_status_kind(&self) -> Option<String> {
        self.agent_capabilities.pointer("/_meta/authStatus/kind").and_then(|k| k.as_str()).map(str::to_string)
    }
}

/// `initialize` with version negotiation.
///
/// ACP rule: the client sends the latest version it supports; the agent answers with the
/// same version if supported, otherwise the latest version it supports. If the client does
/// not support the answered version it must close the connection.
pub async fn initialize(
    conn: &Connection,
    client_name: &str,
    client_version: &str,
) -> Result<InitializeResult, AcpError> {
    let params = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "clientCapabilities": {
            "fs": {"readTextFile": false, "writeTextFile": false},
            "terminal": false
        },
        "clientInfo": {"name": client_name, "title": "acp-runner", "version": client_version}
    });
    let raw = conn.request(methods::INITIALIZE, params).await?;
    let version = raw
        .get("protocolVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AcpError::Protocol("initialize response lacks numeric protocolVersion".into()))?;
    if version != PROTOCOL_VERSION {
        return Err(AcpError::UnsupportedProtocolVersion { agent: version, client: PROTOCOL_VERSION });
    }
    let info = raw.get("agentInfo").cloned().unwrap_or(Value::Null);
    let s = |k: &str| info.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let auth_methods = raw
        .get("authMethods")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(AuthMethod {
                        id: m.get("id")?.as_str()?.to_string(),
                        name: m.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string(),
                        description: m.get("description").and_then(|d| d.as_str()).map(str::to_string),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(InitializeResult {
        protocol_version: version,
        agent_info: AgentInfo { name: s("name"), title: s("title"), version: s("version") },
        agent_capabilities: raw.get("agentCapabilities").cloned().unwrap_or(Value::Null),
        auth_methods,
        raw,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewSessionResult {
    pub session_id: String,
    pub raw: Value,
}

/// `session/new`. acp-runner never calls `authenticate`: login state must be pre-enrolled
/// by a human. An `AuthRequired` error therefore maps to "enrollment required".
pub async fn new_session(conn: &Connection, cwd: &Path) -> Result<NewSessionResult, AcpError> {
    let raw = conn.request(methods::SESSION_NEW, json!({"cwd": cwd.to_string_lossy(), "mcpServers": []})).await?;
    let session_id = raw
        .get("sessionId")
        .and_then(|s| s.as_str())
        .ok_or_else(|| AcpError::Protocol("session/new response lacks sessionId".into()))?
        .to_string();
    Ok(NewSessionResult { session_id, raw })
}

pub fn prompt_params(session_id: &str, text: &str) -> Value {
    json!({"sessionId": session_id, "prompt": [{"type": "text", "text": text}]})
}

pub fn cancel_params(session_id: &str) -> Value {
    json!({"sessionId": session_id})
}

/// `stopReason` of a `session/prompt` response (`end_turn`, `max_tokens`,
/// `max_turn_requests`, `refusal`, `cancelled`).
pub fn stop_reason(prompt_result: &Value) -> String {
    prompt_result.get("stopReason").and_then(|s| s.as_str()).unwrap_or("unknown").to_string()
}

/// Pick a permission option id according to policy. Prefers one-shot options
/// (`allow_once` / `reject_once`) so no policy is persisted by the agent.
pub fn choose_permission_option(request_params: &Value, allow: bool) -> Option<String> {
    let options = request_params.get("options")?.as_array()?;
    let prefs: &[&str] = if allow { &["allow_once", "allow_always"] } else { &["reject_once", "reject_always"] };
    for want in prefs {
        if let Some(o) = options.iter().find(|o| o.get("kind").and_then(|k| k.as_str()) == Some(*want)) {
            return o.get("optionId").and_then(|i| i.as_str()).map(str::to_string);
        }
    }
    None
}

pub fn permission_selected(option_id: &str) -> Value {
    json!({"outcome": {"outcome": "selected", "optionId": option_id}})
}

pub fn permission_cancelled() -> Value {
    json!({"outcome": {"outcome": "cancelled"}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_choice_prefers_once() {
        let p = json!({"options":[
            {"optionId":"a","name":"Always","kind":"allow_always"},
            {"optionId":"o","name":"Once","kind":"allow_once"},
            {"optionId":"r","name":"Reject","kind":"reject_once"}]});
        assert_eq!(choose_permission_option(&p, true).as_deref(), Some("o"));
        assert_eq!(choose_permission_option(&p, false).as_deref(), Some("r"));
        assert_eq!(choose_permission_option(&json!({"options":[]}), true), None);
    }

    #[test]
    fn permission_response_shape() {
        assert_eq!(permission_selected("x")["outcome"]["outcome"], "selected");
        assert_eq!(permission_selected("x")["outcome"]["optionId"], "x");
        assert_eq!(permission_cancelled()["outcome"]["outcome"], "cancelled");
    }
}
