//! Passive observation of the raw ACP stream relayed by the gateway.
//!
//! runnerd never rewrites or originates ACP on the dataplane; it only *reads along* to know
//! whether a prompt turn is running (Idle/Busy — snapshots are consistent only at Idle) and
//! to journal what the agent did (tool calls, the turn's message text) as `source = agent`
//! events. Everything observed from the agent side is an untrusted claim: it influences the
//! journal and the Idle/Busy hint, never the terminal state or the artifact.

use acp_runner_acp::normalize::{self, SessionUpdate};
use acp_runner_core::events::{PermissionRequestData, ToolCallData, ToolResultData, truncate_utf8};
use acp_runner_ipc::AgentEvent;
use serde_json::Value;
use std::collections::HashMap;

const MAX_TURN_TEXT: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Observed {
    /// The caller sent `session/prompt` (a turn starts).
    PromptStarted { bytes: usize, preview: String },
    /// The agent answered a pending `session/prompt`.
    PromptEnded { stop_reason: String, error: Option<String>, text: String },
    /// Something worth journaling.
    Agent(AgentEvent),
}

#[derive(Debug, Default)]
pub struct AcpTap {
    /// JSON-RPC ids (serialized) of in-flight `session/prompt` requests.
    pending: HashMap<String, ()>,
    turn_text: String,
}

fn id_key(v: &Value) -> Option<String> {
    v.get("id").filter(|i| !i.is_null()).map(|i| i.to_string())
}

impl AcpTap {
    pub fn busy(&self) -> bool {
        !self.pending.is_empty()
    }

    /// A message from the caller (towards the harness).
    pub fn caller_message(&mut self, line: &str) -> Vec<Observed> {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return vec![] };
        if v.get("method").and_then(|m| m.as_str()) == Some("session/prompt")
            && let Some(id) = id_key(&v)
        {
            let text: String = v
                .pointer("/params/prompt")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().filter_map(|b| b.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n"))
                .unwrap_or_default();
            if self.pending.is_empty() {
                self.turn_text.clear();
            }
            self.pending.insert(id, ());
            return vec![Observed::PromptStarted { bytes: text.len(), preview: truncate_utf8(&text, 200).0 }];
        }
        vec![]
    }

    /// A message from the harness (towards the caller).
    pub fn agent_message(&mut self, line: &str) -> Vec<Observed> {
        let Ok(v) = serde_json::from_str::<Value>(line) else { return vec![] };
        let method = v.get("method").and_then(|m| m.as_str());
        match (method, id_key(&v)) {
            // response
            (None, Some(id)) if self.pending.remove(&id).is_some() => {
                let stop = v.pointer("/result/stopReason").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let error = v.get("error").map(|e| {
                    let msg = e.get("message").and_then(|m| m.as_str()).unwrap_or("error");
                    truncate_utf8(msg, 500).0
                });
                let stop = if error.is_some() { "error".to_string() } else { stop };
                let text = std::mem::take(&mut self.turn_text);
                vec![Observed::PromptEnded { stop_reason: stop, error, text }]
            }
            (Some("session/update"), None) => {
                let params = v.get("params").cloned().unwrap_or(Value::Null);
                match normalize::decode(&params) {
                    SessionUpdate::AgentMessageChunk { text } => {
                        if self.turn_text.len() < MAX_TURN_TEXT {
                            self.turn_text.push_str(&text);
                        }
                        vec![]
                    }
                    SessionUpdate::ToolCall { id, title, kind, status, raw_input } => {
                        vec![Observed::Agent(AgentEvent::ToolCall {
                            data: ToolCallData { tool_call_id: id, title, kind, status, input: raw_input },
                            raw: None,
                        })]
                    }
                    SessionUpdate::ToolCallUpdate { id, status: Some(status), text, .. }
                        if status == "completed" || status == "failed" =>
                    {
                        vec![Observed::Agent(AgentEvent::ToolResult {
                            data: ToolResultData {
                                tool_call_id: id,
                                is_error: status == "failed",
                                status,
                                output: text.map(|t| truncate_utf8(&t, 4000).0),
                            },
                            raw: None,
                        })]
                    }
                    _ => vec![],
                }
            }
            (Some("session/request_permission"), Some(_)) => {
                let title = v.pointer("/params/toolCall/title").and_then(|t| t.as_str()).unwrap_or("permission");
                vec![Observed::Agent(AgentEvent::PermissionRequest {
                    data: PermissionRequestData {
                        tool_call_id: v
                            .pointer("/params/toolCall/toolCallId")
                            .and_then(|t| t.as_str())
                            .map(str::to_string),
                        title: title.to_string(),
                        decision: "forwarded_to_caller".into(),
                        option_id: None,
                    },
                    raw: None,
                })]
            }
            _ => vec![],
        }
    }

    /// Is this agent message a request (needs an answer from a client)?
    pub fn is_request(line: &str) -> Option<Value> {
        let v: Value = serde_json::from_str(line).ok()?;
        (v.get("method").is_some() && v.get("id").is_some_and(|i| !i.is_null())).then(|| v["id"].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_lifecycle_is_observed_without_changing_bytes() {
        let mut t = AcpTap::default();
        assert!(!t.busy());
        let p = r#"{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s","prompt":[{"type":"text","text":"hi"}]}}"#;
        assert!(matches!(t.caller_message(p)[0], Observed::PromptStarted { bytes: 2, .. }));
        assert!(t.busy());
        t.agent_message(r#"{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}}}"#);
        // a response to some other id does not end the turn
        assert!(t.agent_message(r#"{"jsonrpc":"2.0","id":8,"result":{}}"#).is_empty());
        assert!(t.busy());
        match &t.agent_message(r#"{"jsonrpc":"2.0","id":7,"result":{"stopReason":"end_turn"}}"#)[0] {
            Observed::PromptEnded { stop_reason, text, error } => {
                assert_eq!(stop_reason, "end_turn");
                assert_eq!(text, "hello");
                assert!(error.is_none());
            }
            o => panic!("{o:?}"),
        }
        assert!(!t.busy());
        assert!(
            AcpTap::is_request(r#"{"jsonrpc":"2.0","id":3,"method":"session/request_permission","params":{}}"#)
                .is_some()
        );
        assert!(AcpTap::is_request(r#"{"jsonrpc":"2.0","method":"session/update","params":{}}"#).is_none());
    }
}
