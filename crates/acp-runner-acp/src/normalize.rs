//! Tolerant decoding of `session/update` notifications.
//!
//! Unknown `sessionUpdate` kinds are preserved as [`SessionUpdate::Other`] rather than
//! rejected, so adapter upgrades that add update kinds do not break the runner.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionUpdate {
    AgentMessageChunk { text: String },
    AgentThoughtChunk { text: String },
    UserMessageChunk { text: String },
    ToolCall { id: String, title: String, kind: Option<String>, status: Option<String>, raw_input: Option<Value> },
    ToolCallUpdate { id: String, status: Option<String>, title: Option<String>, text: Option<String> },
    Plan { entries: Value },
    Other { kind: String },
}

pub fn decode(params: &Value) -> SessionUpdate {
    let update = params.get("update").unwrap_or(&Value::Null);
    let kind = update.get("sessionUpdate").and_then(|k| k.as_str()).unwrap_or("");
    let s = |k: &str| update.get(k).and_then(|x| x.as_str()).map(str::to_string);
    match kind {
        "agent_message_chunk" => SessionUpdate::AgentMessageChunk { text: content_text(update.get("content")) },
        "agent_thought_chunk" => SessionUpdate::AgentThoughtChunk { text: content_text(update.get("content")) },
        "user_message_chunk" => SessionUpdate::UserMessageChunk { text: content_text(update.get("content")) },
        "tool_call" => SessionUpdate::ToolCall {
            id: s("toolCallId").unwrap_or_default(),
            title: s("title").unwrap_or_default(),
            kind: s("kind"),
            status: s("status"),
            raw_input: update.get("rawInput").cloned(),
        },
        "tool_call_update" => SessionUpdate::ToolCallUpdate {
            id: s("toolCallId").unwrap_or_default(),
            status: s("status"),
            title: s("title"),
            text: tool_content_text(update.get("content")),
        },
        "plan" => SessionUpdate::Plan { entries: update.get("entries").cloned().unwrap_or(Value::Null) },
        other => SessionUpdate::Other { kind: other.to_string() },
    }
}

/// Text of a single ACP `ContentBlock` (or array of blocks).
pub fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::Array(items)) => items.iter().map(|i| content_text(Some(i))).collect::<Vec<_>>().join(""),
        Some(Value::Object(o)) => match o.get("type").and_then(|t| t.as_str()) {
            Some("text") => o.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string(),
            Some("resource_link") => format!("[resource {}]", o.get("uri").and_then(|u| u.as_str()).unwrap_or("?")),
            Some("resource") => o
                .get("resource")
                .and_then(|r| r.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("[resource]")
                .to_string(),
            Some(other) => format!("[{other}]"),
            None => String::new(),
        },
        _ => String::new(),
    }
}

/// Text summary of `ToolCallContent[]` (`content`, `diff`, `terminal`).
pub fn tool_content_text(content: Option<&Value>) -> Option<String> {
    let arr = content?.as_array()?;
    let mut parts = vec![];
    for item in arr {
        match item.get("type").and_then(|t| t.as_str()) {
            Some("content") => parts.push(content_text(item.get("content"))),
            Some("diff") => parts.push(format!("[diff {}]", item.get("path").and_then(|p| p.as_str()).unwrap_or("?"))),
            Some("terminal") => {
                parts.push(format!("[terminal {}]", item.get("terminalId").and_then(|p| p.as_str()).unwrap_or("?")))
            }
            _ => {}
        }
    }
    if parts.is_empty() { None } else { Some(parts.join("\n")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decodes_known_and_unknown_updates() {
        let p = json!({"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"hello"}}});
        assert_eq!(decode(&p), SessionUpdate::AgentMessageChunk { text: "hello".into() });
        let p = json!({"sessionId":"s","update":{"sessionUpdate":"tool_call","toolCallId":"t1","title":"Edit add.sh","kind":"edit","status":"pending"}});
        assert!(matches!(decode(&p), SessionUpdate::ToolCall { ref id, .. } if id == "t1"));
        let p = json!({"sessionId":"s","update":{"sessionUpdate":"tool_call_update","toolCallId":"t1","status":"completed",
            "content":[{"type":"content","content":{"type":"text","text":"ok"}},{"type":"diff","path":"/w/add.sh","newText":"x"}]}});
        match decode(&p) {
            SessionUpdate::ToolCallUpdate { status, text, .. } => {
                assert_eq!(status.as_deref(), Some("completed"));
                assert_eq!(text.as_deref(), Some("ok\n[diff /w/add.sh]"));
            }
            other => panic!("{other:?}"),
        }
        let p = json!({"sessionId":"s","update":{"sessionUpdate":"brand_new_kind","x":1}});
        assert_eq!(decode(&p), SessionUpdate::Other { kind: "brand_new_kind".into() });
    }
}
