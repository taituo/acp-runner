//! Append-only, provider-neutral event model.
//!
//! Events are journaled in PostgreSQL (`session_events`), never in Kubernetes objects.
//! `data` holds the normalized, redacted payload; `raw` optionally preserves the original
//! ACP/provider message (also redacted, size-capped) for diagnostics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    RunCreated,
    AttemptStarted,
    AgentStarted,
    SessionStarted,
    InputSent,
    AgentOutput,
    ToolCall,
    ToolResult,
    PermissionRequest,
    Progress,
    ArtifactCreated,
    Heartbeat,
    AttemptFailed,
    AttemptTimedOut,
    AttemptCompleted,
    RunCompleted,
    RunFailed,
}

impl EventKind {
    pub const ALL: [EventKind; 17] = [
        EventKind::RunCreated,
        EventKind::AttemptStarted,
        EventKind::AgentStarted,
        EventKind::SessionStarted,
        EventKind::InputSent,
        EventKind::AgentOutput,
        EventKind::ToolCall,
        EventKind::ToolResult,
        EventKind::PermissionRequest,
        EventKind::Progress,
        EventKind::ArtifactCreated,
        EventKind::Heartbeat,
        EventKind::AttemptFailed,
        EventKind::AttemptTimedOut,
        EventKind::AttemptCompleted,
        EventKind::RunCompleted,
        EventKind::RunFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::RunCreated => "RunCreated",
            EventKind::AttemptStarted => "AttemptStarted",
            EventKind::AgentStarted => "AgentStarted",
            EventKind::SessionStarted => "SessionStarted",
            EventKind::InputSent => "InputSent",
            EventKind::AgentOutput => "AgentOutput",
            EventKind::ToolCall => "ToolCall",
            EventKind::ToolResult => "ToolResult",
            EventKind::PermissionRequest => "PermissionRequest",
            EventKind::Progress => "Progress",
            EventKind::ArtifactCreated => "ArtifactCreated",
            EventKind::Heartbeat => "Heartbeat",
            EventKind::AttemptFailed => "AttemptFailed",
            EventKind::AttemptTimedOut => "AttemptTimedOut",
            EventKind::AttemptCompleted => "AttemptCompleted",
            EventKind::RunCompleted => "RunCompleted",
            EventKind::RunFailed => "RunFailed",
        }
    }

    /// Events that prove the agent is making progress (reset the no-progress watchdog).
    pub fn counts_as_progress(self) -> bool {
        matches!(
            self,
            EventKind::AgentStarted
                | EventKind::SessionStarted
                | EventKind::InputSent
                | EventKind::AgentOutput
                | EventKind::ToolCall
                | EventKind::ToolResult
                | EventKind::PermissionRequest
                | EventKind::Progress
                | EventKind::ArtifactCreated
        )
    }

    /// Terminal attempt events reported by runnerd.
    pub fn is_attempt_terminal(self) -> bool {
        matches!(self, EventKind::AttemptFailed | EventKind::AttemptTimedOut | EventKind::AttemptCompleted)
    }

    /// Kinds runnerd is allowed to submit through the ingest API. Run-level and
    /// controller-owned kinds are rejected there.
    pub fn runner_may_emit(self) -> bool {
        !matches!(
            self,
            EventKind::RunCreated | EventKind::AttemptStarted | EventKind::RunCompleted | EventKind::RunFailed
        )
    }

    /// Kinds that may carry `source = agent`. Terminal attempt events, artifacts,
    /// heartbeats and lifecycle facts are only ever reported by runnerd or the controller.
    pub fn agent_may_emit(self) -> bool {
        matches!(
            self,
            EventKind::SessionStarted
                | EventKind::AgentOutput
                | EventKind::ToolCall
                | EventKind::ToolResult
                | EventKind::PermissionRequest
                | EventKind::Progress
        )
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        EventKind::ALL.iter().copied().find(|k| k.as_str() == s).ok_or_else(|| format!("unknown event kind {s:?}"))
    }
}

/// Progress categories that only runnerd may emit. An agent-sent event with one of
/// these categories is either renamed to `agent.<category>` (runnerd) or rejected
/// (ingest), and consumers only honour the runnerd-sourced variant.
pub const RUNNER_OWNED_CATEGORIES: &[&str] =
    &["workspace_ready", "gateway_listening", "environment_ready", "environment_busy", "turn_ended", "timeout"];

/// True if an agent-sent Progress with this category must be renamed/quarantined:
/// the exact list above plus the `snapshot_*`, `credential_writeback*` and `agent_*`
/// families from the trust review.
pub fn is_reserved_agent_category(category: &str) -> bool {
    RUNNER_OWNED_CATEGORIES.contains(&category)
        || category.starts_with("snapshot_")
        || category.starts_with("credential_writeback")
        || category.starts_with("agent_")
}

/// True if consumers must only honour the runnerd-sourced variant: a reserved
/// category, or an already-renamed `agent.<reserved>` which is never authoritative.
pub fn is_runner_owned_category(category: &str) -> bool {
    is_reserved_agent_category(category) || category.strip_prefix("agent.").is_some_and(is_reserved_agent_category)
}

/// Who produced an event. Trust decreases downwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventSource {
    /// The controller/engine (authoritative).
    Controller,
    /// runnerd, the trusted in-sandbox supervisor (authoritative for workspace, patch,
    /// credential write-back and terminal attempt state).
    Runnerd,
    /// agentd / the provider CLI (untrusted claims: conversation, tool calls, progress).
    Agent,
    /// Legacy (wire v1): driver events emitted by the single-process runnerd.
    Driver,
}

impl EventSource {
    pub fn as_str(self) -> &'static str {
        match self {
            EventSource::Controller => "controller",
            EventSource::Runnerd => "runnerd",
            EventSource::Agent => "agent",
            EventSource::Driver => "driver",
        }
    }
}

/// Transport/journal envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    /// Per-attempt sequence number assigned by runnerd (idempotent re-delivery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub ts: DateTime<Utc>,
    pub kind: EventKind,
    pub source: EventSource,
    pub data: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

impl EventEnvelope {
    pub fn new(kind: EventKind, source: EventSource, data: impl Serialize) -> Self {
        EventEnvelope {
            seq: None,
            ts: Utc::now(),
            kind,
            source,
            data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null),
            raw: None,
        }
    }

    pub fn with_raw(mut self, raw: Option<serde_json::Value>) -> Self {
        self.raw = raw;
        self
    }
}

// ---- normalized payloads -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStartedData {
    pub driver: String,
    pub program: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartedData {
    /// Provider-internal session id. Informational only: the canonical identity is the
    /// attempt id, and provider sessions are never resumed across attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_session_id: Option<String>,
    /// e.g. `acp/1` or `claude-stream-json`.
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default)]
    pub capabilities: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputSentData {
    pub bytes: usize,
    pub sha256: String,
    pub preview: String,
    pub has_resume_capsule: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentOutputData {
    /// `message` or `thought`.
    pub channel: String,
    pub text: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallData {
    pub tool_call_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResultData {
    pub tool_call_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub title: String,
    /// `allowed`, `denied` or `cancelled`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressData {
    pub category: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

impl ProgressData {
    pub fn new(category: impl Into<String>, message: impl Into<String>) -> Self {
        ProgressData { category: category.into(), message: message.into(), detail: serde_json::Value::Null }
    }
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = detail;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatData {
    pub agent_alive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_since_progress: Option<u64>,
    pub stage: String,
    /// Directive ids runnerd has consumed (V5a explicit acks). Older runnerds
    /// omit this; redelivery + runnerd-side dedupe cover the gap.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acked_directives: Vec<uuid::Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedPath {
    pub path: String,
    /// git name-status letter: A, M, D, T.
    pub status: String,
    #[serde(default)]
    pub is_symlink: bool,
    #[serde(default)]
    pub is_binary: bool,
    /// Staged git mode (`100644`, `100755`, `120000`, …; V6). Empty for
    /// deletions and for artifacts recorded before V6, so old JSON still parses.
    #[serde(default)]
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactCreatedData {
    pub artifact_id: uuid::Uuid,
    /// `patch` (successful attempt) or `partial_patch` (failed attempt, diagnostic only).
    pub kind: String,
    pub base_revision: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub changed_paths: Vec<ChangedPath>,
    pub storage: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptTerminalData {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<crate::failure::FailureReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
    /// Short summary (last agent message excerpt), used by resume capsules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<uuid::Uuid>,
}

/// Instruction returned to runnerd in the heartbeat response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum RunnerDirective {
    /// Cancel the agent (e.g. the controller detected no agent progress). runnerd forwards
    /// a `Cancel` to agentd, collects the partial patch and reports the terminal state with
    /// `reason`. If the attempt is still active after the grace period, the controller
    /// terminates the sandbox.
    Cancel { reason: crate::failure::FailureReason },
    /// Environment mode: collect a non-terminal workspace snapshot (patch vs. the base) at the
    /// next Idle boundary and upload it. Does not end the session.
    Snapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot_id: Option<uuid::Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Environment mode: quiesce the harness, collect the authoritative final changeset,
    /// hand back refreshed credentials and report completion.
    Finish,
}

/// Body of `POST /v1/attempt/heartbeat` responses (wire v2).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatReply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directive: Option<RunnerDirective>,
    /// Durable-queue row id for `directive` (V5a). runnerd acks it on a later
    /// heartbeat; unacked rows are redelivered. Older ingests omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directive_id: Option<uuid::Uuid>,
    /// V10c: credential lease expiry (unix seconds) when the attempt holds one.
    /// runnerd stops the agent once heartbeats have failed continuously past
    /// this point. Older ingests omit this; absent means "no lease known".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<i64>,
}

/// Truncate a string to at most `max` bytes on a char boundary.
pub fn truncate_utf8(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_roundtrip() {
        for k in EventKind::ALL {
            assert_eq!(k.as_str().parse::<EventKind>().unwrap(), k);
        }
    }

    #[test]
    fn runner_cannot_emit_run_level_events() {
        assert!(!EventKind::RunCompleted.runner_may_emit());
        assert!(!EventKind::AttemptStarted.runner_may_emit());
        assert!(EventKind::AttemptCompleted.runner_may_emit());
        assert!(EventKind::AgentOutput.runner_may_emit());
    }

    #[test]
    fn agent_cannot_emit_authoritative_kinds() {
        for k in [
            EventKind::AttemptCompleted,
            EventKind::AttemptFailed,
            EventKind::AttemptTimedOut,
            EventKind::ArtifactCreated,
            EventKind::Heartbeat,
            EventKind::AgentStarted,
            EventKind::RunCompleted,
        ] {
            assert!(!k.agent_may_emit(), "{k}");
        }
        assert!(EventKind::AgentOutput.agent_may_emit());
        assert_eq!(serde_json::to_value(EventSource::Agent).unwrap(), "agent");
    }

    #[test]
    fn heartbeat_is_not_progress() {
        assert!(!EventKind::Heartbeat.counts_as_progress());
        assert!(EventKind::ToolCall.counts_as_progress());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let (t, cut) = truncate_utf8("ääää", 3);
        assert!(cut);
        assert_eq!(t, "ä");
        let (t, cut) = truncate_utf8("abc", 10);
        assert!(!cut);
        assert_eq!(t, "abc");
    }
}
