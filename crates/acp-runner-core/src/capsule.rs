//! Provider-neutral resume capsule.
//!
//! Retries and fallbacks always start a **new** provider session. Provider-internal state
//! (Claude session files, Codex rollouts) is never assumed portable. Instead the engine
//! builds a capsule from canonical state it owns — the original task, the authoritative
//! base revision, the journaled normalized transcript, the latest failure and the latest
//! patch artifact — and renders it into the prompt of the next attempt.

use crate::events::truncate_utf8;
use crate::spec::RepositoryInput;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CAPSULE_VERSION: u32 = 1;
const MAX_MESSAGE_BYTES: usize = 2_000;
const MAX_DIAGNOSTICS_BYTES: usize = 4_000;
pub const MAX_CAPSULE_PATCH_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeCapsule {
    pub version: u32,
    pub run_id: Uuid,
    pub task_id: String,
    pub original_task: String,
    pub repository: RepositoryInput,
    /// Resolved base revision of the most recent attempt (if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    pub previous_attempts: Vec<PreviousAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_artifact: Option<PreviousArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transcript: Vec<CapsuleMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_diagnostics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviousAttempt {
    pub ordinal: u32,
    pub runner_class: String,
    pub driver: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub tool_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviousArtifact {
    pub attempt_id: Uuid,
    pub sha256: String,
    pub changed_paths: Vec<String>,
    /// Patch text (possibly truncated). Binary hunks remain in git's base85 encoding.
    pub patch: String,
    pub truncated: bool,
    /// True when runnerd applied this patch to the workspace before the agent started.
    pub applied_to_workspace: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleMessage {
    pub attempt_ordinal: u32,
    /// `agent` or `tool`.
    pub role: String,
    pub text: String,
}

impl CapsuleMessage {
    pub fn new(attempt_ordinal: u32, role: &str, text: &str) -> Self {
        let (text, _) = truncate_utf8(text, MAX_MESSAGE_BYTES);
        CapsuleMessage { attempt_ordinal, role: role.to_string(), text }
    }
}

impl PreviousArtifact {
    pub fn from_patch(
        attempt_id: Uuid,
        sha256: String,
        changed_paths: Vec<String>,
        patch: &[u8],
        applied: bool,
    ) -> Self {
        let text = String::from_utf8_lossy(patch);
        let (patch, truncated) = truncate_utf8(&text, MAX_CAPSULE_PATCH_BYTES);
        PreviousArtifact { attempt_id, sha256, changed_paths, patch, truncated, applied_to_workspace: applied }
    }
}

impl ResumeCapsule {
    pub fn set_diagnostics(&mut self, text: &str) {
        let (t, _) = truncate_utf8(text, MAX_DIAGNOSTICS_BYTES);
        self.latest_diagnostics = Some(t);
    }

    /// Render the capsule into provider-neutral prompt text appended to the original task.
    pub fn render_prompt(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.original_task);
        out.push_str("\n\n---\n");
        out.push_str(&format!("[acp-runner resume capsule v{}]\n", self.version));
        out.push_str(
            "This task was attempted before in other, independent agent sessions. Those sessions are \
             not available to you; the summary below is provided as context only. Verify everything \
             yourself against the repository.\n",
        );
        match (&self.base_revision, &self.previous_artifact) {
            (_, Some(a)) if a.applied_to_workspace => out.push_str(&format!(
                "The workspace starts at base revision {} WITH the previous attempt's patch (sha256 {}) already applied.\n",
                self.base_revision.as_deref().unwrap_or(&self.repository.revision),
                &a.sha256[..a.sha256.len().min(12)]
            )),
            (rev, _) => out.push_str(&format!(
                "The workspace has been reset to the base revision {} (previous changes are NOT applied).\n",
                rev.as_deref().unwrap_or(&self.repository.revision)
            )),
        }
        out.push_str("\nPrevious attempts:\n");
        for a in &self.previous_attempts {
            out.push_str(&format!(
                "- attempt {} on runner class `{}` (driver {}): {}",
                a.ordinal, a.runner_class, a.driver, a.phase
            ));
            if let Some(code) = &a.failure_code {
                out.push_str(&format!(" — {code}"));
            }
            if let Some(m) = &a.failure_message {
                out.push_str(&format!(": {m}"));
            }
            out.push_str(&format!(" ({} tool calls)\n", a.tool_calls));
            if let Some(s) = &a.summary {
                out.push_str(&format!("  last message: {}\n", one_line(s, 400)));
            }
        }
        if !self.transcript.is_empty() {
            out.push_str("\nRelevant messages from previous attempts (oldest first):\n");
            for m in &self.transcript {
                out.push_str(&format!("- [attempt {} {}] {}\n", m.attempt_ordinal, m.role, one_line(&m.text, 600)));
            }
        }
        if let Some(d) = &self.latest_diagnostics {
            out.push_str("\nLatest failure diagnostics:\n```\n");
            out.push_str(d);
            out.push_str("\n```\n");
        }
        if let Some(a) = &self.previous_artifact
            && !a.applied_to_workspace
        {
            out.push_str(&format!(
                "\nPartial patch produced by attempt {} (for reference{}):\n```diff\n",
                a.attempt_id,
                if a.truncated { ", truncated" } else { "" }
            ));
            out.push_str(&a.patch);
            if !a.patch.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("```\n");
        }
        out
    }
}

fn one_line(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let (t, cut) = truncate_utf8(&flat, max);
    if cut { format!("{t}…") } else { t }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule() -> ResumeCapsule {
        ResumeCapsule {
            version: CAPSULE_VERSION,
            run_id: Uuid::nil(),
            task_id: "t".into(),
            original_task: "Fix the add function".into(),
            repository: RepositoryInput {
                url: "file:///repo".into(),
                revision: "abc".into(),
                sparse_paths: vec![],
                depth: None,
            },
            base_revision: Some("abcdef0123456789".into()),
            previous_attempts: vec![PreviousAttempt {
                ordinal: 1,
                runner_class: "claude-default".into(),
                driver: "claude".into(),
                phase: "TimedOut".into(),
                failure_code: Some("NoProgressTimeout".into()),
                failure_message: Some("no agent progress for 600s".into()),
                summary: Some("I was running the tests".into()),
                tool_calls: 3,
            }],
            previous_artifact: Some(PreviousArtifact::from_patch(
                Uuid::nil(),
                "deadbeefcafebabe".into(),
                vec!["add.sh".into()],
                b"diff --git a/add.sh b/add.sh\n",
                false,
            )),
            transcript: vec![CapsuleMessage::new(1, "agent", "Looking at add.sh")],
            latest_diagnostics: None,
        }
    }

    #[test]
    fn render_is_provider_neutral_and_contains_context() {
        let mut c = capsule();
        c.set_diagnostics("test failed: expected 5 got -1");
        let p = c.render_prompt();
        assert!(p.starts_with("Fix the add function"));
        assert!(p.contains("resume capsule v1"));
        assert!(p.contains("NoProgressTimeout"));
        assert!(p.contains("```diff"));
        assert!(p.contains("expected 5 got -1"));
        assert!(p.contains("NOT applied"));
        assert!(!p.to_lowercase().contains("claude session id"));
    }

    #[test]
    fn applied_patch_is_not_repeated() {
        let mut c = capsule();
        c.previous_artifact.as_mut().unwrap().applied_to_workspace = true;
        let p = c.render_prompt();
        assert!(p.contains("already applied"));
        assert!(!p.contains("```diff"));
    }

    #[test]
    fn serde_roundtrip() {
        let c = capsule();
        let v = serde_json::to_value(&c).unwrap();
        let back: ResumeCapsule = serde_json::from_value(v).unwrap();
        assert_eq!(back, c);
    }
}
