//! Build a provider-neutral [`ResumeCapsule`] from canonical journal state.

use crate::Engine;
use acp_runner_core::capsule::{CAPSULE_VERSION, CapsuleMessage, PreviousArtifact, PreviousAttempt, ResumeCapsule};
use acp_runner_core::events::EventKind;
use acp_runner_core::spec::RunSpec;
use acp_runner_journal::{AttemptRow, RunRow};

pub struct BuiltCapsule {
    pub capsule: ResumeCapsule,
    /// Full content of the latest previous patch (for `resume.applyPreviousPatch`).
    pub previous_patch: Option<Vec<u8>>,
}

const MAX_APPLY_PATCH_BYTES: i64 = 4 * 1024 * 1024;

pub async fn build(
    engine: &Engine,
    run: &RunRow,
    spec: &RunSpec,
    previous: &[AttemptRow],
) -> anyhow::Result<BuiltCapsule> {
    let mut attempts = vec![];
    for a in previous {
        let tool_calls = engine.journal.count_events(a.id, EventKind::ToolCall).await.unwrap_or(0);
        let failure = a.failure();
        attempts.push(PreviousAttempt {
            ordinal: a.ordinal as u32,
            runner_class: a.runner_class.clone(),
            driver: a.driver.clone(),
            phase: a.phase.clone(),
            failure_code: failure.as_ref().map(|f| f.code().to_string()),
            failure_message: failure.as_ref().map(|f| f.message()),
            summary: a.outcome.as_ref().and_then(|o| o.get("summary")).and_then(|s| s.as_str()).map(str::to_string),
            tool_calls: tool_calls as u32,
        });
    }
    let mut transcript = vec![];
    if spec.resume.include_transcript {
        let max = spec.resume.max_transcript_messages as usize;
        // most recent attempts first, then restore chronological order
        for a in previous.iter().rev() {
            if transcript.len() >= max {
                break;
            }
            let evs = engine
                .journal
                .events_for_attempt(a.id, &[EventKind::AgentOutput, EventKind::ToolResult], (max * 4) as i64)
                .await?;
            let mut msgs: Vec<CapsuleMessage> = evs
                .iter()
                .filter_map(|e| match e.kind.as_str() {
                    "AgentOutput" if e.data.get("channel").and_then(|c| c.as_str()) == Some("message") => e
                        .data
                        .get("text")
                        .and_then(|t| t.as_str())
                        .filter(|t| !t.trim().is_empty())
                        .map(|t| CapsuleMessage::new(a.ordinal as u32, "agent", t)),
                    "ToolResult" if e.data.get("isError").and_then(|x| x.as_bool()) == Some(true) => e
                        .data
                        .get("output")
                        .and_then(|t| t.as_str())
                        .map(|t| CapsuleMessage::new(a.ordinal as u32, "tool-error", t)),
                    _ => None,
                })
                .collect();
            let keep = max.saturating_sub(transcript.len());
            if msgs.len() > keep {
                msgs.drain(..msgs.len() - keep);
            }
            msgs.extend(transcript);
            transcript = msgs;
        }
    }
    let last = previous.last();
    let base_revision = previous.iter().rev().find_map(|a| a.base_revision.clone());
    let mut previous_patch = None;
    let mut previous_artifact = None;
    if let Some(meta) = engine.artifacts.latest_for_run(run.id).await? {
        let content = engine.artifacts.get_content(meta.id).await.ok();
        if let Some(bytes) = content {
            let same_base = base_revision.as_deref().map(|b| b == meta.base_revision).unwrap_or(true);
            let apply = spec.resume.apply_previous_patch && same_base && meta.size_bytes <= MAX_APPLY_PATCH_BYTES;
            let paths: Vec<String> = meta
                .changed_paths
                .as_array()
                .map(|a| a.iter().filter_map(|p| p.get("path").and_then(|x| x.as_str()).map(str::to_string)).collect())
                .unwrap_or_default();
            previous_artifact =
                Some(PreviousArtifact::from_patch(meta.attempt_id, meta.sha256.clone(), paths, &bytes, apply));
            if apply {
                previous_patch = Some(bytes);
            }
        }
    }
    let mut capsule = ResumeCapsule {
        version: CAPSULE_VERSION,
        run_id: run.id,
        task_id: spec.task_id.clone(),
        original_task: spec.prompt.clone(),
        repository: spec.repository.clone(),
        base_revision,
        previous_attempts: attempts,
        previous_artifact,
        transcript,
        latest_diagnostics: None,
    };
    if let Some(f) = last.and_then(|a| a.failure()) {
        capsule.set_diagnostics(&f.message());
    }
    Ok(BuiltCapsule { capsule, previous_patch })
}
