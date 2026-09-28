//! Failure classification.
//!
//! Every failed/timed-out attempt carries exactly one [`FailureReason`]. The reason decides
//! (via [`FailureReason::disposition`]) whether the planner may retry the *same* runner
//! class, must skip to the next fallback class, or must stop the run.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "PascalCase")]
pub enum FailureReason {
    /// The agent CLI/adapter process exited unexpectedly.
    ProcessCrashed { exit_code: Option<i32>, signal: Option<i32>, detail: String },
    /// The sandbox (pod / Sandbox CR / local process) disappeared while the attempt was active.
    SandboxLost { detail: String },
    /// The sandbox failed (image pull, OOM of runnerd, eviction, ...) without a runnerd report.
    SandboxFailed { detail: String },
    /// The sandbox did not start within the startup timeout.
    StartTimeout { seconds: u64 },
    /// runnerd stopped sending heartbeats while the sandbox still looked alive.
    HeartbeatLost { seconds_since_last: u64 },
    /// No agent progress event within the configured window.
    NoProgressTimeout { seconds: u64 },
    /// Hard wall-clock timeout of the attempt.
    HardTimeout { seconds: u64 },
    /// No usable credential login state: a human must (re-)enroll the profile.
    AuthEnrollmentRequired { provider: String, detail: String },
    /// The CLI would have used a forbidden auth path (e.g. an API key). Never retried on this class.
    AuthPolicyViolation { detail: String },
    /// The driver/provider does not support what was requested in this architecture.
    Unsupported { detail: String },
    /// The agent spoke the protocol incorrectly (malformed JSON-RPC, wrong protocol version, ...).
    ProtocolError { detail: String },
    /// The agent ended its turn without success (refusal, max tokens, error result, ...).
    AgentStopped { stop_reason: String, detail: String },
    /// Output expectation required changes but the workspace is unchanged.
    NoChanges,
    /// The patch exceeded the configured size limit.
    ArtifactTooLarge { size_bytes: u64, limit_bytes: u64 },
    /// The agent produced a change that violates workspace policy (symlink escape, path outside allowed set, ...).
    WorkspacePolicyViolation { detail: String },
    /// Preparing the git workspace failed (fetch, checkout, sparse checkout, overlays).
    WorkspacePrepareFailed { detail: String },
    /// An environment bootstrap step failed (bundle verification/placement, workdir, harness
    /// artifact, or an untrusted `bootstrap.exec` command).
    BootstrapFailed { step: String, detail: String },
    /// No credential lease could be obtained for the configured profiles.
    CredentialUnavailable { detail: String },
    /// Run or attempt was cancelled by a user/orchestrator.
    Cancelled { detail: String },
    /// Anything else (bug, invariant violation). Retried on the same class.
    Internal { detail: String },
}

/// What the planner is allowed to do after a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetryDisposition {
    /// Another attempt on the same runner class is permitted (budget permitting).
    RetrySame,
    /// Do not retry this runner class; continue with the next fallback class.
    SkipToFallback,
    /// Stop the run.
    Fatal,
}

impl FailureReason {
    pub fn code(&self) -> &'static str {
        match self {
            FailureReason::ProcessCrashed { .. } => "ProcessCrashed",
            FailureReason::SandboxLost { .. } => "SandboxLost",
            FailureReason::SandboxFailed { .. } => "SandboxFailed",
            FailureReason::StartTimeout { .. } => "StartTimeout",
            FailureReason::HeartbeatLost { .. } => "HeartbeatLost",
            FailureReason::NoProgressTimeout { .. } => "NoProgressTimeout",
            FailureReason::HardTimeout { .. } => "HardTimeout",
            FailureReason::AuthEnrollmentRequired { .. } => "AuthEnrollmentRequired",
            FailureReason::AuthPolicyViolation { .. } => "AuthPolicyViolation",
            FailureReason::Unsupported { .. } => "Unsupported",
            FailureReason::ProtocolError { .. } => "ProtocolError",
            FailureReason::AgentStopped { .. } => "AgentStopped",
            FailureReason::NoChanges => "NoChanges",
            FailureReason::ArtifactTooLarge { .. } => "ArtifactTooLarge",
            FailureReason::WorkspacePolicyViolation { .. } => "WorkspacePolicyViolation",
            FailureReason::WorkspacePrepareFailed { .. } => "WorkspacePrepareFailed",
            FailureReason::BootstrapFailed { .. } => "BootstrapFailed",
            FailureReason::CredentialUnavailable { .. } => "CredentialUnavailable",
            FailureReason::Cancelled { .. } => "Cancelled",
            FailureReason::Internal { .. } => "Internal",
        }
    }

    pub fn disposition(&self) -> RetryDisposition {
        match self {
            FailureReason::Cancelled { .. } => RetryDisposition::Fatal,
            FailureReason::AuthEnrollmentRequired { .. }
            | FailureReason::AuthPolicyViolation { .. }
            | FailureReason::Unsupported { .. }
            | FailureReason::CredentialUnavailable { .. } => RetryDisposition::SkipToFallback,
            _ => RetryDisposition::RetrySame,
        }
    }

    /// True for the timeout family (used for metrics and `AttemptTimedOut` events).
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            FailureReason::NoProgressTimeout { .. }
                | FailureReason::HardTimeout { .. }
                | FailureReason::StartTimeout { .. }
                | FailureReason::HeartbeatLost { .. }
        )
    }

    /// Human readable one-liner, safe for CRD status (never contains credential material:
    /// all constructors receive already-redacted detail strings).
    pub fn message(&self) -> String {
        match self {
            FailureReason::ProcessCrashed { exit_code, signal, detail } => {
                format!("agent process crashed (exit_code={exit_code:?}, signal={signal:?}): {detail}")
            }
            FailureReason::SandboxLost { detail } => format!("sandbox disappeared: {detail}"),
            FailureReason::SandboxFailed { detail } => format!("sandbox failed: {detail}"),
            FailureReason::StartTimeout { seconds } => format!("sandbox did not start within {seconds}s"),
            FailureReason::HeartbeatLost { seconds_since_last } => {
                format!("no runnerd heartbeat for {seconds_since_last}s")
            }
            FailureReason::NoProgressTimeout { seconds } => format!("no agent progress for {seconds}s"),
            FailureReason::HardTimeout { seconds } => format!("hard timeout after {seconds}s"),
            FailureReason::AuthEnrollmentRequired { provider, detail } => {
                format!("{provider}: credential enrollment required: {detail}")
            }
            FailureReason::AuthPolicyViolation { detail } => format!("auth policy violation: {detail}"),
            FailureReason::Unsupported { detail } => format!("unsupported: {detail}"),
            FailureReason::ProtocolError { detail } => format!("protocol error: {detail}"),
            FailureReason::AgentStopped { stop_reason, detail } => {
                format!("agent stopped ({stop_reason}): {detail}")
            }
            FailureReason::NoChanges => "agent finished without changing the workspace".to_string(),
            FailureReason::ArtifactTooLarge { size_bytes, limit_bytes } => {
                format!("patch is {size_bytes} bytes, limit is {limit_bytes}")
            }
            FailureReason::WorkspacePolicyViolation { detail } => format!("workspace policy violation: {detail}"),
            FailureReason::WorkspacePrepareFailed { detail } => format!("workspace preparation failed: {detail}"),
            FailureReason::BootstrapFailed { step, detail } => format!("bootstrap step {step} failed: {detail}"),
            FailureReason::CredentialUnavailable { detail } => format!("credential unavailable: {detail}"),
            FailureReason::Cancelled { detail } => format!("cancelled: {detail}"),
            FailureReason::Internal { detail } => format!("internal error: {detail}"),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        FailureReason::Internal { detail: detail.into() }
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_skip_to_fallback() {
        let r = FailureReason::AuthEnrollmentRequired { provider: "codex".into(), detail: "x".into() };
        assert_eq!(r.disposition(), RetryDisposition::SkipToFallback);
        let r = FailureReason::AuthPolicyViolation { detail: "api key".into() };
        assert_eq!(r.disposition(), RetryDisposition::SkipToFallback);
    }

    #[test]
    fn crash_and_timeouts_retry_same() {
        assert_eq!(
            FailureReason::ProcessCrashed { exit_code: Some(3), signal: None, detail: String::new() }.disposition(),
            RetryDisposition::RetrySame
        );
        let t = FailureReason::NoProgressTimeout { seconds: 5 };
        assert!(t.is_timeout());
        assert_eq!(t.disposition(), RetryDisposition::RetrySame);
    }

    #[test]
    fn serde_is_tagged_by_code() {
        let r = FailureReason::HardTimeout { seconds: 10 };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["code"], "HardTimeout");
        let back: FailureReason = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
        let v = serde_json::to_value(FailureReason::NoChanges).unwrap();
        assert_eq!(v["code"], "NoChanges");
    }
}
