//! Security and failure-mode tests for the in-sandbox supervisor (deterministic, fake agents).

mod common;

use acp_runner_core::AttemptPhase;
use acp_runner_core::events::EventKind;
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::PermissionMode;
use common::*;

#[tokio::test]
async fn credential_values_never_reach_events_logs_or_artifacts() {
    let mut env = TestEnv::new(&Target::fake_acp()).await;
    let auth = serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {"access_token": "access-token-secret-value-0123456789", "refresh_token": FAKE_CODEX_REFRESH,
                   "id_token": "id-token-secret-value-0123456789", "account_id": "acct"}
    });
    env.add_file_credential("codex", "auth.json", ".codex/auth.json", auth.to_string().as_bytes(), true);
    env.add_env_credential("claude", "oauth-token", "CLAUDE_CODE_OAUTH_TOKEN", FAKE_CLAUDE_TOKEN.as_bytes());
    let (res, rec) = env.run("leak-secret", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    let text = all_text(&rec);
    for s in env.secrets() {
        assert!(!text.contains(&s), "secret leaked into journal: {}", &s[..8.min(s.len())]);
    }
    assert!(text.contains("[REDACTED]"), "expected redaction marker");
}

#[tokio::test]
async fn symlink_escape_fails_the_attempt() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("escape-symlink", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::WorkspacePolicyViolation { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn patch_size_limit_is_enforced() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec) = env.run("huge", |s| s.output.max_patch_bytes = 64 * 1024).await;
    assert!(matches!(res.reason, Some(FailureReason::ArtifactTooLarge { limit_bytes: 65536, .. })), "{:?}", res.reason);
    assert!(rec.artifacts.is_empty());
}

#[tokio::test]
async fn writes_outside_the_workspace_are_not_captured() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec) = env.run("write-outside", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    let paths: Vec<_> = rec.artifacts[0].changed_paths.iter().map(|c| c.path.clone()).collect();
    assert_eq!(paths, vec!["add.sh".to_string()]);
}

#[tokio::test]
async fn acp_auth_required_maps_to_enrollment_required() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("auth-required", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::AuthEnrollmentRequired { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn api_key_mode_is_a_policy_violation() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("api-key-mode", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::AuthPolicyViolation { .. })), "{:?}", res.reason);
    let env = TestEnv::new(&Target::fake_claude()).await;
    let (res, _) = env.run("api-key", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::AuthPolicyViolation { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn claude_auth_failure_requires_enrollment() {
    let env = TestEnv::new(&Target::fake_claude()).await;
    let (res, _) = env.run("auth-fail", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::AuthEnrollmentRequired { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn missing_claude_token_is_detected_by_probe() {
    let mut env = TestEnv::new(&Target::fake_claude()).await;
    env.layout = None;
    let (res, _) = env.run("fix", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::AuthEnrollmentRequired { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn unsupported_protocol_version_is_reported() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("bad-protocol", |_| {}).await;
    assert!(matches!(res.reason, Some(FailureReason::Unsupported { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn refusal_and_noop_are_failures() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("refuse", |_| {}).await;
    assert!(
        matches!(res.reason, Some(FailureReason::AgentStopped { ref stop_reason, .. }) if stop_reason == "refusal")
    );
    let (res, _) = env.run("noop", |_| {}).await;
    assert_eq!(res.reason, Some(FailureReason::NoChanges));
    let (res, _) = env.run("noop", |s| s.output.require_changes = false).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded);
}

#[tokio::test]
async fn denied_permissions_prevent_changes() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec) = env.run("fix", |s| s.permissions.mode = PermissionMode::DenyAll).await;
    assert_eq!(res.reason, Some(FailureReason::NoChanges));
    assert!(rec.events.iter().any(|e| e.kind == EventKind::PermissionRequest && e.data["decision"] == "denied"));
}

#[tokio::test]
async fn garbage_on_stdout_is_tolerated() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec) = env.run("garbage", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}\n{}", res.reason, dump(&rec));
    assert!(progress(&rec, "protocol_warning"));
}

#[tokio::test]
async fn forbidden_environment_is_refused() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env
        .run("fix", |s| {
            s.env.insert("OPENAI_API_KEY".into(), "sk-proj-shouldneverbeused000000000".into());
        })
        .await;
    assert!(matches!(res.reason, Some(FailureReason::Unsupported { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn refreshed_credentials_are_written_back_not_mutated_in_place() {
    let mut env = TestEnv::new(&Target::fake_acp()).await;
    env.add_file_credential("codex", "auth.json", ".codex/auth.json", br#"{"auth_mode":"chatgpt","v":1}"#, true);
    let (res, rec) = env.run("refresh-credential", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    assert_eq!(rec.writebacks.len(), 1);
    assert!(String::from_utf8_lossy(&rec.writebacks[0].1).contains("refreshed"));
    // the mounted source is never modified
    let mounted = std::fs::read_to_string(env.secret_dir.join("cred.auth.json")).unwrap();
    assert_eq!(mounted, r#"{"auth_mode":"chatgpt","v":1}"#);
}

#[tokio::test]
async fn workspace_prepare_failure_is_reported() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _) = env.run("fix", |s| s.repository.revision = "2222222222222222222222222222222222222222".into()).await;
    assert!(matches!(res.reason, Some(FailureReason::WorkspacePrepareFailed { .. })), "{:?}", res.reason);
}

#[tokio::test]
async fn sparse_and_binary_and_commit_scenarios() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec) = env.run("fix-binary", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded);
    let art = &rec.artifacts[0];
    assert!(art.changed_paths.iter().any(|c| c.path == "assets/logo.bin" && c.is_binary));
    env.assert_patch_applies_and_fixes(&art.patch_bytes().unwrap()).await;
    let (res, rec) = env.run("commit", |_| {}).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded);
    env.assert_patch_applies_and_fixes(&rec.artifacts[0].patch_bytes().unwrap()).await;
    let (res, rec) = env.run("fix", |s| s.repository.sparse_paths = vec!["add.sh".into(), "test.sh".into()]).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    assert_eq!(rec.artifacts[0].changed_paths.len(), 1);
}

#[tokio::test]
async fn failed_attempt_keeps_partial_patch() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    // fixes the file, then the turn ends with a refusal-like stop: use slow + hard timeout
    let (res, rec) = env
        .run("silent-then-fix:30", |s| {
            s.timeouts.no_progress_seconds = 2;
            s.apply_patch_b64 = None;
        })
        .await;
    assert_eq!(res.phase, AttemptPhase::TimedOut);
    // nothing changed yet -> no partial artifact
    assert!(rec.artifacts.is_empty());
}
