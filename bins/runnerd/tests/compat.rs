//! Driver compatibility / regression suite.
//!
//! Verifies the *driver contract*, never exact LLM prose:
//!
//! | # | contract                                   | test                                   |
//! |---|--------------------------------------------|----------------------------------------|
//! | 1 | executable exists                          | `c01_probe_detects_executable_and_version` |
//! | 2 | version detected                           | `c01_...`                              |
//! | 3 | auth state detected safely (no secrets)    | `c02_auth_state_is_detected_safely`     |
//! | 4 | session/process starts                     | `c03_fix_end_to_end`                    |
//! | 5 | prompt can be sent                         | `c03_...` (InputSent)                   |
//! | 6 | output/event received                      | `c03_...` (AgentOutput/ToolCall)        |
//! | 7 | cancellation works                         | `c04_cancellation`                      |
//! | 8 | process exit recognized                    | `c05_crash_is_recognized`               |
//! | 9 | workspace mutation recognized              | `c03_...` (changed paths)               |
//! |10 | patch collected (parses, applies to base)  | `c03_...`                               |
//! |11 | timeout recognized                         | `c06_no_progress_timeout`, `c07_...`    |
//! |12 | refreshed credential handed back           | `c10_refreshed_credentials_are_written_back` |
//! |13 | env credentials never persist in HOME      | `c11_staged_env_credentials_are_consumed` |
//!
//! Every target runs through the v2 split: runnerd (this test process, trusted) starts
//! agentd, which runs the driver/CLI and talks to runnerd over the local socket.
//!
//! Targets (env `ACP_COMPAT_TARGETS`, comma separated; default `fake-acp,fake-claude,fake-codex`):
//!
//! * `fake-acp`    — `fake` driver + fake-acp-agent (ACP)                         [CI]
//! * `fake-claude` — `claude` driver + fake-acp-agent in claude-mode (stream-json) [CI]
//! * `fake-codex`  — the real `codex` driver + fake-acp-agent as `codex`/`codex-acp` (auth.json
//!   login semantics, refresh + write-back)                                           [CI]
//! * `codex`       — real `codex-acp` + Codex CLI, needs `ACP_COMPAT_CODEX_AUTH_JSON` (enrolled auth.json)  [opt-in, live]
//! * `claude`      — real `claude`, needs `ACP_COMPAT_CLAUDE_TOKEN_FILE` (setup-token)                  [opt-in, live]
//!
//! Live targets spend real subscription usage (small prompts). They are never enabled by
//! default. `codex-noauth` runs the real adapter without credentials and only checks that the
//! missing login is reported as `AuthEnrollmentRequired` (no model call).

mod common;

use acp_runner_core::AttemptPhase;
use acp_runner_core::events::EventKind;
use acp_runner_core::failure::FailureReason;
use common::*;
use std::time::{Duration, Instant};

#[tokio::test]
async fn c01_probe_detects_executable_and_version() {
    for t in targets() {
        let env = TestEnv::new(&t).await;
        let report = env.probe().await.unwrap_or_else(|e| panic!("[{}] probe failed: {e}", t.name));
        assert!(report.executable.is_some(), "[{}] executable not found: {report:?}", t.name);
        assert!(
            report.cli_version.as_deref().map(|v| !v.is_empty()).unwrap_or(false),
            "[{}] version not detected: {report:?}",
            t.name
        );
    }
}

#[tokio::test]
async fn c02_auth_state_is_detected_safely() {
    for t in targets() {
        let env = TestEnv::new(&t).await;
        let report = env.probe().await.unwrap();
        let printed = serde_json::to_string(&report).unwrap();
        for s in env.secrets() {
            assert!(!printed.contains(&s), "[{}] probe output leaked a credential", t.name);
        }
        match t.kind {
            Kind::FakeAcp => assert!(matches!(report.auth, acp_runner_drivers::AuthState::NotRequired)),
            Kind::FakeClaude | Kind::FakeCodex | Kind::Codex | Kind::Claude => {
                assert!(matches!(report.auth, acp_runner_drivers::AuthState::Ready { .. }), "[{}] {report:?}", t.name)
            }
            Kind::CodexNoAuth => {
                assert!(matches!(report.auth, acp_runner_drivers::AuthState::EnrollmentRequired { .. }), "{report:?}")
            }
        }
    }
}

#[tokio::test]
async fn c03_fix_end_to_end() {
    for t in targets().into_iter().filter(|t| t.kind != Kind::CodexNoAuth) {
        let env = TestEnv::new(&t).await;
        let (res, rec) = env.run("fix", |_| {}).await;
        assert_eq!(res.phase, AttemptPhase::Succeeded, "[{}] {:?}\n{}", t.name, res.reason, dump(&rec));
        for k in [
            EventKind::AgentStarted,
            EventKind::SessionStarted,
            EventKind::InputSent,
            EventKind::AgentOutput,
            EventKind::ArtifactCreated,
            EventKind::AttemptCompleted,
        ] {
            assert!(has(&rec, k), "[{}] missing {k}\n{}", t.name, dump(&rec));
        }
        assert!(has(&rec, EventKind::ToolCall) || t.is_live(), "[{}] no tool call", t.name);
        let art = rec.artifacts.first().expect("artifact uploaded");
        assert_eq!(art.kind, "patch");
        assert!(art.changed_paths.iter().any(|c| c.path == "add.sh"), "[{}] {:?}", t.name, art.changed_paths);
        let patch = art.patch_bytes().unwrap();
        assert!(String::from_utf8_lossy(&patch).starts_with("diff --git"), "[{}] patch does not parse", t.name);
        env.assert_patch_applies_and_fixes(&patch).await;
        // only the repository is captured: nothing outside the workspace is in the patch
        assert!(art.changed_paths.iter().all(|c| !c.path.starts_with('/') && !c.path.contains("..")));
    }
}

#[tokio::test]
async fn c04_cancellation() {
    for t in targets().into_iter().filter(|t| t.kind != Kind::CodexNoAuth) {
        let env = TestEnv::new(&t).await;
        let started = Instant::now();
        let (res, rec) = env.run_with_cancel("hang", Duration::from_secs(if t.is_live() { 20 } else { 2 })).await;
        assert_eq!(res.phase, AttemptPhase::Cancelled, "[{}] {:?}\n{}", t.name, res.reason, dump(&rec));
        assert!(started.elapsed() < Duration::from_secs(if t.is_live() { 120 } else { 30 }));
        assert!(has(&rec, EventKind::AttemptFailed));
        // V3b: agentd is untrusted, so its `agent_terminated` claim is quarantined
        // under `agent.agent_terminated` with a protocol_warning marker.
        assert!(progress(&rec, "agent.agent_terminated"), "[{}] agent not terminated\n{}", t.name, dump(&rec));
        assert!(progress(&rec, "protocol_warning"), "[{}] no quarantine marker\n{}", t.name, dump(&rec));
    }
}

#[tokio::test]
async fn c05_crash_is_recognized() {
    for t in targets().into_iter().filter(|t| t.is_fake()) {
        let env = TestEnv::new(&t).await;
        let (res, rec) = env.run("crash", |_| {}).await;
        assert_eq!(res.phase, AttemptPhase::Failed, "[{}]", t.name);
        assert!(
            matches!(res.reason, Some(FailureReason::ProcessCrashed { .. })),
            "[{}] {:?}\n{}",
            t.name,
            res.reason,
            dump(&rec)
        );
    }
}

#[tokio::test]
async fn c06_no_progress_timeout() {
    for t in targets().into_iter().filter(|t| t.is_fake()) {
        let env = TestEnv::new(&t).await;
        let (res, rec) = env
            .run("hang", |s| {
                s.timeouts.no_progress_seconds = 2;
                s.timeouts.grace_seconds = 2;
            })
            .await;
        assert_eq!(res.phase, AttemptPhase::TimedOut, "[{}] {:?}", t.name, res.reason);
        assert!(matches!(res.reason, Some(FailureReason::NoProgressTimeout { seconds: 2 })));
        assert!(has(&rec, EventKind::AttemptTimedOut));
    }
}

#[tokio::test]
async fn c07_hard_timeout_with_forced_termination() {
    // The ACP fake ignores session/cancel in `hang-hard`; runnerd must escalate to signals.
    for t in targets().into_iter().filter(|t| t.is_fake()) {
        let env = TestEnv::new(&t).await;
        let started = Instant::now();
        let (res, rec) = env
            .run("hang-hard", |s| {
                s.timeouts.hard_seconds = 3;
                s.timeouts.grace_seconds = 1;
            })
            .await;
        assert_eq!(res.phase, AttemptPhase::TimedOut, "[{}] {:?}", t.name, res.reason);
        assert!(matches!(res.reason, Some(FailureReason::HardTimeout { .. })));
        assert!(started.elapsed() < Duration::from_secs(20));
        // V3b: untrusted agentd lifecycle claims are quarantined (see c04).
        assert!(progress(&rec, "agent.agent_terminated"), "[{}]\n{}", t.name, dump(&rec));
        assert!(progress(&rec, "protocol_warning"), "[{}]\n{}", t.name, dump(&rec));
    }
}

#[tokio::test]
async fn c08_slow_agent_with_progress_is_not_timed_out() {
    let t = Target::fake_acp();
    let env = TestEnv::new(&t).await;
    let (res, rec) = env
        .run("slow:12", |s| {
            s.timeouts.no_progress_seconds = 1;
            s.timeouts.heartbeat_seconds = 1;
        })
        .await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    assert!(!rec.heartbeats.is_empty());
}

#[tokio::test]
async fn c09_unauthenticated_adapter_requires_enrollment() {
    // Only for `codex-noauth`: the real adapter, no credentials, no model call.
    for t in targets().into_iter().filter(|t| t.kind == Kind::CodexNoAuth) {
        let env = TestEnv::new(&t).await;
        // (a) probe path: missing auth.json
        let (res, _) = env.run("fix", |_| {}).await;
        assert!(matches!(res.reason, Some(FailureReason::AuthEnrollmentRequired { .. })), "{:?}", res.reason);
        // (b) protocol path: skip the probe so the ACP handshake itself must report it
        let mut opts = env.opts();
        opts.skip_probe = true;
        let (res, rec) = env.run_spec(env.spec("fix"), opts, None).await;
        assert!(
            matches!(res.reason, Some(FailureReason::AuthEnrollmentRequired { ref detail, .. }) if detail.contains("session/new")),
            "{:?}\n{}",
            res.reason,
            dump(&rec)
        );
    }
}

#[tokio::test]
async fn c10_refreshed_credentials_are_written_back() {
    // fake-codex refreshes deterministically; the live codex target refreshes only when its
    // access token is due, so there the check is conditional.
    for t in targets().into_iter().filter(|t| matches!(t.kind, Kind::FakeCodex | Kind::Codex)) {
        let env = TestEnv::new(&t).await;
        let scenario = if t.is_fake() { "refresh-credential" } else { "fix" };
        let (res, rec) = env.run(scenario, |_| {}).await;
        assert_eq!(res.phase, AttemptPhase::Succeeded, "[{}] {:?}\n{}", t.name, res.reason, dump(&rec));
        if t.is_fake() {
            assert_eq!(rec.writebacks.len(), 1, "[{}] no write-back", t.name);
        }
        for (key, bytes) in &rec.writebacks {
            assert_eq!(key, "auth.json");
            let v: serde_json::Value = serde_json::from_slice(bytes).expect("refreshed auth.json is JSON");
            assert!(v.get("tokens").is_some());
        }
        // the mounted (leased) original is never modified in place
        let mounted = std::fs::read(env.secret_dir.join("cred.auth.json")).unwrap();
        if t.is_fake() {
            assert_eq!(mounted, fake_codex_auth_json());
        }
    }
}

#[tokio::test]
async fn c11_staged_env_credentials_are_consumed() {
    for t in targets().into_iter().filter(|t| matches!(t.kind, Kind::FakeClaude | Kind::Claude)) {
        let env = TestEnv::new(&t).await;
        let (res, rec) = env.run("fix", |_| {}).await;
        assert_eq!(res.phase, AttemptPhase::Succeeded, "[{}] {:?}\n{}", t.name, res.reason, dump(&rec));
        let dirs = env.last_dirs.lock().unwrap().clone().unwrap();
        // agentd read the staged token and deleted it before starting the CLI
        let staged = dirs.home.join(".acp-credentials");
        assert!(!staged.exists(), "[{}] staged credential left in the shared HOME", t.name);
        let text = all_text(&rec);
        for s in env.secrets() {
            assert!(!text.contains(&s), "[{}] credential leaked into the journal", t.name);
        }
    }
}
