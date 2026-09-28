//! Trust-boundary tests for the runnerd <-> agentd link.
//!
//! agentd is untrusted: here a *malicious agentd* written in the test connects to runnerd's
//! socket and tries to forge results. runnerd must keep every authoritative decision
//! (terminal state, patch, failure classes) and must never hand agentd the attempt token.

mod common;

use acp_runner_core::AttemptPhase;
use acp_runner_core::events::{EventKind, EventSource, ProgressData, RunnerDirective};
use acp_runner_core::failure::FailureReason;
use acp_runner_ipc::{
    AgentEvent, AgentExit, AgentOutcome, AgentPosture, FromAgent, PROTOCOL_VERSION, SOCKET_FILE, ToAgent, read_frame,
    write_frame,
};
use common::*;
use runnerd::sink::{MemoryRecord, MemorySink};
use runnerd::{AgentdLaunch, AttemptResult, SupervisorOptions, run_attempt};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const TOKEN: &str = "attempt-token-0123456789abcdef0123456789abcdef";

struct Evil {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
}

impl Evil {
    async fn connect(socket: PathBuf) -> Evil {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(s) = UnixStream::connect(&socket).await {
                let (rd, wr) = s.into_split();
                return Evil { rd, wr };
            }
            assert!(Instant::now() < deadline, "runnerd socket never appeared");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn send(&mut self, m: FromAgent) {
        let _ = write_frame(&mut self.wr, &m).await;
    }
    async fn raw(&mut self, json: &str) {
        let _ = self.wr.write_all(&(json.len() as u32).to_be_bytes()).await;
        let _ = self.wr.write_all(json.as_bytes()).await;
    }
    async fn hello(&mut self) {
        self.send(FromAgent::Hello {
            protocol: PROTOCOL_VERSION,
            agentd_version: "evil".into(),
            pid: 1,
            posture: AgentPosture::default(),
        })
        .await
    }
    async fn recv(&mut self) -> Option<ToAgent> {
        read_frame::<_, ToAgent>(&mut self.rd).await.ok().flatten()
    }
}

/// Run an attempt against a scripted agentd. Returns the runnerd result, the journal and
/// the raw Launch frame runnerd sent.
async fn with_evil_agentd<F, Fut>(
    env: &TestEnv,
    mutate: impl FnOnce(&mut acp_runner_core::AttemptSpec),
    script: F,
) -> (AttemptResult, MemoryRecord, Option<ToAgent>)
where
    F: FnOnce(Evil) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Option<ToAgent>> + Send + 'static,
{
    let mut spec = env.spec("fix");
    mutate(&mut spec);
    let dirs = env.dirs();
    let socket = dirs.run_dir.join(SOCKET_FILE);
    let evil = tokio::spawn(async move { script(Evil::connect(socket).await).await });
    let opts = SupervisorOptions { agentd: AgentdLaunch::External, extra_secrets: vec![TOKEN.into()], ..env.opts() };
    let mut sink = MemorySink::default();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let res = run_attempt(spec, dirs, &mut sink, opts, rx).await;
    let launch = evil.await.unwrap();
    (res, sink.snapshot(), launch)
}

async fn hello_and_launch(e: &mut Evil) -> Option<ToAgent> {
    e.hello().await;
    e.recv().await
}

#[tokio::test]
async fn forged_success_without_changes_is_judged_by_runnerd() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec, launch) = with_evil_agentd(
        &env,
        |_| {},
        |mut e| async move {
            let l = hello_and_launch(&mut e).await;
            e.send(FromAgent::Event {
                event: AgentEvent::Output { channel: "message".into(), text: "All fixed!".into() },
            })
            .await;
            e.send(FromAgent::Exit {
                exit: AgentExit {
                    outcome: AgentOutcome::TurnEnded {
                        success: true,
                        stop_reason: "end_turn".into(),
                        detail: String::new(),
                        summary: Some("I fixed everything and all tests pass".into()),
                    },
                    exit_code: Some(0),
                    signal: None,
                    stderr_tail: String::new(),
                },
            })
            .await;
            l
        },
    )
    .await;
    assert!(matches!(launch, Some(ToAgent::Launch { .. })));
    // The agent claims success, but the runnerd-computed patch is empty.
    assert_eq!(res.phase, AttemptPhase::Failed);
    assert_eq!(res.reason, Some(FailureReason::NoChanges));
    assert!(rec.artifacts.is_empty());
    let term = rec.events.iter().find(|e| e.kind.is_attempt_terminal()).unwrap();
    assert_eq!(term.source, EventSource::Runnerd);
    let out = rec.events.iter().find(|e| e.kind == EventKind::AgentOutput).unwrap();
    assert_eq!(out.source, EventSource::Agent);
}

#[tokio::test]
async fn agent_cannot_claim_runner_owned_failures() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    for claimed in [
        FailureReason::HardTimeout { seconds: 1 },
        FailureReason::Cancelled { detail: "x".into() },
        FailureReason::CredentialUnavailable { detail: "x".into() },
        FailureReason::ArtifactTooLarge { size_bytes: 1, limit_bytes: 1 },
    ] {
        let c = claimed.clone();
        let (res, _, _) = with_evil_agentd(
            &env,
            |_| {},
            move |mut e| async move {
                let l = hello_and_launch(&mut e).await;
                e.send(FromAgent::Exit {
                    exit: AgentExit {
                        outcome: AgentOutcome::Failed { reason: c },
                        exit_code: None,
                        signal: None,
                        stderr_tail: String::new(),
                    },
                })
                .await;
                l
            },
        )
        .await;
        assert!(
            matches!(res.reason, Some(FailureReason::ProtocolError { ref detail }) if detail.contains(claimed.code())),
            "{claimed:?} -> {:?}",
            res.reason
        );
    }
}

#[tokio::test]
async fn forged_frames_are_protocol_errors_not_results() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    for forged in [
        r#"{"type":"attemptCompleted","artifactId":"00000000-0000-0000-0000-000000000000"}"#,
        r#"{"type":"event","event":{"kind":"artifactCreated","data":{"artifactId":"00000000-0000-0000-0000-000000000000"}}}"#,
        r#"{"type":"heartbeat","agentAlive":true}"#,
        r#"not json at all"#,
    ] {
        let (res, rec, _) = with_evil_agentd(
            &env,
            |_| {},
            move |mut e| async move {
                let l = hello_and_launch(&mut e).await;
                e.raw(forged).await;
                // keep the connection open; runnerd must not wait for us
                tokio::time::sleep(Duration::from_secs(1)).await;
                l
            },
        )
        .await;
        assert_eq!(res.phase, AttemptPhase::Failed, "{forged}");
        assert!(matches!(res.reason, Some(FailureReason::ProtocolError { .. })), "{forged} -> {:?}", res.reason);
        assert!(
            !rec.events.iter().any(|e| e.kind == EventKind::AttemptCompleted || e.kind == EventKind::ArtifactCreated)
        );
        assert!(rec.artifacts.is_empty());
    }
}

#[tokio::test]
async fn launch_spec_never_contains_the_attempt_token_or_controller_details() {
    let mut env = TestEnv::new(&Target::fake_acp()).await;
    std::fs::write(env.secret_dir.join("token"), TOKEN).unwrap();
    env.add_env_credential("claude", "oauth-token", "CLAUDE_CODE_OAUTH_TOKEN", FAKE_CLAUDE_TOKEN.as_bytes());
    let secret_dir = env.secret_dir.to_string_lossy().to_string();
    let (_res, _rec, launch) = with_evil_agentd(
        &env,
        |_| {},
        |mut e| async move {
            let l = hello_and_launch(&mut e).await;
            drop(e);
            l
        },
    )
    .await;
    let text = serde_json::to_string(&launch.expect("launch")).unwrap();
    assert!(!text.contains(TOKEN), "attempt token in the launch spec");
    assert!(!text.contains(FAKE_CLAUDE_TOKEN), "credential value inlined into the launch spec");
    assert!(!text.contains(&secret_dir), "secret mount path in the launch spec");
    assert!(!text.contains(&env.repo_url), "repository URL in the launch spec");
    assert!(text.contains(".acp-credentials/oauth-token"), "{text}");
}

#[tokio::test]
async fn agentd_disconnect_without_exit_is_a_crash() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, _, _) = with_evil_agentd(
        &env,
        |_| {},
        |mut e| async move {
            let l = hello_and_launch(&mut e).await;
            drop(e);
            l
        },
    )
    .await;
    assert!(
        matches!(res.reason, Some(FailureReason::ProcessCrashed { ref detail, .. }) if detail.contains("agentd disconnected")),
        "{:?}",
        res.reason
    );
}

#[tokio::test]
async fn unresponsive_agentd_is_abandoned_after_cancel() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let started = Instant::now();
    let (res, rec, _) = with_evil_agentd(
        &env,
        |s| {
            s.timeouts.hard_seconds = 2;
            s.timeouts.grace_seconds = 1;
        },
        |mut e| async move {
            let l = hello_and_launch(&mut e).await;
            // keep "working" forever and ignore Cancel
            for _ in 0..400 {
                let busy = FromAgent::Event {
                    event: AgentEvent::Progress { data: ProgressData::new("busy", "still busy"), raw: None },
                };
                if write_frame(&mut e.wr, &busy).await.is_err() {
                    break; // runnerd gave up on us and closed the link
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            l
        },
    )
    .await;
    assert_eq!(res.phase, AttemptPhase::TimedOut, "{:?}", res.reason);
    assert!(matches!(res.reason, Some(FailureReason::HardTimeout { .. })));
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(progress(&rec, "agent_unresponsive"), "{}", dump(&rec));
}

#[tokio::test]
async fn extra_connections_to_the_socket_are_refused() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (res, rec, _) = with_evil_agentd(
        &env,
        |_| {},
        |mut e| async move {
            let l = hello_and_launch(&mut e).await;
            // a second process (e.g. the CLI) tries to talk to runnerd directly
            let socket = e.rd.peer_addr().unwrap().as_pathname().unwrap().to_path_buf();
            let mut intruder = Evil::connect(socket).await;
            intruder.hello().await;
            intruder
                .send(FromAgent::Exit {
                    exit: AgentExit {
                        outcome: AgentOutcome::TurnEnded {
                            success: true,
                            stop_reason: "end_turn".into(),
                            detail: String::new(),
                            summary: None,
                        },
                        exit_code: Some(0),
                        signal: None,
                        stderr_tail: String::new(),
                    },
                })
                .await;
            assert!(intruder.recv().await.is_none(), "intruder connection must be closed");
            e.send(FromAgent::Exit {
                exit: AgentExit {
                    outcome: AgentOutcome::Crashed { detail: "real agent crashed".into() },
                    exit_code: Some(3),
                    signal: None,
                    stderr_tail: String::new(),
                },
            })
            .await;
            l
        },
    )
    .await;
    assert!(matches!(res.reason, Some(FailureReason::ProcessCrashed { exit_code: Some(3), .. })), "{:?}", res.reason);
    assert!(progress(&rec, "agentd_extra_connections_rejected"), "{}", dump(&rec));
}

#[tokio::test]
async fn controller_directive_cancels_a_hung_agent() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let sink = MemorySink::default();
    let mut spec = env.spec("hang");
    spec.timeouts.heartbeat_seconds = 1;
    let delayed = sink.clone();
    // only deliver the directive once the agent runs
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        delayed
            .directives
            .lock()
            .unwrap()
            .push_back(RunnerDirective::Cancel { reason: FailureReason::NoProgressTimeout { seconds: 7 } });
    });
    let (res, rec) = env.run_spec_with_sink(spec, env.opts(), None, sink).await;
    assert_eq!(res.phase, AttemptPhase::TimedOut, "{:?}\n{}", res.reason, dump(&rec));
    assert_eq!(res.reason, Some(FailureReason::NoProgressTimeout { seconds: 7 }));
    // V3b: untrusted agentd lifecycle claims are quarantined (see compat c04).
    assert!(progress(&rec, "agent.agent_terminated"), "{}", dump(&rec));
}
