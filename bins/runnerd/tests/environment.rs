//! Environment-mode supervisor + raw ACP gateway end-to-end (deterministic fake harnesses).
//!
//! Covers: create→Ready, connect with a signed ticket, plain ACP (`initialize`,
//! `session/new`, `session/prompt`) over both transports (HTTP upgrade to newline-delimited
//! JSON-RPC, and WebSocket), a second turn in the same session, snapshot at Idle, a later
//! modification + second snapshot, finish producing the final patch and closing the
//! connection, unexpected harness exit → Failed with a partial artifact, transparency of the
//! gateway for ACP methods it does not know, Claude Code multi-turn through the ACP bridge,
//! credentials absent from events, and ticket authorization (garbage, expired, replayed,
//! foreign-environment tickets).

mod common;

use acp_runner_client::{AcpClient, ClientError, Transport, connect_session};
use acp_runner_core::environment::EnvironmentPhase;
use acp_runner_core::events::RunnerDirective;
use acp_runner_core::ticket;
use common::env_mode::*;
use common::*;
use std::time::Duration;
use uuid::Uuid;

async fn two_turns_snapshot_finish(transport: Transport) {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let r = Running::start(&env, |_| {}).await;
    // connect with a signed ticket; plain ACP from here on.
    let (mut client, session) = connect_session(&r.gateway, &r.ticket(), transport).await.expect("attach");
    assert_eq!(client.info.environment_id.as_deref(), Some(r.id.to_string().as_str()));
    assert_eq!(client.info.phase.as_deref(), Some("Idle"));
    assert!(client.info.workdir.is_some());
    // one ACP turn completes without destroying the environment.
    let t1 = client.prompt(&session, "[[fake:fix]] fix add.sh").await.unwrap();
    assert_eq!(t1.stop_reason, "end_turn");
    assert!(t1.text.contains("Fixed add.sh"), "{t1:?}");
    // snapshot at Idle → BASE-relative patch, environment still alive.
    r.directive(RunnerDirective::Snapshot { snapshot_id: Some(Uuid::now_v7()), label: Some("s1".into()) });
    wait_event_n(&r.sink, "snapshot_created", 1).await;
    assert!(latest_snapshot(&r.sink).unwrap().iter().any(|c| c.path == "add.sh"));
    // second turn, same ACP session, new file; second snapshot is cumulative.
    let t2 = client.prompt(&session, "[[fake:touch:extra.txt]] add a file").await.unwrap();
    assert_eq!(t2.stop_reason, "end_turn");
    r.directive(RunnerDirective::Snapshot { snapshot_id: Some(Uuid::now_v7()), label: Some("s2".into()) });
    wait_event_n(&r.sink, "snapshot_created", 2).await;
    let paths: Vec<String> = latest_snapshot(&r.sink).unwrap().iter().map(|c| c.path.clone()).collect();
    assert!(paths.contains(&"add.sh".to_string()) && paths.contains(&"extra.txt".to_string()), "{paths:?}");
    // the passive tap journaled the turns and the tool call of turn 1 (source = agent).
    let rec = r.sink.snapshot();
    assert_eq!(
        rec.events.iter().filter(|e| e.data.get("category").and_then(|c| c.as_str()) == Some("turn_ended")).count(),
        2
    );
    assert!(has(&rec, acp_runner_core::EventKind::ToolCall));
    // finish → final patch, environment destroyed, connection closed.
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed, "{res:?}");
    assert_eq!(res.turns, 2);
    assert!(res.snapshots >= 2);
    let rec = sink.snapshot();
    let finals: Vec<_> = rec.artifacts.iter().filter(|a| a.kind == "final").collect();
    assert_eq!(finals.len(), 1);
    let paths: Vec<&str> = finals[0].changed_paths.iter().map(|c| c.path.as_str()).collect();
    assert!(paths.contains(&"add.sh") && paths.contains(&"extra.txt"), "{paths:?}");
    let after = tokio::time::timeout(Duration::from_secs(10), client.prompt(&session, "again")).await.unwrap();
    assert!(after.is_err(), "the gateway kept the connection open after finish");
}

#[tokio::test]
async fn raw_acp_two_turns_snapshot_and_finish() {
    two_turns_snapshot_finish(Transport::Raw).await;
}

#[tokio::test]
async fn websocket_acp_two_turns_snapshot_and_finish() {
    two_turns_snapshot_finish(Transport::WebSocket).await;
}

#[tokio::test]
async fn gateway_relays_acp_methods_it_does_not_know() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let r = Running::start(&env, |_| {}).await;
    let mut client = AcpClient::connect(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    client.initialize().await.unwrap();
    // An extension method: runnerd has no idea what it is; the harness answers it.
    let e = client.request("_vendor/experimental", serde_json::json!({"x": 1})).await.unwrap_err();
    assert!(e.to_string().contains("method not found: _vendor/experimental"), "{e}");
    let (res, _) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed);
}

#[tokio::test]
async fn unexpected_harness_exit_fails_with_partial_artifact() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let r = Running::start(&env, |_| {}).await;
    let (mut client, session) = connect_session(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    // fix add.sh first (so a partial changeset exists), then crash on the next turn.
    client.prompt(&session, "[[fake:fix]] fix it").await.unwrap();
    let crashed = client.prompt(&session, "[[fake:crash]] now crash").await;
    assert!(crashed.is_err());
    let res = tokio::time::timeout(Duration::from_secs(30), r.handle).await.unwrap().unwrap();
    assert_eq!(res.phase, EnvironmentPhase::Failed, "{res:?}");
    let rec = r.sink.snapshot();
    let partials: Vec<_> = rec.artifacts.iter().filter(|a| a.kind == "partial_final").collect();
    assert_eq!(partials.len(), 1, "expected a partial artifact");
    assert!(partials[0].changed_paths.iter().any(|c| c.path == "add.sh"));
}

#[tokio::test]
async fn gateway_denies_bad_expired_replayed_and_foreign_tickets() {
    let env = TestEnv::new(&Target::fake_claude()).await;
    let a = Running::start(&env, |_| {}).await;
    let b = Running::start(&env, |_| {}).await;
    let rejected = |r: Result<AcpClient, ClientError>| match r {
        Err(ClientError::Rejected { status, reason }) => (status, reason),
        Err(e) => panic!("expected a rejection, got {e}"),
        Ok(_) => panic!("connection was accepted"),
    };
    // garbage / missing tickets
    let (st, _) = rejected(AcpClient::connect(&a.gateway, "not-a-ticket", Transport::Raw).await);
    assert_eq!(st, 401);
    // expired
    let old = ticket::issue(&a.key, &ticket::claims_for(a.id, chrono::Utc::now().timestamp() - 1000, 60));
    let (st, reason) = rejected(AcpClient::connect(&a.gateway, &old, Transport::WebSocket).await);
    assert_eq!(st, 401, "{reason}");
    // B's ticket at A's gateway (and vice versa): different K_env → refused.
    let (_, reason) = rejected(AcpClient::connect(&a.gateway, &b.ticket(), Transport::Raw).await);
    assert!(reason.contains("not valid for this environment"), "{reason}");
    rejected(AcpClient::connect(&b.gateway, &a.ticket(), Transport::WebSocket).await);
    // a valid ticket works exactly once
    let t = a.ticket();
    let c = AcpClient::connect(&a.gateway, &t, Transport::Raw).await.expect("valid ticket");
    let (st, reason) = rejected(AcpClient::connect(&a.gateway, &t, Transport::Raw).await);
    assert_eq!((st, reason.as_str()), (401, "ticket already used"));
    drop(c);
    // rejections are journaled without the ticket.
    wait_event_n(&a.sink, "caller_rejected", 4).await;
    let (_, sink_a) = a.finish().await;
    let (_, sink_b) = b.finish().await;
    for sink in [sink_a, sink_b] {
        let text = all_text(&sink.snapshot());
        assert!(!text.contains(&t), "ticket leaked into events");
        // credentials never appear in events.
        for s in env.secrets() {
            assert!(!text.contains(&s), "credential leaked into events");
        }
    }
}

#[tokio::test]
async fn claude_code_multi_turn_through_the_acp_bridge() {
    let env = TestEnv::new(&Target::fake_claude()).await;
    let r = Running::start(&env, |_| {}).await;
    let (mut client, session) = connect_session(&r.gateway, &r.ticket(), Transport::WebSocket).await.unwrap();
    let init = client.init.as_ref().unwrap();
    assert_eq!(init.agent_info.name.as_deref(), Some("claude-acp-bridge"));
    let t1 = client.prompt(&session, "[[fake:fix]] fix add.sh").await.unwrap();
    assert_eq!(t1.stop_reason, "end_turn", "{t1:?}");
    assert!(t1.text.contains("new session") && t1.tool_calls >= 1, "{t1:?}");
    // second turn resumes the same Claude Code session (`--resume <id>`).
    let t2 = client.prompt(&session, "[[fake:touch:second.txt]] another file").await.unwrap();
    assert_eq!(t2.stop_reason, "end_turn", "{t2:?}");
    assert!(t2.text.contains("resumed session"), "{t2:?}");
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed, "{res:?}");
    let rec = sink.snapshot();
    let fin = rec.artifacts.iter().find(|a| a.kind == "final").expect("final artifact");
    let paths: Vec<&str> = fin.changed_paths.iter().map(|c| c.path.as_str()).collect();
    assert!(paths.contains(&"add.sh") && paths.contains(&"second.txt"), "{paths:?}");
    let text = all_text(&rec);
    for s in env.secrets() {
        assert!(!text.contains(&s), "Claude token leaked into events");
    }
}
