//! V5a: the durable directive queue across two ingest replicas, driven over
//! HTTP like production (no direct journal shortcut for delivery).
//! Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_core::events::{EventEnvelope, EventKind, EventSource, HeartbeatReply, RunnerDirective};
use acp_runner_engine::backend::{LocalProcessBackend, SandboxBackend};
use acp_runner_engine::creds::FileCredentialStore;
use acp_runner_engine::environment::{EnvironmentConfig, EnvironmentProvider};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{new_token, token_hash};
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, Journal, NewAttempt, NewEnvironment, NewRun, PgArtifactStore};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

struct Ingest {
    state: Arc<IngestState>,
    base: String,
    _tmp: tempfile::TempDir,
}

async fn spawn_ingest(journal: Journal, redeliver_after: Option<Duration>) -> Ingest {
    let tmp = tempfile::tempdir().unwrap();
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
    let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
    let mut state = IngestState::new(journal, artifacts, creds, Arc::new(Metrics::new()), None);
    if let Some(d) = redeliver_after {
        state.directive_redelivery_after = d;
    }
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn({
        let state = state.clone();
        async move { axum::serve(listener, router(state)).await.unwrap() }
    });
    Ingest { state, base, _tmp: tmp }
}

/// Minimal blocking HTTP client returning (status, body).
async fn post(path_base: &str, path: &str, bearer: &str, body: &str) -> (u16, String) {
    let (base, path, bearer, body) =
        (path_base.to_string(), path.to_string(), bearer.to_string(), body.to_string());
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let rest = base.strip_prefix("http://").unwrap();
        let (host, _) = rest.split_once(':').unwrap_or((rest, ""));
        let mut s = std::net::TcpStream::connect(rest).unwrap();
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nx-acp-runner-wire-version: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            acp_runner_core::WIRE_VERSION,
            body.len()
        )
        .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let mut parts = text.splitn(2, "\r\n\r\n");
        let head = parts.next().unwrap_or("");
        let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, parts.next().unwrap_or("").to_string())
    })
    .await
    .unwrap()
}

async fn heartbeat(base: &str, token: &str, acks: &[Uuid]) -> (u16, Option<HeartbeatReply>) {
    let body = json!({"agentAlive": true, "stage": "Idle", "ackedDirectives": acks}).to_string();
    let (status, text) = post(base, "/v1/attempt/heartbeat", token, &body).await;
    let reply = if status == 200 && !text.trim().is_empty() {
        Some(serde_json::from_str::<HeartbeatReply>(&text).expect("HeartbeatReply"))
    } else {
        None
    };
    (status, reply)
}

struct H {
    db: Option<TempDb>,
    attempt_id: Uuid,
    run_id: Uuid,
    token: String,
}

impl H {
    async fn new() -> Option<H> {
        let db = temp_database().await?;
        let run_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let token = new_token();
        db.journal
            .ensure_run(&NewRun {
                id: run_id,
                k8s_namespace: "test".into(),
                k8s_name: "directives".into(),
                k8s_uid: format!("directives-{}", Uuid::now_v7().simple()),
                task_id: "directives".into(),
                spec: json!({}),
            })
            .await
            .unwrap();
        db.journal
            .start_attempt(
                &NewAttempt {
                    id: attempt_id,
                    run_id,
                    ordinal: 0,
                    class_index: 0,
                    class_attempt: 0,
                    runner_class: "fake".into(),
                    driver: "fake".into(),
                    spec: json!({}),
                    ingest_token_hash: token_hash(&token),
                    lease_owner: "test".into(),
                    lease_ttl: Duration::from_secs(60),
                },
                None,
            )
            .await
            .unwrap();
        Some(H { db: Some(db), attempt_id, run_id, token })
    }

    fn journal(&self) -> Journal {
        self.db.as_ref().unwrap().journal.clone()
    }

    async fn done(mut self) {
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

/// V5a core: a directive queued on replica A is delivered on replica B's
/// heartbeat, and acked — a second heartbeat has nothing left.
#[tokio::test]
async fn directive_queued_on_a_delivered_on_b_with_ack() {
    let Some(h) = H::new().await else { return };
    let a = spawn_ingest(h.journal(), None).await;
    let b = spawn_ingest(h.journal(), None).await;
    let sid = Uuid::now_v7();
    let id = a
        .state
        .push_env_directive(h.attempt_id, RunnerDirective::Snapshot { snapshot_id: Some(sid), label: None })
        .await
        .unwrap();
    let (status, reply) = heartbeat(&b.base, &h.token, &[]).await;
    assert_eq!(status, 200);
    let reply = reply.expect("directive reply");
    assert_eq!(reply.directive_id, Some(id));
    assert!(matches!(reply.directive, Some(RunnerDirective::Snapshot { snapshot_id: Some(s), .. }) if s == sid));
    // ack on the next heartbeat drains the queue
    let (status, reply) = heartbeat(&b.base, &h.token, &[id]).await;
    assert_eq!(status, 204, "{reply:?}");
    let (status, _) = heartbeat(&b.base, &h.token, &[]).await;
    assert_eq!(status, 204);
    h.done().await;
}

/// V5a: cancel is checked before the queue — a queued snapshot must not delay
/// a cancellation.
#[tokio::test]
async fn cancel_is_checked_before_the_queue() {
    use acp_runner_core::failure::FailureReason;
    let Some(h) = H::new().await else { return };
    let b = spawn_ingest(h.journal(), None).await;
    h.journal()
        .push_env_directive(
            h.attempt_id,
            &RunnerDirective::Snapshot { snapshot_id: Some(Uuid::now_v7()), label: None },
        )
        .await
        .unwrap();
    h.journal()
        .request_attempt_cancel(h.attempt_id, &FailureReason::Cancelled { detail: "stop now".into() })
        .await
        .unwrap();
    let (status, reply) = heartbeat(&b.base, &h.token, &[]).await;
    assert_eq!(status, 200);
    assert!(matches!(reply.unwrap().directive, Some(RunnerDirective::Cancel { .. })));
    h.done().await;
}

/// V5a: an unacked delivery is redelivered after the timeout (runnerd died
/// mid-directive); the ack ends the redelivery.
#[tokio::test]
async fn unacked_directive_is_redelivered() {
    let Some(h) = H::new().await else { return };
    let b = spawn_ingest(h.journal(), Some(Duration::from_millis(0))).await;
    let id = h.journal().push_env_directive(h.attempt_id, &RunnerDirective::Finish).await.unwrap();
    let (_, first) = heartbeat(&b.base, &h.token, &[]).await;
    assert_eq!(first.unwrap().directive_id, Some(id));
    // no ack: redelivered on the very next heartbeat
    let (_, second) = heartbeat(&b.base, &h.token, &[]).await;
    assert_eq!(second.unwrap().directive_id, Some(id));
    let (status, _) = heartbeat(&b.base, &h.token, &[id]).await;
    assert_eq!(status, 204);
    h.done().await;
}

/// V5b: `refresh()` over 200k events stays under 50ms (no full-attempt scan).
#[tokio::test]
async fn refresh_over_200k_events_stays_fast() {
    let Some(h) = H::new().await else { return };
    let j = h.journal();
    let env_id = Uuid::now_v7();
    j.create_environment(&NewEnvironment {
        id: env_id,
        external_ref: "perf".into(),
        attempt_id: h.attempt_id,
        run_id: h.run_id,
        harness: "fake".into(),
        spec: json!({}),
        parent_artifact_id: None,
        parent_environment_id: None,
        k8s_namespace: None,
        k8s_name: None,
        k8s_uid: None,
        key_version: "v1".into(),
    })
    .await
    .unwrap();
    let prog = |category: &str, detail: serde_json::Value| {
        EventEnvelope::new(
            EventKind::Progress,
            EventSource::Runnerd,
            json!({"category": category, "message": "m", "detail": detail}),
        )
    };
    let mut batch = vec![
        prog("gateway_listening", json!({"addr": "127.0.0.1:9"})),
        prog("workspace_ready", json!({"baseRevision": "abc"})),
        prog("environment_busy", json!({})),
    ];
    for i in 0..200_000 {
        batch.push(EventEnvelope::new(
            EventKind::Progress,
            EventSource::Agent,
            json!({"category": "noise", "message": "m", "n": i}),
        ));
        if batch.len() >= 5000 {
            let n = j.append_events(h.run_id, Some(h.attempt_id), &batch).await.unwrap();
            assert_eq!(n, batch.len());
            batch.clear();
        }
    }
    batch.push(prog("turn_ended", json!({})));
    j.append_events(h.run_id, Some(h.attempt_id), &batch).await.unwrap();
    // Production has autovacuum; a fresh bulk load needs explicit stats or the
    // planner seq-scans.
    sqlx::query("ANALYZE session_events").execute(j.pool()).await.unwrap();

    let backend: Arc<dyn SandboxBackend> =
        Arc::new(LocalProcessBackend::new("/nonexistent/runnerd".into(), std::env::temp_dir(), String::new()));
    let provider = EnvironmentProvider::new(
        j,
        backend,
        Arc::new(FileCredentialStore { root: std::env::temp_dir() }),
        Arc::new(PgArtifactStore::new(h.journal(), 8 << 20, None)),
        Arc::new(IngestState::new(
            h.journal(),
            Arc::new(PgArtifactStore::new(h.journal(), 8 << 20, None)),
            Arc::new(FileCredentialStore { root: std::env::temp_dir() }),
            Arc::new(Metrics::new()),
            None,
        )),
        EnvironmentConfig::default(),
    );
    let start = Instant::now();
    let view = provider.get(env_id).await.unwrap().unwrap();
    let elapsed = start.elapsed();
    assert_eq!(view.phase, acp_runner_core::environment::EnvironmentPhase::Idle, "{view:?}");
    assert_eq!(view.base_revision.as_deref(), Some("abc"), "{view:?}");
    assert!(elapsed < Duration::from_millis(50), "refresh took {elapsed:?}");
    h.done().await;
}

/// V10c: a heartbeat for an attempt holding a credential lease reports the
/// lease expiry (runnerd stops the agent once failures span its remainder);
/// a leaseless attempt keeps the empty 204.
#[tokio::test]
async fn heartbeat_reports_the_credential_lease_expiry() {
    use acp_runner_journal::{LeaseRequest, ProfileUpsert};
    let Some(h) = H::new().await else { return };
    h.journal()
        .upsert_profile(&ProfileUpsert {
            name: "p1".into(),
            provider: "codex".into(),
            store: "test".into(),
            max_concurrent_leases: 1,
            metadata: json!({}),
            material_fingerprint: "fp1".into(),
            allowed_namespaces: vec!["test".into()],
            allowed_classes: vec!["fake".into()],
        })
        .await
        .unwrap();
    let run_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    let token = new_token();
    h.journal()
        .ensure_run(&NewRun {
            id: run_id,
            k8s_namespace: "test".into(),
            k8s_name: "leased".into(),
            k8s_uid: format!("leased-{}", Uuid::now_v7().simple()),
            task_id: "leased".into(),
            spec: json!({}),
        })
        .await
        .unwrap();
    h.journal()
        .start_attempt(
            &NewAttempt {
                id: attempt_id,
                run_id,
                ordinal: 0,
                class_index: 0,
                class_attempt: 0,
                runner_class: "fake".into(),
                driver: "fake".into(),
                spec: json!({}),
                ingest_token_hash: token_hash(&token),
                lease_owner: "test".into(),
                lease_ttl: Duration::from_secs(60),
            },
            Some(&LeaseRequest { provider: "codex".into(), candidates: vec!["p1".into()], holder: "test".into(), ttl: Duration::from_secs(3600) }),
        )
        .await
        .unwrap();
    let leased = spawn_ingest(h.journal(), None).await;
    let (status, reply) = heartbeat(&leased.base, &token, &[]).await;
    assert_eq!(status, 200);
    let reply = reply.expect("leased heartbeat carries the expiry");
    assert!(reply.directive.is_none());
    let exp = reply.lease_expires_at.expect("lease_expires_at");
    let stored =
        h.journal().lease_for_attempt(attempt_id).await.unwrap().expect("lease row").expires_at.timestamp();
    assert_eq!(exp, stored);
    // leaseless attempt: empty 204 as before
    let a = spawn_ingest(h.journal(), None).await;
    let (status, reply) = heartbeat(&a.base, &h.token, &[]).await;
    assert_eq!(status, 204);
    assert!(reply.is_none());
    h.done().await;
}
