use super::*;
use crate::testing::temp_database;
use acp_runner_core::events::{EventEnvelope, EventKind, EventSource};
use serde_json::json;
use std::sync::Arc;

fn new_run() -> NewRun {
    let id = Uuid::now_v7();
    NewRun {
        id,
        k8s_namespace: "default".into(),
        k8s_name: format!("run-{}", id.simple()),
        k8s_uid: Uuid::new_v4().to_string(),
        task_id: "task".into(),
        spec: json!({"x": 1}),
    }
}

fn new_attempt(run: Uuid, ordinal: i32) -> NewAttempt {
    NewAttempt {
        id: Uuid::now_v7(),
        run_id: run,
        ordinal,
        class_index: 0,
        class_attempt: ordinal,
        runner_class: "codex-default".into(),
        driver: "codex".into(),
        spec: json!({}),
        ingest_token_hash: Uuid::new_v4().simple().to_string(),
        lease_owner: "controller-a".into(),
        lease_ttl: Duration::from_secs(60),
    }
}

fn lease_req(ttl: Duration) -> LeaseRequest {
    LeaseRequest { provider: "codex".into(), candidates: vec!["p1".into()], holder: "controller-a".into(), ttl }
}

async fn profile(j: &Journal, name: &str, max: i32) {
    // Granted to the namespace/class these tests use (see new_run/new_attempt).
    j.upsert_profile(&ProfileUpsert {
        name: name.into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: max,
        metadata: json!({}),
        material_fingerprint: "fp1".into(),
        allowed_namespaces: vec!["default".into()],
        allowed_classes: vec!["codex-default".into()],
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn run_creation_is_idempotent_and_journaled_once() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.migrate().await.unwrap(); // idempotent
    let nr = new_run();
    let (r1, created1) = j.ensure_run(&nr).await.unwrap();
    let (r2, created2) = j.ensure_run(&nr).await.unwrap();
    assert!(created1 && !created2);
    assert_eq!(r1.id, r2.id);
    let evs = j.events_for_run(r1.id, 0, 100).await.unwrap();
    assert_eq!(evs.iter().filter(|e| e.kind == "RunCreated").count(), 1);
    db.drop_db().await;
}

#[tokio::test]
async fn session_events_are_append_only_and_idempotent() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    let mut ev = EventEnvelope::new(EventKind::AgentOutput, EventSource::Driver, json!({"text": "hi"}));
    ev.seq = Some(1);
    assert_eq!(j.append_events(run.id, Some(a.id), &[ev.clone(), ev.clone()]).await.unwrap(), 1);
    assert!(!j.append_event(run.id, Some(a.id), &ev).await.unwrap());
    let upd = sqlx::query("UPDATE session_events SET kind = 'X'").execute(j.pool()).await;
    assert!(upd.unwrap_err().to_string().contains("append-only"));
    let del = sqlx::query("DELETE FROM session_events").execute(j.pool()).await;
    assert!(del.unwrap_err().to_string().contains("append-only"));
    db.drop_db().await;
}

#[tokio::test]
async fn attempt_artifact_must_belong_to_the_attempt() {
    // V3a, database layer: attempts.artifact_id can only reference an artifact row
    // of the same attempt (the application layer checks first; this is the backstop).
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 0), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    let b = match j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    let store = PgArtifactStore::new(j.clone(), 8 << 20, None);
    let art = store
        .put(
            &NewArtifact {
                environment_id: None,
                parent_artifact_id: None,
                parent_environment_id: None,
                run_id: run.id,
                attempt_id: a.id,
                kind: "patch".into(),
                base_revision: "a".repeat(40),
                sha256: "5ffe96f05cd75a91d28f8289223bd2e614a7890927a5be503892f23b131e3423".into(), // sha256("patch-bytes")
                changed_paths: vec![],
                driver: "fake".into(),
                driver_version: None,
            },
            b"patch-bytes",
        )
        .await
        .unwrap();
    j.set_attempt_details(a.id, None, None, Some(art.id)).await.unwrap();
    let err = j.set_attempt_details(b.id, None, None, Some(art.id)).await.unwrap_err();
    assert!(err.to_string().contains("does not belong"), "{err}");
    // Same attempt id recorded under a different run is also rejected: the
    // binding covers (attempt_id, run_id), not attempt_id alone.
    let (run2, _) = j.ensure_run(&new_run()).await.unwrap();
    let crossed = store
        .put(
            &NewArtifact {
                environment_id: None,
                parent_artifact_id: None,
                parent_environment_id: None,
                run_id: run2.id,
                attempt_id: a.id,
                kind: "patch".into(),
                base_revision: "a".repeat(40),
                sha256: "5ffe96f05cd75a91d28f8289223bd2e614a7890927a5be503892f23b131e3423".into(), // sha256("patch-bytes")
                changed_paths: vec![],
                driver: "fake".into(),
                driver_version: None,
            },
            b"patch-bytes",
        )
        .await
        .unwrap();
    let err = j.set_attempt_details(a.id, None, None, Some(crossed.id)).await.unwrap_err();
    assert!(err.to_string().contains("does not belong"), "{err}");
    db.drop_db().await;
}

#[tokio::test]
async fn profile_policy_denies_by_default_and_grants_explicitly() {
    // V2: no grant → CredentialUnusable (never a lease, never retry-later);
    // a grant for another namespace/class still denies; an exact grant leases.
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&ProfileUpsert {
        name: "p1".into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: 5,
        metadata: json!({}),
        material_fingerprint: "fp1".into(),
        allowed_namespaces: vec![],
        allowed_classes: vec![],
    })
    .await
    .unwrap();
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let r = j.start_attempt(&new_attempt(run.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r, StartAttempt::CredentialUnusable { .. }), "{r:?}");
    // Grant for the wrong namespace only: still denied.
    j.set_profile_policy("p1", &["other-ns".to_string()], &["codex-default".to_string()]).await.unwrap();
    let r = j.start_attempt(&new_attempt(run.id, 2), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r, StartAttempt::CredentialUnusable { .. }), "{r:?}");
    // Exact grant: leased.
    j.set_profile_policy("p1", &["default".to_string()], &["codex-default".to_string()]).await.unwrap();
    let r = j.start_attempt(&new_attempt(run.id, 3), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r, StartAttempt::Started { lease: Some(_), .. }), "{r:?}");
    db.drop_db().await;
}

#[tokio::test]
async fn advisory_run_lock_is_exclusive() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let id = Uuid::now_v7();
    let l1 = j.try_lock_run(id).await.unwrap().expect("first lock");
    assert!(j.try_lock_run(id).await.unwrap().is_none());
    assert!(j.try_lock_run(Uuid::now_v7()).await.unwrap().is_some());
    l1.release().await.unwrap();
    assert!(j.try_lock_run(id).await.unwrap().is_some());
    // dropping without release also frees it (transaction rollback)
    {
        let _l = j.try_lock_run(id).await.unwrap().unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(j.try_lock_run(id).await.unwrap().is_some());
    db.drop_db().await;
}

#[tokio::test]
async fn credential_leases_are_exclusive_expire_and_respect_status() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    profile(j, "p1", 1).await;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a1 = new_attempt(run.id, 1);
    let r1 = j.start_attempt(&a1, Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    let StartAttempt::Started { lease: Some(l1), attempt } = r1 else { panic!("{r1:?}") };
    assert_eq!(l1.profile_name, "p1");
    assert_eq!(attempt.credential_profile.as_deref(), Some("p1"));

    // second run cannot lease the exclusive profile; nothing is persisted for it
    let (run2, _) = j.ensure_run(&new_run()).await.unwrap();
    let a2 = new_attempt(run2.id, 1);
    let r2 = j.start_attempt(&a2, Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r2, StartAttempt::NoCredentialAvailable { .. }), "{r2:?}");
    assert!(j.attempts_for_run(run2.id).await.unwrap().is_empty());

    // release -> available
    assert!(j.release_lease(a1.id).await.unwrap());
    let r2 = j.start_attempt(&a2, Some(&lease_req(Duration::from_millis(1)))).await.unwrap();
    assert!(matches!(r2, StartAttempt::Started { lease: Some(_), .. }));

    // an expired (stale) lease no longer blocks
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (run3, _) = j.ensure_run(&new_run()).await.unwrap();
    let r3 = j.start_attempt(&new_attempt(run3.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r3, StartAttempt::Started { lease: Some(_), .. }), "{r3:?}");

    // needs_reauth profiles are unusable; re-enrollment (new fingerprint) re-activates
    j.set_profile_status("p1", "needs_reauth", Some("401")).await.unwrap();
    let (run4, _) = j.ensure_run(&new_run()).await.unwrap();
    let r4 = j.start_attempt(&new_attempt(run4.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap();
    assert!(matches!(r4, StartAttempt::CredentialUnusable { .. }), "{r4:?}");
    j.upsert_profile(&ProfileUpsert {
        name: "p1".into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: 1,
        metadata: json!({}),
        material_fingerprint: "fp2".into(),
        allowed_namespaces: vec!["default".into()],
        allowed_classes: vec!["codex-default".into()],
    })
    .await
    .unwrap();
    assert_eq!(j.get_profile("p1").await.unwrap().unwrap().status, "active");
    db.drop_db().await;
}

#[tokio::test]
async fn supervision_lease_takeover_of_stale_controller() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let mut na = new_attempt(run.id, 1);
    na.lease_owner = "dead-controller".into();
    na.lease_ttl = Duration::from_millis(1);
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&na, None).await.unwrap() else { panic!() };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let r = j.renew_supervision_lease(attempt.id, "controller-b", Duration::from_secs(30)).await.unwrap();
    assert_eq!(r, Ok(Some("dead-controller".to_string())));
    // a live lease held by B cannot be taken by C
    let r = j.renew_supervision_lease(attempt.id, "controller-c", Duration::from_secs(30)).await.unwrap();
    assert_eq!(r, Err("controller-b".to_string()));
    // B renews its own lease
    assert_eq!(j.renew_supervision_lease(attempt.id, "controller-b", Duration::from_secs(30)).await.unwrap(), Ok(None));
    db.drop_db().await;
}

#[tokio::test]
async fn attempt_transitions_are_conditional() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() else {
        panic!()
    };
    assert!(
        j.transition_attempt(attempt.id, &[AttemptPhase::Pending], AttemptPhase::Starting, None, None).await.unwrap()
    );
    assert!(
        !j.transition_attempt(attempt.id, &[AttemptPhase::Pending], AttemptPhase::Running, None, None).await.unwrap()
    );
    let f = FailureReason::NoChanges;
    assert!(
        j.transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Failed, Some(&f), None).await.unwrap()
    );
    assert!(
        !j.transition_attempt(attempt.id, &AttemptPhase::ACTIVE, AttemptPhase::Succeeded, None, None).await.unwrap()
    );
    let a = j.get_attempt(attempt.id).await.unwrap();
    assert_eq!(a.phase(), AttemptPhase::Failed);
    assert_eq!(a.failure(), Some(FailureReason::NoChanges));
    assert!(a.finished_at.is_some());
    let r = j.get_run(run.id).await.unwrap();
    assert_eq!(r.phase(), RunPhase::Running);
    assert_eq!(r.current_attempt_id, Some(attempt.id));
    db.drop_db().await;
}

#[tokio::test]
async fn artifact_store_inline_external_and_limits() {
    let Some(db) = temp_database().await else { return };
    let j = db.journal.clone();
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let StartAttempt::Started { attempt, .. } = j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() else {
        panic!()
    };
    let meta = |content: &[u8]| NewArtifact {
        run_id: run.id,
        attempt_id: attempt.id,
        kind: "patch".into(),
        base_revision: "abc".into(),
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content)),
        changed_paths: vec![],
        driver: "fake".into(),
        driver_version: None,
        environment_id: None,
        parent_artifact_id: None,
        parent_environment_id: None,
    };
    let inline_only = PgArtifactStore::new(j.clone(), 16, None);
    let small = b"diff --git a b\n";
    let s = inline_only.put(&meta(small), small).await.unwrap();
    assert_eq!(s.storage, "postgres");
    assert_eq!(inline_only.get_content(s.id).await.unwrap(), small);
    let big = vec![b'x'; 100];
    assert!(matches!(inline_only.put(&meta(&big), &big).await, Err(JournalError::TooLarge { size: 100, limit: 16 })));
    let mut bad = meta(small);
    bad.sha256 = "00".into();
    assert!(inline_only.put(&bad, small).await.is_err());

    let dir = tempfile_dir();
    let with_fs = PgArtifactStore::new(j.clone(), 16, Some(Arc::new(FsBlobStore { root: dir.clone() })));
    let s = with_fs.put(&meta(&big), &big).await.unwrap();
    assert_eq!(s.storage, "fs");
    assert_eq!(with_fs.get_content(s.id).await.unwrap(), big);
    assert_eq!(with_fs.latest_for_run(run.id).await.unwrap().unwrap().id, s.id);
    let _ = std::fs::remove_dir_all(dir);
    db.drop_db().await;
}

fn tempfile_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("acp-blob-{}", Uuid::new_v4().simple()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

use acp_runner_core::events::RunnerDirective;

async fn started_attempt(j: &Journal, run: Uuid, ordinal: i32) -> AttemptRow {
    match j.start_attempt(&new_attempt(run, ordinal), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => *attempt,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn env_directives_queue_deliver_ack_and_redeliver() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = started_attempt(j, run.id, 1).await;
    let snap = RunnerDirective::Snapshot { snapshot_id: Some(Uuid::now_v7()), label: None };
    let id = j.push_env_directive(a.id, &snap).await.unwrap();
    // first delivery
    let (got_id, got) = j.next_env_directive(a.id, Duration::from_secs(60)).await.unwrap().expect("directive");
    assert_eq!(got_id, id);
    assert!(matches!(got, RunnerDirective::Snapshot { .. }));
    // delivered but unacked: not due again yet
    assert!(j.next_env_directive(a.id, Duration::from_secs(60)).await.unwrap().is_none());
    // acked: gone
    assert!(j.ack_env_directive(id).await.unwrap());
    assert!(!j.ack_env_directive(id).await.unwrap());
    assert!(j.next_env_directive(a.id, Duration::from_secs(0)).await.unwrap().is_none());
    // unacked long enough: redelivered (runnerd died mid-directive)
    let id2 = j.push_env_directive(a.id, &RunnerDirective::Finish).await.unwrap();
    sqlx::query("UPDATE environment_directives SET delivered_at = now() - interval '1 hour' WHERE id = $1")
        .bind(id2)
        .execute(j.pool())
        .await
        .unwrap();
    let (red_id, _) = j.next_env_directive(a.id, Duration::from_secs(30)).await.unwrap().expect("redelivery");
    assert_eq!(red_id, id2);
    // terminal hygiene acks everything pending
    assert_eq!(j.ack_env_directives_for_attempt(a.id).await.unwrap(), 1);
    assert!(j.next_env_directive(a.id, Duration::from_secs(0)).await.unwrap().is_none());
    db.drop_db().await;
}

#[tokio::test]
async fn claim_heartbeat_journal_throttles() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = started_attempt(j, run.id, 1).await;
    assert!(j.claim_heartbeat_journal(a.id, Duration::from_secs(60)).await.unwrap());
    assert!(!j.claim_heartbeat_journal(a.id, Duration::from_secs(60)).await.unwrap());
    sqlx::query("UPDATE attempts SET last_heartbeat_journaled_at = now() - interval '2 hours' WHERE id = $1")
        .bind(a.id)
        .execute(j.pool())
        .await
        .unwrap();
    assert!(j.claim_heartbeat_journal(a.id, Duration::from_secs(60)).await.unwrap());
    db.drop_db().await;
}

#[tokio::test]
async fn targeted_progress_reads_replace_full_scans() {
    use acp_runner_core::events::ProgressData;
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = started_attempt(j, run.id, 1).await;
    let prog = |source, category: &str, detail: serde_json::Value| {
        EventEnvelope::new(EventKind::Progress, source, ProgressData::new(category, "m").with_detail(detail))
    };
    // agent noise (must be invisible to runnerd-scoped reads) + forged snapshot
    j.append_event(run.id, Some(a.id), &prog(EventSource::Agent, "environment_ready", json!({}))).await.unwrap();
    j.append_event(run.id, Some(a.id), &prog(EventSource::Runnerd, "environment_ready", json!({}))).await.unwrap();
    j.append_event(
        run.id,
        Some(a.id),
        &prog(EventSource::Runnerd, "gateway_listening", json!({"addr": "127.0.0.1:9"})),
    )
    .await
    .unwrap();
    j.append_event(
        run.id,
        Some(a.id),
        &prog(EventSource::Runnerd, "workspace_ready", json!({"baseRevision": "abc"})),
    )
    .await
    .unwrap();
    let sid = Uuid::now_v7();
    j.append_event(
        run.id,
        Some(a.id),
        &prog(EventSource::Runnerd, "snapshot_created", json!({"snapshotId": sid})),
    )
    .await
    .unwrap();
    // forged AFTER the real one: the query must still return the runnerd row
    j.append_event(
        run.id,
        Some(a.id),
        &prog(EventSource::Agent, "snapshot_created", json!({"snapshotId": sid})),
    )
    .await
    .unwrap();
    j.append_event(run.id, Some(a.id), &prog(EventSource::Runnerd, "turn_ended", json!({}))).await.unwrap();
    j.append_event(run.id, Some(a.id), &prog(EventSource::Runnerd, "environment_busy", json!({}))).await.unwrap();
    j.append_event(run.id, Some(a.id), &EventEnvelope::new(EventKind::AttemptCompleted, EventSource::Runnerd, json!({})))
        .await
        .unwrap();

    let gw = j.earliest_runner_progress(a.id, "gateway_listening").await.unwrap().expect("gateway");
    assert_eq!(gw.data.pointer("/detail/addr").and_then(|v| v.as_str()), Some("127.0.0.1:9"));
    let ws = j.earliest_runner_progress(a.id, "workspace_ready").await.unwrap().expect("base");
    assert_eq!(ws.data.pointer("/detail/baseRevision").and_then(|v| v.as_str()), Some("abc"));
    assert!(j.earliest_runner_progress(a.id, "nope").await.unwrap().is_none());

    let latest = j.latest_runner_progress(a.id, &["environment_ready", "turn_ended", "environment_busy"]).await.unwrap();
    assert_eq!(latest.len(), 3, "{latest:?}");
    let top = latest.iter().max_by_key(|r| r.id).unwrap();
    assert_eq!(top.data.get("category").and_then(|c| c.as_str()), Some("environment_busy"));

    let term = j.latest_terminal_event(a.id).await.unwrap().expect("terminal");
    assert_eq!(term.kind, "AttemptCompleted");

    let snap = j.progress_by_detail(a.id, "snapshotId", &sid.to_string()).await.unwrap().expect("snapshot");
    assert_eq!(snap.source, "runnerd");
    assert_eq!(snap.data.get("category").and_then(|c| c.as_str()), Some("snapshot_created"));
    assert!(j.progress_by_detail(a.id, "snapshotId", &Uuid::now_v7().to_string()).await.unwrap().is_none());
    db.drop_db().await;
}

#[tokio::test]
async fn lease_extension_is_capped_at_the_hard_deadline() {
    // V10c: heartbeats extend the lease but never past the sandbox's hard
    // deadline (the cap); without a cap the legacy behavior stays.
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    profile(j, "p1", 1).await;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap()
    {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    // no cap: extends to now + window
    assert!(j.extend_lease(a.id, Duration::from_secs(600), None).await.unwrap());
    let uncapped = j.lease_for_attempt(a.id).await.unwrap().unwrap().expires_at;
    assert!(uncapped > chrono::Utc::now() + chrono::Duration::seconds(500), "{uncapped}");
    // cap below now + window: pinned at the cap, never beyond it
    let cap = chrono::Utc::now() + chrono::Duration::seconds(100);
    assert!(j.extend_lease(a.id, Duration::from_secs(600), Some(cap)).await.unwrap());
    let capped = j.lease_for_attempt(a.id).await.unwrap().unwrap().expires_at;
    assert!(capped <= cap, "{capped} > {cap}");
    assert!(capped > cap - chrono::Duration::seconds(10), "{capped} not extended to the cap");
    // a cap above the window extends normally
    let high = chrono::Utc::now() + chrono::Duration::seconds(10_000);
    assert!(j.extend_lease(a.id, Duration::from_secs(600), Some(high)).await.unwrap());
    let l = j.lease_for_attempt(a.id).await.unwrap().unwrap().expires_at;
    assert!(l > capped, "extension with a high cap did not move the expiry");
    db.drop_db().await;
}

#[tokio::test]
async fn leases_for_profile_lists_unreleased_including_expired() {
    // V10c fencing inspects exactly the expired-but-unreleased leases.
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    profile(j, "p1", 1).await;
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 1), Some(&lease_req(Duration::from_secs(60)))).await.unwrap()
    {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    assert_eq!(j.leases_for_profile("p1").await.unwrap().len(), 1);
    assert!(j.leases_for_profile("nope").await.unwrap().is_empty());
    // released leases disappear from the fencing view
    assert!(j.release_lease(a.id).await.unwrap());
    assert!(j.leases_for_profile("p1").await.unwrap().is_empty());
    // an expired (1ms ttl) unreleased lease stays visible for fencing
    let (run2, _) = j.ensure_run(&new_run()).await.unwrap();
    let b = match j
        .start_attempt(&new_attempt(run2.id, 1), Some(&lease_req(Duration::from_millis(1))))
        .await
        .unwrap()
    {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let rows = j.leases_for_profile("p1").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].attempt_id, b.id);
    assert!(rows[0].expires_at < chrono::Utc::now());
    assert!(j.active_leases().await.unwrap().is_empty(), "expired lease must not look active");
    db.drop_db().await;
}
