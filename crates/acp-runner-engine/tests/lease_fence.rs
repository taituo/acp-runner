//! V10c fencing: an exclusive credential lease is never granted to a new holder
//! while a previous holder's sandbox is still authoritatively live. Expired
//! leases with live sandboxes (zombies) are terminated first; anything
//! unverifiable fails closed.
//! Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_engine::backend::{BackendError, SandboxBackend, SandboxObservation, SandboxRef, fence_exclusive_lease};
use acp_runner_journal::testing::temp_database;
use acp_runner_journal::{Journal, LeaseRequest, NewAttempt, NewRun, ProfileUpsert, StartAttempt};
use async_trait::async_trait;
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

struct StubBackend {
    /// Scripted `observe` answers, consumed in order (last repeats).
    observations: Mutex<VecDeque<SandboxObservation>>,
    terminated: Mutex<Vec<String>>,
    terminate_err: Mutex<Option<String>>,
}

impl StubBackend {
    fn new(first: SandboxObservation) -> Arc<Self> {
        Arc::new(StubBackend {
            observations: Mutex::new(VecDeque::from([first])),
            terminated: Mutex::new(vec![]),
            terminate_err: Mutex::new(None),
        })
    }
    fn then(mut obs: Vec<SandboxObservation>) -> Arc<Self> {
        let first = obs.remove(0);
        let b = Self::new(first);
        b.observations.lock().unwrap().extend(obs);
        b
    }
}

#[async_trait]
impl SandboxBackend for StubBackend {
    fn name(&self) -> &'static str {
        "stub"
    }
    async fn create(&self, _req: &acp_runner_engine::backend::SandboxRequest) -> Result<SandboxRef, BackendError> {
        Err(BackendError::Permanent("stub cannot create".into()))
    }
    async fn observe(&self, _r: &SandboxRef) -> Result<SandboxObservation, BackendError> {
        let mut q = self.observations.lock().unwrap();
        Ok(q.pop_front().unwrap_or(SandboxObservation::Missing))
    }
    async fn terminate(&self, r: &SandboxRef, _grace: Duration) -> Result<(), BackendError> {
        self.terminated.lock().unwrap().push(r.name.clone());
        match self.terminate_err.lock().unwrap().clone() {
            Some(e) => Err(BackendError::Transient(e)),
            None => Ok(()),
        }
    }
}

fn profile_upsert(name: &str) -> ProfileUpsert {
    ProfileUpsert {
        name: name.into(),
        provider: "codex".into(),
        store: "test".into(),
        max_concurrent_leases: 1,
        metadata: json!({}),
        material_fingerprint: "fp1".into(),
        allowed_namespaces: vec!["default".into()],
        allowed_classes: vec!["codex-default".into()],
    }
}

fn new_run() -> NewRun {
    let id = Uuid::now_v7();
    NewRun {
        id,
        k8s_namespace: "default".into(),
        k8s_name: format!("run-{}", id.simple()),
        k8s_uid: Uuid::new_v4().to_string(),
        task_id: "task".into(),
        spec: json!({}),
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
        lease_owner: "test".into(),
        lease_ttl: Duration::from_secs(60),
    }
}

fn lease_req(ttl: Duration) -> LeaseRequest {
    LeaseRequest { provider: "codex".into(), candidates: vec!["p1".into()], holder: "test".into(), ttl }
}

fn sref(name: &str) -> serde_json::Value {
    serde_json::to_value(SandboxRef { backend: "stub".into(), namespace: None, name: name.into() }).unwrap()
}

/// First holder with an (expired or fresh) lease + recorded sandbox; returns
/// (journal, holder attempt id).
async fn holder_with(j: &Journal, ttl: Duration, sandbox: &str) -> Uuid {
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let a = match j.start_attempt(&new_attempt(run.id, 1), Some(&lease_req(ttl))).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    j.set_attempt_sandbox(a.id, &sref(sandbox)).await.unwrap();
    a.id
}

async fn fresh_attempt(j: &Journal) -> Uuid {
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    match j.start_attempt(&new_attempt(run.id, 1), None).await.unwrap() {
        StartAttempt::Started { attempt, .. } => attempt.id,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn ended_previous_sandbox_needs_no_fencing() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&profile_upsert("p1")).await.unwrap();
    holder_with(j, Duration::from_millis(1), "old-sandbox").await;
    tokio::time::sleep(Duration::from_millis(20)).await; // let the lease lapse
    let own = fresh_attempt(j).await;
    let backend = StubBackend::new(SandboxObservation::Exited { exit_code: Some(0), reason: None, message: None });
    fence_exclusive_lease(j, backend.as_ref(), "p1", own).await.expect("exited sandbox fences clean");
    assert!(backend.terminated.lock().unwrap().is_empty(), "nothing to terminate");
    db.drop_db().await;
}

#[tokio::test]
async fn live_zombie_is_terminated_before_the_grant() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&profile_upsert("p1")).await.unwrap();
    holder_with(j, Duration::from_millis(1), "zombie").await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let own = fresh_attempt(j).await;
    // Running once, then gone after the terminate.
    let backend = StubBackend::then(vec![
        SandboxObservation::Running,
        SandboxObservation::Exited { exit_code: Some(143), reason: None, message: None },
    ]);
    fence_exclusive_lease(j, backend.as_ref(), "p1", own).await.expect("zombie terminated, grant proceeds");
    assert_eq!(backend.terminated.lock().unwrap().as_slice(), ["zombie"]);
    db.drop_db().await;
}

#[tokio::test]
async fn unterminable_zombie_fails_closed() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&profile_upsert("p1")).await.unwrap();
    holder_with(j, Duration::from_millis(1), "stubborn").await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let own = fresh_attempt(j).await;
    // terminate errors: no grant, and the failure names the sandbox.
    let backend = StubBackend::new(SandboxObservation::Running);
    *backend.terminate_err.lock().unwrap() = Some("api down".into());
    let err = fence_exclusive_lease(j, backend.as_ref(), "p1", own).await.unwrap_err();
    assert!(err.to_string().contains("stubborn"), "unexpected: {err}");
    db.drop_db().await;
}

#[tokio::test]
async fn active_co_holder_is_not_fenced() {
    // max_concurrent_leases is 1 here but the lease is still valid: fencing
    // only inspects lapsed leases, never a live holder.
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&profile_upsert("p1")).await.unwrap();
    holder_with(j, Duration::from_secs(600), "live-holder").await;
    let own = fresh_attempt(j).await;
    let backend = StubBackend::new(SandboxObservation::Running);
    fence_exclusive_lease(j, backend.as_ref(), "p1", own).await.expect("active holder is legitimate");
    assert!(backend.terminated.lock().unwrap().is_empty());
    db.drop_db().await;
}

#[tokio::test]
async fn never_launched_holder_needs_no_fencing() {
    let Some(db) = temp_database().await else { return };
    let j = &db.journal;
    j.upsert_profile(&profile_upsert("p1")).await.unwrap();
    // lease granted but the sandbox was never created (died before launch).
    let (run, _) = j.ensure_run(&new_run()).await.unwrap();
    let _ = match j.start_attempt(&new_attempt(run.id, 1), Some(&lease_req(Duration::from_millis(1))))
        .await
        .unwrap()
    {
        StartAttempt::Started { attempt, .. } => attempt,
        other => panic!("{other:?}"),
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let own = fresh_attempt(j).await;
    let backend = StubBackend::new(SandboxObservation::Running);
    fence_exclusive_lease(j, backend.as_ref(), "p1", own).await.expect("no sandbox, nothing to fence");
    db.drop_db().await;
}
