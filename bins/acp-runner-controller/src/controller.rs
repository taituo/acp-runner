//! kube-runtime controller: ACPRun -> engine.reconcile -> ACPRun.status.
//!
//! Multiple replicas are safe: each reconcile holds a PostgreSQL advisory lock on the run,
//! attempts carry supervision leases, and all state lives in PostgreSQL. No leader election
//! is required (a replica that dies simply stops renewing its leases).

use acp_runner_engine::backend::RunKey;
use acp_runner_engine::{Engine, RunInput, RunView};
use acp_runner_k8s::crds::{
    ACPRun, ACPRunStatus, ACPRunnerClass, ArtifactRefStatus, FINALIZER, FailureStatus, SandboxRefStatus,
};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::watcher;
use kube::{Client, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

pub struct Ctx {
    pub client: Client,
    pub engine: Arc<Engine>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("engine: {0}")]
    Engine(String),
    #[error("finalizer: {0}")]
    Finalizer(String),
}

pub async fn run(client: Client, engine: Arc<Engine>, namespace: Option<String>) {
    let runs: Api<ACPRun> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let pods: Api<Pod> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let ctx = Arc::new(Ctx { client, engine });
    Controller::new(runs, watcher::Config::default())
        .owns(pods, watcher::Config::default().labels("app.kubernetes.io/managed-by=acp-runner"))
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::debug!(error = %e, "reconcile loop error");
            }
        })
        .await;
}

fn error_policy(run: Arc<ACPRun>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(run = %run.name_any(), error = %err, "reconcile failed; requeueing");
    Action::requeue(Duration::from_secs(10))
}

async fn reconcile(run: Arc<ACPRun>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = run.namespace().unwrap_or_else(|| "default".into());
    let api: Api<ACPRun> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, run, |event| async {
        match event {
            Event::Apply(run) => apply(run, ctx.clone()).await,
            Event::Cleanup(run) => cleanup(run, ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| Error::Finalizer(e.to_string()))
}

fn key(run: &ACPRun) -> RunKey {
    RunKey { namespace: run.namespace().unwrap_or_default(), name: run.name_any(), uid: run.uid().unwrap_or_default() }
}

async fn apply(run: Arc<ACPRun>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let ns = run.namespace().unwrap_or_default();
    let classes_api: Api<ACPRunnerClass> = Api::namespaced(ctx.client.clone(), &ns);
    let already_known = run.status.as_ref().and_then(|s| s.run_id.clone()).is_some();
    let mut classes = vec![];
    for name in run.spec.class_names() {
        match classes_api.get_opt(&name).await? {
            Some(c) => classes.push(c.spec.to_core(&name)),
            None if already_known => {} // the engine uses its snapshot
            None => {
                let status = ACPRunStatus {
                    phase: Some("Pending".into()),
                    message: Some(format!("ACPRunnerClass {name:?} not found in namespace {ns}")),
                    observed_generation: run.metadata.generation,
                    ..Default::default()
                };
                patch_status(&ctx.client, &run, status).await?;
                return Ok(Action::requeue(Duration::from_secs(30)));
            }
        }
    }
    let input = RunInput { key: key(&run), spec: run.spec.to_core(classes), cancel: run.spec.cancel };
    let view = ctx.engine.reconcile(&input).await.map_err(|e| Error::Engine(format!("{e:#}")))?;
    let status = to_status(&view, run.metadata.generation);
    if run.status.as_ref() != Some(&status) {
        patch_status(&ctx.client, &run, status).await?;
    }
    Ok(match view.requeue_after {
        Some(d) => Action::requeue(d.max(Duration::from_millis(500))),
        None => Action::await_change(),
    })
}

async fn cleanup(run: Arc<ACPRun>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    ctx.engine.cancel(&key(&run), "ACPRun deleted").await.map_err(|e| Error::Engine(format!("{e:#}")))?;
    tracing::info!(run = %run.name_any(), "ACPRun deleted; sandboxes terminated and leases released");
    Ok(Action::await_change())
}

async fn patch_status(client: &Client, run: &ACPRun, status: ACPRunStatus) -> Result<(), Error> {
    let api: Api<ACPRun> = Api::namespaced(client.clone(), &run.namespace().unwrap_or_default());
    let patch = serde_json::json!({"status": status});
    api.patch_status(&run.name_any(), &PatchParams::default(), &Patch::Merge(&patch)).await?;
    Ok(())
}

fn ts(t: Option<chrono::DateTime<chrono::Utc>>) -> Option<String> {
    t.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

pub fn to_status(v: &RunView, generation: Option<i64>) -> ACPRunStatus {
    let c = v.current.as_ref();
    ACPRunStatus {
        phase: Some(v.phase.as_str().to_string()),
        run_id: Some(v.run_id.to_string()),
        observed_generation: generation,
        current_attempt: c.map(|c| c.ordinal),
        attempt_id: c.map(|c| c.id.to_string()),
        attempt_phase: c.map(|c| c.phase.as_str().to_string()),
        runner_class: c.map(|c| c.runner_class.clone()),
        driver: c.map(|c| c.driver.clone()),
        credential_profile: c.and_then(|c| c.credential_profile.clone()),
        sandbox_ref: c.and_then(|c| c.sandbox.as_ref()).map(|s| SandboxRefStatus {
            kind: match s.backend.as_str() {
                "pod" => "Pod".to_string(),
                "agent-sandbox" => "Sandbox".to_string(),
                other => other.to_string(),
            },
            namespace: s.namespace.clone(),
            name: s.name.clone(),
        }),
        started_at: ts(v.started_at),
        finished_at: ts(v.finished_at),
        last_heartbeat_time: ts(c.and_then(|c| c.last_heartbeat_at)),
        last_progress_time: ts(c.and_then(|c| c.last_progress_at)),
        failure_reason: v.failure.as_ref().map(|f| FailureStatus { code: f.code().to_string(), message: f.message() }),
        artifact_ref: v.artifact.as_ref().map(|a| ArtifactRefStatus {
            id: a.id.to_string(),
            kind: a.kind.clone(),
            sha256: a.sha256.clone(),
            size_bytes: a.size_bytes,
            changed_paths: a.changed_paths as i64,
            base_revision: a.base_revision.clone(),
            storage: a.storage.clone(),
        }),
        message: v.waiting_reason.clone(),
    }
}
