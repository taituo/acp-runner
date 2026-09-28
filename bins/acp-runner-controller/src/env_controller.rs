//! kube-runtime controller: AgentEnvironment -> EnvironmentProvider -> AgentEnvironment.status.
//!
//! The provider is PostgreSQL-backed, so `finish`, `cancel` and `destroy` survive
//! controller restarts: on re-list the controller adopts the live journal row for
//! its object (UID-guarded) instead of creating a duplicate environment. The
//! finalizer destroys the environment (sandbox, lease) and removes the gateway
//! Service/NetworkPolicy. Status never carries tickets.

use acp_runner_engine::environment::{EnvironmentProvider, EnvironmentView, K8sOwner};
use acp_runner_k8s::crds::{
    AgentEnvironment, AgentEnvironmentStatus, EnvArtifactRef, EnvConnection, EnvLineage, FailureStatus,
    StatusHarness,
};
use acp_runner_k8s::env_net;
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{Event, finalizer};
use kube::runtime::watcher;
use kube::{Client, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

pub const ENV_FINALIZER: &str = "acp-runner.dev/environment-cleanup";
/// How long reconcile waits for a graceful finish/cancel/destroy before requeueing.
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct EnvCtx {
    pub client: Client,
    pub provider: Arc<EnvironmentProvider>,
    pub gateway_port: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvError {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    #[error("environment networking: {0}")]
    EnvNet(#[from] acp_runner_k8s::env_net::EnvNetError),
    #[error("provider: {0}")]
    Provider(String),
    #[error("finalizer: {0}")]
    Finalizer(String),
}

pub async fn run(client: Client, provider: Arc<EnvironmentProvider>, gateway_port: i32, namespace: Option<String>) {
    let envs: Api<AgentEnvironment> = match &namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };
    let ctx = Arc::new(EnvCtx { client, provider, gateway_port });
    Controller::new(envs, watcher::Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::debug!(error = %e, "environment reconcile loop error");
            }
        })
        .await;
}

fn error_policy(env: Arc<AgentEnvironment>, err: &EnvError, _ctx: Arc<EnvCtx>) -> Action {
    tracing::warn!(env = %env.name_any(), error = %err, "environment reconcile failed; requeueing");
    Action::requeue(Duration::from_secs(10))
}

async fn reconcile(env: Arc<AgentEnvironment>, ctx: Arc<EnvCtx>) -> Result<Action, EnvError> {
    let ns = env.namespace().unwrap_or_else(|| "default".into());
    let api: Api<AgentEnvironment> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, ENV_FINALIZER, env, |event| async {
        match event {
            Event::Apply(env) => apply(env, ctx.clone()).await,
            Event::Cleanup(env) => cleanup(env, ctx.clone()).await,
        }
    })
    .await
    .map_err(|e| EnvError::Finalizer(e.to_string()))
}

fn owner(ns: &str, env: &AgentEnvironment) -> K8sOwner {
    K8sOwner { namespace: ns.to_string(), name: env.name_any(), uid: env.uid().unwrap_or_default() }
}

/// Adopt the live row, replace a stale one, or create the environment; then apply
/// the lifecycle request and report status. Returns the view plus attempt id.
async fn ensure_live(env: &AgentEnvironment, ns: &str, ctx: &EnvCtx) -> Result<(EnvironmentView, uuid::Uuid), EnvError> {
    let o = owner(ns, env);
    if let Some(row) = ctx.provider.journal.live_environment_by_k8s(ns, &o.name).await.map_err(provider_err)? {
        if row.k8s_uid.as_deref() == Some(o.uid.as_str()) {
            let view = apply_lifecycle(&row.id, env, ctx).await?;
            return Ok((view, row.attempt_id));
        }
        // Stale row: the object was deleted and recreated with the same name (e.g.
        // the old finalizer never ran). Destroy fencing-safe, drop the row, recreate.
        tracing::info!(env = %o.name, "replacing stale environment row");
        ctx.provider.destroy(row.id, LIFECYCLE_TIMEOUT).await.map_err(provider_err)?;
        ctx.provider.journal.delete_environment(row.id).await.map_err(provider_err)?;
    }
    let spec = env.spec.to_core().map_err(EnvError::Provider)?;
    let _ = ctx.provider.create_namespaced(spec, o).await.map_err(provider_err)?;
    let row = ctx
        .provider
        .journal
        .live_environment_by_k8s(ns, &env.name_any())
        .await
        .map_err(provider_err)?
        .ok_or_else(|| EnvError::Provider("environment row missing after create".into()))?;
    let view = apply_lifecycle(&row.id, env, ctx).await?;
    Ok((view, row.attempt_id))
}

/// `spec.lifecycle: finish|cancel` advances a live environment; no-ops when terminal.
async fn apply_lifecycle(id: &uuid::Uuid, env: &AgentEnvironment, ctx: &EnvCtx) -> Result<EnvironmentView, EnvError> {
    match env.spec.lifecycle.as_deref() {
        Some("finish") => ctx.provider.finish(*id, LIFECYCLE_TIMEOUT).await.map_err(provider_err),
        Some("cancel") => ctx.provider.cancel(*id, "cancelled via AgentEnvironment lifecycle", LIFECYCLE_TIMEOUT).await.map_err(provider_err),
        Some(other) => Err(EnvError::Provider(format!("unknown lifecycle request {other:?} (want finish|cancel)"))),
        None => ctx.provider.get(*id).await.map_err(provider_err)?.ok_or_else(|| EnvError::Provider("environment row vanished".into())),
    }
}

async fn apply(env: Arc<AgentEnvironment>, ctx: Arc<EnvCtx>) -> Result<Action, EnvError> {
    let ns = env.namespace().unwrap_or_else(|| "default".into());
    let (view, attempt_id) = ensure_live(&env, &ns, &ctx).await?;
    if view.phase.is_terminal() {
        // Terminal: the gateway is gone (sandbox terminated, lease released by
        // finalization); drop the Service/Policy but keep reporting status.
        env_net::delete_gateway_net(ctx.client.clone(), &ns, &env.name_any()).await?;
    } else {
        let svc = env_net::ensure_gateway_net(
            ctx.client.clone(),
            &ns,
            &env.name_any(),
            &env.uid().unwrap_or_default(),
            &attempt_id.to_string(),
            ctx.gateway_port,
        )
        .await?;
        let addr = env_net::cluster_gateway_addr(&ns, &svc, ctx.gateway_port);
        let status = to_status(&view, Some(addr), env.metadata.generation);
        if env.status.as_ref() != Some(&status) {
            patch_status(&ctx.client, &ns, &env.name_any(), status).await?;
        }
        return Ok(if view.phase == acp_runner_core::environment::EnvironmentPhase::Creating {
            Action::requeue(Duration::from_secs(5))
        } else {
            Action::await_change()
        });
    }
    let status = to_status(&view, None, env.metadata.generation);
    if env.status.as_ref() != Some(&status) {
        patch_status(&ctx.client, &ns, &env.name_any(), status).await?;
    }
    Ok(Action::await_change())
}

async fn cleanup(env: Arc<AgentEnvironment>, ctx: Arc<EnvCtx>) -> Result<Action, EnvError> {
    let ns = env.namespace().unwrap_or_else(|| "default".into());
    if let Some(row) = ctx.provider.journal.live_environment_by_k8s(&ns, &env.name_any()).await.map_err(provider_err)? {
        ctx.provider.destroy(row.id, LIFECYCLE_TIMEOUT).await.map_err(provider_err)?;
        ctx.provider.journal.delete_environment(row.id).await.map_err(provider_err)?;
    }
    env_net::delete_gateway_net(ctx.client.clone(), &ns, &env.name_any()).await?;
    tracing::info!(env = %env.name_any(), "AgentEnvironment deleted; sandbox, lease and gateway net released");
    Ok(Action::await_change())
}

fn provider_err(e: impl std::fmt::Display) -> EnvError {
    EnvError::Provider(e.to_string())
}

async fn patch_status(client: &Client, ns: &str, name: &str, status: AgentEnvironmentStatus) -> Result<(), EnvError> {
    let api: Api<AgentEnvironment> = Api::namespaced(client.clone(), ns);
    let patch = serde_json::json!({"status": status});
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch)).await?;
    Ok(())
}

/// Plan 10a.2: phase, endpoint, resolved revision, lineage and error. Never tickets.
pub fn to_status(view: &EnvironmentView, endpoint: Option<String>, generation: Option<i64>) -> AgentEnvironmentStatus {
    AgentEnvironmentStatus {
        phase: Some(view.phase.as_str().to_string()),
        environment_id: Some(view.id.to_string()),
        harness: Some(StatusHarness { name: view.harness.clone(), version: None, digest: None }),
        resolved_revision: view.base_revision.clone(),
        workdir: Some(view.workdir.clone()),
        connection: endpoint.map(|gateway| EnvConnection { gateway }),
        lineage: Some(EnvLineage {
            parent_artifact_id: view.lineage.parent_artifact_id.map(|id| id.to_string()),
            parent_environment_id: view.lineage.parent_environment_id.map(|id| id.to_string()),
        }),
        last_heartbeat_time: None,
        last_progress_time: None,
        latest_snapshot_ref: view.snapshots.last().map(|s| EnvArtifactRef {
            artifact_id: s.artifact_id.to_string(),
            sha256: Some(s.sha256.clone()),
            base_revision: view.base_revision.clone(),
        }),
        final_artifact_ref: view.final_artifact_id.map(|id| EnvArtifactRef {
            artifact_id: id.to_string(),
            sha256: None,
            base_revision: view.base_revision.clone(),
        }),
        failure_reason: view.failure.as_ref().map(|f| FailureStatus { code: f.code().to_string(), message: f.message() }),
        observed_generation: generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_runner_core::attempt_spec::Lineage;

    fn view() -> EnvironmentView {
        EnvironmentView {
            id: uuid::Uuid::now_v7(),
            external_ref: "task-1".into(),
            harness: "fake".into(),
            phase: acp_runner_core::environment::EnvironmentPhase::Idle,
            base_revision: Some("abc".into()),
            workdir: String::new(),
            connection: None,
            lineage: Lineage::default(),
            final_artifact_id: None,
            snapshots: vec![],
            failure: None,
        }
    }

    #[test]
    fn status_reports_phase_endpoint_revision_lineage_and_error_without_tickets() {
        // Plan 10a.2: phase, endpoint, resolved revision, lineage, error — never tickets.
        let s = to_status(&view(), Some("review-gw.team-a.svc.cluster.local:4713".into()), Some(3));
        assert_eq!(s.phase.as_deref(), Some("Idle"));
        assert_eq!(s.connection.as_ref().unwrap().gateway, "review-gw.team-a.svc.cluster.local:4713");
        assert_eq!(s.resolved_revision.as_deref(), Some("abc"));
        assert!(s.lineage.is_some());
        assert_eq!(s.observed_generation, Some(3));
        let raw = serde_json::to_string(&s).unwrap();
        assert!(!raw.to_lowercase().contains("ticket"), "{raw}");
    }
}
