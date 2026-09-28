//! Kubernetes sandbox backends.
//!
//! * [`PodBackend`] (default): one hardened Pod (+ per-attempt Secret) per attempt.
//! * [`AgentSandboxBackend`]: one `agents.x-k8s.io/v1beta1` `Sandbox` per attempt, using
//!   kubernetes-sigs/agent-sandbox (v1.0.x) for the isolated-compute lifecycle. Our pod
//!   template is embedded unchanged; the Sandbox controller owns pod creation/deletion and
//!   `shutdownTime` is set as an extra expiry backstop. Warm pools / claims are not used:
//!   an attempt's pod needs its per-attempt credential Secret at creation time.

use crate::pod::{PodConfig, RUNNERD_CONTAINER, build_pod, build_secret, labels, pod_spec_json, secret_name};
use acp_runner_engine::backend::{BackendError, SandboxBackend, SandboxObservation, SandboxRef, SandboxRequest};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Pod, Secret};
use kube::Client;
use kube::api::{Api, DeleteParams, DynamicObject, PostParams, PropagationPolicy};
use kube::core::{ApiResource, GroupVersionKind};
use serde_json::json;
use std::time::Duration;

fn err(e: kube::Error) -> BackendError {
    match &e {
        kube::Error::Api(s) if s.is_forbidden() || s.is_invalid() || s.code == 400 => {
            BackendError::Permanent(e.to_string())
        }
        _ => BackendError::Transient(e.to_string()),
    }
}

fn not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(s) if s.is_not_found())
}

async fn delete_ignore_missing<K>(api: &Api<K>, name: &str, grace: Option<u32>) -> Result<(), BackendError>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let dp = DeleteParams {
        grace_period_seconds: grace,
        propagation_policy: Some(PropagationPolicy::Background),
        ..Default::default()
    };
    match api.delete(name, &dp).await {
        Ok(_) => Ok(()),
        Err(e) if not_found(&e) => Ok(()),
        Err(e) => Err(err(e)),
    }
}

async fn wait_gone<K>(api: &Api<K>, name: &str, timeout: Duration) -> Result<(), BackendError>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match api.get_opt(name).await {
            Ok(None) => return Ok(()),
            Ok(Some(_)) if std::time::Instant::now() >= deadline => {
                return Err(BackendError::Transient(format!("{name} still terminating")));
            }
            Ok(Some(_)) => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(e) => return Err(err(e)),
        }
    }
}

/// Waiting reasons that will not resolve by themselves.
const FATAL_WAITING: &[&str] = &[
    "ErrImagePull",
    "ImagePullBackOff",
    "InvalidImageName",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
];

/// Map a pod to an observation. The attempt's liveness is runnerd's: when the runnerd
/// container has terminated the sandbox counts as exited even if agentd is still running
/// (the engine then deletes the pod).
pub fn classify_pod(p: &Pod) -> SandboxObservation {
    let Some(status) = &p.status else { return SandboxObservation::Pending { reason: None } };
    let statuses = status.container_statuses.clone().unwrap_or_default();
    for c in &statuses {
        if let Some(w) = c.state.as_ref().and_then(|s| s.waiting.clone())
            && let Some(reason) = &w.reason
            && FATAL_WAITING.contains(&reason.as_str())
        {
            return SandboxObservation::Exited {
                exit_code: None,
                reason: Some(format!("{}: {reason}", c.name)),
                message: w.message.clone(),
            };
        }
    }
    let state = statuses.iter().find(|c| c.name == RUNNERD_CONTAINER).and_then(|c| c.state.clone());
    if let Some(term) = state.as_ref().and_then(|s| s.terminated.clone()) {
        return SandboxObservation::Exited {
            exit_code: Some(term.exit_code),
            reason: term.reason.clone().or_else(|| status.reason.clone()),
            message: term.message.clone().or_else(|| status.message.clone()),
        };
    }
    match status.phase.as_deref() {
        Some("Running") => SandboxObservation::Running,
        Some("Succeeded") | Some("Failed") => {
            let term = state.and_then(|s| s.terminated);
            SandboxObservation::Exited {
                exit_code: term.as_ref().map(|t| t.exit_code),
                reason: term.as_ref().and_then(|t| t.reason.clone()).or_else(|| status.reason.clone()),
                message: term.as_ref().and_then(|t| t.message.clone()).or_else(|| status.message.clone()),
            }
        }
        _ => SandboxObservation::Pending {
            reason: state.and_then(|s| s.waiting).and_then(|w| w.reason).or_else(|| status.reason.clone()),
        },
    }
}

// ---------------------------------------------------------------------------------------

pub struct PodBackend {
    pub client: Client,
    pub cfg: PodConfig,
}

#[async_trait]
impl SandboxBackend for PodBackend {
    fn name(&self) -> &'static str {
        "pod"
    }

    async fn create(&self, req: &SandboxRequest) -> Result<SandboxRef, BackendError> {
        let ns = self.cfg.namespace_for(req);
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &ns);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &ns);
        // replace leftovers from an interrupted earlier create of the same attempt
        delete_ignore_missing(&pods, &req.name, Some(0)).await?;
        delete_ignore_missing(&secrets, &secret_name(req), None).await?;
        wait_gone(&pods, &req.name, Duration::from_secs(30)).await?;
        wait_gone(&secrets, &secret_name(req), Duration::from_secs(10)).await?;
        secrets.create(&PostParams::default(), &build_secret(req, &self.cfg)).await.map_err(err)?;
        pods.create(&PostParams::default(), &build_pod(req, &self.cfg)).await.map_err(err)?;
        Ok(SandboxRef { backend: "pod".into(), namespace: Some(ns), name: req.name.clone() })
    }

    async fn observe(&self, r: &SandboxRef) -> Result<SandboxObservation, BackendError> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), r.namespace.as_deref().unwrap_or("default"));
        match pods.get_opt(&r.name).await.map_err(err)? {
            None => Ok(SandboxObservation::Missing),
            Some(p) => Ok(classify_pod(&p)),
        }
    }

    async fn terminate(&self, r: &SandboxRef, grace: Duration) -> Result<(), BackendError> {
        let ns = r.namespace.as_deref().unwrap_or("default");
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), ns);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), ns);
        delete_ignore_missing(&pods, &r.name, Some(grace.as_secs() as u32)).await?;
        delete_ignore_missing(&secrets, &format!("{}-att", r.name), None).await
    }
}

// ---------------------------------------------------------------------------------------

pub fn sandbox_api_resource() -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk("agents.x-k8s.io", "v1beta1", "Sandbox"), "sandboxes")
}

pub const SANDBOX_POD_NAME_ANNOTATION: &str = "agents.x-k8s.io/pod-name";

pub struct AgentSandboxBackend {
    pub client: Client,
    pub cfg: PodConfig,
}

impl AgentSandboxBackend {
    fn api(&self, ns: &str) -> Api<DynamicObject> {
        Api::namespaced_with(self.client.clone(), ns, &sandbox_api_resource())
    }

    pub fn build_sandbox(req: &SandboxRequest, cfg: &PodConfig) -> serde_json::Value {
        let t = &req.timeouts;
        // V10c: the embedded pod carries activeDeadlineSeconds == hard_deadline
        // (see pod_spec_json); the Sandbox-level shutdown is the same bound
        // plus a collection backstop.
        let expiry = chrono::Utc::now()
            + chrono::Duration::seconds((t.hard_deadline().as_secs() + 300) as i64);
        let pod = build_pod(req, cfg);
        json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": req.name,
                "namespace": cfg.namespace_for(req),
                "labels": labels(req),
                "ownerReferences": pod.metadata.owner_references,
            },
            "spec": {
                "podTemplate": {
                    "metadata": {"labels": labels(req)},
                    "spec": pod_spec_json(req, cfg)
                },
                "service": false,
                "shutdownTime": expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "shutdownPolicy": "Delete"
            }
        })
    }
}

#[async_trait]
impl SandboxBackend for AgentSandboxBackend {
    fn name(&self) -> &'static str {
        "agent-sandbox"
    }

    async fn create(&self, req: &SandboxRequest) -> Result<SandboxRef, BackendError> {
        let ns = self.cfg.namespace_for(req);
        let api = self.api(&ns);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &ns);
        delete_ignore_missing(&api, &req.name, None).await?;
        delete_ignore_missing(&secrets, &secret_name(req), None).await?;
        wait_gone(&api, &req.name, Duration::from_secs(30)).await?;
        wait_gone(&secrets, &secret_name(req), Duration::from_secs(10)).await?;
        secrets.create(&PostParams::default(), &build_secret(req, &self.cfg)).await.map_err(err)?;
        let obj: DynamicObject = serde_json::from_value(Self::build_sandbox(req, &self.cfg))
            .map_err(|e| BackendError::Permanent(e.to_string()))?;
        api.create(&PostParams::default(), &obj).await.map_err(err)?;
        Ok(SandboxRef { backend: "agent-sandbox".into(), namespace: Some(ns), name: req.name.clone() })
    }

    async fn observe(&self, r: &SandboxRef) -> Result<SandboxObservation, BackendError> {
        let ns = r.namespace.as_deref().unwrap_or("default");
        let Some(sb) = self.api(ns).get_opt(&r.name).await.map_err(err)? else {
            return Ok(SandboxObservation::Missing);
        };
        let pod_name = sb
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(SANDBOX_POD_NAME_ANNOTATION).cloned())
            .unwrap_or_else(|| r.name.clone());
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), ns);
        let pod = pods.get_opt(&pod_name).await.map_err(err)?;
        let conditions = sb.data.pointer("/status/conditions").and_then(|c| c.as_array()).cloned().unwrap_or_default();
        let finished = conditions
            .iter()
            .find(|c| c["type"] == "Finished" && c["status"] == "True")
            .and_then(|c| c["reason"].as_str().map(str::to_string));
        match (finished, pod) {
            (Some(reason), Some(p)) if reason != "SandboxExpired" => Ok(match classify_pod(&p) {
                SandboxObservation::Running | SandboxObservation::Pending { .. } => SandboxObservation::Exited {
                    exit_code: Some(if reason == "PodSucceeded" { 0 } else { 1 }),
                    reason: Some(reason),
                    message: None,
                },
                other => other,
            }),
            (Some(reason), _) => Ok(SandboxObservation::Exited {
                exit_code: if reason == "PodSucceeded" { Some(0) } else { None },
                reason: Some(reason),
                message: None,
            }),
            (None, Some(p)) => Ok(classify_pod(&p)),
            (None, None) => Ok(SandboxObservation::Pending {
                reason: conditions
                    .iter()
                    .find(|c| c["type"] == "Ready")
                    .and_then(|c| c["reason"].as_str().map(str::to_string)),
            }),
        }
    }

    async fn terminate(&self, r: &SandboxRef, _grace: Duration) -> Result<(), BackendError> {
        // The pod template carries terminationGracePeriodSeconds = grace + 15.
        let ns = r.namespace.as_deref().unwrap_or("default");
        delete_ignore_missing(&self.api(ns), &r.name, None).await?;
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), ns);
        delete_ignore_missing(&secrets, &format!("{}-att", r.name), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod::tests::request;
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateTerminated, ContainerStateWaiting, ContainerStatus, PodStatus,
    };

    fn pod_with(phase: &str, state: ContainerState) -> Pod {
        Pod {
            status: Some(PodStatus {
                phase: Some(phase.into()),
                container_statuses: Some(vec![ContainerStatus {
                    name: "runnerd".into(),
                    state: Some(state),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn pod_classification() {
        let p = pod_with(
            "Pending",
            ContainerState {
                waiting: Some(ContainerStateWaiting {
                    reason: Some("ImagePullBackOff".into()),
                    message: Some("nope".into()),
                }),
                ..Default::default()
            },
        );
        assert!(matches!(classify_pod(&p), SandboxObservation::Exited { exit_code: None, .. }));
        let p = pod_with(
            "Pending",
            ContainerState {
                waiting: Some(ContainerStateWaiting { reason: Some("ContainerCreating".into()), message: None }),
                ..Default::default()
            },
        );
        assert!(matches!(classify_pod(&p), SandboxObservation::Pending { .. }));
        let p = pod_with(
            "Failed",
            ContainerState {
                terminated: Some(ContainerStateTerminated {
                    exit_code: 137,
                    reason: Some("OOMKilled".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        assert_eq!(
            classify_pod(&p),
            SandboxObservation::Exited { exit_code: Some(137), reason: Some("OOMKilled".into()), message: None }
        );
        // runnerd finished, agentd still running (pod phase Running): exited
        let mut p = pod_with(
            "Running",
            ContainerState {
                terminated: Some(ContainerStateTerminated { exit_code: 0, ..Default::default() }),
                ..Default::default()
            },
        );
        p.status.as_mut().unwrap().container_statuses.as_mut().unwrap().push(ContainerStatus {
            name: "agentd".into(),
            state: Some(ContainerState { running: Some(Default::default()), ..Default::default() }),
            ..Default::default()
        });
        assert!(matches!(classify_pod(&p), SandboxObservation::Exited { exit_code: Some(0), .. }));
        // an agentd image problem is fatal as well
        let mut p = pod_with("Pending", ContainerState::default());
        p.status.as_mut().unwrap().container_statuses.as_mut().unwrap().push(ContainerStatus {
            name: "agentd".into(),
            state: Some(ContainerState {
                waiting: Some(ContainerStateWaiting {
                    reason: Some("CreateContainerConfigError".into()),
                    message: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert!(matches!(classify_pod(&p), SandboxObservation::Exited { exit_code: None, .. }));
    }

    #[test]
    fn sandbox_object_embeds_the_hardened_pod_template() {
        let v = AgentSandboxBackend::build_sandbox(&request(Some("gvisor")), &PodConfig::default());
        assert_eq!(v["apiVersion"], "agents.x-k8s.io/v1beta1");
        let spec = &v["spec"]["podTemplate"]["spec"];
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(spec["runtimeClassName"], "gvisor");
        assert_eq!(v["spec"]["shutdownPolicy"], "Delete");
        assert_eq!(v["spec"]["service"], false);
        let _: DynamicObject = serde_json::from_value(v).unwrap();
    }
}
