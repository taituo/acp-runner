//! Per-environment gateway networking (V10a): a ClusterIP Service in front of the
//! environment sandbox's runnerd gateway plus a NetworkPolicy that allows ingress
//! to the gateway only from the calling namespace (the `AgentEnvironment`'s own
//! namespace). Both carry an owner reference to the `AgentEnvironment` and are
//! removed by the environment finalizer; all operations are idempotent across
//! controller restarts (server-side apply).

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, Patch, PatchParams};
use std::collections::BTreeMap;

pub const FIELD_MANAGER: &str = "acp-runner-controller";
/// Label selecting exactly one environment sandbox (mirrors [`crate::pod::labels`]).
pub const ATTEMPT_LABEL: &str = "acp-runner.dev/attempt-id";

#[derive(Debug, thiserror::Error)]
pub enum EnvNetError {
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
}

/// `<env-name>-gw`, truncated to a valid DNS subdomain.
pub fn service_name(env_name: &str) -> String {
    let mut n = format!("{env_name}-gw");
    if n.len() > 63 {
        n.truncate(63);
    }
    n.trim_end_matches(|c: char| !c.is_ascii_alphanumeric()).to_string()
}

pub fn policy_name(env_name: &str) -> String {
    service_name(env_name)
}

fn owner_ref(owner_uid: &str, owner_name: &str) -> OwnerReference {
    OwnerReference {
        api_version: "acp-runner.dev/v1alpha1".to_string(),
        kind: "AgentEnvironment".to_string(),
        name: owner_name.to_string(),
        uid: owner_uid.to_string(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

fn selector(attempt_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("app.kubernetes.io/managed-by".to_string(), "acp-runner".to_string()), (ATTEMPT_LABEL.to_string(), attempt_id.to_string())])
}

/// ClusterIP Service `svc` in `ns` selecting the sandbox pods of `attempt_id` and
/// forwarding `port` (the runnerd gateway port) 1:1.
pub fn gateway_service(ns: &str, svc: &str, attempt_id: &str, port: i32, owner: &OwnerReference) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(svc.to_string()),
            namespace: Some(ns.to_string()),
            labels: Some(BTreeMap::from([("app.kubernetes.io/managed-by".to_string(), "acp-runner".to_string())])),
            owner_references: Some(vec![owner.clone()]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".to_string()),
            selector: Some(selector(attempt_id)),
            ports: Some(vec![ServicePort { name: Some("gateway".to_string()), port, target_port: Some(IntOrString::Int(port)), protocol: Some("TCP".to_string()), ..Default::default() }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// NetworkPolicy: allow TCP `port` to the sandbox pods only from pods in `caller_ns`
/// (the `AgentEnvironment`'s namespace). Default-deny otherwise for these pods.
pub fn gateway_policy(ns: &str, name: &str, caller_ns: &str, attempt_id: &str, port: i32, owner: &OwnerReference) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(ns.to_string()),
            labels: Some(BTreeMap::from([("app.kubernetes.io/managed-by".to_string(), "acp-runner".to_string())])),
            owner_references: Some(vec![owner.clone()]),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector { match_labels: Some(BTreeMap::from([(ATTEMPT_LABEL.to_string(), attempt_id.to_string())])), ..Default::default() }),
            policy_types: Some(vec!["Ingress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([("kubernetes.io/metadata.name".to_string(), caller_ns.to_string())])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector { ..Default::default() }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(port)),
                    protocol: Some("TCP".to_string()),
                    end_port: None,
                }]),
            }]),
            egress: None,
        }),
    }
}

fn apply_params() -> PatchParams {
    let mut p = PatchParams::apply(FIELD_MANAGER);
    p.force = true;
    p
}

/// Ensure the gateway Service and ingress NetworkPolicy exist (idempotent).
pub async fn ensure_gateway_net(
    client: kube::Client,
    ns: &str,
    env_name: &str,
    owner_uid: &str,
    attempt_id: &str,
    gateway_port: i32,
) -> Result<String, EnvNetError> {
    let owner = owner_ref(owner_uid, env_name);
    let svc = service_name(env_name);
    let services: Api<Service> = Api::namespaced(client.clone(), ns);
    services.patch(&svc, &apply_params(), &Patch::Apply(gateway_service(ns, &svc, attempt_id, gateway_port, &owner))).await?;
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), ns);
    policies
        .patch(&policy_name(env_name), &apply_params(), &Patch::Apply(gateway_policy(ns, &policy_name(env_name), ns, attempt_id, gateway_port, &owner)))
        .await?;
    Ok(svc)
}

fn is_not_found(e: &kube::Error) -> bool {
    matches!(e, kube::Error::Api(s) if s.code == 404)
}

/// Remove the gateway Service and NetworkPolicy (missing objects are fine).
pub async fn delete_gateway_net(client: kube::Client, ns: &str, env_name: &str) -> Result<(), EnvNetError> {
    let services: Api<Service> = Api::namespaced(client.clone(), ns);
    let dp = kube::api::DeleteParams::default();
    match services.delete(&service_name(env_name), &dp).await {
        Ok(_) => {}
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(e.into()),
    }
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), ns);
    match policies.delete(&policy_name(env_name), &dp).await {
        Ok(_) => {}
        Err(e) if is_not_found(&e) => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// In-cluster gateway address callers use: `<svc>.<ns>.svc.cluster.local:<port>`.
pub fn cluster_gateway_addr(ns: &str, svc: &str, port: i32) -> String {
    format!("{svc}.{ns}.svc.cluster.local:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_selects_the_attempt_and_forwards_the_gateway_port() {
        let o = owner_ref("uid-1", "review");
        let s = gateway_service("team-a", "review-gw", "attempt-1", 4713, &o);
        let spec = s.spec.unwrap();
        assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(spec.selector.unwrap()[ATTEMPT_LABEL], "attempt-1");
        let p = spec.ports.unwrap().pop().unwrap();
        assert_eq!(p.port, 4713);
        assert_eq!(p.target_port, Some(IntOrString::Int(4713)));
        let ors = s.metadata.owner_references.unwrap();
        assert_eq!(ors[0].kind, "AgentEnvironment");
        assert_eq!(ors[0].uid, "uid-1");
    }

    #[test]
    fn policy_allows_only_the_caller_namespace_to_the_gateway_port() {
        let o = owner_ref("uid-1", "review");
        let n = gateway_policy("team-a", "review-gw", "team-a", "attempt-1", 4713, &o);
        let spec = n.spec.unwrap();
        assert_eq!(spec.policy_types.unwrap(), vec!["Ingress".to_string()]);
        assert_eq!(
            spec.pod_selector.unwrap().match_labels.unwrap()[ATTEMPT_LABEL],
            "attempt-1"
        );
        let rule = spec.ingress.unwrap().pop().unwrap();
        let peer = rule.from.unwrap().pop().unwrap();
        assert_eq!(
            peer.namespace_selector.unwrap().match_labels.unwrap()["kubernetes.io/metadata.name"],
            "team-a"
        );
        assert!(peer.pod_selector.is_some());
        let port = rule.ports.unwrap().pop().unwrap();
        assert_eq!(port.port, Some(IntOrString::Int(4713)));
    }

    #[test]
    fn names_stay_valid_dns_subdomains() {
        assert_eq!(service_name("review"), "review-gw");
        let long = "a".repeat(70);
        assert!(service_name(&long).len() <= 63);
        assert_eq!(cluster_gateway_addr("team-a", "review-gw", 4713), "review-gw.team-a.svc.cluster.local:4713");
    }
}
