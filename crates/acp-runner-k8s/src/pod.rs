//! Hardened attempt pod (and per-attempt Secret) construction.
//!
//! Every attempt pod has two containers from the same runner image, split by trust:
//!
//! ```text
//! Pod (shareProcessNamespace: false, automountServiceAccountToken: false)
//! ├── runnerd   TRUSTED    attempt token + leased credential (Secret, read-only),
//! │                        private state (/var/lib/acp-runner), ingest URL, heartbeats,
//! │                        workspace prepare, patch collection, credential write-back
//! └── agentd    UNTRUSTED  provider CLI, disposable workspace, synthetic HOME,
//!                          local IPC -> runnerd
//! shared (emptyDir):      /workspace  /home/agent  /run/acp-runner
//! shared, agentd RO:      /opt/harness  (pinned harness artifact materialized by runnerd)
//! runnerd only:           /var/run/acp-runner/attempt (Secret)  /var/lib/acp-runner  /tmp
//! agentd only:            /tmp
//! ```
//!
//! agentd's environment contains no controller URL and no `ACP_RUNNER_*` configuration;
//! containers have separate PID namespaces, so agentd cannot see runnerd's process or read
//! its `/proc` entries; they share the pod network namespace (the ingest API is reachable
//! but useless without the token, which only runnerd has).
//!
//! Security posture of both containers:
//!
//! * `automountServiceAccountToken: false`, dedicated service account without RBAC
//! * `enableServiceLinks: false` (no service discovery env vars)
//! * non-root (`runAsNonRoot`, uid/gid 10001 by default), `fsGroup` for volume access
//! * `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`,
//!   `capabilities.drop: [ALL]`, `seccompProfile: RuntimeDefault`
//! * writable mounts are emptyDirs only (memory-backed by default); no hostPath, no
//!   container runtime socket, no PVCs, no host namespaces
//! * optional `runtimeClassName` (e.g. `gvisor`) applies to the whole pod
//! * `activeDeadlineSeconds` as a kubelet-enforced hard stop behind runnerd and the engine

use acp_runner_core::attempt_spec::{TOKEN_FILE_NAME, secret_file_name};
use acp_runner_core::spec::StorageMedium;
use acp_runner_engine::backend::SandboxRequest;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{Pod, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const SECRET_MOUNT: &str = "/var/run/acp-runner/attempt";
pub const RUN_DIR: &str = "/run/acp-runner";
pub const STATE_DIR: &str = "/var/lib/acp-runner";
pub const WORKSPACE_DIR: &str = "/workspace";
pub const HOME_DIR: &str = "/home/agent";
pub const DEFAULT_UID: i64 = 10001;
pub const DEFAULT_SERVICE_ACCOUNT: &str = "acp-runner-agent";
pub const RUNNERD_CONTAINER: &str = "runnerd";
pub const AGENTD_CONTAINER: &str = "agentd";

#[derive(Debug, Clone)]
pub struct PodConfig {
    /// Namespace for agent sandboxes. `None` = same namespace as the ACPRun (owner refs set).
    pub agent_namespace: Option<String>,
    pub strict_posture: bool,
    /// Propagate `ACP_RUNNER_ALLOW_FILE_REPOS=true` into the runnerd container
    /// (V8.3). Trusted operator setting: mirrors the controller process' own
    /// `acp_runner_core::spec::allow_file_repos()` value. Default false —
    /// runnerd pods deny `file://` repository URLs unless the operator opts in.
    /// Never set from RunSpec caller input.
    pub allow_file_repos: bool,
    pub runnerd_command: Vec<String>,
    pub agentd_command: Vec<String>,
    /// Resources of the runnerd container (the runner class' `resources` apply to agentd,
    /// which runs the CLI).
    pub runnerd_resources: Value,
    pub default_service_account: String,
}

impl Default for PodConfig {
    fn default() -> Self {
        PodConfig {
            agent_namespace: None,
            strict_posture: true,
            allow_file_repos: false,
            runnerd_command: vec!["/usr/bin/tini".into(), "--".into(), "/usr/local/bin/runnerd".into(), "pod".into()],
            agentd_command: vec!["/usr/bin/tini".into(), "--".into(), "/usr/local/bin/agentd".into(), "run".into()],
            runnerd_resources: json!({"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "1Gi"}}),
            default_service_account: DEFAULT_SERVICE_ACCOUNT.into(),
        }
    }
}

impl PodConfig {
    pub fn namespace_for(&self, req: &SandboxRequest) -> String {
        self.agent_namespace.clone().unwrap_or_else(|| req.run_key.namespace.clone())
    }

    fn owner_refs(&self, req: &SandboxRequest) -> Option<Vec<OwnerReference>> {
        if self.agent_namespace.as_deref().is_some_and(|ns| ns != req.run_key.namespace) {
            return None; // cross-namespace owner references are not allowed; finalizer cleans up
        }
        Some(vec![OwnerReference {
            api_version: format!("{}/{}", crate::crds::GROUP, crate::crds::VERSION),
            kind: "ACPRun".into(),
            name: req.run_key.name.clone(),
            uid: req.run_key.uid.clone(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }])
    }
}

pub fn secret_name(req: &SandboxRequest) -> String {
    format!("{}-att", req.name)
}

pub fn labels(req: &SandboxRequest) -> BTreeMap<String, String> {
    let mut run_name = req.run_key.name.clone();
    run_name.truncate(63);
    BTreeMap::from([
        ("app.kubernetes.io/name".to_string(), "acp-runner-agent".to_string()),
        ("app.kubernetes.io/managed-by".to_string(), "acp-runner".to_string()),
        ("acp-runner.dev/run-id".to_string(), req.run_id.to_string()),
        ("acp-runner.dev/attempt-id".to_string(), req.attempt_id.to_string()),
        (
            "acp-runner.dev/run-name".to_string(),
            run_name.trim_end_matches(|c: char| !c.is_ascii_alphanumeric()).to_string(),
        ),
        ("acp-runner.dev/driver".to_string(), req.class.driver.clone()),
        ("acp-runner.dev/runner-class".to_string(), req.class.name.clone()),
        ("acp-runner.dev/ordinal".to_string(), req.ordinal.to_string()),
        // selects the NetworkPolicy set (deploy/agents/networkpolicy.yaml)
        ("acp-runner.dev/egress".to_string(), req.class.egress.effective_mode().as_str().to_string()),
    ])
}

fn meta(req: &SandboxRequest, cfg: &PodConfig, name: String) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: Some(cfg.namespace_for(req)),
        labels: Some(labels(req)),
        owner_references: cfg.owner_refs(req),
        ..Default::default()
    }
}

/// The per-attempt Secret: attempt token + the leased profile's whitelisted files. Mounted
/// into the runnerd container only.
pub fn build_secret(req: &SandboxRequest, cfg: &PodConfig) -> Secret {
    let mut data = BTreeMap::new();
    data.insert(TOKEN_FILE_NAME.to_string(), ByteString(req.token.as_bytes().to_vec()));
    for (k, v) in &req.credential_files {
        data.insert(secret_file_name(k), ByteString(v.clone()));
    }
    for (name, v) in &req.runner_secret_files {
        data.insert(name.clone(), ByteString(v.clone()));
    }
    Secret {
        metadata: meta(req, cfg, secret_name(req)),
        type_: Some("Opaque".into()),
        immutable: Some(true),
        data: Some(data),
        ..Default::default()
    }
}

fn container_security(uid: i64) -> Value {
    json!({
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "privileged": false,
        "runAsNonRoot": true,
        "runAsUser": uid,
        "runAsGroup": uid,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"}
    })
}

fn env(pairs: &[(&str, String)]) -> Value {
    Value::Array(pairs.iter().map(|(k, v)| json!({"name": k, "value": v})).collect())
}

/// The PodSpec (JSON) shared by the Pod backend and the Agent Sandbox backend.
pub fn pod_spec_json(req: &SandboxRequest, cfg: &PodConfig) -> Value {
    let c = &req.class;
    let t = &req.timeouts;
    let uid = c.run_as_user.unwrap_or(DEFAULT_UID);
    let medium = |m: StorageMedium| if m == StorageMedium::Memory { json!("Memory") } else { Value::Null };
    let mut workspace_dir = json!({"sizeLimit": c.workspace.size_limit});
    if let Value::String(m) = medium(c.workspace.medium) {
        workspace_dir["medium"] = json!(m);
    }
    // runnerd-private: authoritative git directory snapshot + scratch (same size class as
    // the workspace, never mounted into the agent).
    let state_dir = workspace_dir.clone();
    let flag = |b: bool| if b { "true".to_string() } else { "false".to_string() };
    // runnerd-only operator settings. `ACP_RUNNER_ALLOW_FILE_REPOS` is added
    // only on explicit opt-in (V8.3) — and never to the agentd container
    // (see the `no controller identity` assertion in tests).
    let mut runnerd_env: Vec<(&str, String)> = vec![
        ("ACP_RUNNER_INGEST_URL", req.ingest_url.clone()),
        ("ACP_RUNNER_SECRET_DIR", SECRET_MOUNT.into()),
        ("ACP_RUNNER_WORKSPACE", WORKSPACE_DIR.into()),
        ("ACP_RUNNER_HOME", HOME_DIR.into()),
        ("ACP_RUNNER_TMP", "/tmp".into()),
        ("ACP_RUNNER_RUN_DIR", RUN_DIR.into()),
        ("ACP_RUNNER_STATE_DIR", STATE_DIR.into()),
        ("ACP_RUNNER_AGENT_TMP", "/tmp".into()),
        ("ACP_RUNNER_HARNESS_DIR", acp_runner_core::harness::HARNESS_ROOT.into()),
        ("ACP_RUNNER_AGENT_HARNESS", acp_runner_core::harness::HARNESS_ROOT.into()),
        ("ACP_RUNNER_AGENTD", "external".into()),
        ("ACP_RUNNER_CONTROLLER_WATCHDOG", "true".into()),
        ("ACP_RUNNER_STRICT_POSTURE", flag(cfg.strict_posture)),
        ("HOME", "/tmp".into()),
        ("RUNNERD_LOG", "info".into()),
    ];
    if cfg.allow_file_repos {
        runnerd_env.push(("ACP_RUNNER_ALLOW_FILE_REPOS", "true".into()));
    }
    let mut runnerd = json!({
        "name": RUNNERD_CONTAINER,
        "image": c.image,
        "command": cfg.runnerd_command,
        "env": env(&runnerd_env),
        "securityContext": container_security(uid),
        "volumeMounts": [
            {"name": "workspace", "mountPath": WORKSPACE_DIR},
            {"name": "home", "mountPath": HOME_DIR},
            {"name": "run", "mountPath": RUN_DIR},
            {"name": "state", "mountPath": STATE_DIR},
            {"name": "runnerd-tmp", "mountPath": "/tmp"},
            {"name": "harness", "mountPath": acp_runner_core::harness::HARNESS_ROOT},
            {"name": "attempt", "mountPath": SECRET_MOUNT, "readOnly": true}
        ],
        "resources": cfg.runnerd_resources,
        "terminationMessagePolicy": "FallbackToLogsOnError"
    });
    let mut agentd = json!({
        "name": AGENTD_CONTAINER,
        "image": c.image,
        "command": cfg.agentd_command,
        "workingDir": WORKSPACE_DIR,
        "env": env(&[
            ("ACP_AGENTD_SOCKET", format!("{RUN_DIR}/{}", acp_runner_ipc::SOCKET_FILE)),
            ("ACP_AGENTD_CONNECT_TIMEOUT", (t.startup_seconds + 120).to_string()),
            ("HOME", HOME_DIR.into()),
            ("AGENTD_LOG", "info".into()),
        ]),
        "securityContext": container_security(uid),
        "volumeMounts": [
            {"name": "workspace", "mountPath": WORKSPACE_DIR},
            {"name": "home", "mountPath": HOME_DIR},
            {"name": "run", "mountPath": RUN_DIR},
            {"name": "agent-tmp", "mountPath": "/tmp"},
            {"name": "harness", "mountPath": acp_runner_core::harness::HARNESS_ROOT, "readOnly": true}
        ],
        "terminationMessagePolicy": "FallbackToLogsOnError"
    });
    if let Some(p) = &c.image_pull_policy {
        runnerd["imagePullPolicy"] = json!(p);
        agentd["imagePullPolicy"] = json!(p);
    }
    if let Some(r) = &c.resources {
        agentd["resources"] = r.clone();
    }
    let mut spec = json!({
        "restartPolicy": "Never",
        "automountServiceAccountToken": false,
        "serviceAccountName": c.service_account_name.clone().unwrap_or_else(|| cfg.default_service_account.clone()),
        "enableServiceLinks": false,
        "shareProcessNamespace": false,
        "hostNetwork": false,
        "hostPID": false,
        "hostIPC": false,
        "terminationGracePeriodSeconds": t.grace_seconds + 15,
        // V10c: identical to TimeoutPolicy::hard_deadline (credential leases share the bound).
        "activeDeadlineSeconds": t.hard_deadline().as_secs(),
        "securityContext": {
            "runAsNonRoot": true,
            "runAsUser": uid,
            "runAsGroup": uid,
            "fsGroup": uid,
            "seccompProfile": {"type": "RuntimeDefault"}
        },
        "containers": [runnerd, agentd],
        "volumes": [
            {"name": "workspace", "emptyDir": workspace_dir},
            {"name": "home", "emptyDir": {"medium": "Memory", "sizeLimit": c.workspace.home_size_limit}},
            {"name": "run", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}},
            {"name": "state", "emptyDir": state_dir},
            {"name": "runnerd-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": c.workspace.tmp_size_limit}},
            {"name": "agent-tmp", "emptyDir": {"medium": "Memory", "sizeLimit": c.workspace.tmp_size_limit}},
            {"name": "harness", "emptyDir": {"sizeLimit": "4Gi"}},
            {"name": "attempt", "secret": {"secretName": secret_name(req), "defaultMode": 0o440, "optional": false}}
        ]
    });
    if let Some(rc) = &c.runtime_class_name {
        spec["runtimeClassName"] = json!(rc);
    }
    spec
}

pub fn build_pod(req: &SandboxRequest, cfg: &PodConfig) -> Pod {
    Pod {
        metadata: meta(req, cfg, req.name.clone()),
        spec: Some(serde_json::from_value(pod_spec_json(req, cfg)).expect("pod spec json is valid")),
        status: None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use acp_runner_core::spec::*;
    use acp_runner_engine::backend::RunKey;
    use uuid::Uuid;

    pub fn request(runtime_class: Option<&str>) -> SandboxRequest {
        SandboxRequest {
            run_key: RunKey { namespace: "team-a".into(), name: "fix-bug".into(), uid: "uid-1".into() },
            run_id: Uuid::nil(),
            attempt_id: Uuid::nil(),
            ordinal: 1,
            name: "acp-fix-bug-a1-00000000".into(),
            class: RunnerClassSpec {
                name: "codex-default".into(),
                driver: "codex".into(),
                driver_config: json!({}),
                image: "ghcr.io/example/acp-runner-runner:0.1.0".into(),
                image_pull_policy: Some("IfNotPresent".into()),
                runtime_class_name: runtime_class.map(str::to_string),
                resources: Some(json!({"limits": {"memory": "4Gi", "cpu": "2"}})),
                credentials: CredentialRequirement::default(),
                workspace: WorkspacePolicy::default(),
                timeouts: TimeoutPolicy::default(),
                permissions: PermissionPolicy::default(),
                egress: EgressPolicy::default(),
                env: Default::default(),
                allow_run_overrides: false,
                run_as_user: None,
                service_account_name: None,
            },
            ingest_url: "http://acp-runner-ingest.acp-runner-system.svc:8081".into(),
            token: "t".repeat(64),
            credential_files: BTreeMap::from([("auth.json".to_string(), b"{\"secret\":1}".to_vec())]),
            runner_secret_files: Default::default(),
            timeouts: TimeoutPolicy::default(),
        }
    }

    fn container<'a>(spec: &'a Value, name: &str) -> &'a Value {
        spec["containers"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap()
    }

    fn mount_names(c: &Value) -> Vec<String> {
        c["volumeMounts"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn pod_is_hardened() {
        let req = request(None);
        let pod = build_pod(&req, &PodConfig::default());
        let v = serde_json::to_value(&pod).unwrap();
        let spec = &v["spec"];
        assert_eq!(spec["automountServiceAccountToken"], false);
        assert_eq!(spec["enableServiceLinks"], false);
        assert_eq!(spec["shareProcessNamespace"], false);
        assert_eq!(spec["restartPolicy"], "Never");
        assert_eq!(spec["securityContext"]["runAsNonRoot"], true);
        assert!(spec.get("runtimeClassName").is_none());
        assert_eq!(spec["containers"].as_array().unwrap().len(), 2);
        for c in spec["containers"].as_array().unwrap() {
            assert_eq!(c["securityContext"]["allowPrivilegeEscalation"], false, "{}", c["name"]);
            assert_eq!(c["securityContext"]["readOnlyRootFilesystem"], true);
            assert_eq!(c["securityContext"]["runAsNonRoot"], true);
            assert_eq!(c["securityContext"]["capabilities"]["drop"][0], "ALL");
        }
        // V10c: the pod deadline and the credential lease share one bound.
        assert_eq!(
            spec["activeDeadlineSeconds"].as_u64().unwrap(),
            req.timeouts.hard_deadline().as_secs(),
            "pod deadline diverged from the shared lease bound"
        );
        // no host paths, no PVCs, no projected SA tokens
        for vol in spec["volumes"].as_array().unwrap() {
            let keys: Vec<_> = vol.as_object().unwrap().keys().filter(|k| *k != "name").cloned().collect();
            assert!(keys == vec!["emptyDir"] || keys == vec!["secret"], "unexpected volume {vol}");
        }
        assert_eq!(spec["volumes"][0]["emptyDir"]["medium"], "Memory");
        // secret values never appear in the pod spec / env
        let text = v.to_string();
        assert!(!text.contains(&"t".repeat(64)));
        assert!(!text.contains("\"secret\":1"));
        // owner reference for GC when agent namespace == run namespace
        assert_eq!(v["metadata"]["ownerReferences"][0]["kind"], "ACPRun");
    }

    #[test]
    fn secret_and_private_state_are_mounted_into_runnerd_only() {
        let v = serde_json::to_value(build_pod(&request(None), &PodConfig::default())).unwrap();
        let spec = &v["spec"];
        let runnerd = container(spec, RUNNERD_CONTAINER);
        let agentd = container(spec, AGENTD_CONTAINER);
        // runnerd: the Secret read-only at the attempt mount
        let secret_mounts: Vec<_> =
            runnerd["volumeMounts"].as_array().unwrap().iter().filter(|m| m["name"] == "attempt").collect();
        assert_eq!(secret_mounts.len(), 1);
        assert_eq!(secret_mounts[0]["readOnly"], true);
        assert_eq!(secret_mounts[0]["mountPath"], SECRET_MOUNT);
        // agentd: only the shared volumes + its own tmp (+ the harness root, read-only)
        assert_eq!(mount_names(agentd), vec!["workspace", "home", "run", "agent-tmp", "harness"]);
        let harness = agentd["volumeMounts"].as_array().unwrap().iter().find(|m| m["name"] == "harness").unwrap();
        assert_eq!(harness["readOnly"], true);
        assert_eq!(harness["mountPath"], "/opt/harness");
        for m in agentd["volumeMounts"].as_array().unwrap() {
            let path = m["mountPath"].as_str().unwrap();
            assert!(!path.starts_with("/var/run/acp-runner") && !path.starts_with(STATE_DIR), "{path}");
        }
        // shared volumes are exactly the documented three + the (agent read-only) harness root
        let shared: Vec<_> = mount_names(runnerd).into_iter().filter(|n| mount_names(agentd).contains(n)).collect();
        assert_eq!(shared, vec!["workspace", "home", "run", "harness"]);
        // agentd gets no controller identity through its environment
        let env = agentd["env"].to_string();
        assert!(!env.contains("ACP_RUNNER_"), "{env}");
        assert!(!env.contains("ingest"), "{env}");
        assert!(runnerd["env"].to_string().contains("ACP_RUNNER_INGEST_URL"));
        assert!(runnerd["env"].to_string().contains("\"external\""));
        // class resources apply to the agent container
        assert_eq!(agentd["resources"]["limits"]["memory"], "4Gi");
        assert_eq!(runnerd["resources"]["limits"]["memory"], "1Gi");
    }

    fn runnerd_env(cfg: &PodConfig) -> String {
        let v = serde_json::to_value(build_pod(&request(None), cfg)).unwrap();
        let spec = &v["spec"];
        let runnerd = container(spec, RUNNERD_CONTAINER);
        let agentd = container(spec, AGENTD_CONTAINER);
        let agent_env = agentd["env"].to_string();
        assert!(!agent_env.contains("ACP_RUNNER_ALLOW_FILE_REPOS"), "{agent_env}");
        runnerd["env"].to_string()
    }

    #[test]
    fn file_repos_opt_in_reaches_runnerd_only() {
        // V8.3 deny path: default PodConfig adds no flag — runnerd pods deny
        // file:// URLs unless the operator opts in.
        assert!(!runnerd_env(&PodConfig::default()).contains("ACP_RUNNER_ALLOW_FILE_REPOS"));
        // V8.3 allow path: operator opt-in propagates the trusted flag into
        // the runnerd container env (never agentd — asserted in runnerd_env).
        let cfg = PodConfig { allow_file_repos: true, ..Default::default() };
        let env = runnerd_env(&cfg);
        assert!(env.contains("\"name\":\"ACP_RUNNER_ALLOW_FILE_REPOS\",\"value\":\"true\""), "{env}");
    }

    #[test]
    fn egress_mode_selects_the_network_policy_label() {
        let mut req = request(None);
        assert_eq!(labels(&req)["acp-runner.dev/egress"], "direct");
        req.class.egress.https_proxy = Some("http://acp-egress-proxy.acp-egress.svc:3128".into());
        assert_eq!(labels(&req)["acp-runner.dev/egress"], "proxy");
        let pod = serde_json::to_value(build_pod(&req, &PodConfig::default())).unwrap();
        assert_eq!(pod["metadata"]["labels"]["acp-runner.dev/egress"], "proxy");
    }

    #[test]
    fn gvisor_is_opt_in() {
        let pod = build_pod(&request(Some("gvisor")), &PodConfig::default());
        assert_eq!(pod.spec.unwrap().runtime_class_name.as_deref(), Some("gvisor"));
    }

    #[test]
    fn secret_holds_only_token_and_whitelisted_files() {
        let s = build_secret(&request(None), &PodConfig::default());
        let keys: Vec<_> = s.data.unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["cred.auth.json".to_string(), "token".to_string()]);
        assert_eq!(s.immutable, Some(true));
    }

    #[test]
    fn cross_namespace_sandboxes_have_no_owner_refs() {
        let cfg = PodConfig { agent_namespace: Some("acp-agents".into()), ..Default::default() };
        let pod = build_pod(&request(None), &cfg);
        assert!(pod.metadata.owner_references.is_none());
        assert_eq!(pod.metadata.namespace.as_deref(), Some("acp-agents"));
    }
}
