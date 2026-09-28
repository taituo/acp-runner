//! Kubernetes end-to-end test against a real kube-apiserver (envtest or any cluster
//! without letting a real kubelet run the pods).
//!
//! A *simulated kubelet* in this test executes each attempt pod's container as a local
//! runnerd process (secret volume materialized to a temp dir, pod status patched), so the
//! whole chain — CRDs, controller, finalizer, PodBackend, per-attempt Secrets, ingest,
//! runnerd, fake agent, journal, status — is exercised without Docker.
//!
//! Opt-in: requires `ACP_E2E_KUBECONFIG` (e.g. from `scripts/envtest-up.sh`) and
//! `ACP_TEST_DATABASE_URL`. Optionally `ACP_E2E_AGENT_SANDBOX_CRDS` (path to the upstream
//! agent-sandbox release manifest) to validate `Sandbox` objects against the real schema.

use acp_runner_core::credentials::{CredentialBundle, Provider, validate_bundle};
use acp_runner_engine::backend::{RunKey, SandboxBackend, SandboxObservation, SandboxRequest};
use acp_runner_engine::creds::{CredentialStore, StoredProfile};
use acp_runner_journal::Journal;
use acp_runner_k8s::backends::AgentSandboxBackend;
use acp_runner_k8s::crds::{ACPRun, ACPRunnerClass, AgentEnvironment};
use acp_runner_k8s::pod::PodConfig;
use acp_runner_k8s::secret_store::K8sSecretStore;
use k8s_openapi::api::core::v1::{Namespace, Pod, Secret, ServiceAccount};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config, ResourceExt};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

fn build_bins() {
    let st = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent", "-p", "acp-runner-controller"])
        .status()
        .unwrap();
    assert!(st.success());
}

async fn client_from(path: &str, impersonate: Option<&str>) -> Client {
    let kc = Kubeconfig::read_from(path).unwrap();
    let mut cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default()).await.unwrap();
    cfg.proxy_url = None; // local apiserver; ignore HTTPS_PROXY of the test environment
    if let Some(user) = impersonate {
        cfg.auth_info.impersonate = Some(user.to_string());
    }
    Client::try_from(cfg).unwrap()
}

/// (pod, container, environment) of every container the simulated kubelet started.
type Launched = Arc<Mutex<Vec<(String, String, HashMap<String, String>)>>>;

/// One launched container of a simulated pod.
struct SimContainer {
    name: String,
    child: Child,
    exit: Option<i32>,
    /// Container stdout/stderr capture (for failure diagnostics only).
    log_path: std::path::PathBuf,
}

/// Print the tail of a failed container's log to test stderr. Only the
/// container's own stdout/stderr capture — never secret volume files.
fn dump_failed_container_log(pod: &str, c: &SimContainer) {
    let Ok(text) = std::fs::read_to_string(&c.log_path) else { return };
    let lines: Vec<&str> = text.lines().collect();
    let tail = &lines[lines.len().saturating_sub(30)..];
    eprintln!("--- simulated container {}/{} exited {}: last {} log lines ---", pod, c.name, c.exit.unwrap_or(-1), tail.len());
    for l in tail {
        eprintln!("[{}/{}] {}", pod, c.name, l.chars().take(500).collect::<String>());
    }
    eprintln!("--- end {}/{} log ---", pod, c.name);
}

/// Minimal kubelet stand-in: runs every container of each pod as a local process according to
/// the pod spec (volumes materialized as directories, the Secret volume written to disk,
/// container paths in env/command translated to the host directories of *that container's*
/// volume mounts) and reports container/pod status like the kubelet.
struct FakeKubelet {
    pods: Arc<Mutex<HashMap<String, Vec<SimContainer>>>>,
    seen_specs: Arc<Mutex<Vec<serde_json::Value>>>,
    launched: Launched,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

fn kill_container(c: &mut SimContainer, sig: nix::sys::signal::Signal) {
    let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(c.child.id() as i32), sig);
}

/// Translate a container path through the container's volume mounts.
fn host_path(mounts: &[(String, PathBuf)], value: &str) -> Option<String> {
    mounts
        .iter()
        .filter(|(mp, _)| value == mp || value.starts_with(&format!("{mp}/")))
        .max_by_key(|(mp, _)| mp.len())
        .map(|(mp, host)| format!("{}{}", host.display(), &value[mp.len()..]))
}

fn container_mounts(
    c: &k8s_openapi::api::core::v1::Container,
    vols: &HashMap<String, PathBuf>,
) -> Vec<(String, PathBuf)> {
    c.volume_mounts.clone().unwrap_or_default().iter().map(|m| (m.mount_path.clone(), vols[&m.name].clone())).collect()
}

impl FakeKubelet {
    fn start(client: Client, ns: String, work: PathBuf) -> FakeKubelet {
        let pods_state: Arc<Mutex<HashMap<String, Vec<SimContainer>>>> = Arc::default();
        let seen_specs: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
        let launched: Launched = Arc::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (p2, s2, l2, stop2) = (pods_state.clone(), seen_specs.clone(), launched.clone(), stop.clone());
        tokio::spawn(async move {
            let pods: Api<Pod> = Api::namespaced(client.clone(), &ns);
            let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
            let bin_dir = target_dir();
            let mut started: HashSet<String> = HashSet::new();
            let mut reported: HashMap<String, String> = HashMap::new();
            while !stop2.load(std::sync::atomic::Ordering::SeqCst) {
                let list =
                    match pods.list(&ListParams::default().labels("app.kubernetes.io/managed-by=acp-runner")).await {
                        Ok(l) => l.items,
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            continue;
                        }
                    };
                let names: HashSet<String> = list.iter().map(|p| p.name_any()).collect();
                // pods deleted -> kill their containers (like the kubelet would)
                let gone: Vec<String> = p2.lock().unwrap().keys().filter(|n| !names.contains(*n)).cloned().collect();
                for n in gone {
                    if let Some(mut cs) = p2.lock().unwrap().remove(&n) {
                        for c in cs.iter_mut() {
                            kill_container(c, nix::sys::signal::Signal::SIGCONT);
                            kill_container(c, nix::sys::signal::Signal::SIGTERM);
                        }
                        std::thread::sleep(Duration::from_millis(300));
                        for c in cs.iter_mut() {
                            kill_container(c, nix::sys::signal::Signal::SIGKILL);
                            let _ = c.child.wait();
                        }
                    }
                }
                for pod in &list {
                    let name = pod.name_any();
                    if started.contains(&name) || pod.metadata.deletion_timestamp.is_some() {
                        continue;
                    }
                    started.insert(name.clone());
                    s2.lock().unwrap().push(serde_json::to_value(pod).unwrap());
                    let spec = pod.spec.clone().unwrap();
                    let dir = work.join(&name);
                    // volumes
                    let mut vols: HashMap<String, PathBuf> = HashMap::new();
                    for v in spec.volumes.clone().unwrap_or_default() {
                        let d = dir.join("volumes").join(&v.name);
                        std::fs::create_dir_all(&d).unwrap();
                        if let Some(sv) = &v.secret {
                            let secret = secrets.get(sv.secret_name.as_deref().unwrap()).await.unwrap();
                            for (k, val) in secret.data.unwrap_or_default() {
                                std::fs::write(d.join(k), val.0).unwrap();
                            }
                        }
                        vols.insert(v.name.clone(), d);
                    }
                    let agentd_mounts = spec
                        .containers
                        .iter()
                        .find(|c| c.name == "agentd")
                        .map(|c| container_mounts(c, &vols))
                        .unwrap_or_default();
                    let mut containers = vec![];
                    for c in &spec.containers {
                        let mounts = container_mounts(c, &vols);
                        let mut env: HashMap<String, String> = HashMap::new();
                        for e in c.env.clone().unwrap_or_default() {
                            let Some(v) = e.value else { continue };
                            // runnerd describes the agent's view: translate with agentd's mounts
                            let m = if e.name.starts_with("ACP_RUNNER_AGENT_") { &agentd_mounts } else { &mounts };
                            env.insert(e.name, host_path(m, &v).unwrap_or(v));
                        }
                        // command: drop tini, map /usr/local/bin/<x> to the build output
                        let cmd: Vec<String> = c.command.clone().unwrap_or_default();
                        let cmd: Vec<String> = match cmd.first().map(String::as_str) {
                            Some("/usr/bin/tini") => cmd[2..].to_vec(),
                            _ => cmd,
                        };
                        let program = bin_dir.join(cmd[0].rsplit('/').next().unwrap());
                        let cwd = c
                            .working_dir
                            .as_deref()
                            .and_then(|w| host_path(&mounts, w))
                            .map(PathBuf::from)
                            .unwrap_or_else(|| dir.clone());
                        use std::os::unix::process::CommandExt;
                        let log = std::fs::File::create(dir.join(format!("{}.log", c.name))).unwrap();
                        let child = std::process::Command::new(&program)
                            .args(&cmd[1..])
                            .env_clear()
                            .env("PATH", std::env::var("PATH").unwrap_or_default())
                            .envs(&env)
                            .current_dir(&cwd)
                            .stdout(log.try_clone().unwrap())
                            .stderr(log)
                            .process_group(0)
                            .spawn()
                            .unwrap();
                        l2.lock().unwrap().push((name.clone(), c.name.clone(), env));
                        let log_path = dir.join(format!("{}.log", c.name));
                        containers.push(SimContainer { name: c.name.clone(), child, exit: None, log_path });
                    }
                    p2.lock().unwrap().insert(name.clone(), containers);
                }
                // report container / pod status
                let mut updates = vec![];
                for (n, cs) in p2.lock().unwrap().iter_mut() {
                    for c in cs.iter_mut() {
                        if c.exit.is_none()
                            && let Ok(Some(st)) = c.child.try_wait()
                        {
                            c.exit = Some(st.code().unwrap_or(137));
                            if c.exit != Some(0) {
                                dump_failed_container_log(n, c);
                            }
                        }
                    }
                    let statuses: Vec<serde_json::Value> = cs
                        .iter()
                        .map(|c| match c.exit {
                            None => json!({"name": c.name, "ready": true, "restartCount": 0, "image": "x", "imageID": "",
                                           "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}),
                            Some(code) => json!({"name": c.name, "ready": false, "restartCount": 0, "image": "x", "imageID": "",
                                           "state": {"terminated": {"exitCode": code, "reason": if code == 0 {"Completed"} else {"Error"},
                                                     "startedAt": "2026-01-01T00:00:00Z", "finishedAt": "2026-01-01T00:00:01Z"}}}),
                        })
                        .collect();
                    let phase = if cs.iter().any(|c| c.exit.is_none()) {
                        "Running"
                    } else if cs.iter().all(|c| c.exit == Some(0)) {
                        "Succeeded"
                    } else {
                        "Failed"
                    };
                    let body = json!({"status": {"phase": phase, "containerStatuses": statuses}});
                    if reported.get(n) != Some(&body.to_string()) {
                        reported.insert(n.clone(), body.to_string());
                        updates.push((n.clone(), body));
                    }
                }
                for (n, body) in updates {
                    let _ = pods.patch_status(&n, &PatchParams::default(), &Patch::Merge(body)).await;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
        FakeKubelet { pods: pods_state, seen_specs, launched, stop }
    }
}

impl Drop for FakeKubelet {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for (_, mut cs) in self.pods.lock().unwrap().drain() {
            for c in cs.iter_mut() {
                kill_container(c, nix::sys::signal::Signal::SIGCONT);
                kill_container(c, nix::sys::signal::Signal::SIGKILL);
                let _ = c.child.wait();
            }
        }
    }
}

async fn apply_yaml_crds(client: &Client, yaml: &str) {
    use serde::Deserialize;
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for doc in serde_yaml::Deserializer::from_str(yaml) {
        let v = serde_yaml::Value::deserialize(doc).unwrap();
        if v.is_null() || v.get("kind").and_then(|k| k.as_str()) != Some("CustomResourceDefinition") {
            continue;
        }
        let crd: CustomResourceDefinition = serde_yaml::from_value(v).unwrap();
        let name = crd.name_any();
        crds.patch(&name, &PatchParams::apply("acp-e2e").force(), &Patch::Apply(&crd)).await.unwrap();
        for _ in 0..100 {
            let c = crds.get(&name).await.unwrap();
            let established = c
                .status
                .and_then(|s| s.conditions)
                .map(|cs| cs.iter().any(|c| c.type_ == "Established" && c.status == "True"))
                .unwrap_or(false);
            if established {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn wait_run(api: &Api<ACPRun>, name: &str, want: &[&str], limit: Duration) -> ACPRun {
    let start = Instant::now();
    loop {
        let r = api.get(name).await.unwrap();
        let phase = r.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
        if want.contains(&phase.as_str()) {
            return r;
        }
        assert!(start.elapsed() < limit, "run {name} stuck in {phase:?}: {:?}", r.status);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn class(name: &str, fake: &Path, scenario: &str, extra: serde_json::Value) -> ACPRunnerClass {
    let mut spec = json!({
        "driver": "fake",
        "driverConfig": {"command": fake.to_string_lossy(), "scenario": scenario},
        "image": "acp-runner/runner:dev@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "timeouts": {"hardSeconds": 120, "noProgressSeconds": 30, "graceSeconds": 2, "heartbeatSeconds": 1, "startupSeconds": 60},
        "env": [{"name": "FAKE_ACP_SCENARIO", "value": scenario}]
    });
    if let (Some(s), Some(e)) = (spec.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            s.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(json!({"apiVersion": "acp-runner.dev/v1alpha1", "kind": "ACPRunnerClass",
        "metadata": {"name": name}, "spec": spec}))
    .unwrap()
}

fn run(name: &str, class: &str, fallbacks: &[&str], repo: &str, rev: &str, retries: u32) -> ACPRun {
    serde_json::from_value(json!({
        "apiVersion": "acp-runner.dev/v1alpha1", "kind": "ACPRun", "metadata": {"name": name},
        "spec": {"taskId": format!("task-{name}"), "runnerClassName": class, "fallbackRunnerClassNames": fallbacks,
                 "repository": {"url": repo, "revision": rev}, "prompt": {"text": "Fix add.sh so that test.sh passes."},
                 "retry": {"maxAttemptsPerRunner": retries}}
    }))
    .unwrap()
}

fn fixture_repo(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n").unwrap();
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "buggy"]);
    git(&["rev-parse", "HEAD"])
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn controller_end_to_end_on_a_real_apiserver() {
    let Ok(kubeconfig) = std::env::var("ACP_E2E_KUBECONFIG") else {
        if std::env::var("ACP_REQUIRE_DB_TESTS").as_deref() == Ok("1") {
            panic!("ACP_E2E_KUBECONFIG is required when ACP_REQUIRE_DB_TESTS=1 (refusing to SKIP)");
        }
        eprintln!("SKIPPED: set ACP_E2E_KUBECONFIG (scripts/envtest-up.sh) and ACP_TEST_DATABASE_URL");
        return;
    };
    let Some(db) = acp_runner_journal::testing::temp_database().await else { return };
    build_bins();
    let client = client_from(&kubeconfig, None).await;
    apply_yaml_crds(&client, &acp_runner_k8s::crds_yaml()).await;
    let ns = format!("acp-e2e-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let nss: Api<Namespace> = Api::all(client.clone());
    nss.create(&PostParams::default(), &serde_json::from_value(json!({"metadata": {"name": ns}})).unwrap())
        .await
        .unwrap();
    let sas: Api<ServiceAccount> = Api::namespaced(client.clone(), &ns);
    sas.create(
        &PostParams::default(),
        &serde_json::from_value(
            json!({"metadata": {"name": "acp-runner-agent"}, "automountServiceAccountToken": false}),
        )
        .unwrap(),
    )
    .await
    .unwrap();

    // v3 AgentEnvironment examples pass the apiserver's structural schema and convert to
    // valid provider specs (source/overlays/workdir/bootstrap/lifetime/output).
    let envs: Api<AgentEnvironment> = Api::namespaced(client.clone(), &ns);
    for f in ["agentenvironment-codex.yaml", "agentenvironment-review.yaml"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/examples").join(f);
        let mut ae: AgentEnvironment = serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        ae.metadata.namespace = Some(ns.clone());
        let created = envs.create(&PostParams::default(), &ae).await.unwrap_or_else(|e| panic!("{f}: {e}"));
        created.spec.to_core().unwrap_or_else(|e| panic!("{f}: {e}"));
        assert_eq!(
            created.spec.workspace.as_ref().and_then(|w| w.workdir.clone()),
            ae.spec.workspace.and_then(|w| w.workdir)
        );
    }
    // a malformed overlay type is rejected by the schema itself
    let bad: AgentEnvironment = serde_json::from_value(json!({
        "apiVersion": "acp-runner.dev/v1alpha1", "kind": "AgentEnvironment",
        "metadata": {"name": "bad", "namespace": ns},
        "spec": {"externalRef": "x", "harness": {"name": "fake"}}
    }))
    .unwrap();
    let mut bad_json = serde_json::to_value(&bad).unwrap();
    bad_json["spec"]["workspace"] = json!({"overlays": [{"type": "tarball", "artifactId": "x"}]});
    let dynapi: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), &ns, &kube::discovery::ApiResource::erase::<AgentEnvironment>(&()));
    assert!(
        dynapi.create(&PostParams::default(), &serde_json::from_value(bad_json).unwrap()).await.is_err(),
        "schema accepted an unknown overlay type"
    );

    let tmp = tempfile::tempdir().unwrap();
    let sha = fixture_repo(&tmp.path().join("upstream"));
    let repo = format!("file://{}", tmp.path().join("upstream").display());
    let fake = target_dir().join("fake-acp-agent");
    let _kubelet = FakeKubelet::start(client.clone(), ns.clone(), tmp.path().join("nodes"));

    // controller process
    let (ingest_port, metrics_port) = (free_port(), free_port());
    let log = std::fs::File::create(tmp.path().join("controller.log")).unwrap();
    let mut controller = std::process::Command::new(target_dir().join("acp-runner-controller"))
        .arg("run")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env("KUBECONFIG", &kubeconfig)
        .env("DATABASE_URL", &db.url)
        .env("POD_NAME", "controller-e2e")
        .env("ACP_RUNNER_INGEST_URL", format!("http://127.0.0.1:{ingest_port}"))
        .env("ACP_RUNNER_INGEST_LISTEN", format!("127.0.0.1:{ingest_port}"))
        .env("ACP_RUNNER_METRICS_LISTEN", format!("127.0.0.1:{metrics_port}"))
        .env("ACP_RUNNER_WATCH_NAMESPACE", &ns)
        .env("ACP_RUNNER_CREDENTIAL_NAMESPACE", &ns)
        // V1a: no live provider is reachable here, so verifying write-back is
        // off: the controller must fail closed (store untouched) while the run
        // still succeeds. Successful verification through the Secret store is
        // covered by engine e2e with a scripted refresher; pointing this
        // binary at a fake endpoint would require weakening the production
        // endpoint pin, which the hardening reviews forbid.
        .env("ACP_RUNNER_CODEX_REFRESH", "false")
        .env(
            "ACP_RUNNER_ALLOWED_IMAGES",
            "acp-runner/runner:dev@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .env("ACP_RUNNER_STRICT_POSTURE", "false")
        .env("RUST_LOG", "info")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();

    let classes: Api<ACPRunnerClass> = Api::namespaced(client.clone(), &ns);
    let runs: Api<ACPRun> = Api::namespaced(client.clone(), &ns);
    let pods: Api<Pod> = Api::namespaced(client.clone(), &ns);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    let pp = PostParams::default();
    classes.create(&pp, &class("fake-fix", &fake, "fix", json!({}))).await.unwrap();
    classes.create(&pp, &class("fake-crash", &fake, "crash", json!({}))).await.unwrap();
    classes.create(&pp, &class("fake-hang", &fake, "hang", json!({}))).await.unwrap();

    // 1. success
    runs.create(&pp, &run("ok", "fake-fix", &[], &repo, &sha, 1)).await.unwrap();
    let r = wait_run(&runs, "ok", &["Succeeded", "Failed"], Duration::from_secs(120)).await;
    let st = r.status.clone().unwrap();
    assert_eq!(
        st.phase.as_deref(),
        Some("Succeeded"),
        "{st:?}\n{}",
        std::fs::read_to_string(tmp.path().join("controller.log")).unwrap_or_default()
    );
    assert_eq!(st.current_attempt, Some(1));
    assert_eq!(st.sandbox_ref.as_ref().unwrap().kind, "Pod");
    let art = st.artifact_ref.clone().expect("artifactRef");
    assert_eq!(art.base_revision, sha);
    assert!(st.run_id.is_some());
    assert!(r.finalizers().iter().any(|f| f == acp_runner_k8s::crds::FINALIZER));
    // pod + attempt secret were cleaned up
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(pods.list(&ListParams::default()).await.unwrap().items.is_empty());
    assert!(
        secrets
            .list(&ListParams::default().labels("app.kubernetes.io/name=acp-runner-agent"))
            .await
            .unwrap()
            .items
            .is_empty()
    );
    // hardened two-container pod spec as submitted to the API server
    let spec = _kubelet.seen_specs.lock().unwrap()[0].clone();
    assert_eq!(spec["spec"]["automountServiceAccountToken"], false);
    assert_eq!(spec["spec"]["shareProcessNamespace"], false);
    let names: Vec<_> = spec["spec"]["containers"].as_array().unwrap().iter().map(|c| c["name"].clone()).collect();
    assert_eq!(names, vec![json!("runnerd"), json!("agentd")]);
    for c in spec["spec"]["containers"].as_array().unwrap() {
        assert_eq!(c["securityContext"]["readOnlyRootFilesystem"], true);
    }
    let agentd = &spec["spec"]["containers"][1];
    assert!(
        !agentd["volumeMounts"].as_array().unwrap().iter().any(|m| m["name"] == "attempt"),
        "the attempt Secret must not be mounted into agentd"
    );
    assert_eq!(spec["metadata"]["ownerReferences"][0]["kind"], "ACPRun");
    // the agentd process got no controller identity (env as launched by the kubelet)
    for (_, container, env) in _kubelet.launched.lock().unwrap().iter() {
        if container == "agentd" {
            assert!(env.keys().all(|k| !k.starts_with("ACP_RUNNER_")), "{env:?}");
            assert!(!env.values().any(|v| v.contains("/volumes/attempt")), "{env:?}");
        }
    }
    // V8.3: the operator file-repos opt-in propagates into the runnerd
    // container — both in the submitted pod spec and in the launched process
    // env. runnerd validates the file:// fixture repo a second time in
    // workspace preparation, so without this the run fails there even when
    // the controller's own validation passed.
    let runnerd_spec = &spec["spec"]["containers"][0];
    assert_eq!(runnerd_spec["name"], "runnerd");
    assert!(
        runnerd_spec["env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["name"] == "ACP_RUNNER_ALLOW_FILE_REPOS" && e["value"] == "true"),
        "runnerd pod spec lacks the file-repos opt-in: {}",
        runnerd_spec["env"]
    );
    let mut saw_runnerd = false;
    for (_, container, env) in _kubelet.launched.lock().unwrap().iter() {
        if container == "runnerd" {
            saw_runnerd = true;
            assert_eq!(env.get("ACP_RUNNER_ALLOW_FILE_REPOS").map(String::as_str), Some("true"), "{env:?}");
        }
    }
    assert!(saw_runnerd, "runnerd was never launched");
    // journal
    let journal = Journal::connect(&db.url, 2).await.unwrap();
    let run_id = uuid::Uuid::parse_str(st.run_id.as_ref().unwrap()).unwrap();
    let kinds: Vec<String> =
        journal.events_for_run(run_id, 0, 10_000).await.unwrap().into_iter().map(|e| e.kind).collect();
    for k in [
        "RunCreated",
        "AttemptStarted",
        "AgentStarted",
        "SessionStarted",
        "AgentOutput",
        "ArtifactCreated",
        "AttemptCompleted",
        "RunCompleted",
    ] {
        assert!(kinds.iter().any(|x| x == k), "missing {k}");
    }

    // 2. retry + fallback
    runs.create(&pp, &run("fallback", "fake-crash", &["fake-fix"], &repo, &sha, 2)).await.unwrap();
    let r = wait_run(&runs, "fallback", &["Succeeded", "Failed"], Duration::from_secs(180)).await;
    let st = r.status.unwrap();
    assert_eq!(st.phase.as_deref(), Some("Succeeded"), "{st:?}");
    assert_eq!(st.current_attempt, Some(3));
    assert_eq!(st.runner_class.as_deref(), Some("fake-fix"));

    // 3. credential lease + validated write-back through the Secret-backed store
    let store = K8sSecretStore { client: client.clone(), namespace: ns.clone() };
    let mut bundle = CredentialBundle::new();
    let b64 = |v: serde_json::Value| base64_url(&v.to_string());
    let jwt = |c: serde_json::Value| format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(c), b64(json!("sig")));
    bundle.insert(
        "auth.json".into(),
        json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{"id_token": jwt(json!({"https://api.openai.com/auth":{"chatgpt_account_id":"acct-9"}})),
            "access_token": jwt(json!({"exp":1900000000})),"refresh_token":"rt_e2e_refresh_token_value_000000000","account_id":"acct-9"}})
        .to_string()
        .into_bytes(),
    );
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    store
        .save(
            &StoredProfile {
                name: "codex-e2e".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 1,
                metadata: md,
                // V2: the test namespace/class are explicitly granted.
                allowed_namespaces: vec![ns.clone()],
                allowed_classes: vec!["fake-codexish".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    classes
        .create(
            &pp,
            &class(
                "fake-codexish",
                &fake,
                "refresh-credential",
                json!({"credentials": {"provider": "codex", "profiles": ["codex-e2e"]},
                       "egress": {"mode": "proxy", "httpsProxy": "http://acp-egress-proxy.acp-egress.svc:3128"}}),
            ),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(16)).await; // profile sync loop (15s)
    runs.create(&pp, &run("creds", "fake-codexish", &[], &repo, &sha, 1)).await.unwrap();
    let r = wait_run(&runs, "creds", &["Succeeded", "Failed"], Duration::from_secs(120)).await;
    let st = r.status.unwrap();
    assert_eq!(st.phase.as_deref(), Some("Succeeded"), "{st:?}");
    assert_eq!(st.credential_profile.as_deref(), Some("codex-e2e"));
    // V1a fail-closed: the agent-submitted refresh was rejected (no verifier),
    // so the Secret store still holds exactly the enrolled bytes — no agent
    // byte reached the credential store.
    let (_, b) = store.load("codex-e2e").await.unwrap();
    let stored = String::from_utf8_lossy(&b["auth.json"]);
    assert!(!stored.contains("\"refreshed\""), "agent bytes reached the store: {stored}");
    assert!(stored.contains("rt_e2e_refresh_token_value_000000000"), "{stored}");

    // 4. deletion -> finalizer cancels, terminates the sandbox, releases the lease
    runs.create(&pp, &run("doomed", "fake-hang", &[], &repo, &sha, 1)).await.unwrap();
    let start = Instant::now();
    loop {
        let r = runs.get("doomed").await.unwrap();
        if r.status.as_ref().and_then(|s| s.attempt_phase.as_deref()) == Some("Running") {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "{:?}", r.status);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    runs.delete("doomed", &DeleteParams::default()).await.unwrap();
    let start = Instant::now();
    while runs.get_opt("doomed").await.unwrap().is_some() {
        assert!(start.elapsed() < Duration::from_secs(60), "finalizer did not complete");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let doomed = journal.find_runs("doomed", Some(&ns)).await.unwrap();
    assert_eq!(doomed[0].phase, "Cancelled");
    assert!(pods.list(&ListParams::default()).await.unwrap().items.is_empty());

    // 5. the agent service account cannot read Secrets (RBAC)
    let agent = client_from(&kubeconfig, Some(&format!("system:serviceaccount:{ns}:acp-runner-agent"))).await;
    let err = Api::<Secret>::namespaced(agent, &ns).list(&ListParams::default()).await.unwrap_err();
    assert!(matches!(err, kube::Error::Api(ref s) if s.code == 403), "{err:?}");

    // 5b. a credentialed runner class with egress.mode: direct is rejected (no proxy).
    classes
        .create(
            &pp,
            &class(
                "fake-cred-direct",
                &fake,
                "fix",
                json!({"credentials": {"provider": "codex", "profiles": ["codex-e2e"]}, "egress": {"mode": "direct"}}),
            ),
        )
        .await
        .unwrap();
    runs.create(&pp, &run("cred-direct", "fake-cred-direct", &[], &repo, &sha, 1)).await.unwrap();
    let r = wait_run(&runs, "cred-direct", &["Succeeded", "Failed"], Duration::from_secs(60)).await;
    let st = r.status.unwrap();
    assert_eq!(st.phase.as_deref(), Some("Failed"), "{st:?}");
    let fr = st.failure_reason.expect("failureReason");
    assert!(fr.message.contains("egress"), "expected an egress-policy failure, got {fr:?}");

    // 6. Agent Sandbox backend objects validate against the upstream v1beta1 CRD
    if let Ok(path) = std::env::var("ACP_E2E_AGENT_SANDBOX_CRDS") {
        apply_yaml_crds(&client, &std::fs::read_to_string(path).unwrap()).await;
        let backend = AgentSandboxBackend {
            client: client.clone(),
            cfg: PodConfig { strict_posture: false, ..Default::default() },
        };
        let spec: ACPRunnerClass = class("x", &fake, "fix", json!({"runtimeClassName": "gvisor"}));
        let req = SandboxRequest {
            run_key: RunKey { namespace: ns.clone(), name: "sb".into(), uid: uuid::Uuid::new_v4().to_string() },
            run_id: uuid::Uuid::new_v4(),
            attempt_id: uuid::Uuid::new_v4(),
            ordinal: 1,
            name: "acp-sb-a1-test".into(),
            class: spec.spec.to_core("x"),
            ingest_url: "http://ingest".into(),
            token: "t".repeat(64),
            credential_files: Default::default(),
            runner_secret_files: Default::default(),
            timeouts: Default::default(),
        };
        let sref = backend.create(&req).await.expect("Sandbox accepted by the v1beta1 schema");
        let obs = backend.observe(&sref).await.unwrap();
        assert!(matches!(obs, SandboxObservation::Pending { .. }), "{obs:?}");
        let sandboxes: Api<DynamicObject> =
            Api::namespaced_with(client.clone(), &ns, &acp_runner_k8s::backends::sandbox_api_resource());
        let obj = sandboxes.get("acp-sb-a1-test").await.unwrap();
        assert_eq!(obj.data["spec"]["podTemplate"]["spec"]["runtimeClassName"], "gvisor");
        backend.terminate(&sref, Duration::from_secs(1)).await.unwrap();
        assert!(sandboxes.get_opt("acp-sb-a1-test").await.unwrap().is_none());
    }

    let _ = controller.kill();
    let _ = controller.wait();
    let _ = nss.delete(&ns, &DeleteParams::default()).await;
    db.drop_db().await;
}

fn base64_url(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let b = s.as_bytes();
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | ((x as u32) << (16 - 8 * i)));
        for i in 0..(chunk.len() + 1) {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
