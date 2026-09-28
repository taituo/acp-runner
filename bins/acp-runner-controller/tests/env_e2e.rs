//! AgentEnvironment production wiring (V10a) against a real kube-apiserver
//! (envtest): the controller binary reconciles `AgentEnvironment` objects —
//! create/status/lifecycle/finalizer — with a simulated kubelet running the
//! environment pods as local runnerd/agentd processes.
//!
//! Flow: apply CRDs -> create AgentEnvironment -> Ready/Idle -> gateway
//! Service+NetworkPolicy exist -> ACP session through a provider ticket ->
//! snapshot -> controller restart (same DB + ticket key file) -> finish via
//! `spec.lifecycle` -> delete -> finalizer removes the row, Service and Policy.
//!
//! Opt-in: requires `ACP_E2E_KUBECONFIG` and `ACP_TEST_DATABASE_URL`.

use acp_runner_client::{Transport, connect_session};
use acp_runner_engine::environment::{EnvironmentConfig, EnvironmentProvider, TicketKey, TicketKeyRing};
use acp_runner_engine::ingest::IngestState;
use acp_runner_engine::metrics::Metrics;
use acp_runner_journal::{ArtifactStore, Journal, PgArtifactStore};
use acp_runner_k8s::backends::PodBackend;
use acp_runner_k8s::crds::AgentEnvironment;
use acp_runner_k8s::pod::PodConfig;
use k8s_openapi::api::core::v1::{Namespace, Pod, Secret, Service, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config, ResourceExt};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
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

async fn client_from(path: &str) -> Client {
    let kc = Kubeconfig::read_from(path).unwrap();
    let mut cfg = Config::from_custom_kubeconfig(kc, &KubeConfigOptions::default()).await.unwrap();
    cfg.proxy_url = None; // local apiserver; ignore HTTPS_PROXY of the test environment
    Client::try_from(cfg).unwrap()
}

fn fixture_repo(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("buggy.py"), "print('oops')\n").unwrap();
    let git = |args: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(o.status.success());
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

async fn apply_yaml_crds(client: &Client, yaml: &str) {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
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

// ---- simulated kubelet (mirrors kube_e2e.rs; pods run as local processes) ----

struct SimContainer {
    name: String,
    child: std::process::Child,
    exit: Option<i32>,
    log_path: PathBuf,
}

struct FakeKubelet {
    pods: Arc<Mutex<HashMap<String, Vec<SimContainer>>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

fn kill_container(c: &mut SimContainer, sig: nix::sys::signal::Signal) {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    let _ = kill(Pid::from_raw(c.child.id() as i32), sig);
}

fn host_path(mounts: &[(String, PathBuf)], value: &str) -> Option<String> {
    let mut best: Option<(&str, &PathBuf)> = None;
    for (mp, host) in mounts {
        if (value == mp || value.starts_with(&format!("{mp}/"))) && best.is_none_or(|(p, _)| mp.len() > p.len()) {
            best = Some((mp, host));
        }
    }
    best.map(|(mp, host)| format!("{}{}", host.display(), &value[mp.len()..]))
}

impl FakeKubelet {
    fn start(client: Client, ns: String, work: PathBuf) -> FakeKubelet {
        let pods_state: Arc<Mutex<HashMap<String, Vec<SimContainer>>>> = Arc::default();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (p2, stop2) = (pods_state.clone(), stop.clone());
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
                let gone: Vec<String> = p2.lock().unwrap().keys().filter(|n| !names.contains(*n)).cloned().collect();
                for n in gone {
                    if let Some(mut cs) = p2.lock().unwrap().remove(&n) {
                        for c in cs.iter_mut() {
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
                    let spec = pod.spec.clone().unwrap();
                    let dir = work.join(&name);
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
                        .map(|c| {
                            c.volume_mounts
                                .clone()
                                .unwrap_or_default()
                                .iter()
                                .map(|m| (m.mount_path.clone(), vols[&m.name].clone()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let mut containers = vec![];
                    for c in &spec.containers {
                        let mounts: Vec<(String, PathBuf)> = c
                            .volume_mounts
                            .clone()
                            .unwrap_or_default()
                            .iter()
                            .map(|m| (m.mount_path.clone(), vols[&m.name].clone()))
                            .collect();
                        let mut env: HashMap<String, String> = HashMap::new();
                        for e in c.env.clone().unwrap_or_default() {
                            let Some(v) = e.value else { continue };
                            let m = if e.name.starts_with("ACP_RUNNER_AGENT_") { &agentd_mounts } else { &mounts };
                            env.insert(e.name, host_path(m, &v).unwrap_or(v));
                        }
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
                        let log_path = dir.join(format!("{}.log", c.name));
                        containers.push(SimContainer { name: c.name.clone(), child, exit: None, log_path });
                    }
                    p2.lock().unwrap().insert(name.clone(), containers);
                }
                let mut updates = vec![];
                for (n, cs) in p2.lock().unwrap().iter_mut() {
                    for c in cs.iter_mut() {
                        if c.exit.is_none()
                            && let Ok(Some(st)) = c.child.try_wait()
                        {
                            c.exit = Some(st.code().unwrap_or(137));
                            if c.exit != Some(0) {
                                eprintln!("container {n}/{} exited {}", c.name, c.exit.unwrap());
                                if let Ok(t) = std::fs::read_to_string(&c.log_path) {
                                    eprintln!("--- log tail ---\n{}", t.chars().rev().take(2000).collect::<String>().chars().rev().collect::<String>());
                                }
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
        FakeKubelet { pods: pods_state, stop }
    }
}

impl Drop for FakeKubelet {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        for (_, mut cs) in self.pods.lock().unwrap().drain() {
            for c in cs.iter_mut() {
                kill_container(c, nix::sys::signal::Signal::SIGKILL);
                let _ = c.child.wait();
            }
        }
    }
}

// ---- test ----

#[allow(clippy::too_many_arguments)]
fn spawn_controller(
    kubeconfig: &str,
    db_url: &str,
    ns: &str,
    ingest_port: u16,
    metrics_port: u16,
    gw_port: u16,
    key_file: &Path,
    log_path: &Path,
) -> std::process::Child {
    let log = std::fs::File::create(log_path).unwrap();
    std::process::Command::new(target_dir().join("acp-runner-controller"))
        .arg("run")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env("KUBECONFIG", kubeconfig)
        .env("DATABASE_URL", db_url)
        .env("POD_NAME", "controller-env-e2e")
        .env("ACP_RUNNER_INGEST_URL", format!("http://127.0.0.1:{ingest_port}"))
        .env("ACP_RUNNER_INGEST_LISTEN", format!("127.0.0.1:{ingest_port}"))
        .env("ACP_RUNNER_METRICS_LISTEN", format!("127.0.0.1:{metrics_port}"))
        .env("ACP_RUNNER_WATCH_NAMESPACE", ns)
        .env("ACP_RUNNER_CREDENTIAL_NAMESPACE", ns)
        .env("ACP_RUNNER_CODEX_REFRESH", "false")
        .env("ACP_RUNNER_STRICT_POSTURE", "false")
        .env("ACP_RUNNER_ALLOW_FILE_REPOS", "true")
        .env("ACP_RUNNER_ENV_GATEWAY_LISTEN", format!("127.0.0.1:{gw_port}"))
        .env("ACP_RUNNER_TICKET_KEY_FILE", key_file)
        .env("RUST_LOG", "info")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap()
}

async fn wait_env_phase(api: &Api<AgentEnvironment>, name: &str, want: &[&str], limit: Duration) -> AgentEnvironment {
    let start = Instant::now();
    loop {
        let e = api.get(name).await.unwrap();
        let phase = e.status.as_ref().and_then(|s| s.phase.clone()).unwrap_or_default();
        if want.contains(&phase.as_str()) {
            return e;
        }
        assert!(Instant::now() - start < limit, "env {name} stuck at phase {phase:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn agentenvironment_reconcile_status_lifecycle_finalizer() {
    let Ok(kubeconfig) = std::env::var("ACP_E2E_KUBECONFIG") else {
        if std::env::var("ACP_REQUIRE_DB_TESTS").as_deref() == Ok("1") {
            panic!("ACP_E2E_KUBECONFIG is required when ACP_REQUIRE_DB_TESTS=1 (refusing to SKIP)");
        }
        eprintln!("SKIPPED: set ACP_E2E_KUBECONFIG (scripts/envtest-up.sh) and ACP_TEST_DATABASE_URL");
        return;
    };
    let Some(db) = acp_runner_journal::testing::temp_database().await else { return };
    build_bins();
    let client = client_from(&kubeconfig).await;
    apply_yaml_crds(&client, &acp_runner_k8s::crds_yaml()).await;
    let ns = format!("acp-env-e2e-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let nss: Api<Namespace> = Api::all(client.clone());
    nss.create(&PostParams::default(), &serde_json::from_value(json!({"metadata": {"name": ns}})).unwrap())
        .await
        .unwrap();
    let sas: Api<ServiceAccount> = Api::namespaced(client.clone(), &ns);
    sas.create(
        &PostParams::default(),
        &serde_json::from_value(json!({"metadata": {"name": "acp-runner-agent"}, "automountServiceAccountToken": false}))
            .unwrap(),
    )
    .await
    .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let sha = fixture_repo(&tmp.path().join("upstream"));
    let repo = format!("file://{}", tmp.path().join("upstream").display());
    let fake = target_dir().join("fake-acp-agent").display().to_string();
    // shared ticket key: the controller and this test mint for the same environments.
    let key_file = tmp.path().join("ticket.key");
    std::fs::write(&key_file, rand_bytes()).unwrap();
    let _kubelet = FakeKubelet::start(client.clone(), ns.clone(), tmp.path().join("nodes"));

    let (ingest_port, metrics_port, gw_port) = (free_port(), free_port(), free_port());
    // controller logs outside the tempdir so failures stay inspectable.
    let logdir = std::env::temp_dir().join(format!("acp-env-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&logdir).unwrap();
    eprintln!("env-e2e logs: {}", logdir.display());
    let mut controller = spawn_controller(
        &kubeconfig,
        &db.url,
        &ns,
        ingest_port,
        metrics_port,
        gw_port,
        &key_file,
        &logdir.join("c1.log"),
    );

    let envs: Api<AgentEnvironment> = Api::namespaced(client.clone(), &ns);
    let manifest = format!(
        r#"apiVersion: acp-runner.dev/v1alpha1
kind: AgentEnvironment
metadata: {{name: env-e2e, namespace: {ns}}}
spec:
  externalRef: e2e-1
  harness: {{name: fake, config: {{command: "{fake}"}}}}
  workspace: {{source: {{type: git, url: "{repo}", revision: "{sha}"}}}}
  lifetime: {{idleSeconds: 600}}
"#
    );
    let ae: AgentEnvironment = serde_yaml::from_str(&manifest).unwrap();
    let created = envs.create(&PostParams::default(), &ae).await.unwrap();
    let uid1 = created.uid().unwrap();

    // Ready: status carries phase/endpoint/revision, Service+Policy exist.
    let e = wait_env_phase(&envs, "env-e2e", &["Idle"], Duration::from_secs(180)).await;
    let st = e.status.clone().unwrap();
    assert_eq!(st.phase.as_deref(), Some("Idle"));
    assert_eq!(st.resolved_revision.as_deref(), Some(sha.as_str()));
    assert_eq!(
        st.connection.as_ref().unwrap().gateway,
        format!("env-e2e-gw.{ns}.svc.cluster.local:{gw_port}")
    );
    assert!(st.environment_id.is_some());
    let raw = serde_json::to_value(&st).unwrap().to_string();
    assert!(!raw.to_lowercase().contains("ticket"), "status leaks ticket material: {raw}");

    let svcs: Api<Service> = Api::namespaced(client.clone(), &ns);
    let svc = svcs.get("env-e2e-gw").await.unwrap();
    let spec = svc.spec.unwrap();
    assert!(spec.selector.as_ref().unwrap().contains_key("acp-runner.dev/attempt-id"));
    assert_eq!(spec.ports.as_ref().unwrap()[0].port, gw_port as i32);
    let nps: Api<NetworkPolicy> = Api::namespaced(client.clone(), &ns);
    let np = nps.get("env-e2e-gw").await.unwrap();
    let from = &np.spec.as_ref().unwrap().ingress.as_ref().unwrap()[0].from.as_ref().unwrap()[0];
    assert_eq!(
        from.namespace_selector.as_ref().unwrap().match_labels.as_ref().unwrap()["kubernetes.io/metadata.name"],
        ns
    );

    // ACP session through a provider ticket (test-side provider, same DB + key).
    let journal = Journal::connect(&db.url, 4).await.unwrap();
    journal.migrate().await.unwrap();
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
    let metrics = Arc::new(Metrics::new());
    let ingest = Arc::new(IngestState::new(journal.clone(), artifacts.clone(), Arc::new(acp_runner_engine::creds::FileCredentialStore { root: tmp.path().join("creds") }), metrics, None));
    let backend = Arc::new(PodBackend { client: client.clone(), cfg: PodConfig::default() });
    let tprovider = EnvironmentProvider::new(
        journal.clone(),
        backend,
        Arc::new(acp_runner_engine::creds::FileCredentialStore { root: tmp.path().join("creds") }),
        artifacts,
        ingest,
        EnvironmentConfig {
            controller_id: "env-e2e-test".into(),
            ingest_url: format!("http://127.0.0.1:{ingest_port}"),
            gateway_listen: format!("127.0.0.1:{gw_port}"),
            require_egress_proxy_for_credentials: false,
            runner_image: "local".into(),
            allowed_images: vec![],
            allowed_service_accounts: vec![],
            ticket_keys: TicketKeyRing::new(TicketKey::from_file(&key_file).unwrap()),
            ticket_ttl_seconds: acp_runner_core::ticket::DEFAULT_TICKET_TTL_SECONDS,
        },
    );
    let env_id: uuid::Uuid = st.environment_id.as_ref().unwrap().parse().unwrap();
    let row = journal.live_environment_by_k8s(&ns, "env-e2e").await.unwrap().expect("live row mapped");
    assert_eq!(row.id, env_id);
    assert_eq!(row.k8s_uid.as_deref(), Some(uid1.as_str()));
    assert_eq!(row.key_version, TicketKeyRing::id_for(&TicketKey::from_file(&key_file).unwrap()));
    let conn = tprovider.connect(env_id, Duration::from_secs(60)).await.unwrap();
    let (mut acp, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.expect("attach");
    assert_eq!(acp.prompt(&session, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");
    assert_eq!(acp.prompt(&session, "[[fake:touch:extra.txt]] add file").await.unwrap().stop_reason, "end_turn");
    let snap = tprovider.snapshot_and_wait(env_id, Some("e2e".into()), Duration::from_secs(60)).await.unwrap();
    assert_ne!(snap.to_string(), "");

    // Restart the controller: same DB + key file re-adopts the live environment.
    controller.kill().unwrap();
    controller.wait().unwrap();
    let row2 = journal.live_environment_by_k8s(&ns, "env-e2e").await.unwrap().expect("row survives restart");
    assert_eq!(row2.id, env_id, "restart must adopt, not duplicate");
    controller = spawn_controller(
        &kubeconfig,
        &db.url,
        &ns,
        ingest_port,
        metrics_port,
        gw_port,
        &key_file,
        &logdir.join("c2.log"),
    );
    let conn2 = tprovider.connect(env_id, Duration::from_secs(60)).await.unwrap();
    assert_ne!(conn2.ticket, conn.ticket);
    let (mut acp2, session2) = connect_session(&conn2.gateway, &conn2.ticket, Transport::Raw).await.expect("attach after restart");
    assert_eq!(acp2.prompt(&session2, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");

    // finish via spec.lifecycle, then delete: finalizer cleans row + Service + Policy.
    let patch = json!({"spec": {"lifecycle": "finish"}});
    envs.patch("env-e2e", &PatchParams::default(), &Patch::Merge(&patch)).await.unwrap();
    let e = wait_env_phase(&envs, "env-e2e", &["Completed"], Duration::from_secs(180)).await;
    assert!(e.status.as_ref().unwrap().final_artifact_ref.is_some());
    envs.delete("env-e2e", &DeleteParams::default()).await.unwrap();
    let start = Instant::now();
    loop {
        match envs.get("env-e2e").await {
            Err(kube::Error::Api(s)) if s.code == 404 => break,
            Ok(_) if Instant::now() - start > Duration::from_secs(120) => panic!("object stuck behind finalizer"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    assert!(journal.live_environment_by_k8s(&ns, "env-e2e").await.unwrap().is_none());
    assert!(svcs.get("env-e2e-gw").await.is_err());
    assert!(nps.get("env-e2e-gw").await.is_err());

    controller.kill().unwrap();
    let _ = controller.wait();
    db.drop_db().await;
}

fn rand_bytes() -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // test-only key material (48 bytes from a local hash chain, never reused).
    let mut out = Vec::with_capacity(48);
    let mut h = DefaultHasher::new();
    (std::process::id(), std::time::SystemTime::now()).hash(&mut h);
    let mut x = h.finish();
    while out.len() < 48 {
        x = x.wrapping_mul(0x5851f42d4c957f2d).wrapping_add(0x14057b7ef767814f);
        out.extend_from_slice(&x.to_be_bytes());
    }
    out
}
