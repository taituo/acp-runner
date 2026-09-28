//! Trust-boundary regression tests for the runnerd/agentd split under real Linux isolation.
//!
//! The agent side runs in its own mount + PID (and, in `egress.mode: proxy`, network)
//! namespace via [`LocalProcessBackend`] isolation, so this checks the properties the
//! Kubernetes two-container pod is meant to enforce:
//!
//! * the per-attempt Secret directory is not visible or readable to the agent;
//! * no `ACP_RUNNER_*` controller configuration is in the agent environment;
//! * runnerd's process (and its `/proc`) is not visible to the agent;
//! * in `egress.mode: proxy`, arbitrary outbound connections are impossible and the
//!   allowlisting egress proxy refuses non-allowlisted hosts while permitting allowlisted
//!   ones;
//! * the agent still runs the turn and runnerd still produces the authoritative patch.
//!
//! Requires root + util-linux (namespaces); skips cleanly otherwise, and requires
//! `ACP_TEST_DATABASE_URL` like the other engine tests.

use acp_runner_core::RunPhase;
use acp_runner_core::spec::*;
use acp_runner_engine::backend::{LocalIsolation, LocalProcessBackend, RunKey};
use acp_runner_engine::creds::FileCredentialStore;
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig, RunInput, RunView, local_container};
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, PgArtifactStore};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

fn build() {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        let st = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent", "-p", "acp-egress-proxy"])
            .status()
            .unwrap();
        assert!(st.success());
    });
}

async fn fixture(dir: &std::path::Path) -> String {
    tokio::fs::create_dir_all(dir).await.unwrap();
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n").unwrap();
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

struct H {
    db: Option<TempDb>,
    engine: Arc<Engine>,
    _tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    fake: PathBuf,
    ingest_addr: std::net::SocketAddr,
}

impl H {
    async fn new(isolation: LocalIsolation) -> Option<H> {
        build();
        let db = temp_database().await?;
        let tmp = tempfile::tempdir().unwrap();
        // world-traversable so the unprivileged agent uid can reach the sandbox dirs
        let _ = std::process::Command::new("chmod").args(["0755", &tmp.path().to_string_lossy()]).status();
        let src = tmp.path().join("upstream");
        let base_sha = fixture(&src).await;
        // runnerd runs as the agent uid; own the file:// upstream so local git fetch does not
        // trip "dubious ownership" in the remote upload-pack (a real remote is https/baked-in).
        std::process::Command::new("chown")
            .args(["-R", &format!("{}:{}", isolation.uid, isolation.gid), &src.to_string_lossy()])
            .status()
            .unwrap();
        let journal = db.journal.clone();
        let metrics = Arc::new(Metrics::new());
        let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
        let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
        let state =
            Arc::new(IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingest_addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        let mut backend =
            LocalProcessBackend::new(target_dir().join("runnerd"), tmp.path().join("sandboxes"), path_env());
        backend.isolation = Some(isolation);
        let engine = Arc::new(Engine {
            journal,
            backend: Arc::new(backend),
            creds,
            artifacts,
            metrics,
            cfg: EngineConfig {
                controller_id: "iso".into(),
                ingest_url: format!("http://{ingest_addr}"),
                active_requeue: Duration::from_millis(200),
                waiting_requeue: Duration::from_millis(300),
                allowed_images: vec![
                    "local@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                ],
                ..Default::default()
            },
        });
        Some(H {
            db: Some(db),
            engine,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            fake: target_dir().join("fake-acp-agent"),
            ingest_addr,
            _tmp: tmp,
        })
    }

    fn class(&self, env: BTreeMap<String, String>, egress: EgressPolicy) -> RunnerClassSpec {
        RunnerClassSpec {
            name: "iso".into(),
            driver: "fake".into(),
            driver_config: json!({"command": self.fake.to_string_lossy()}),
            image: "local@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            image_pull_policy: None,
            runtime_class_name: None,
            resources: None,
            credentials: CredentialRequirement::default(),
            workspace: WorkspacePolicy::default(),
            timeouts: TimeoutPolicy {
                hard_seconds: 120,
                no_progress_seconds: 60,
                grace_seconds: 3,
                heartbeat_seconds: 1,
                startup_seconds: 60,
            },
            permissions: PermissionPolicy::default(),
            egress,
            env,
            allow_run_overrides: false,
            run_as_user: None,
            service_account_name: None,
        }
    }

    async fn run(&self, class: RunnerClassSpec) -> (RunView, Vec<acp_runner_journal::EventRow>) {
        let uid = Uuid::new_v4().to_string();
        let input = RunInput {
            key: RunKey { namespace: "default".into(), name: format!("iso-{}", &uid[..8]), uid },
            spec: RunSpec {
                task_id: "iso".into(),
                prompt: "trust probe".into(),
                repository: RepositoryInput {
                    url: self.repo_url.clone(),
                    revision: self.base_sha.clone(),
                    sparse_paths: vec![],
                    depth: None,
                },
                output: OutputExpectation { require_changes: false, ..Default::default() },
                retry: RetryPolicy { max_attempts_per_runner: 1, max_total_attempts: None },
                timeouts: TimeoutOverrides::default(),
                resume: ResumePolicy::default(),
                runner_classes: vec![class],
                overrides: RunOverrides::default(),
            },
            cancel: false,
        };
        let start = Instant::now();
        let v = loop {
            let v = self.engine.reconcile(&input).await.expect("reconcile");
            if v.phase.is_terminal() || start.elapsed() > Duration::from_secs(90) {
                break v;
            }
            tokio::time::sleep(v.requeue_after.unwrap_or(Duration::from_millis(200)).max(Duration::from_millis(100)))
                .await;
        };
        let evs = self.engine.journal.events_for_run(v.run_id, 0, 100_000).await.unwrap();
        (v, evs)
    }

    async fn done(mut self) {
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

fn path_env() -> String {
    // The agent uid must be able to execute the built binaries + the fake agent.
    std::env::var("PATH").unwrap_or_default()
}

/// The `TRUST-PROBE {json}` object the fake agent reported.
fn probe_report(evs: &[acp_runner_journal::EventRow]) -> Value {
    for e in evs {
        if e.kind == "AgentOutput"
            && let Some(t) = e.data.get("text").and_then(|t| t.as_str())
            && let Some(idx) = t.find("TRUST-PROBE ")
        {
            let json = t[idx + "TRUST-PROBE ".len()..].trim();
            return serde_json::from_str(json).unwrap_or(Value::Null);
        }
    }
    Value::Null
}

fn ro_paths() -> Vec<PathBuf> {
    // The agent needs the built binaries (fake agent + agentd) on its read-only view.
    let mut v = vec![target_dir()];
    if let Ok(p) = std::env::var("PATH") {
        for d in p.split(':') {
            let d = PathBuf::from(d);
            if d.join("node").exists() || d.is_dir() && d.starts_with("/") && !d.starts_with("/proc") {
                v.push(d);
            }
        }
    }
    v.sort();
    v.dedup();
    v.into_iter().filter(|p| p.exists()).collect()
}

#[tokio::test]
async fn agent_is_isolated_from_secret_env_and_supervisor() {
    if !local_container::available() {
        eprintln!("SKIPPED: namespaces unavailable (needs root + util-linux)");
        return;
    }
    let iso = LocalIsolation {
        uid: 10001,
        gid: 10001,
        ro_paths: ro_paths(),
        proxy_socket: None,
        relay: target_dir().join("acp-egress-proxy"),
    };
    let Some(h) = H::new(iso).await else { return };
    let env: BTreeMap<String, String> = [
        ("FAKE_ACP_SCENARIO".to_string(), "trust-probe".to_string()),
        ("FAKE_PROBE_INGEST".to_string(), h.ingest_addr.to_string()),
    ]
    .into_iter()
    .collect();
    // direct mode: the agent shares the host network (like sharing the pod network), so the
    // ingest API is reachable at L3 but rejects the agent (no token).
    let (v, evs) = h.run(h.class(env, EgressPolicy::default())).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let r = probe_report(&evs);
    assert_ne!(r, Value::Null, "no trust-probe report");
    assert_eq!(r["secretDirVisible"], false, "the attempt Secret directory is visible to the agent");
    assert_eq!(r["secretReadable"], false, "the agent can read the attempt Secret");
    assert_eq!(
        r["acpRunnerEnv"].as_array().unwrap().len(),
        0,
        "ACP_RUNNER_* env leaked to the agent: {}",
        r["acpRunnerEnv"]
    );
    assert_eq!(r["runnerdVisible"], false, "runnerd process is visible to the agent");
    assert_eq!(r["runnerdEnvironReadable"], false);
    // the ingest API rejects the agent (it holds no attempt token)
    assert_eq!(r["ingest"]["authStatus"], "401", "ingest did not reject the tokenless agent: {}", r["ingest"]);
    // credential material never appears in the journal
    let all = serde_json::to_string(&evs.iter().map(|e| (&e.data, &e.raw)).collect::<Vec<_>>()).unwrap();
    assert!(!all.contains("attempt-token"));
    h.done().await;
}

#[tokio::test]
async fn proxy_egress_blocks_arbitrary_hosts_and_allows_the_allowlist() {
    build();
    if !local_container::available() {
        eprintln!("SKIPPED: namespaces unavailable (needs root + util-linux)");
        return;
    }
    // A host-side "allowed provider" that accepts a TCP connection.
    let provider = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_port = provider.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((s, _)) = provider.accept().await {
            drop(s);
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    std::process::Command::new("chmod").args(["0755", &tmp.path().to_string_lossy()]).status().unwrap();
    let sock = tmp.path().join("egress.sock");
    // The allowlisting proxy (allowlist: localhost; allow_private + provider port for the test).
    let mut proxy = std::process::Command::new(target_dir().join("acp-egress-proxy"))
        .args(["serve", "--listen", "none", "--listen-unix"])
        .arg(&sock)
        .args(["--allow", "localhost", "--allow-private-destinations", "--allow-port"])
        .arg(provider_port.to_string())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    std::process::Command::new("chmod").args(["0666", &sock.to_string_lossy()]).status().unwrap();

    let iso = LocalIsolation {
        uid: 10001,
        gid: 10001,
        ro_paths: ro_paths(),
        proxy_socket: Some(sock.clone()),
        relay: target_dir().join("acp-egress-proxy"),
    };
    let Some(h) = H::new(iso).await else {
        let _ = proxy.kill();
        let _ = proxy.wait();
        return;
    };
    let env: BTreeMap<String, String> = [
        ("FAKE_ACP_SCENARIO".to_string(), "trust-probe".to_string()),
        ("FAKE_PROBE_BLOCKED".to_string(), "notallowed.example:443".to_string()),
        ("FAKE_PROBE_ALLOWED".to_string(), format!("localhost:{provider_port}")),
    ]
    .into_iter()
    .collect();
    let egress = EgressPolicy {
        mode: Some(EgressMode::Proxy),
        https_proxy: Some(format!("http://{}", acp_runner_engine::backend::LOCAL_PROXY_LISTEN)),
        no_proxy: None,
    };
    let (v, evs) = h.run(h.class(env, egress)).await;
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let r = probe_report(&evs);
    assert_ne!(r, Value::Null, "no trust-probe report");
    // a non-allowlisted host: not reachable directly, and refused by the proxy
    assert_ne!(
        r["blockedHost"]["directConnect"], "connected",
        "arbitrary direct egress was possible: {}",
        r["blockedHost"]
    );
    assert_eq!(
        r["blockedHost"]["viaProxy"], "403",
        "proxy did not refuse a non-allowlisted host: {}",
        r["blockedHost"]
    );
    // the allowlisted host is reachable only through the proxy
    assert_eq!(r["allowedHost"], "200", "allowlisted host not reachable through the proxy: {}", r["allowedHost"]);
    h.done().await;
}
