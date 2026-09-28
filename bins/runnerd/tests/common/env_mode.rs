//! Environment-mode harness shared by the environment/bootstrap suites.

use super::*;
use acp_runner_core::AttemptSpec;
use acp_runner_core::attempt_spec::{AttemptOutput, DriverSpec, GATEWAY_KEY_FILE_NAME, SessionMode};
use acp_runner_core::events::RunnerDirective;
use acp_runner_core::spec::{EgressPolicy, OutputKind, PermissionPolicy, RepositoryInput, TimeoutPolicy};
use acp_runner_core::ticket;
use runnerd::sink::MemorySink;
use runnerd::{EnvironmentResult, RunnerDirs, SupervisorOptions};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const MASTER: &[u8] = b"test-master-key-0123456789abcdef-0123456789";

pub fn env_spec(env: &TestEnv, environment_id: Uuid) -> AttemptSpec {
    AttemptSpec {
        wire_version: acp_runner_core::WIRE_VERSION,
        run_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        task_id: "env".into(),
        ordinal: 1,
        class_attempt: 1,
        runner_class: "env".into(),
        driver: DriverSpec { name: env.driver.clone(), config: env.config.clone() },
        repository: RepositoryInput {
            url: env.repo_url.clone(),
            revision: env.base_sha.clone(),
            sparse_paths: vec![],
            depth: None,
        },
        prompt: String::new(),
        capsule: None,
        apply_patch_b64: None,
        output: AttemptOutput {
            kind: OutputKind::Patch,
            require_changes: false,
            max_patch_bytes: 1 << 20,
            allowed_paths: vec![],
            allow_submodules: false,
        },
        timeouts: TimeoutPolicy {
            hard_seconds: 120,
            no_progress_seconds: 60,
            grace_seconds: 3,
            heartbeat_seconds: 1,
            startup_seconds: 30,
        },
        permissions: PermissionPolicy::default(),
        egress: EgressPolicy::default(),
        credentials: env.layout.clone(),
        record_raw_payloads: true,
        env: Default::default(),
        session: SessionMode::Environment {
            environment_id,
            gateway_listen: "127.0.0.1:0".into(),
            idle_timeout_seconds: None,
            max_lifetime_seconds: None,
        },
        bootstrap: Default::default(),
    }
}

/// A running environment under test.
pub struct Running {
    pub id: Uuid,
    pub key: [u8; 32],
    pub sink: MemorySink,
    pub handle: JoinHandle<EnvironmentResult>,
    pub gateway: String,
    pub dirs: RunnerDirs,
}

impl Running {
    /// Start runnerd in environment mode with its own secret dir (credentials + `K_env`) and
    /// wait for the gateway.
    pub async fn start(env: &TestEnv, mutate: impl FnOnce(&mut AttemptSpec)) -> Running {
        Self::start_with_sink(env, mutate, MemorySink::default()).await
    }

    /// Like [`Running::start`] with a sink that already serves overlays/bundles/harnesses.
    pub async fn start_with_sink(env: &TestEnv, mutate: impl FnOnce(&mut AttemptSpec), sink: MemorySink) -> Running {
        let r = Self::launch(env, mutate, sink);
        let gateway = wait_gateway_addr(&r.sink).await;
        Running { gateway, ..r }
    }

    /// Start without waiting for the gateway (for bootstrap failures).
    pub fn launch(env: &TestEnv, mutate: impl FnOnce(&mut AttemptSpec), sink: MemorySink) -> Running {
        let id = Uuid::new_v4();
        let mut spec = env_spec(env, id);
        mutate(&mut spec);
        let key = ticket::derive_env_key(MASTER, id).unwrap();
        let mut dirs = env.dirs();
        let secret = dirs.state.parent().unwrap().join("secret-env");
        std::fs::create_dir_all(&secret).unwrap();
        for e in std::fs::read_dir(&env.secret_dir).unwrap().flatten() {
            std::fs::copy(e.path(), secret.join(e.file_name())).unwrap();
        }
        std::fs::write(secret.join(GATEWAY_KEY_FILE_NAME), hex::encode(key)).unwrap();
        dirs.secret_dir = Some(secret);
        let opts = SupervisorOptions {
            agentd: env.opts().agentd,
            agent_path_env: env.opts().agent_path_env,
            ..Default::default()
        };
        let (tx, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(tx);
        let mut s = sink.clone();
        let d = dirs.clone();
        let handle = tokio::spawn(async move { runnerd::run_environment(spec, d, &mut s, opts, rx).await });
        Running { id, key, sink, handle, gateway: String::new(), dirs }
    }

    pub async fn result(self) -> (EnvironmentResult, MemorySink) {
        let res = tokio::time::timeout(Duration::from_secs(60), self.handle).await.unwrap().unwrap();
        (res, self.sink)
    }

    pub fn ticket(&self) -> String {
        let now = chrono::Utc::now().timestamp();
        ticket::issue(&self.key, &ticket::claims_for(self.id, now, 60))
    }

    pub fn directive(&self, d: RunnerDirective) {
        self.sink.directives.lock().unwrap().push_back(d);
    }

    pub async fn finish(self) -> (EnvironmentResult, MemorySink) {
        self.directive(RunnerDirective::Finish);
        let res = tokio::time::timeout(Duration::from_secs(60), self.handle).await.unwrap().unwrap();
        (res, self.sink)
    }
}

/// Poll the sink for the `gateway_listening` progress event and return the bound address.
pub async fn wait_gateway_addr(sink: &MemorySink) -> String {
    let start = Instant::now();
    loop {
        if let Some(a) = sink.snapshot().events.iter().find_map(|e| {
            (e.data.get("category").and_then(|c| c.as_str()) == Some("gateway_listening"))
                .then(|| e.data.pointer("/detail/addr").and_then(|a| a.as_str()).map(str::to_string))
                .flatten()
        }) {
            return a;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "gateway never bound: {}", dump(&sink.snapshot()));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn wait_event_n(sink: &MemorySink, category: &str, n: usize) {
    let start = Instant::now();
    loop {
        let count = sink
            .snapshot()
            .events
            .iter()
            .filter(|e| e.data.get("category").and_then(|c| c.as_str()) == Some(category))
            .count();
        if count >= n {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "event {category} x{n} never arrived");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub fn latest_snapshot(sink: &MemorySink) -> Option<Vec<acp_runner_core::events::ChangedPath>> {
    sink.snapshot().artifacts.iter().rev().find(|a| a.kind == "snapshot").map(|a| a.changed_paths.clone())
}
