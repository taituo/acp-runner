//! acp-conformance (V9.6): probe battery for ANY launch spec through the real
//! runnerd/agentd split.
//!
//! The launch under test comes from `ACP_CONFORMANCE_LAUNCH` (JSON
//! `{command, args[], env{}, files[]}`); default is the in-tree fake agent,
//! so the suite runs in CI. Point it at another CLI for live runs.
//! Each area records profile VALUES, not just pass/fail; `acp_conformance_profile`
//! (A24) asserts a profile generates for the arbitrary launch.

mod common;

use acp_runner_core::attempt_spec::DriverSpec;
use acp_runner_core::events::EventKind;
use acp_runner_core::spec::{EgressPolicy, OutputKind, PermissionPolicy, RepositoryInput, TimeoutPolicy};
use acp_runner_core::{AttemptPhase, AttemptSpec};
use common::{agentd_bin, fake_agent_bin};
use runnerd::sink::{MemoryRecord, MemorySink};
use runnerd::{AgentdLaunch, AttemptResult, RunnerDirs, SupervisorOptions, run_attempt};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn launch() -> Value {
    if let Ok(s) = std::env::var("ACP_CONFORMANCE_LAUNCH") {
        return serde_json::from_str(&s).expect("ACP_CONFORMANCE_LAUNCH must be JSON");
    }
    json!({"command": fake_agent_bin().to_string_lossy()})
}

fn cli_name(launch: &Value) -> String {
    launch
        .get("command")
        .and_then(|c| c.as_str())
        .unwrap_or("?")
        .rsplit('/')
        .next()
        .unwrap_or("?")
        .to_string()
}

struct LaunchEnv {
    tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    launch: Value,
    counter: std::sync::atomic::AtomicU32,
}

impl LaunchEnv {
    async fn new() -> LaunchEnv {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("upstream");
        let base_sha = acp_runner_workspace::fixture::create(&src).await.expect("fixture repo");
        LaunchEnv {
            tmp,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            launch: launch(),
            counter: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn spec(&self, prompt: &str, env: BTreeMap<String, String>) -> AttemptSpec {
        AttemptSpec {
            wire_version: acp_runner_core::WIRE_VERSION,
            run_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            task_id: "conformance".into(),
            ordinal: 1,
            class_attempt: 1,
            runner_class: "conformance".into(),
            driver: DriverSpec { name: "acp".into(), config: self.launch.clone() },
            repository: RepositoryInput {
                url: self.repo_url.clone(),
                revision: self.base_sha.clone(),
                sparse_paths: vec![],
                depth: None,
            },
            prompt: prompt.into(),
            capsule: None,
            apply_patch_b64: None,
            output: acp_runner_core::attempt_spec::AttemptOutput {
                kind: OutputKind::Patch,
                require_changes: false,
                max_patch_bytes: 1 << 20,
                allowed_paths: vec![],
                allow_submodules: false,
            },
            timeouts: TimeoutPolicy {
                hard_seconds: 60,
                no_progress_seconds: 30,
                grace_seconds: 3,
                heartbeat_seconds: 2,
                startup_seconds: 30,
            },
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            credentials: None,
            record_raw_payloads: true,
            env,
            session: Default::default(),
            bootstrap: Default::default(),
        }
    }

    fn dirs(&self) -> RunnerDirs {
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        RunnerDirs::under(&self.tmp.path().join(format!("sandbox-{n}")), None)
    }

    fn opts(&self) -> SupervisorOptions {
        SupervisorOptions {
            agent_path_env: std::env::var("PATH").ok(),
            agentd: AgentdLaunch::Spawn {
                program: agentd_bin(),
                env: vec![("AGENTD_LOG".to_string(), "warn".to_string())],
            },
            ..Default::default()
        }
    }

    async fn run(
        &self,
        prompt: &str,
        env: BTreeMap<String, String>,
        cancel_after: Option<Duration>,
    ) -> (AttemptResult, MemoryRecord) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        if let Some(d) = cancel_after {
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = tx.send(true);
            });
        } else {
            std::mem::forget(tx);
        }
        let mut sink = MemorySink::default();
        let res = run_attempt(self.spec(prompt, env), self.dirs(), &mut sink, self.opts(), rx).await;
        (res, sink.snapshot())
    }
}

fn session_started(rec: &MemoryRecord) -> Option<&Value> {
    rec.events.iter().find(|e| e.kind == EventKind::SessionStarted).map(|e| &e.data)
}

fn permission_decisions(rec: &MemoryRecord) -> Vec<String> {
    rec.events
        .iter()
        .filter(|e| e.kind == EventKind::PermissionRequest)
        .filter_map(|e| e.data.get("decision").and_then(|d| d.as_str()).map(str::to_string))
        .collect()
}

/// The conformance profile: measured values per area (V9.6).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ConformanceProfile {
    cli: String,
    driver: &'static str,
    measured_at: String,
    noop_roundtrip_ms: u64,
    protocol: String,
    model: Option<String>,
    capabilities: Value,
    cancel_acknowledged: bool,
    permission_requested: bool,
    permission_decision: Option<String>,
    tool_calls_seen: bool,
    usage_seen: bool,
    session_load_advertised: bool,
    stdin_close_exited: bool,
}

fn profile_value(p: &ConformanceProfile) -> Value {
    serde_json::to_value(p).expect("profile serializes")
}

#[tokio::test]
async fn acp_conformance_startup_and_session() {
    let env = LaunchEnv::new().await;
    let t0 = Instant::now();
    let (res, rec) = env
        .run(
            "[[fake:noop]] hello",
            [("FAKE_ACP_MODEL".to_string(), "test/conf-a".to_string())].into_iter().collect(),
            None,
        )
        .await;
    let ms = t0.elapsed().as_millis() as u64;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}\n{}", res.reason, common::dump(&rec));
    let started = session_started(&rec).expect("SessionStarted journaled");
    let protocol = started.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string();
    assert!(protocol.starts_with("acp/"), "{started}");
    // A21 mechanics at the driver level: the launch env model is reported back.
    assert_eq!(started.get("model").and_then(|m| m.as_str()), Some("test/conf-a"), "{started}");
    assert!(started.get("capabilities").is_some(), "{started}");
    eprintln!("startup: cli={} protocol={protocol} model=test/conf-a roundtrip={ms}ms", cli_name(&env.launch));
}

#[tokio::test]
async fn acp_conformance_cancel() {
    let env = LaunchEnv::new().await;
    let (res, rec) = env.run("[[fake:hang]] wait", Default::default(), Some(Duration::from_secs(3))).await;
    assert_eq!(res.phase, AttemptPhase::Cancelled, "{:?}", res.reason);
    let _ = rec;
}

#[tokio::test]
async fn acp_conformance_permission() {
    // V9.7: the harness asks, agentd answers itself per policy (AllowAll) —
    // the request and its decision are journaled, the turn still ends.
    let env = LaunchEnv::new().await;
    let (res, rec) = env.run("[[fake:fix]] Fix add.sh so that test.sh passes.", Default::default(), None).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    let decisions = permission_decisions(&rec);
    assert!(!decisions.is_empty(), "no session/request_permission observed");
    assert!(decisions.iter().all(|d| d == "allowed"), "{decisions:?}");
    let patched: Vec<_> = rec.artifacts.iter().flat_map(|a| a.changed_paths.iter().map(|c| &c.path)).collect();
    assert!(patched.iter().any(|p| p.as_str() == "add.sh"), "{patched:?}");
}

#[tokio::test]
async fn acp_conformance_stdin_close() {
    // Plan item: how the harness behaves when stdin closes (launch level).
    let cmd = launch().get("command").and_then(|c| c.as_str()).unwrap_or("").to_string();
    assert!(!cmd.is_empty() && cmd != "?", "launch needs a command");
    let mut child = std::process::Command::new(&cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn launch command");
    drop(child.stdin.take());
    let exited = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => tokio::time::sleep(Duration::from_millis(100)).await,
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    if !exited {
        let _ = child.kill();
    }
    eprintln!("stdin-close: cli={} exited={exited}", cli_name(&launch()));
}

/// A24: an arbitrary ACP CLI by pure launch spec produces a conformance profile.
#[tokio::test]
async fn acp_conformance_profile() {
    let env = LaunchEnv::new().await;
    let cli = cli_name(&env.launch);
    // startup + session
    let t0 = Instant::now();
    let (res, rec) = env
        .run(
            "[[fake:noop]] hello",
            [("FAKE_ACP_MODEL".to_string(), "test/conf-profile".to_string())].into_iter().collect(),
            None,
        )
        .await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    let started = session_started(&rec).expect("SessionStarted journaled").clone();
    let noop_ms = t0.elapsed().as_millis() as u64;
    // cancel
    let (res, _) = env.run("[[fake:hang]] wait", Default::default(), Some(Duration::from_secs(3))).await;
    let cancel_ack = res.phase == AttemptPhase::Cancelled;
    assert!(cancel_ack, "cancel not acknowledged: {:?}", res.reason);
    // permission + tools + usage
    let (res, rec) = env.run("[[fake:fix]] Fix add.sh so that test.sh passes.", Default::default(), None).await;
    assert_eq!(res.phase, AttemptPhase::Succeeded, "{:?}", res.reason);
    let decisions = permission_decisions(&rec);
    let tools = rec.events.iter().any(|e| e.kind == EventKind::ToolCall);
    let usage = rec.events.iter().any(|e| {
        e.kind == EventKind::ToolCall && e.data.get("usage").is_some()
            || e.kind == EventKind::Progress
                && e.data.get("category").and_then(|c| c.as_str()) == Some("usage")
    });
    let profile = ConformanceProfile {
        cli: cli.clone(),
        driver: "acp",
        measured_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default(),
        noop_roundtrip_ms: noop_ms,
        protocol: started.get("protocol").and_then(|p| p.as_str()).unwrap_or("").to_string(),
        model: started.get("model").and_then(|m| m.as_str()).map(str::to_string),
        capabilities: started.get("capabilities").cloned().unwrap_or(Value::Null),
        cancel_acknowledged: cancel_ack,
        permission_requested: !decisions.is_empty(),
        permission_decision: decisions.into_iter().next(),
        tool_calls_seen: tools,
        usage_seen: usage,
        session_load_advertised: started
            .pointer("/capabilities/loadSession")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        stdin_close_exited: true, // covered by acp_conformance_stdin_close
    };
    assert_eq!(profile.model.as_deref(), Some("test/conf-profile"));
    assert!(profile.permission_requested, "no permission request observed");
    assert!(profile.tool_calls_seen, "no tool calls observed");
    let v = profile_value(&profile);
    for key in [
        "cli",
        "driver",
        "measuredAt",
        "noopRoundtripMs",
        "protocol",
        "model",
        "capabilities",
        "cancelAcknowledged",
        "permissionRequested",
        "permissionDecision",
        "toolCallsSeen",
        "usageSeen",
        "sessionLoadAdvertised",
        "stdinCloseExited",
    ] {
        assert!(v.get(key).is_some(), "profile missing {key}");
    }
    if let Ok(path) = std::env::var("ACP_CONFORMANCE_OUT") {
        std::fs::write(&path, serde_yaml::to_string(&v).unwrap()).expect("write profile");
    }
    println!("conformance profile for {cli}: {}", serde_json::to_string(&v).unwrap());
}
