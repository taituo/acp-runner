//! End-to-end engine tests without Kubernetes:
//! PostgreSQL journal + ingest API + LocalProcessBackend (real runnerd processes) +
//! deterministic fake agents. Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_core::credentials::{CredentialBundle, Provider, validate_bundle};
use acp_runner_core::events::EventKind;
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::*;
use acp_runner_core::{AttemptPhase, RunPhase};
use acp_runner_engine::backend::{LocalProcessBackend, RunKey};
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, StoredProfile, sync_profiles};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig, RunInput, RunView};
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, PgArtifactStore};
use base64::Engine as _;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// V2: digest-pinned allowlisted test image for credentialed classes.
const TEST_IMAGE: &str = "local@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn bins() -> (PathBuf, PathBuf) {
    static BUILD: std::sync::Once = std::sync::Once::new();
    BUILD.call_once(|| {
        let st = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent"])
            .status()
            .unwrap();
        assert!(st.success());
    });
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    (dir.join("runnerd"), dir.join("fake-acp-agent"))
}

struct H {
    db: Option<TempDb>,
    engine: Arc<Engine>,
    backend: Arc<LocalProcessBackend>,
    creds: Arc<FileCredentialStore>,
    metrics: Arc<Metrics>,
    _tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    fake: PathBuf,
    ingest_url: String,
    refresher: Arc<SwitchableRefresher>,
}

impl H {
    async fn new() -> Option<H> {
        Self::with(|_| {}, 8 * 1024 * 1024).await
    }

    async fn with(tune: impl FnOnce(&mut EngineConfig), inline_limit: u64) -> Option<H> {
        let db = temp_database().await?;
        let (runnerd, fake) = bins();
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("upstream");
        let base_sha = acp_runner_workspace_fixture(&src).await;
        let journal = db.journal.clone();
        let metrics = Arc::new(Metrics::new());
        let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), inline_limit, None));
        let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
        // V1a: write-backs go through the real verifying path (refresh +
        // account binding) with a scripted refresher double. Only the enrolled
        // test refresh token is honored, for the enrolled account; the HTTP
        // fake-endpoint path is covered by codex_refresh unit tests.
        let switchable = Arc::new(SwitchableRefresher::new(Arc::new(FakeCodexRefresher)));
        let mut ingest_state =
            IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None);
        ingest_state.codex_refresher = Some(switchable.clone());
        let state = Arc::new(ingest_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap() });
        // `codex` / `codex-acp` resolve to the fake agent's Codex emulation.
        let fake_codex = tmp.path().join("fake-codex-bin");
        std::fs::create_dir_all(&fake_codex).unwrap();
        for name in ["codex", "codex-acp"] {
            std::os::unix::fs::symlink(&fake, fake_codex.join(name)).unwrap();
        }
        let backend = Arc::new(LocalProcessBackend::new(
            runnerd,
            tmp.path().join("sandboxes"),
            format!("{}:{}", fake_codex.display(), std::env::var("PATH").unwrap_or_default()),
        ));
        let mut cfg = EngineConfig {
            controller_id: "controller-a".into(),
            ingest_url: format!("http://{addr}"),
            active_requeue: Duration::from_millis(200),
            waiting_requeue: Duration::from_millis(300),
            supervision_lease: Duration::from_secs(30),
            // LocalProcessBackend without namespace isolation is not an isolation boundary and
            // has no egress proxy; the proxy requirement is exercised by the isolation and
            // kube_e2e suites.
            require_egress_proxy_for_credentials: false,
            allowed_images: vec![TEST_IMAGE.to_string()],
            ..Default::default()
        };
        tune(&mut cfg);
        let ingest_url = cfg.ingest_url.clone();
        let engine = Arc::new(Engine {
            journal,
            backend: backend.clone(),
            creds: creds.clone(),
            artifacts,
            metrics: metrics.clone(),
            cfg,
        });
        Some(H {
            db: Some(db),
            engine,
            backend,
            creds,
            metrics,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            fake,
            _tmp: tmp,
            ingest_url,
            refresher: switchable,
        })
    }

    fn class(&self, name: &str, scenario: &str) -> RunnerClassSpec {
        RunnerClassSpec {
            name: name.into(),
            driver: "fake".into(),
            driver_config: json!({"command": self.fake.to_string_lossy(), "scenario": scenario}),
            image: TEST_IMAGE.into(),
            image_pull_policy: None,
            runtime_class_name: None,
            resources: None,
            credentials: CredentialRequirement::default(),
            workspace: WorkspacePolicy::default(),
            timeouts: TimeoutPolicy {
                hard_seconds: 60,
                no_progress_seconds: 20,
                grace_seconds: 2,
                heartbeat_seconds: 1,
                startup_seconds: 30,
            },
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            env: [("FAKE_ACP_SCENARIO".to_string(), scenario.to_string())].into_iter().collect(),
            allow_run_overrides: false,
            run_as_user: None,
            service_account_name: None,
        }
    }

    fn input(&self, classes: Vec<RunnerClassSpec>, max_per_runner: u32) -> RunInput {
        self.input_in("default", classes, max_per_runner)
    }

    fn input_in(&self, namespace: &str, classes: Vec<RunnerClassSpec>, max_per_runner: u32) -> RunInput {
        let uid = Uuid::new_v4().to_string();
        RunInput {
            key: RunKey { namespace: namespace.into(), name: format!("run-{}", &uid[..8]), uid },
            spec: RunSpec {
                task_id: "fix-add".into(),
                prompt: "Fix add.sh so that test.sh passes.".into(),
                repository: RepositoryInput {
                    url: self.repo_url.clone(),
                    revision: self.base_sha.clone(),
                    sparse_paths: vec![],
                    depth: None,
                },
                output: OutputExpectation::default(),
                retry: RetryPolicy { max_attempts_per_runner: max_per_runner, max_total_attempts: None },
                timeouts: TimeoutOverrides::default(),
                resume: ResumePolicy::default(),
                runner_classes: classes,
                overrides: RunOverrides::default(),
            },
            cancel: false,
        }
    }

    async fn drive(&self, input: &RunInput, limit: Duration) -> RunView {
        drive_with(&self.engine, input, limit).await
    }

    async fn kinds(&self, run_id: Uuid) -> Vec<String> {
        self.engine.journal.events_for_run(run_id, 0, 10_000).await.unwrap().into_iter().map(|e| e.kind).collect()
    }

    async fn done(mut self) {
        for n in self.backend.names() {
            let _ = self.backend.simulate_disappearance(&n);
        }
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

async fn drive_with(engine: &Engine, input: &RunInput, limit: Duration) -> RunView {
    let start = Instant::now();
    loop {
        let v = engine.reconcile(input).await.expect("reconcile");
        if v.phase.is_terminal() || start.elapsed() > limit {
            return v;
        }
        tokio::time::sleep(v.requeue_after.unwrap_or(Duration::from_millis(200)).max(Duration::from_millis(100))).await;
    }
}

async fn acp_runner_workspace_fixture(dir: &std::path::Path) -> String {
    // same fixture as the workspace crate (kept local to avoid a dev-dependency cycle)
    tokio::fs::create_dir_all(dir).await.unwrap();
    std::fs::write(
        dir.join("add.sh"),
        "#!/bin/sh\n# add A B -> prints A+B\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("test.sh"), "#!/bin/sh\nset -e\nout=$(sh \"$(dirname \"$0\")/add.sh\" 2 3)\nif [ \"$out\" = \"5\" ]; then echo PASS; exit 0; fi\necho \"FAIL: expected 5, got $out\"; exit 1\n").unwrap();
    let git = |args: &[&str]| {
        let st = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
        String::from_utf8_lossy(&st.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "buggy"]);
    git(&["rev-parse", "HEAD"])
}

fn has(kinds: &[String], k: EventKind) -> bool {
    kinds.iter().any(|x| x == k.as_str())
}

// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn fake_run_succeeds_with_journal_and_patch_artifact() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("fake-default", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    assert_eq!(v.attempt_count, 1);
    let art = v.artifact.clone().expect("artifact");
    assert_eq!(art.kind, "patch");
    assert_eq!(art.base_revision, h.base_sha);
    let content = h.engine.artifacts.get_content(art.id).await.unwrap();
    assert!(String::from_utf8_lossy(&content).contains("+  echo $(( $1 + $2 ))"));
    let kinds = h.kinds(v.run_id).await;
    for k in [
        EventKind::RunCreated,
        EventKind::AttemptStarted,
        EventKind::AgentStarted,
        EventKind::SessionStarted,
        EventKind::InputSent,
        EventKind::AgentOutput,
        EventKind::ToolCall,
        EventKind::ToolResult,
        EventKind::PermissionRequest,
        EventKind::Progress,
        EventKind::ArtifactCreated,
        EventKind::Heartbeat,
        EventKind::AttemptCompleted,
        EventKind::RunCompleted,
    ] {
        assert!(has(&kinds, k), "missing {k}: {kinds:?}");
    }
    // the sandbox is gone and the attempt is marked released
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert!(a.sandbox_released_at.is_some());
    assert!(a.last_heartbeat_at.is_some());
    assert!(h.backend.names().is_empty());
    let m = h.metrics.render();
    assert!(m.contains("acp_runner_attempts_total"));
    h.done().await;
}

#[tokio::test]
async fn crashed_attempt_is_retried_with_resume_capsule() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("fake-flaky", "crash-until:2")], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::ProcessCrashed { .. })), "{:?}", attempts[0].failure());
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.capsule.is_some());
    assert!(spec2.prompt.contains("resume capsule"));
    assert!(spec2.prompt.contains("ProcessCrashed"));
    assert!(has(&h.kinds(v.run_id).await, EventKind::AttemptFailed));
    h.done().await;
}

#[tokio::test]
async fn fallback_to_another_runner_class_starts_a_new_session() {
    let Some(h) = H::new().await else { return };
    let mut b = h.class("fallback-b", "fix");
    b.driver_config["scenario"] = json!("fix");
    let input = h.input(vec![h.class("primary-a", "crash"), b], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    let classes: Vec<_> = attempts.iter().map(|a| a.runner_class.as_str()).collect();
    assert_eq!(classes, vec!["primary-a", "primary-a", "fallback-b"]);
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    let started: Vec<_> = evs.iter().filter(|e| e.kind == "AttemptStarted").collect();
    assert_eq!(started[2].data["fallback"], true);
    // fallback = new provider session: distinct session ids
    let sessions: Vec<_> = evs
        .iter()
        .filter(|e| e.kind == "SessionStarted")
        .filter_map(|e| e.data.get("providerSessionId").and_then(|s| s.as_str()).map(str::to_string))
        .collect();
    let uniq: std::collections::HashSet<_> = sessions.iter().collect();
    assert_eq!(uniq.len(), sessions.len());
    assert!(h.metrics.render().contains("acp_runner_fallbacks_total{from_driver=\"fake\",to_driver=\"fake\"} 1"));
    h.done().await;
}

#[tokio::test]
async fn hung_agent_times_out_then_fallback_succeeds() {
    let Some(h) = H::new().await else { return };
    let mut hung = h.class("hung", "hang");
    hung.timeouts.no_progress_seconds = 2;
    let input = h.input(vec![hung, h.class("good", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts[0].phase(), AttemptPhase::TimedOut);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::NoProgressTimeout { seconds: 2 })));
    assert!(has(&h.kinds(v.run_id).await, EventKind::AttemptTimedOut));
    assert!(h.metrics.render().contains("acp_runner_timeouts_total"));
    // detected by the controller (agent-progress signal) and delivered as a heartbeat directive
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(
        evs.iter().any(|e| e.source == "controller" && e.data["category"] == "no_progress_detected"),
        "controller did not detect the missing progress"
    );
    assert!(attempts[0].cancel_requested_at.is_some());
    h.done().await;
}

#[tokio::test]
async fn hung_agentd_is_cancelled_then_sandbox_killed_and_retried() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("hang-once", "hang-until:2");
    c.timeouts.no_progress_seconds = 3;
    c.timeouts.grace_seconds = 1;
    let input = h.input(vec![c], 2);
    let start = Instant::now();
    let name = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break h.backend.names().pop().unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // agentd (the agent container) freezes: no events, no reaction to Cancel.
    assert!(h.backend.simulate_agentd_hang(&name));
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].phase(), AttemptPhase::TimedOut);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::NoProgressTimeout { seconds: 3 })));
    assert!(attempts[0].sandbox_released_at.is_some(), "the frozen sandbox was not terminated");
    let evs = h.engine.journal.events_for_attempt(attempts[0].id, &[EventKind::Progress], 1000).await.unwrap();
    let cats: Vec<String> = evs.iter().filter_map(|e| e.data["category"].as_str().map(str::to_string)).collect();
    assert!(cats.contains(&"no_progress_detected".to_string()), "{cats:?}");
    assert!(cats.contains(&"agent_unresponsive".to_string()), "{cats:?}");
    assert!(!h.backend.names().contains(&name), "frozen agentd still registered");
    h.done().await;
}

#[tokio::test]
async fn sandbox_disappearance_is_detected_and_retried() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("hang-long", "hang"), h.class("good", "fix")], 1);
    // drive until the first attempt is running
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "attempt never started: {v:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().expect("sandbox");
    assert!(h.backend.simulate_disappearance(&name));
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert!(matches!(attempts[0].failure(), Some(FailureReason::SandboxLost { .. })), "{:?}", attempts[0].failure());
    h.done().await;
}

#[tokio::test]
async fn frozen_runnerd_is_detected_by_heartbeat_loss() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("hang-long", "hang");
    c.timeouts.no_progress_seconds = 300;
    let input = h.input(vec![c, h.class("good", "fix")], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running && c.last_heartbeat_at.is_some()) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().unwrap();
    assert!(h.backend.simulate_hang(&name));
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert!(matches!(attempts[0].failure(), Some(FailureReason::HeartbeatLost { .. })), "{:?}", attempts[0].failure());
    h.done().await;
}

#[tokio::test]
async fn stale_controller_is_taken_over_by_another_instance() {
    let Some(h) = H::with(|c| c.supervision_lease = Duration::from_secs(2), 8 << 20).await else { return };
    let mut slow = h.class("slow", "slow:25");
    slow.timeouts.no_progress_seconds = 30;
    let input = h.input(vec![slow], 1);
    // controller A starts the attempt, then "crashes" (stops reconciling)
    let v = h.engine.reconcile(&input).await.unwrap();
    assert!(v.current.is_some());
    // controller B shares journal + cluster (backend) but has another identity
    let b = Engine {
        journal: h.engine.journal.clone(),
        backend: h.backend.clone(),
        creds: h.creds.clone(),
        artifacts: h.engine.artifacts.clone(),
        metrics: Arc::new(Metrics::new()),
        cfg: EngineConfig { controller_id: "controller-b".into(), ..h.engine.cfg.clone() },
    };
    let v = drive_with(&b, &input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(
        evs.iter().any(|e| e.kind == "Progress" && e.data["category"] == "supervision_takeover"),
        "no takeover event"
    );
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert_eq!(a.lease_owner.as_deref(), Some("controller-b"));
    h.done().await;
}

fn fake_id_jwt(account: &str) -> String {
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let claims = json!({"email":"a@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"plus","chatgpt_account_id":account}});
    format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
}

fn fake_codex_auth(account: &str) -> Vec<u8> {
    fake_codex_auth_rt(account, "rt_test_refresh_token_value_0000000000")
}

fn fake_codex_auth_rt(account: &str, rt: &str) -> Vec<u8> {
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let jwt = |claims: serde_json::Value| {
        format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
    };
    json!({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"id_token": fake_id_jwt(account),
                   "access_token": jwt(json!({"exp": 1900000000})), "refresh_token": rt, "account_id": account},
        "last_refresh": "2026-09-20T00:00:00Z"
    })
    .to_string()
    .into_bytes()
}

/// V1a refresher indirection: the ingest server delegates to whatever is
/// installed here, so a test can swap the provider double mid-run (e.g. to a
/// blocking one) without rebuilding the harness.
struct SwitchableRefresher(std::sync::RwLock<Arc<dyn acp_runner_engine::codex_refresh::CodexRefresher>>);

impl SwitchableRefresher {
    fn new(inner: Arc<dyn acp_runner_engine::codex_refresh::CodexRefresher>) -> Self {
        Self(std::sync::RwLock::new(inner))
    }

    fn swap(&self, inner: Arc<dyn acp_runner_engine::codex_refresh::CodexRefresher>) {
        *self.0.write().unwrap() = inner;
    }
}

#[async_trait::async_trait]
impl acp_runner_engine::codex_refresh::CodexRefresher for SwitchableRefresher {
    async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<acp_runner_engine::codex_refresh::RefreshedTokens, acp_runner_engine::codex_refresh::RefreshError>
    {
        // Clone the Arc out of the lock so no lock is held across the call.
        let inner = self.0.read().unwrap().clone();
        inner.refresh(refresh_token).await
    }
}

/// V1a scripted provider double: only the enrolled test refresh token works,
/// and it binds the enrolled account with a rotated refresh token.
struct FakeCodexRefresher;

#[async_trait::async_trait]
impl acp_runner_engine::codex_refresh::CodexRefresher for FakeCodexRefresher {
    async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<acp_runner_engine::codex_refresh::RefreshedTokens, acp_runner_engine::codex_refresh::RefreshError>
    {
        use acp_runner_engine::codex_refresh::{RefreshError, RefreshedTokens};
        if refresh_token != "rt_test_refresh_token_value_0000000000" {
            return Err(RefreshError::Permanent { reason: "invalid_grant".into() });
        }
        Ok(RefreshedTokens {
            access_token: "access-e2e-rotated".into(),
            id_token: fake_id_jwt("acct-1"),
            refresh_token: Some("rt_test_refresh_token_value_0000000001".into()),
            account_id: "acct-1".into(),
        })
    }
}

/// Refresh token honored only by [`BlockingRefresher`] below.
const BLOCKING_RT: &str = "rt_block_for_race_test";

/// V1a race-test double: blocks inside `refresh` (i.e. *after* the ingest
/// took the `FOR UPDATE` write-back guard) until released, then binds acct-1
/// with a rotated token.
struct BlockingRefresher {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl acp_runner_engine::codex_refresh::CodexRefresher for BlockingRefresher {
    async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<acp_runner_engine::codex_refresh::RefreshedTokens, acp_runner_engine::codex_refresh::RefreshError>
    {
        use acp_runner_engine::codex_refresh::{RefreshError, RefreshedTokens};
        if refresh_token != BLOCKING_RT {
            return Err(RefreshError::Permanent { reason: "invalid_grant".into() });
        }
        self.entered.notify_one();
        self.release.notified().await;
        Ok(RefreshedTokens {
            access_token: "access-race-rotated".into(),
            id_token: fake_id_jwt("acct-1"),
            refresh_token: Some("rt_block_for_race_test_rotated".into()),
            account_id: "acct-1".into(),
        })
    }
}

async fn enroll_codex(h: &H, name: &str, classes: &[&str]) {
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: name.into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: classes.iter().map(|c| c.to_string()).collect(),
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
}

#[tokio::test]
async fn exclusive_credential_lease_serializes_runs_and_writeback_is_validated() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1", &["codexish", "codexish-refresh"]).await;
    // codex profiles are exclusive regardless of the requested max
    assert_eq!(h.engine.journal.get_profile("codex-1").await.unwrap().unwrap().max_concurrent_leases, 1);
    let mut c = h.class("codexish", "slow:10");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    let mut r = h.class("codexish-refresh", "refresh-credential");
    r.credentials = c.credentials.clone();
    let in1 = h.input(vec![c], 1);
    let in2 = h.input(vec![r], 1);
    let v1 = h.engine.reconcile(&in1).await.unwrap();
    assert_eq!(v1.current.as_ref().unwrap().credential_profile.as_deref(), Some("codex-1"));
    let v2 = h.engine.reconcile(&in2).await.unwrap();
    assert!(v2.current.is_none());
    assert!(v2.waiting_reason.as_deref().unwrap_or("").contains("credential lease"), "{v2:?}");
    let (a, b) = tokio::join!(h.drive(&in1, Duration::from_secs(60)), h.drive(&in2, Duration::from_secs(90)));
    assert_eq!(a.phase, RunPhase::Succeeded, "{a:?}");
    assert_eq!(b.phase, RunPhase::Succeeded, "{b:?}");
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    // the refreshed auth.json went through validated write-back into the store
    let (_, bundle) = h.creds.load("codex-1").await.unwrap();
    // V1a: the stored file is controller-built from the provider response,
    // never the agent-submitted bytes: rotated refresh token, provider-bound
    // access token and account, fresh last_refresh.
    let stored = String::from_utf8_lossy(&bundle["auth.json"]);
    let stored_json: serde_json::Value = serde_json::from_slice(&bundle["auth.json"]).unwrap();
    assert_eq!(stored_json["auth_mode"], json!("chatgpt"), "{stored}");
    assert_eq!(stored_json["tokens"]["access_token"], json!("access-e2e-rotated"), "{stored}");
    assert_eq!(stored_json["tokens"]["refresh_token"], json!("rt_test_refresh_token_value_0000000001"), "{stored}");
    assert_eq!(stored_json["tokens"]["account_id"], json!("acct-1"), "{stored}");
    assert!(stored_json["last_refresh"].as_str().is_some(), "{stored}");
    assert!(!stored.contains("\"refreshed\""), "agent bytes reached the store: {stored}");
    let p = h.engine.journal.get_profile("codex-1").await.unwrap().unwrap();
    assert!(p.generation >= 1);
    assert!(h.metrics.render().contains("acp_runner_credential_writebacks_total{result=\"accepted\",reason=\"ok\"} 1"));
    h.done().await;
}

const FAKE_CLAUDE_TOKEN: &str = "sk-ant-oat01-e2eFAKEtokenFAKEtokenFAKEtoken000000";

async fn enroll_claude(h: &H, name: &str, classes: &[&str]) {
    let mut bundle = CredentialBundle::new();
    bundle.insert("oauth-token".into(), FAKE_CLAUDE_TOKEN.as_bytes().to_vec());
    let md = validate_bundle(Provider::Claude, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: name.into(),
                provider: Provider::Claude,
                max_concurrent_leases: 2,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: classes.iter().map(|c| c.to_string()).collect(),
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
}

/// DoD: Claude fails (subscription login rejected) -> fallback to Codex in a new session with
/// a resume capsule; Codex authenticates from the leased auth.json, refreshes it, and the
/// refreshed file is validated and written back. No credential value reaches the journal.
#[tokio::test]
async fn claude_failure_falls_back_to_codex_with_refresh_writeback() {
    let Some(h) = H::new().await else { return };
    enroll_claude(&h, "claude-max-1", &["claude-max"]).await;
    enroll_codex(&h, "codex-personal-1", &["codex-personal"]).await;
    let mut claude = h.class("claude-max", "auth-fail");
    claude.driver = "claude".into();
    claude.driver_config = json!({"command": h.fake.to_string_lossy(), "commandArgs": ["claude-mode"]});
    claude.credentials = CredentialRequirement {
        provider: Some("claude".into()),
        profiles: vec!["claude-max-1".into()],
        file_targets: BTreeMap::new(),
    };
    let mut codex = h.class("codex-personal", "refresh-credential");
    codex.driver = "codex".into();
    codex.driver_config = json!({});
    codex.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-personal-1".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![claude, codex], 2);
    let v = h.drive(&input, Duration::from_secs(90)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2, "an auth failure must not be retried on the same class");
    assert!(
        matches!(attempts[0].failure(), Some(FailureReason::AuthEnrollmentRequired { ref provider, .. }) if provider == "claude"),
        "{:?}",
        attempts[0].failure()
    );
    assert_eq!(attempts[1].driver, "codex");
    assert_eq!(attempts[1].phase(), AttemptPhase::Succeeded);
    assert!(attempts[1].driver_version.as_deref().unwrap_or("").contains("fake"), "{:?}", attempts[1].driver_version);
    // the rejected Claude login is flagged for re-enrollment
    assert_eq!(h.engine.journal.get_profile("claude-max-1").await.unwrap().unwrap().status, "needs_reauth");
    // resume capsule across providers
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.prompt.contains("AuthEnrollmentRequired"), "{}", spec2.prompt);
    // Codex refreshed its auth.json; the refreshed copy went through validated write-back
    let (_, bundle) = h.creds.load("codex-personal-1").await.unwrap();
    // V1a: the stored file is controller-built from the provider response,
    // never the agent-submitted bytes: rotated refresh token, provider-bound
    // access token and account, fresh last_refresh.
    let stored = String::from_utf8_lossy(&bundle["auth.json"]);
    let stored_json: serde_json::Value = serde_json::from_slice(&bundle["auth.json"]).unwrap();
    assert_eq!(stored_json["auth_mode"], json!("chatgpt"), "{stored}");
    assert_eq!(stored_json["tokens"]["access_token"], json!("access-e2e-rotated"), "{stored}");
    assert_eq!(stored_json["tokens"]["refresh_token"], json!("rt_test_refresh_token_value_0000000001"), "{stored}");
    assert_eq!(stored_json["tokens"]["account_id"], json!("acct-1"), "{stored}");
    assert!(stored_json["last_refresh"].as_str().is_some(), "{stored}");
    assert!(!stored.contains("\"refreshed\""), "agent bytes reached the store: {stored}");
    assert!(h.metrics.render().contains("acp_runner_credential_writebacks_total{result=\"accepted\",reason=\"ok\"} 1"));
    // agent events are tagged as untrusted, the terminal events as runnerd's
    let evs = h.engine.journal.events_for_run(v.run_id, 0, 10_000).await.unwrap();
    assert!(evs.iter().filter(|e| e.kind == "SessionStarted").all(|e| e.source == "agent"));
    assert!(evs.iter().filter(|e| e.kind == "AttemptCompleted").all(|e| e.source == "runnerd"));
    assert_eq!(evs.iter().filter(|e| e.kind == "SessionStarted").count(), 2);
    // no credential material anywhere in the journal
    let all = serde_json::to_string(&evs.iter().map(|e| (&e.data, &e.raw)).collect::<Vec<_>>()).unwrap();
    for secret in [FAKE_CLAUDE_TOKEN, "rt_test_refresh_token_value_0000000000"] {
        assert!(!all.contains(secret), "credential leaked into the journal");
    }
    h.done().await;
}

#[tokio::test]
async fn missing_credential_profile_skips_to_fallback() {
    let Some(h) = H::new().await else { return };
    let mut c = h.class("claude-default", "fix");
    c.credentials = CredentialRequirement {
        provider: Some("claude".into()),
        profiles: vec!["not-enrolled".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c, h.class("fallback", "fix")], 3);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 2, "must not retry an unusable class");
    assert!(matches!(attempts[0].failure(), Some(FailureReason::CredentialUnavailable { .. })));
    h.done().await;
}

#[tokio::test]
async fn cancellation_terminates_sandbox_and_releases_lease() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-2", &["hang"]).await;
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-2".into()],
        file_targets: BTreeMap::new(),
    };
    let mut input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    input.cancel = true;
    let v = h.engine.reconcile(&input).await.unwrap();
    assert_eq!(v.phase, RunPhase::Cancelled);
    assert!(h.backend.names().is_empty());
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    let a = &h.engine.journal.attempts_for_run(v.run_id).await.unwrap()[0];
    assert_eq!(a.phase(), AttemptPhase::Cancelled);
    h.done().await;
}

#[tokio::test]
async fn oversized_artifact_is_rejected_by_ingest() {
    let Some(h) = H::with(|_| {}, 64).await else { return };
    let input = h.input(vec![h.class("fake", "fix")], 1);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(matches!(v.failure, Some(FailureReason::ArtifactTooLarge { limit_bytes: 64, .. })), "{:?}", v.failure);
    h.done().await;
}

#[tokio::test]
async fn previous_partial_patch_can_be_applied_for_the_next_attempt() {
    let Some(h) = H::new().await else { return };
    let mut input = h.input(vec![h.class("crashy", "fix-then-crash"), h.class("noop", "noop")], 1);
    input.spec.resume.apply_previous_patch = true;
    let v = h.drive(&input, Duration::from_secs(60)).await;
    // attempt 2 made no changes itself, but its workspace started with attempt 1's patch
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    let spec2: acp_runner_core::AttemptSpec = serde_json::from_value(attempts[1].spec.clone()).unwrap();
    assert!(spec2.apply_patch_b64.is_some());
    assert!(spec2.capsule.unwrap().previous_artifact.unwrap().applied_to_workspace);
    h.done().await;
}

#[tokio::test]
async fn ingest_rejects_bad_tokens_and_forbidden_event_kinds() {
    let Some(h) = H::new().await else { return };
    let client = reqwest_like::Client::new();
    let url = format!("{}/v1/attempt", h.ingest_url);
    assert_eq!(client.get(&url, Some("x".repeat(64).as_str())).await, 401);
    assert_eq!(client.get(&url, None).await, 401);
    h.done().await;
}

#[tokio::test]
async fn ingest_refuses_agent_sourced_authoritative_events_even_with_a_valid_token() {
    let Some(h) = H::new().await else { return };
    let input = h.input(vec![h.class("hang", "hang")], 1);
    let start = Instant::now();
    let v = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break v;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // Read the token the way only runnerd can (from the sandbox's secret directory).
    let name = h.backend.names().pop().unwrap();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&name).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/events", h.ingest_url);
    let client = reqwest_like::Client::new();
    for kind in ["AttemptCompleted", "ArtifactCreated", "Heartbeat", "AgentStarted"] {
        let body = json!({"events": [{"seq": 900_000, "ts": "2026-09-26T00:00:00Z", "kind": kind, "source": "agent",
                                       "data": {"artifactId": Uuid::nil()}}]});
        assert_eq!(client.post(&url, &token, &body.to_string()).await, 400, "{kind}");
    }
    // A plain agent message is fine.
    let ok = json!({"events": [{"seq": 900_001, "ts": "2026-09-26T00:00:00Z", "kind": "AgentOutput", "source": "agent",
                                 "data": {"channel": "message", "text": "hi"}}]});
    assert_eq!(client.post(&url, &token, &ok.to_string()).await, 200);
    let a = h.engine.journal.get_attempt(v.current.unwrap().id).await.unwrap();
    assert!(a.phase().is_active(), "a forged agent event changed the attempt state");
    h.done().await;
}

#[tokio::test]
async fn ingest_rejects_a_foreign_terminal_artifact_id() {
    // V3a: a terminal artifactId from another attempt fails this attempt with
    // ProtocolError and is never attached.
    let Some(h) = H::new().await else { return };
    let v1 = h.drive(&h.input(vec![h.class("fake", "fix")], 1), Duration::from_secs(60)).await;
    assert_eq!(v1.phase, RunPhase::Succeeded, "{v1:?}");
    let foreign = h.engine.journal.attempts_for_run(v1.run_id).await.unwrap()[0]
        .artifact_id
        .expect("attempt 1 must have an artifact");
    let input = h.input(vec![h.class("hang", "hang")], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().unwrap();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&name).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/events", h.ingest_url);
    let client = reqwest_like::Client::new();
    // An agent-sourced reserved Progress category is rejected outright.
    let forged = json!({"events": [{"seq": 901_000, "ts": "2026-09-26T00:00:00Z", "kind": "Progress",
                                    "source": "agent",
                                    "data": {"category": "workspace_ready",
                                             "message": "forged",
                                             "detail": {"baseRevision": "0".repeat(40)}}} ]});
    assert_eq!(client.post(&url, &token, &forged.to_string()).await, 400);
    // A runnerd-sourced terminal event pointing at the other attempt's artifact.
    let body = json!({"events": [{"seq": 901_001, "ts": "2026-09-26T00:00:00Z", "kind": "AttemptCompleted",
                                  "source": "runnerd", "data": {"artifactId": foreign}}]});
    assert_eq!(client.post(&url, &token, &body.to_string()).await, 200);
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    let attempts = h.engine.journal.attempts_for_run(v.run_id).await.unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].phase(), AttemptPhase::Failed);
    assert!(matches!(attempts[0].failure(), Some(FailureReason::ProtocolError { .. })), "{:?}", attempts[0].failure());
    assert_eq!(attempts[0].artifact_id, None, "foreign artifact was attached");
    h.done().await;
}

/// V1a PoC (review findings 1 + 10): a forged plaintext `account_id` and a PAT
/// swap are rejected — only the provider-bound account is accepted.
#[tokio::test]
async fn writeback_rejects_forged_account_and_pat_swap() {
    let Some(h) = H::new().await else { return };
    // Enrolled as victim-acct, but holding the test refresh token the fake
    // provider binds to acct-1: the submitted plaintext account must lose.
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth_rt("victim-acct", "rt_test_refresh_token_value_0000000000"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-victim".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-victim".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let name = h.backend.names().pop().unwrap();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&name).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    // Forged plaintext account (matches enrollment) + valid refresh token
    // (binds acct-1 at the provider): rejected, nothing stored.
    assert_eq!(
        cred_post(client.clone(), url.clone(), token.clone(), fake_codex_auth_rt("victim-acct", "rt_test_refresh_token_value_0000000000"))
            .await,
        422
    );
    // PAT swap: no refresh token at all.
    assert_eq!(
        cred_post(client.clone(), url.clone(), token.clone(), br#"{"auth_mode":"personalAccessToken","personal_access_token":{"token":"pat-evil"}}"#.to_vec())
            .await,
        422
    );
    // Garbage refresh token.
    assert_eq!(cred_post(client.clone(), url.clone(), token.clone(), fake_codex_auth_rt("victim-acct", "garbage-rt")).await, 422);
    let (_, stored) = h.creds.load("codex-victim").await.unwrap();
    assert_eq!(stored["auth.json"], fake_codex_auth_rt("victim-acct", "rt_test_refresh_token_value_0000000000"));
    let rendered = h.metrics.render();
    assert!(rendered.contains("reason=\"account-mismatch\""), "{rendered}");
    assert!(rendered.contains("reason=\"no-refresh-token\""), "{rendered}");
    assert!(rendered.contains("reason=\"refresh-rejected\""), "{rendered}");
    h.done().await;
}

/// Finding 10: a write-back racing cancellation is still accepted inside the
/// terminal window while the lease is unreleased.
#[tokio::test]
async fn writeback_accepted_in_terminal_window() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1", &["hang"]).await;
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    let attempt_id = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if let Some(cur) = &v.current
            && cur.phase == AttemptPhase::Running
        {
            break cur.id;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // Cancel out-of-band (no cleanup runs, so the lease stays held).
    h.engine
        .journal
        .transition_attempt(
            attempt_id,
            &AttemptPhase::ACTIVE,
            AttemptPhase::Cancelled,
            Some(&FailureReason::Cancelled { detail: "test cancel".into() }),
            None,
        )
        .await
        .unwrap();
    let names = h.backend.names();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&names[0]).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    let body = json!({"key": "auth.json", "contentB64": base64::engine::general_purpose::STANDARD.encode(fake_codex_auth("acct-1"))})
        .to_string();
    assert_eq!(client.post(&url, &token, &body).await, 204);
    let (_, stored) = h.creds.load("codex-1").await.unwrap();
    assert!(String::from_utf8_lossy(&stored["auth.json"]).contains("rt_test_refresh_token_value_0000000001"));
    h.done().await;
}

async fn cred_post(client: reqwest_like::Client, url: String, token: String, content: Vec<u8>) -> u16 {
    let body = json!({"key": "auth.json", "contentB64": base64::engine::general_purpose::STANDARD.encode(&content)})
        .to_string();
    client.post(&url, &token, &body).await
}

/// Finding 10, coordinated: a write-back whose provider refresh is in flight
/// (write-back guard holding `FOR UPDATE`) races a real `Engine` cancel. The
/// cancel's lease release must wait for the guard; after release the POST
/// completes 204, the cancel completes, and the lease ends released.
///
/// Window semantics (see `authenticate_for_credential`): a write-back is
/// accepted while the attempt is active, or terminal with `finished_at` < 10
/// min ago **and** the lease still unreleased. Once cleanup has released the
/// lease, late posts are intentionally denied (`lease-lost`): no live sandbox
/// remains that could use refreshed tokens, and the profile may already be
/// leased to another attempt.
#[tokio::test]
async fn writeback_race_with_cancel_keeps_lease_until_guard_commits() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth_rt("acct-1", BLOCKING_RT));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-race".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-race".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    let attempt_id = loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if let Some(cur) = &v.current
            && cur.phase == AttemptPhase::Running
        {
            break cur.id;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let names = h.backend.names();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&names[0]).join("secret/token")).unwrap();
    // Arm the blocking refresher, then start the write-back: it blocks inside
    // `refresh`, i.e. after the guard took the FOR UPDATE lease lock.
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    h.refresher.swap(Arc::new(BlockingRefresher { entered: entered.clone(), release: release.clone() }));
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    let content = fake_codex_auth_rt("acct-1", BLOCKING_RT);
    let post = tokio::spawn(cred_post(client, url, token, content));
    entered.notified().await;
    // Real cancel while the guard is held: cleanup must block on release.
    let mut cancel_input = input.clone();
    cancel_input.cancel = true;
    let engine = h.engine.clone();
    let mut cancelled = tokio::spawn(async move { engine.reconcile(&cancel_input).await });
    assert!(
        tokio::time::timeout(Duration::from_secs(3), &mut cancelled).await.is_err(),
        "cancel completed while the write-back guard was held"
    );
    let lease = h.engine.journal.lease_for_attempt(attempt_id).await.unwrap().expect("lease row");
    assert!(lease.released_at.is_none(), "lease released under an active guard");
    // Unblock: the POST stores controller-built tokens and commits, the
    // cancel's release then proceeds.
    release.notify_one();
    assert_eq!(post.await.unwrap(), 204);
    let v = cancelled.await.unwrap().unwrap();
    assert_eq!(v.phase, RunPhase::Cancelled, "{v:?}");
    let lease = h.engine.journal.lease_for_attempt(attempt_id).await.unwrap().expect("lease row");
    assert!(lease.released_at.is_some(), "lease was never released after cancel");
    let (_, stored) = h.creds.load("codex-race").await.unwrap();
    assert!(String::from_utf8_lossy(&stored["auth.json"]).contains("rt_block_for_race_test_rotated"));
    h.done().await;
}

/// Write-back vs concurrent `sync_profiles`: the guard holds the profile row
/// locked across the refresh, so a profile sync racing the write-back blocks
/// instead of overwriting the committed metadata with stale data afterwards.
#[tokio::test]
async fn writeback_race_with_profile_sync_keeps_committed_metadata() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth_rt("acct-1", BLOCKING_RT));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-syncrace".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let gen0 = h.engine.journal.get_profile("codex-syncrace").await.unwrap().expect("profile").generation;
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-syncrace".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let names = h.backend.names();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&names[0]).join("secret/token")).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    h.refresher.swap(Arc::new(BlockingRefresher { entered: entered.clone(), release: release.clone() }));
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    let content = fake_codex_auth_rt("acct-1", BLOCKING_RT);
    let post = tokio::spawn(cred_post(client, url, token, content));
    entered.notified().await;
    // A profile sync racing the in-flight refresh must wait on the profile
    // row lock instead of racing past it.
    let creds = h.creds.clone();
    let journal = h.engine.journal.clone();
    let mut synced =
        tokio::spawn(async move { sync_profiles(creds.as_ref(), &journal).await });
    assert!(
        tokio::time::timeout(Duration::from_secs(3), &mut synced).await.is_err(),
        "profile sync completed while the write-back guard was held"
    );
    release.notify_one();
    assert_eq!(post.await.unwrap(), 204);
    assert_eq!(synced.await.unwrap().unwrap(), 1);
    // The committed metadata matches the store file (no stale overwrite) and
    // generation advanced exactly once (the write-back commit; the racing sync
    // saw identical fingerprints and bumped nothing).
    let (_, stored) = h.creds.load("codex-syncrace").await.unwrap();
    let prof = h.engine.journal.get_profile("codex-syncrace").await.unwrap().expect("profile");
    let stored_md: serde_json::Value = serde_json::from_slice(&stored["auth.json"]).unwrap();
    assert_eq!(stored_md["tokens"]["refresh_token"], json!("rt_block_for_race_test_rotated"));
    let file_fp = acp_runner_core::credentials::fingerprint(&stored["auth.json"]);
    assert_eq!(prof.material_fingerprint.as_deref(), Some(file_fp.as_str()), "profile regressed");
    assert_eq!(prof.generation, gen0 + 1, "unexpected generation bump");
    h.done().await;
}

/// Re-enrollment changes the account mid-lease: the write-back must authorize
/// against the locked *current* profile row, never lease-time (stale)
/// metadata. Here the admin re-enrolls acct-1 → acct-2 before the POST, so a
/// refresh binding acct-1 is rejected even though the lease was granted under
/// acct-1.
///
/// Known limitation (documented, out of scope): the credential *file* itself
/// is last-writer-wins at the filesystem level. The DB authorization record
/// stays consistent via the profile row lock.
#[tokio::test]
async fn writeback_rejects_after_reenrollment_changed_account() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-reenroll".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-reenroll".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Admin re-enrolls the same profile for a different account. The live
    // lease (granted under acct-1) does not entitle the old account anymore.
    let reenroll_bytes = fake_codex_auth_rt("acct-2", "rt_reenroll_never_used");
    let mut b = CredentialBundle::new();
    b.insert("auth.json".into(), reenroll_bytes.clone());
    let md = validate_bundle(Provider::Codex, &b).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-reenroll".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &b,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let names = h.backend.names();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&names[0]).join("secret/token")).unwrap();
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    // Refresh binds acct-1; the locked profile now says acct-2: reject.
    assert_eq!(cred_post(client, url, token, fake_codex_auth("acct-1")).await, 422);
    let (_, stored) = h.creds.load("codex-reenroll").await.unwrap();
    assert_eq!(stored["auth.json"], reenroll_bytes, "rejected write-back touched the store");
    let rendered = h.metrics.render();
    assert!(rendered.contains("reason=\"account-mismatch\""), "{rendered}");
    h.done().await;
}

/// Write-back vs concurrent admin save: the store compares against the
/// authorized baseline fingerprint, so an enrollment that landed mid-flight
/// is not clobbered — the conflicting write-back is denied with 409 and both
/// the store file and the profile row keep the newer enrollment.
#[tokio::test]
async fn writeback_race_with_admin_save_keeps_newer_enrollment() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth_rt("acct-1", BLOCKING_RT));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-savrace".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let mut c = h.class("hang", "hang");
    c.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-savrace".into()],
        file_targets: BTreeMap::new(),
    };
    let input = h.input(vec![c], 1);
    let start = Instant::now();
    loop {
        let v = h.engine.reconcile(&input).await.unwrap();
        if v.current.as_ref().is_some_and(|c| c.phase == AttemptPhase::Running) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let names = h.backend.names();
    let token = std::fs::read_to_string(h._tmp.path().join("sandboxes").join(&names[0]).join("secret/token")).unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    h.refresher.swap(Arc::new(BlockingRefresher { entered: entered.clone(), release: release.clone() }));
    let url = format!("{}/v1/attempt/credential", h.ingest_url);
    let client = reqwest_like::Client::new();
    let content = fake_codex_auth_rt("acct-1", BLOCKING_RT);
    let post = tokio::spawn(cred_post(client, url, token, content));
    entered.notified().await;
    // Admin re-enrolls mid-flight (store files replaced; no sync yet).
    let admin_bytes = fake_codex_auth_rt("acct-2", "rt_admin_savrace");
    let mut b = CredentialBundle::new();
    b.insert("auth.json".into(), admin_bytes.clone());
    let md = validate_bundle(Provider::Codex, &b).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-savrace".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 5,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["hang".into()],
                store_ref: String::new(),
            },
            &b,
        )
        .await
        .unwrap();
    release.notify_one();
    assert_eq!(post.await.unwrap(), 409);
    let (_, stored) = h.creds.load("codex-savrace").await.unwrap();
    assert_eq!(stored["auth.json"], admin_bytes, "stale write-back clobbered the newer enrollment");
    let rendered = h.metrics.render();
    assert!(rendered.contains("reason=\"store-conflict\""), "{rendered}");
    h.done().await;
}

/// V2 attack: a namespace user names the admin's credentialed runner class
/// (same class name, own namespace copy pointing at the admin's image) and
/// the admin's profile. Without an explicit (namespace, class) grant the
/// lease is denied; no task input elevates. With the grant, the same run
/// leases fine.
#[tokio::test]
async fn cross_namespace_class_reference_cannot_borrow_credentials() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-admin", &["admin-class"]).await;
    // Admin granted only ("admin", "admin-class"); fix the namespace below.
    h.engine.journal.set_profile_policy("codex-admin", &["admin".to_string()], &["admin-class".to_string()]).await.unwrap();
    let mut evil = h.class("admin-class", "fix");
    evil.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-admin".into()],
        file_targets: BTreeMap::new(),
    };
    // Attack from another namespace: denied, no lease, run fails.
    let v = h.drive(&h.input_in("evil", vec![evil.clone()], 1), Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(
        matches!(&v.failure, Some(FailureReason::CredentialUnavailable { detail }) if detail.contains("not granted")),
        "{:?}",
        v.failure
    );
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    // Same request from the granted namespace: leases and succeeds.
    let v = h.drive(&h.input_in("admin", vec![evil], 1), Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    h.done().await;
}

/// V2 admission: credentialed classes need a digest-pinned allowlisted image
/// and an allowlisted service account, checked before any lease.
#[tokio::test]
async fn credentialed_class_admission_rejects_unpinned_unknown_image_and_sa() {
    let Some(h) = H::new().await else { return };
    enroll_codex(&h, "codex-1", &["admin-class"]).await;
    let mut base = h.class("admin-class", "fix");
    base.credentials = CredentialRequirement {
        provider: Some("codex".into()),
        profiles: vec!["codex-1".into()],
        file_targets: BTreeMap::new(),
    };
    // Unpinned image.
    let mut unpinned = base.clone();
    unpinned.image = "local".into();
    let v = h.drive(&h.input(vec![unpinned], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(matches!(&v.failure, Some(FailureReason::Unsupported { detail }) if detail.contains("digest")), "{v:?}");
    // Pinned but not allowlisted.
    let mut unknown = base.clone();
    unknown.image = "evil@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into();
    let v = h.drive(&h.input(vec![unknown], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(matches!(&v.failure, Some(FailureReason::Unsupported { detail }) if detail.contains("allowlist")), "{v:?}");
    // Forbidden service account.
    let mut bad_sa = base.clone();
    bad_sa.service_account_name = Some("evil-sa".into());
    let v = h.drive(&h.input(vec![bad_sa], 1), Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(matches!(&v.failure, Some(FailureReason::Unsupported { detail }) if detail.contains("serviceAccount")), "{v:?}");
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    h.done().await;
}

/// V9.3 (A22): per-run overrides without `allowRunOverrides` fail
/// `Unsupported` before any sandbox exists — for non-acp drivers and for acp
/// classes that did not opt in.
#[tokio::test]
async fn run_overrides_without_opt_in_fail_before_any_sandbox() {
    let Some(h) = H::new().await else { return };
    let sandboxes = h._tmp.path().join("sandboxes");
    let mut input = h.input(vec![h.class("fix", "fix")], 1);
    input.spec.overrides =
        RunOverrides { env: [("FOO".to_string(), "bar".to_string())].into_iter().collect(), files: vec![] };
    // `fake` driver: overrides are acp-only.
    let v = h.drive(&input, Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(
        matches!(&v.failure, Some(FailureReason::Unsupported { detail }) if detail.contains("only supported for the acp driver")),
        "{v:?}"
    );
    // `acp` driver without the class opt-in.
    let mut acp = h.class("acp-fix", "fix");
    acp.driver = "acp".into();
    acp.driver_config = serde_json::json!({"command": h.fake.to_string_lossy()});
    let mut input = h.input(vec![acp], 1);
    input.spec.overrides =
        RunOverrides { env: [("FOO".to_string(), "bar".to_string())].into_iter().collect(), files: vec![] };
    let v = h.drive(&input, Duration::from_secs(30)).await;
    assert_eq!(v.phase, RunPhase::Failed, "{v:?}");
    assert!(
        matches!(&v.failure, Some(FailureReason::Unsupported { detail }) if detail.contains("allowRunOverrides")),
        "{v:?}"
    );
    // No sandbox was ever created.
    let empty = std::fs::read_dir(&sandboxes).map(|mut d| d.next().is_none()).unwrap_or(true);
    assert!(empty, "sandbox created despite pre-sandbox rejection");
    h.done().await;
}

/// V9.5 end-to-end: a files profile leases, lands at `fileTargets`, and is
/// never written back (static secrets have no refresh).
#[tokio::test]
async fn files_profile_leases_and_lands_at_file_targets() {
    let Some(h) = H::new().await else { return };
    let original = br#"{"openai":{"type":"api","key":"sk-test-000000000000000000000000"}}"#.to_vec();
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), original.clone());
    let md = validate_bundle(Provider::Files, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "files-1".into(),
                provider: Provider::Files,
                max_concurrent_leases: 2,
                metadata: md,
                allowed_namespaces: vec!["default".into()],
                allowed_classes: vec!["acp-files".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.engine.journal).await.unwrap();
    let mut acp = h.class("acp-files", "fix");
    acp.driver = "acp".into();
    acp.driver_config = serde_json::json!({"command": h.fake.to_string_lossy()});
    acp.credentials = CredentialRequirement {
        provider: Some("files".into()),
        profiles: vec!["files-1".into()],
        file_targets: [("auth.json".to_string(), ".local/share/opencode/auth.json".to_string())]
            .into_iter()
            .collect(),
    };
    let v = h.drive(&h.input(vec![acp], 1), Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    assert!(h.engine.journal.active_leases().await.unwrap().is_empty());
    // static secret: the store is byte-identical (no write-back happened).
    let (_, stored) = h.creds.load("files-1").await.unwrap();
    assert_eq!(stored["auth.json"], original);
    h.done().await;
}

/// V9 (A21): same class, two runs with different models via
/// `overrides.env` — `SessionStarted.model` matches the request in both.
#[tokio::test]
async fn same_class_two_runs_with_different_models_via_overrides() {
    let Some(h) = H::new().await else { return };
    let mut acp = h.class("acp-model", "fix");
    acp.driver = "acp".into();
    acp.driver_config = serde_json::json!({"command": h.fake.to_string_lossy()});
    acp.allow_run_overrides = true;
    for model in ["test/model-a", "test/model-b"] {
        let mut input = h.input(vec![acp.clone()], 1);
        input.spec.overrides = RunOverrides {
            env: [("FAKE_ACP_MODEL".to_string(), model.to_string())].into_iter().collect(),
            files: vec![],
        };
        let v = h.drive(&input, Duration::from_secs(60)).await;
        assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
        let models: Vec<String> = h
            .engine
            .journal
            .events_for_run(v.run_id, 0, 10_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "SessionStarted")
            .filter_map(|e| e.data.get("model").and_then(|m| m.as_str()).map(str::to_string))
            .collect();
        assert_eq!(models, vec![model.to_string()], "{model}");
    }
    h.done().await;
}

/// V9.4 (A23): `overrides.env` trying to set HOME/XDG/proxy variables does
/// not fail the run — runnerd's values win (unit-proven in
/// `drivers::env::runnerd_owned_variables_win_over_overrides`).
#[tokio::test]
async fn run_overrides_cannot_redirect_home_or_proxy() {
    let Some(h) = H::new().await else { return };
    let mut acp = h.class("acp-fix", "fix");
    acp.driver = "acp".into();
    acp.driver_config = serde_json::json!({"command": h.fake.to_string_lossy()});
    acp.allow_run_overrides = true;
    let mut input = h.input(vec![acp], 1);
    input.spec.overrides = RunOverrides {
        env: [
            ("HOME".to_string(), "/evil".to_string()),
            ("XDG_CONFIG_HOME".to_string(), "/evil".to_string()),
            ("HTTPS_PROXY".to_string(), "http://evil:9".to_string()),
        ]
        .into_iter()
        .collect(),
        files: vec![],
    };
    let v = h.drive(&input, Duration::from_secs(60)).await;
    assert_eq!(v.phase, RunPhase::Succeeded, "{v:?}");
    h.done().await;
}

/// Minimal HTTP client on hyper-less std TCP to avoid another dev-dependency.
mod reqwest_like {
    use std::io::{Read, Write};
    #[derive(Clone)]
    pub struct Client;
    impl Client {
        pub fn new() -> Self {
            Client
        }
        pub async fn get(&self, url: &str, bearer: Option<&str>) -> u16 {
            let url = url.to_string();
            let bearer = bearer.map(str::to_string);
            tokio::task::spawn_blocking(move || {
                let rest = url.strip_prefix("http://").unwrap();
                let (host, path) = rest.split_once('/').unwrap();
                let mut s = std::net::TcpStream::connect(host).unwrap();
                let auth = bearer.map(|b| format!("Authorization: Bearer {b}\r\n")).unwrap_or_default();
                write!(s, "GET /{path} HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n").unwrap();
                let mut buf = String::new();
                s.read_to_string(&mut buf).unwrap();
                buf.split_whitespace().nth(1).unwrap().parse().unwrap()
            })
            .await
            .unwrap()
        }
        pub async fn post(&self, url: &str, bearer: &str, body: &str) -> u16 {
            let (url, bearer, body) = (url.to_string(), bearer.trim().to_string(), body.to_string());
            tokio::task::spawn_blocking(move || {
                let rest = url.strip_prefix("http://").unwrap();
                let (host, path) = rest.split_once('/').unwrap();
                let mut s = std::net::TcpStream::connect(host).unwrap();
                write!(
                    s,
                    "POST /{path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nx-acp-runner-wire-version: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    acp_runner_core::WIRE_VERSION,
                    body.len()
                )
                .unwrap();
                let mut buf = String::new();
                s.read_to_string(&mut buf).unwrap();
                buf.split_whitespace().nth(1).unwrap().parse().unwrap()
            })
            .await
            .unwrap()
        }
    }
}
