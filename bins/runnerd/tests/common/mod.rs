#![allow(dead_code)]
//! Shared harness for the compatibility and security suites.

pub mod env_mode;

use acp_runner_core::AttemptSpec;
use acp_runner_core::attempt_spec::{
    AttemptOutput, CredentialEnvLayout, CredentialFileLayout, CredentialLayout, DriverSpec, secret_file_name,
};
use acp_runner_core::events::EventKind;
use acp_runner_core::spec::{EgressPolicy, OutputKind, PermissionPolicy, RepositoryInput, TimeoutPolicy};
use acp_runner_drivers::{DriverContext, DriverError, ProbeReport, driver_for};
use runnerd::sink::{MemoryRecord, MemorySink};
use runnerd::{AgentdLaunch, AttemptResult, RunnerDirs, SupervisorOptions, run_attempt};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

pub const FAKE_CLAUDE_TOKEN: &str = "sk-ant-oat01-FAKEtokenFAKEtokenFAKEtoken0123456789";
pub const FAKE_CODEX_REFRESH: &str = "rt_fake_refresh_token_value_0123456789abcdef";

/// A ChatGPT-login shaped `auth.json` for the fake Codex emulation (never a real token).
pub fn fake_codex_auth_json() -> Vec<u8> {
    serde_json::json!({
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": null,
        "tokens": {"id_token": "fake-id-token-0123456789abcdef", "access_token": "fake-access-token-0123456789abcdef",
                   "refresh_token": FAKE_CODEX_REFRESH, "account_id": "acct-fake"},
        "last_refresh": "2026-09-20T00:00:00Z"
    })
    .to_string()
    .into_bytes()
}

/// Directory with `codex` and `codex-acp` symlinks to the fake agent (fake-codex target).
pub fn fake_codex_bin_dir(base: &Path) -> PathBuf {
    let dir = base.join("fake-codex-bin");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["codex", "codex-acp"] {
        let link = dir.join(name);
        if !link.exists() {
            std::os::unix::fs::symlink(fake_agent_bin(), &link).unwrap();
        }
    }
    dir
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    FakeAcp,
    FakeClaude,
    FakeCodex,
    Codex,
    Claude,
    CodexNoAuth,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub kind: Kind,
}

impl Target {
    pub fn fake_acp() -> Target {
        Target { name: "fake-acp".into(), kind: Kind::FakeAcp }
    }
    pub fn fake_claude() -> Target {
        Target { name: "fake-claude".into(), kind: Kind::FakeClaude }
    }
    pub fn fake_codex() -> Target {
        Target { name: "fake-codex".into(), kind: Kind::FakeCodex }
    }
    pub fn is_fake(&self) -> bool {
        matches!(self.kind, Kind::FakeAcp | Kind::FakeClaude | Kind::FakeCodex)
    }
    pub fn is_live(&self) -> bool {
        matches!(self.kind, Kind::Codex | Kind::Claude)
    }
}

pub fn targets() -> Vec<Target> {
    let spec = std::env::var("ACP_COMPAT_TARGETS").unwrap_or_else(|_| "fake-acp,fake-claude,fake-codex".into());
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let kind = match s {
                "fake-acp" => Kind::FakeAcp,
                "fake-claude" => Kind::FakeClaude,
                "fake-codex" => Kind::FakeCodex,
                "codex" => Kind::Codex,
                "claude" => Kind::Claude,
                "codex-noauth" => Kind::CodexNoAuth,
                other => panic!("unknown compat target {other}"),
            };
            Target { name: s.to_string(), kind }
        })
        .collect()
}

fn build_helpers() -> PathBuf {
    static BUILT: std::sync::Once = std::sync::Once::new();
    let exe = std::env::current_exe().expect("test exe");
    // target/<profile>/deps/<test> -> target/<profile>/
    let profile_dir = exe.parent().and_then(|p| p.parent()).expect("target dir").to_path_buf();
    BUILT.call_once(|| {
        let status = std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-q", "-p", "fake-acp-agent", "-p", "agentd"])
            .status()
            .expect("cargo build fake-acp-agent agentd");
        assert!(status.success());
    });
    profile_dir
}

/// Path of the fake agent binary (built on demand).
pub fn fake_agent_bin() -> PathBuf {
    if let Ok(p) = std::env::var("FAKE_ACP_AGENT") {
        return PathBuf::from(p);
    }
    let bin = build_helpers().join("fake-acp-agent");
    assert!(bin.exists(), "fake-acp-agent not found at {}", bin.display());
    bin
}

/// Path of the agentd binary (built on demand).
pub fn agentd_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ACP_RUNNER_AGENTD_BIN") {
        return PathBuf::from(p);
    }
    let bin = build_helpers().join("agentd");
    assert!(bin.exists(), "agentd not found at {}", bin.display());
    bin
}

pub struct TestEnv {
    pub tmp: tempfile::TempDir,
    pub target: Target,
    pub repo_url: String,
    pub base_sha: String,
    pub secret_dir: PathBuf,
    pub layout: Option<CredentialLayout>,
    pub driver: String,
    pub config: Value,
    /// Prepended to PATH for agent processes (fake-codex symlinks).
    pub path_prefix: Option<PathBuf>,
    /// Directories of the most recent run (to inspect the sandbox afterwards).
    pub last_dirs: std::sync::Mutex<Option<RunnerDirs>>,
    secrets: Vec<String>,
    counter: AtomicU32,
}

impl TestEnv {
    pub async fn new(target: &Target) -> TestEnv {
        let tmp = tempfile::tempdir().expect("tempdir");
        let src = tmp.path().join("upstream");
        let base_sha = acp_runner_workspace::fixture::create(&src).await.expect("fixture repo");
        let repo_url = format!("file://{}", src.display());
        let secret_dir = tmp.path().join("secret");
        std::fs::create_dir_all(&secret_dir).unwrap();
        let mut env = TestEnv {
            tmp,
            target: target.clone(),
            repo_url,
            base_sha,
            secret_dir,
            layout: None,
            driver: String::new(),
            config: Value::Null,
            path_prefix: None,
            last_dirs: std::sync::Mutex::new(None),
            secrets: vec![],
            counter: AtomicU32::new(0),
        };
        let fake = || fake_agent_bin().to_string_lossy().to_string();
        match target.kind {
            Kind::FakeAcp => {
                env.driver = "fake".into();
                env.config = json!({"command": fake()});
            }
            Kind::FakeClaude => {
                env.driver = "claude".into();
                env.config = json!({"command": fake(), "commandArgs": ["claude-mode"]});
                env.add_env_credential(
                    "claude",
                    "oauth-token",
                    "CLAUDE_CODE_OAUTH_TOKEN",
                    FAKE_CLAUDE_TOKEN.as_bytes(),
                );
            }
            Kind::FakeCodex => {
                env.driver = "codex".into();
                env.config = json!({});
                env.path_prefix = Some(fake_codex_bin_dir(env.tmp.path()));
                env.add_file_credential("codex", "auth.json", ".codex/auth.json", &fake_codex_auth_json(), true);
            }
            Kind::Codex => {
                env.driver = "codex".into();
                env.config = json!({});
                let p = std::env::var("ACP_COMPAT_CODEX_AUTH_JSON")
                    .expect("ACP_COMPAT_CODEX_AUTH_JSON (enrolled auth.json) required for live codex target");
                let bytes = std::fs::read(p).expect("read codex auth.json");
                env.add_file_credential("codex", "auth.json", ".codex/auth.json", &bytes, true);
            }
            Kind::Claude => {
                env.driver = "claude".into();
                env.config = json!({});
                let p = std::env::var("ACP_COMPAT_CLAUDE_TOKEN_FILE")
                    .expect("ACP_COMPAT_CLAUDE_TOKEN_FILE (setup-token) required for live claude target");
                let bytes = std::fs::read(p).expect("read claude token");
                env.add_env_credential(
                    "claude",
                    "oauth-token",
                    "CLAUDE_CODE_OAUTH_TOKEN",
                    String::from_utf8_lossy(&bytes).trim().as_bytes(),
                );
            }
            Kind::CodexNoAuth => {
                env.driver = "codex".into();
                env.config = json!({});
            }
        }
        env
    }

    pub fn add_env_credential(&mut self, provider: &str, key: &str, env_name: &str, value: &[u8]) {
        std::fs::write(self.secret_dir.join(secret_file_name(key)), value).unwrap();
        self.secrets.push(String::from_utf8_lossy(value).to_string());
        let l = self.layout.get_or_insert_with(|| CredentialLayout {
            provider: provider.into(),
            profile: "test-profile".into(),
            files: vec![],
            env: vec![],
        });
        l.env.push(CredentialEnvLayout { key: key.into(), env_name: env_name.into() });
    }

    pub fn add_file_credential(&mut self, provider: &str, key: &str, target: &str, value: &[u8], writeback: bool) {
        std::fs::write(self.secret_dir.join(secret_file_name(key)), value).unwrap();
        self.secrets.push(String::from_utf8_lossy(value).to_string());
        if let Ok(v) = serde_json::from_slice::<Value>(value) {
            collect_strings(&v, &mut self.secrets);
        }
        let l = self.layout.get_or_insert_with(|| CredentialLayout {
            provider: provider.into(),
            profile: "test-profile".into(),
            files: vec![],
            env: vec![],
        });
        l.files.push(CredentialFileLayout { key: key.into(), target: target.into(), mode: 0o600, writeback });
    }

    pub fn secrets(&self) -> Vec<String> {
        self.secrets.iter().filter(|s| s.len() >= 12).cloned().collect()
    }

    fn prompt(&self, scenario: &str) -> String {
        if self.target.is_live() {
            match scenario {
                "fix" => "The POSIX shell script add.sh in the current directory should print the sum of its two \
                          arguments, but it has a bug. Fix add.sh so that `sh test.sh` prints PASS. Only modify add.sh. \
                          Do not create commits."
                    .into(),
                "hang" => "Run the shell command `sleep 600` with your shell tool, wait for it to finish, then reply DONE.".into(),
                other => format!("Reply with the single word {other}."),
            }
        } else {
            format!("[[fake:{scenario}]] Fix add.sh so that test.sh passes.")
        }
    }

    pub fn spec(&self, scenario: &str) -> AttemptSpec {
        let live = self.target.is_live();
        AttemptSpec {
            wire_version: acp_runner_core::WIRE_VERSION,
            run_id: Uuid::new_v4(),
            attempt_id: Uuid::new_v4(),
            task_id: "compat".into(),
            ordinal: 1,
            class_attempt: 1,
            runner_class: format!("compat-{}", self.target.name),
            driver: DriverSpec { name: self.driver.clone(), config: self.config.clone() },
            repository: RepositoryInput {
                url: self.repo_url.clone(),
                revision: self.base_sha.clone(),
                sparse_paths: vec![],
                depth: None,
            },
            prompt: self.prompt(scenario),
            capsule: None,
            apply_patch_b64: None,
            output: AttemptOutput {
                kind: OutputKind::Patch,
                require_changes: true,
                max_patch_bytes: 1 << 20,
                allowed_paths: vec![],
                allow_submodules: false,
            },
            timeouts: TimeoutPolicy {
                hard_seconds: if live { 900 } else { 60 },
                no_progress_seconds: if live { 300 } else { 30 },
                grace_seconds: if live { 20 } else { 3 },
                heartbeat_seconds: if live { 10 } else { 2 },
                startup_seconds: if live { 180 } else { 30 },
            },
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            credentials: self.layout.clone(),
            record_raw_payloads: true,
            // Scenarios that act before the prompt (initialize/session/new) need the env var.
            env: if self.target.is_fake() {
                [("FAKE_ACP_SCENARIO".to_string(), scenario.to_string())].into_iter().collect()
            } else {
                Default::default()
            },
            session: Default::default(),
            bootstrap: Default::default(),
        }
    }

    pub fn dirs(&self) -> RunnerDirs {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        RunnerDirs::under(&self.tmp.path().join(format!("sandbox-{n}")), Some(self.secret_dir.clone()))
    }

    pub fn opts(&self) -> SupervisorOptions {
        let path = std::env::var("ACP_COMPAT_PATH").ok().or_else(|| std::env::var("PATH").ok());
        let path = match (&self.path_prefix, path) {
            (Some(pre), Some(p)) => Some(format!("{}:{p}", pre.display())),
            (Some(pre), None) => Some(pre.display().to_string()),
            (None, p) => p,
        };
        SupervisorOptions {
            agent_path_env: path.clone(),
            agentd: AgentdLaunch::Spawn {
                program: agentd_bin(),
                env: path
                    .map(|p| vec![("PATH".to_string(), p), ("AGENTD_LOG".to_string(), "warn".to_string())])
                    .unwrap_or_default(),
            },
            ..Default::default()
        }
    }

    pub async fn probe(&self) -> Result<ProbeReport, DriverError> {
        let dirs = self.dirs();
        let mut r = acp_runner_core::redact::Redactor::new();
        let h = runnerd::home::prepare_home(&dirs.home, self.layout.as_ref(), Some(&self.secret_dir), &mut r)
            .expect("prepare home");
        let credential_env = h
            .staged_env
            .iter()
            .map(|s| (s.env_name.clone(), std::fs::read_to_string(dirs.home.join(&s.rel)).unwrap()))
            .collect();
        std::fs::create_dir_all(&dirs.workspace).unwrap();
        let ctx = DriverContext {
            attempt_id: Uuid::new_v4(),
            ordinal: 1,
            workspace: dirs.workspace.clone(),
            home: dirs.home.clone(),
            tmp: std::env::temp_dir(),
            config: self.config.clone(),
            class_env: Default::default(),
            credential_env,
            permissions: Default::default(),
            egress: Default::default(),
            record_raw: false,
            path_env: self.opts().agent_path_env,
            extra_ca_file: None,
            bridge_exe: Some(agentd_bin()),
        };
        let d = driver_for(&self.driver)?;
        d.prepare(&ctx).await?;
        d.probe(&ctx).await
    }

    pub async fn run(&self, scenario: &str, mutate: impl FnOnce(&mut AttemptSpec)) -> (AttemptResult, MemoryRecord) {
        let mut spec = self.spec(scenario);
        mutate(&mut spec);
        self.run_spec(spec, self.opts(), None).await
    }

    pub async fn run_spec(
        &self,
        spec: AttemptSpec,
        opts: SupervisorOptions,
        cancel_after: Option<Duration>,
    ) -> (AttemptResult, MemoryRecord) {
        self.run_spec_with_sink(spec, opts, cancel_after, MemorySink::default()).await
    }

    pub async fn run_spec_with_sink(
        &self,
        spec: AttemptSpec,
        opts: SupervisorOptions,
        cancel_after: Option<Duration>,
        mut sink: MemorySink,
    ) -> (AttemptResult, MemoryRecord) {
        let (tx, rx) = watch::channel(false);
        if let Some(d) = cancel_after {
            tokio::spawn(async move {
                tokio::time::sleep(d).await;
                let _ = tx.send(true);
            });
        } else {
            std::mem::forget(tx);
        }
        let dirs = self.dirs();
        *self.last_dirs.lock().unwrap() = Some(dirs.clone());
        let res = run_attempt(spec, dirs, &mut sink, opts, rx).await;
        (res, sink.snapshot())
    }

    pub async fn run_with_cancel(&self, scenario: &str, after: Duration) -> (AttemptResult, MemoryRecord) {
        self.run_spec(self.spec(scenario), self.opts(), Some(after)).await
    }

    pub async fn assert_patch_applies_and_fixes(&self, patch: &[u8]) {
        let dir = self.tmp.path().join(format!("verify-{}", self.counter.fetch_add(1, Ordering::SeqCst)));
        acp_runner_workspace::check_patch_applies(&self.repo_url, &self.base_sha, patch, &dir)
            .await
            .expect("patch applies to base revision");
        let repo = dir.join("repo");
        let pfile = dir.join("fix.patch");
        std::fs::write(&pfile, patch).unwrap();
        let st = std::process::Command::new("git")
            .args(["apply", "--binary"])
            .arg(&pfile)
            .current_dir(&repo)
            .status()
            .unwrap();
        assert!(st.success());
        let out = std::process::Command::new("sh").arg("test.sh").current_dir(&repo).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("PASS"), "patched repo does not pass test.sh");
    }
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

pub fn has(rec: &MemoryRecord, kind: EventKind) -> bool {
    rec.events.iter().any(|e| e.kind == kind)
}

pub fn progress(rec: &MemoryRecord, category: &str) -> bool {
    rec.events
        .iter()
        .any(|e| e.kind == EventKind::Progress && e.data.get("category").and_then(|c| c.as_str()) == Some(category))
}

pub fn dump(rec: &MemoryRecord) -> String {
    rec.events
        .iter()
        .map(|e| {
            let d = e.data.to_string();
            format!("  {:>3} {:<18} {}", e.seq.unwrap_or(0), e.kind.as_str(), &d[..d.len().min(300)])
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn all_text(rec: &MemoryRecord) -> String {
    let mut s = serde_json::to_string(&rec.events).unwrap();
    s.push_str(&serde_json::to_string(&rec.heartbeats).unwrap());
    s.push_str(&serde_json::to_string(&rec.artifacts).unwrap());
    s
}

pub fn fixture_path(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
}
