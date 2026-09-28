//! Sandbox backends: *where* an attempt's runnerd executes.
//!
//! The engine only knows this trait. Implementations:
//!
//! * [`LocalProcessBackend`] — runnerd + agentd as two local processes (development, CI,
//!   deterministic end-to-end tests without Kubernetes). NOT an isolation boundary.
//! * `PodBackend` (crate `acp-runner-k8s`) — one hardened two-container Pod per attempt.
//! * `AgentSandboxBackend` (crate `acp-runner-k8s`) — one `agents.x-k8s.io/v1beta1`
//!   `Sandbox` per attempt (kubernetes-sigs/agent-sandbox).

use acp_runner_core::spec::{RunnerClassSpec, TimeoutPolicy};
use async_trait::async_trait;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

/// Identity of the orchestrator-facing resource that owns a run (the `ACPRun`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunKey {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone)]
pub struct SandboxRequest {
    pub run_key: RunKey,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub ordinal: u32,
    /// Deterministic DNS-1123 name for the sandbox.
    pub name: String,
    pub class: RunnerClassSpec,
    pub ingest_url: String,
    /// Per-attempt bearer token (secret).
    pub token: String,
    /// Leased credential material, key -> bytes (secret). Mounted read-only as `cred.<key>`.
    pub credential_files: BTreeMap<String, Vec<u8>>,
    /// Other per-attempt secret files for runnerd only, file name -> bytes (environment mode:
    /// `gateway-key`). Never visible to the agent.
    pub runner_secret_files: BTreeMap<String, Vec<u8>>,
    pub timeouts: TimeoutPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRef {
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxObservation {
    Pending { reason: Option<String> },
    Running,
    Exited { exit_code: Option<i32>, reason: Option<String>, message: Option<String> },
    Missing,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Worth retrying on the next reconcile (API unavailable, conflict, ...).
    #[error("transient backend error: {0}")]
    Transient(String),
    /// The request can never succeed (invalid spec, forbidden, ...).
    #[error("permanent backend error: {0}")]
    Permanent(String),
}

#[async_trait]
pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;
    /// Create the sandbox. Must replace a leftover sandbox with the same name.
    async fn create(&self, req: &SandboxRequest) -> Result<SandboxRef, BackendError>;
    async fn observe(&self, r: &SandboxRef) -> Result<SandboxObservation, BackendError>;
    /// Terminate with a bounded grace period (SIGTERM, then SIGKILL). Idempotent.
    async fn terminate(&self, r: &SandboxRef, grace: Duration) -> Result<(), BackendError>;
}

/// Fencing for exclusive credential leases (V10c): after a lease is granted,
/// confirm no *other* unreleased lease for the same profile still has a live
/// sandbox. An expired lease whose sandbox is still observed live is a zombie
/// (dead controller, crashed runnerd): terminate it and re-observe until it is
/// authoritatively gone before the new holder proceeds. Anything unverifiable
/// fails closed — an exclusive profile is never shared with a live sandbox.
///
/// Active (unexpired) leases of other holders are left alone: with
/// `max_concurrent_leases > 1` they are legitimate co-holders, and with 1 the
/// grant itself would already have been refused.
pub async fn fence_exclusive_lease(
    journal: &acp_runner_journal::Journal,
    backend: &dyn SandboxBackend,
    profile_name: &str,
    own_attempt_id: Uuid,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    for lease in journal.leases_for_profile(profile_name).await.map_err(|e| anyhow::anyhow!("{e}"))? {
        if lease.attempt_id == own_attempt_id || lease.released_at.is_some() || lease.expires_at > now {
            continue;
        }
        let attempt =
            journal.get_attempt(lease.attempt_id).await.map_err(|e| anyhow::anyhow!("fencing: {e}"))?;
        let Some(sref) = attempt.sandbox_ref.clone() else { continue }; // never launched: nothing to fence
        let sref: SandboxRef = serde_json::from_value(sref)
            .map_err(|e| anyhow::anyhow!("fencing: previous sandbox ref: {e}"))?;
        // A single authoritative observation decides: Exited/Missing needs no
        // fencing (this never waits — a live sandbox must be terminated first).
        match backend.observe(&sref).await {
            Ok(SandboxObservation::Exited { .. }) | Ok(SandboxObservation::Missing) => continue,
            Ok(SandboxObservation::Running) | Ok(SandboxObservation::Pending { .. }) => {}
            Err(e) => anyhow::bail!("fencing: cannot observe previous sandbox {}: {e}", sref.name),
        }
        // Zombie: terminate, then require an authoritative Exited/Missing.
        backend
            .terminate(&sref, Duration::from_secs(20))
            .await
            .map_err(|e| anyhow::anyhow!("fencing: terminating zombie sandbox {}: {e}", sref.name))?;
        if sandbox_ended(backend, &sref).await? {
            continue;
        }
        anyhow::bail!(
            "credential profile {profile_name} is fenced: previous sandbox {} still live",
            sref.name
        );
    }
    Ok(())
}

/// Poll `observe` until the sandbox is authoritatively gone (bounded).
async fn sandbox_ended(backend: &dyn SandboxBackend, sref: &SandboxRef) -> anyhow::Result<bool> {
    for _ in 0..30 {
        match backend.observe(sref).await {
            Ok(SandboxObservation::Exited { .. }) | Ok(SandboxObservation::Missing) => return Ok(true),
            Ok(SandboxObservation::Running) | Ok(SandboxObservation::Pending { .. }) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => anyhow::bail!("fencing: cannot observe previous sandbox {}: {e}", sref.name),
        }
    }
    Ok(false)
}

/// DNS-1123 label derived from run name, ordinal and attempt id.
pub fn sandbox_name(run_name: &str, ordinal: u32, attempt_id: Uuid) -> String {
    let mut base: String = run_name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect();
    base = base.trim_matches('-').to_string();
    base.truncate(40);
    let base = base.trim_end_matches('-');
    let short = &attempt_id.simple().to_string()[24..];
    format!("acp-{base}-a{ordinal}-{short}")
}

// ---------------------------------------------------------------------------------------

/// Runs an attempt as two local processes that mirror the two containers of the pod:
/// runnerd (with a per-attempt "secret directory" holding `token` and `cred.<key>` files,
/// 0400) and agentd (without it: its environment only names the shared socket and HOME).
/// Workspace, HOME and run directory are shared directories. Development and deterministic
/// tests only: both processes run as the same user on the same filesystem, so this is NOT
/// an isolation boundary (the Kubernetes pod is).
pub struct LocalProcessBackend {
    pub runnerd: PathBuf,
    pub agentd: PathBuf,
    pub base_dir: PathBuf,
    pub path_env: String,
    pub keep_dirs: bool,
    /// Optional (root-only) isolation of the agent side, see [`crate::local_container`].
    pub isolation: Option<LocalIsolation>,
    children: Mutex<HashMap<String, LocalSandbox>>,
}

/// Local stand-in for the pod's container boundaries (tests on Linux as root):
/// runnerd runs as `uid` in the host mount namespace (like its container with the Secret);
/// agentd runs as `uid` in its own mount/PID (and, for `egress.mode: proxy`, network)
/// namespace that contains only the shared volumes.
#[derive(Debug, Clone)]
pub struct LocalIsolation {
    pub uid: u32,
    pub gid: u32,
    /// Host paths made visible read-only at the same path in the agent's view (binaries,
    /// fake CLIs).
    pub ro_paths: Vec<PathBuf>,
    /// Unix socket of an `acp-egress-proxy serve --listen-unix`, reachable from proxy-mode
    /// agents through a relay on 127.0.0.1:3128 inside their network namespace.
    pub proxy_socket: Option<PathBuf>,
    /// `acp-egress-proxy` binary (relay).
    pub relay: PathBuf,
}

/// Agent-view paths used with [`LocalIsolation`] (same as the pod's).
pub const AGENT_VIEW_WORKSPACE: &str = "/workspace";
pub const AGENT_VIEW_HOME: &str = "/home/agent";
pub const AGENT_VIEW_RUN: &str = "/run/acp-runner";
pub const LOCAL_PROXY_LISTEN: &str = "127.0.0.1:3128";

fn chown_tree(p: &std::path::Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let (u, g) = (Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)));
    nix::unistd::chown(p, u, g).map_err(std::io::Error::from)?;
    if std::fs::symlink_metadata(p)?.is_dir() {
        for e in std::fs::read_dir(p)? {
            chown_tree(&e?.path(), uid, gid)?;
        }
    }
    Ok(())
}

struct LocalSandbox {
    runnerd: std::process::Child,
    agentd: Option<std::process::Child>,
}

fn kill_group(c: &std::process::Child, sig: Signal) {
    let _ = killpg(Pid::from_raw(c.id() as i32), sig);
}

impl LocalProcessBackend {
    /// `agentd` is expected next to `runnerd`.
    pub fn new(runnerd: PathBuf, base_dir: PathBuf, path_env: String) -> Self {
        let agentd = runnerd.parent().map(|d| d.join("agentd")).unwrap_or_else(|| PathBuf::from("agentd"));
        LocalProcessBackend {
            runnerd,
            agentd,
            base_dir,
            path_env,
            keep_dirs: false,
            isolation: None,
            children: Mutex::new(HashMap::new()),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }

    /// Test hook: make a sandbox vanish (SIGKILL both processes + forget), like a deleted pod.
    pub fn simulate_disappearance(&self, name: &str) -> bool {
        let sb = self.children.lock().expect("lock").remove(name);
        match sb {
            Some(mut sb) => {
                kill_group(&sb.runnerd, Signal::SIGKILL);
                let _ = sb.runnerd.wait();
                if let Some(mut a) = sb.agentd.take() {
                    kill_group(&a, Signal::SIGKILL);
                    let _ = a.wait();
                }
                true
            }
            None => false,
        }
    }

    /// Test hook: freeze runnerd (SIGSTOP) to simulate a hung supervisor.
    pub fn simulate_hang(&self, name: &str) -> bool {
        match self.children.lock().expect("lock").get(name) {
            Some(sb) => killpg(Pid::from_raw(sb.runnerd.id() as i32), Signal::SIGSTOP).is_ok(),
            None => false,
        }
    }

    /// Test hook: freeze agentd (SIGSTOP) to simulate a hung/compromised agent container
    /// that neither reports nor honours `Cancel`.
    pub fn simulate_agentd_hang(&self, name: &str) -> bool {
        match self.children.lock().expect("lock").get(name).and_then(|sb| sb.agentd.as_ref()) {
            Some(a) => killpg(Pid::from_raw(a.id() as i32), Signal::SIGSTOP).is_ok(),
            None => false,
        }
    }

    /// Is the agentd process of a sandbox still running?
    pub fn agentd_alive(&self, name: &str) -> bool {
        let mut map = self.children.lock().expect("lock");
        match map.get_mut(name).and_then(|sb| sb.agentd.as_mut()) {
            Some(a) => matches!(a.try_wait(), Ok(None)),
            None => false,
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.children.lock().expect("lock").keys().cloned().collect()
    }
}

#[async_trait]
impl SandboxBackend for LocalProcessBackend {
    fn name(&self) -> &'static str {
        "local"
    }

    async fn create(&self, req: &SandboxRequest) -> Result<SandboxRef, BackendError> {
        let r = SandboxRef { backend: "local".into(), namespace: None, name: req.name.clone() };
        let _ = self.terminate(&r, Duration::from_secs(1)).await;
        let dir = self.dir(&req.name);
        let _ = std::fs::remove_dir_all(&dir);
        let secret = dir.join("secret");
        let io = |e: std::io::Error| BackendError::Transient(e.to_string());
        std::fs::create_dir_all(&secret).map_err(io)?;
        let write_secret = |name: &str, bytes: &[u8]| -> Result<(), BackendError> {
            let p = secret.join(name);
            std::fs::write(&p, bytes).map_err(io)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).map_err(io)
        };
        write_secret("token", req.token.as_bytes())?;
        for (k, v) in &req.credential_files {
            write_secret(&acp_runner_core::attempt_spec::secret_file_name(k), v)?;
        }
        for (name, v) in &req.runner_secret_files {
            write_secret(name, v)?;
        }
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o500)).map_err(io)?;
        for d in ["workspace", "home", "run", "state", "tmp", "agent-tmp", "agent-root", "harness"] {
            std::fs::create_dir_all(dir.join(d)).map_err(io)?;
        }
        if let Some(iso) = &self.isolation {
            chown_tree(&dir, iso.uid, iso.gid).map_err(io)?;
        }
        use std::os::unix::process::CommandExt;
        // "runnerd container"
        let log = std::fs::File::create(dir.join("runnerd.log")).map_err(io)?;
        let mut cmd = match &self.isolation {
            Some(iso) => {
                let mut c = std::process::Command::new("/usr/bin/setpriv");
                c.args(crate::local_container::setpriv_args(iso.uid, iso.gid)).arg(&self.runnerd);
                c
            }
            None => std::process::Command::new(&self.runnerd),
        };
        if self.isolation.is_some() {
            cmd.env("ACP_RUNNER_AGENT_WORKSPACE", AGENT_VIEW_WORKSPACE)
                .env("ACP_RUNNER_AGENT_HOME", AGENT_VIEW_HOME)
                .env("ACP_RUNNER_AGENT_TMP", "/tmp");
        }
        cmd.arg("pod")
            .env("PATH", &self.path_env)
            .env("HOME", dir.join("tmp"))
            .env("ACP_RUNNER_INGEST_URL", &req.ingest_url)
            .env("ACP_RUNNER_SECRET_DIR", &secret)
            .env("ACP_RUNNER_WORKSPACE", dir.join("workspace"))
            .env("ACP_RUNNER_HOME", dir.join("home"))
            .env("ACP_RUNNER_TMP", dir.join("tmp"))
            .env("ACP_RUNNER_RUN_DIR", dir.join("run"))
            .env("ACP_RUNNER_STATE_DIR", dir.join("state"))
            .env("ACP_RUNNER_AGENT_TMP", dir.join("agent-tmp"))
            .env("ACP_RUNNER_HARNESS_DIR", dir.join("harness"))
            .env("ACP_RUNNER_AGENTD", "external")
            .env("ACP_RUNNER_CONTROLLER_WATCHDOG", "true")
            .env("ACP_RUNNER_AGENT_PATH", &self.path_env)
            .env("RUNNERD_LOG", "info")
            .current_dir(&dir)
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().map_err(io)?)
            .stderr(log)
            .process_group(0);
        if self.isolation.is_some() {
            cmd.env("ACP_RUNNER_AGENT_WORKSPACE", AGENT_VIEW_WORKSPACE)
                .env("ACP_RUNNER_AGENT_HOME", AGENT_VIEW_HOME)
                .env("ACP_RUNNER_AGENT_TMP", "/tmp")
                .env("ACP_RUNNER_AGENT_HARNESS", acp_runner_core::harness::HARNESS_ROOT);
        }
        let runnerd = cmd.spawn().map_err(|e| BackendError::Permanent(format!("spawning runnerd: {e}")))?;
        // "agentd container": no secret directory, no ACP_RUNNER_* configuration
        let log = std::fs::File::create(dir.join("agentd.log")).map_err(io)?;
        let connect_timeout = (req.timeouts.startup_seconds + 120).to_string();
        let mut cmd = match &self.isolation {
            None => {
                let mut c = std::process::Command::new(&self.agentd);
                c.arg("run")
                    .env_clear()
                    .env("PATH", &self.path_env)
                    .env("HOME", dir.join("home"))
                    .env("ACP_AGENTD_SOCKET", dir.join("run").join("agentd.sock"))
                    .env("ACP_AGENTD_CONNECT_TIMEOUT", &connect_timeout)
                    .env("AGENTD_LOG", "info")
                    .current_dir(dir.join("workspace"));
                c
            }
            Some(iso) => {
                use crate::local_container::{LocalContainer, Mount, Net};
                let rw = |h: &str, c: &str| Mount { host: dir.join(h), container: c.into(), read_only: false };
                let mut mounts = vec![
                    rw("workspace", AGENT_VIEW_WORKSPACE),
                    rw("home", AGENT_VIEW_HOME),
                    rw("run", AGENT_VIEW_RUN),
                    rw("agent-tmp", "/tmp"),
                    // materialized harness: written by runnerd, read-only for the agent
                    Mount {
                        host: dir.join("harness"),
                        container: acp_runner_core::harness::HARNESS_ROOT.into(),
                        read_only: true,
                    },
                ];
                for p in &iso.ro_paths {
                    mounts.push(Mount { host: p.clone(), container: p.clone(), read_only: true });
                }
                let proxy_mode = req.class.egress.effective_mode() == acp_runner_core::spec::EgressMode::Proxy;
                let net = match (&iso.proxy_socket, proxy_mode) {
                    (Some(sock), true) => Net::ProxyOnly {
                        listen: LOCAL_PROXY_LISTEN.into(),
                        proxy_socket: sock.clone(),
                        relay: iso.relay.clone(),
                    },
                    _ => Net::Host,
                };
                let c = LocalContainer {
                    root: dir.join("agent-root"),
                    mounts,
                    uid: iso.uid,
                    gid: iso.gid,
                    env: vec![
                        ("PATH".into(), self.path_env.clone()),
                        ("HOME".into(), AGENT_VIEW_HOME.into()),
                        ("ACP_AGENTD_SOCKET".into(), format!("{AGENT_VIEW_RUN}/agentd.sock")),
                        ("ACP_AGENTD_CONNECT_TIMEOUT".into(), connect_timeout.clone()),
                        ("AGENTD_LOG".into(), "info".into()),
                    ],
                    cwd: AGENT_VIEW_WORKSPACE.into(),
                    program: self.agentd.clone(),
                    args: vec!["run".into()],
                    net,
                };
                c.command()
            }
        };
        cmd.stdin(std::process::Stdio::null()).stdout(log.try_clone().map_err(io)?).stderr(log).process_group(0);
        let agentd = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let mut runnerd = runnerd;
                kill_group(&runnerd, Signal::SIGKILL);
                let _ = runnerd.wait();
                return Err(BackendError::Permanent(format!("spawning agentd {}: {e}", self.agentd.display())));
            }
        };
        self.children.lock().expect("lock").insert(req.name.clone(), LocalSandbox { runnerd, agentd: Some(agentd) });
        Ok(r)
    }

    async fn observe(&self, r: &SandboxRef) -> Result<SandboxObservation, BackendError> {
        let mut map = self.children.lock().expect("lock");
        let Some(sb) = map.get_mut(&r.name) else { return Ok(SandboxObservation::Missing) };
        // The attempt lives as long as runnerd does (like the runnerd container status).
        match sb.runnerd.try_wait() {
            Ok(None) => Ok(SandboxObservation::Running),
            Ok(Some(st)) => {
                use std::os::unix::process::ExitStatusExt;
                Ok(SandboxObservation::Exited {
                    exit_code: st.code(),
                    reason: st.signal().map(|s| format!("signal {s}")),
                    message: None,
                })
            }
            Err(e) => Err(BackendError::Transient(e.to_string())),
        }
    }

    async fn terminate(&self, r: &SandboxRef, grace: Duration) -> Result<(), BackendError> {
        let sb = self.children.lock().expect("lock").remove(&r.name);
        if let Some(sb) = sb {
            let mut procs: Vec<std::process::Child> = std::iter::once(sb.runnerd).chain(sb.agentd).collect();
            for c in &procs {
                kill_group(c, Signal::SIGCONT);
                kill_group(c, Signal::SIGTERM);
            }
            let deadline = std::time::Instant::now() + grace;
            for c in procs.iter_mut() {
                loop {
                    match c.try_wait() {
                        Ok(Some(_)) => break,
                        _ if std::time::Instant::now() >= deadline => {
                            kill_group(c, Signal::SIGKILL);
                            let _ = c.wait();
                            break;
                        }
                        _ => tokio::time::sleep(Duration::from_millis(50)).await,
                    }
                }
                kill_group(c, Signal::SIGKILL);
            }
        }
        if !self.keep_dirs {
            let dir = self.dir(&r.name);
            // secret dir is read-only; make it removable
            let _ = std::fs::set_permissions(dir.join("secret"), std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&dir);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_dns_labels() {
        let id = Uuid::parse_str("0192f0f0-0000-7000-8000-00000000abcd").unwrap();
        let n = sandbox_name("My_Run.With-Weird--Name_and_a_really_long_suffix_exceeding_limits", 3, id);
        assert!(n.len() <= 63, "{n}");
        assert!(n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        assert!(n.ends_with("-a3-0000abcd"), "{n}");
        assert!(n.starts_with("acp-my-run-with"));
    }
}
