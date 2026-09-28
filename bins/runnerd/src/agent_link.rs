//! runnerd's end of the local agentd link (Unix domain socket, see `acp-runner-ipc`).
//!
//! * runnerd binds `<run_dir>/agentd.sock` and accepts exactly **one** connection. Any
//!   further connection (e.g. the CLI trying to talk to runnerd directly) is closed
//!   immediately and counted; the count is journaled.
//! * Messages from agentd are parsed by a reader task; a malformed or oversized frame ends
//!   the link with a protocol error.
//! * In Kubernetes agentd is a separate container (`AgentdLaunch::External`). For local
//!   development and the driver compatibility suite runnerd can start agentd itself
//!   (`AgentdLaunch::Spawn`) — that shares runnerd's trust domain and is NOT an isolation
//!   boundary.

use acp_runner_ipc::{DATA_SOCKET_FILE, FromAgent, IpcError, SOCKET_FILE, ToAgent, read_frame, write_frame};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Child;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum AgentdLaunch {
    /// agentd runs elsewhere (its own container) and connects to the socket.
    External,
    /// runnerd starts agentd as a child process (local/dev only).
    Spawn { program: PathBuf, env: Vec<(String, String)> },
}

impl AgentdLaunch {
    pub fn is_spawn(&self) -> bool {
        matches!(self, AgentdLaunch::Spawn { .. })
    }
}

impl Default for AgentdLaunch {
    fn default() -> Self {
        AgentdLaunch::Spawn { program: default_agentd_program(), env: vec![] }
    }
}

/// `agentd` next to the running runnerd binary, else `agentd` from PATH.
pub fn default_agentd_program() -> PathBuf {
    if let Ok(p) = std::env::var("ACP_RUNNER_AGENTD_BIN") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("agentd")))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from("agentd"))
}

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("agentd did not connect within {0:?}")]
    Timeout(Duration),
    #[error("agentd exited before connecting (exit {0:?})")]
    AgentdExited(Option<i32>),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Ipc(#[from] IpcError),
}

fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(_) => {}
    }
    let listener = UnixListener::bind(path)?;
    // Same uid (or fsGroup) in both containers; nobody else needs access.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Environment mode: the data link carrying raw ACP bytes between the harness (through
/// agentd) and the gateway. Exactly one connection is accepted.
pub struct DataListener {
    listener: UnixListener,
}

impl DataListener {
    pub fn bind(run_dir: &Path) -> std::io::Result<DataListener> {
        std::fs::create_dir_all(run_dir)?;
        Ok(DataListener { listener: bind_socket(&run_dir.join(DATA_SOCKET_FILE))? })
    }

    /// Accept agentd's data connection, then refuse every further one.
    pub async fn accept(self, timeout: Duration) -> Result<UnixStream, LinkError> {
        let (s, _) =
            tokio::time::timeout(timeout, self.listener.accept()).await.map_err(|_| LinkError::Timeout(timeout))??;
        let listener = self.listener;
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });
        Ok(s)
    }
}

pub struct AgentListener {
    listener: UnixListener,
    pub socket: PathBuf,
    child: Option<Child>,
    rejected: Arc<AtomicU32>,
}

impl AgentListener {
    pub fn bind(run_dir: &Path) -> std::io::Result<AgentListener> {
        std::fs::create_dir_all(run_dir)?;
        let socket = run_dir.join(SOCKET_FILE);
        let listener = bind_socket(&socket)?;
        Ok(AgentListener { listener, socket, child: None, rejected: Arc::new(AtomicU32::new(0)) })
    }

    /// Start agentd as a child process (own process group; killed with runnerd).
    pub fn spawn_agentd(&mut self, program: &Path, env: &[(String, String)]) -> std::io::Result<u32> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.arg("run")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .env("ACP_AGENTD_SOCKET", &self.socket)
            .stdin(std::process::Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        if !env.iter().any(|(k, _)| k == "PATH")
            && let Ok(p) = std::env::var("PATH")
        {
            cmd.env("PATH", p);
        }
        // SAFETY: only async-signal-safe prctl(2) between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGKILL))
                    .map_err(std::io::Error::from)?;
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id().unwrap_or(0);
        self.child = Some(child);
        Ok(pid)
    }

    pub fn spawned_pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }

    /// Exit status of a spawned agentd, if it has exited.
    pub fn spawned_exit(&mut self) -> Option<(Option<i32>, Option<i32>)> {
        let st = self.child.as_mut()?.try_wait().ok()??;
        Some((st.code(), st.signal()))
    }

    /// Accept the one agentd connection.
    pub async fn accept(&mut self, timeout: Duration) -> Result<AgentConn, LinkError> {
        let (listener, child) = (&self.listener, &mut self.child);
        let accept = async move {
            let child_wait = async {
                match child.as_mut() {
                    Some(c) => c.wait().await.ok(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                r = listener.accept() => r.map(|(s, _)| s).map_err(LinkError::from),
                st = child_wait => Err(LinkError::AgentdExited(st.and_then(|s| s.code()))),
            }
        };
        let stream = tokio::time::timeout(timeout, accept).await.map_err(|_| LinkError::Timeout(timeout))??;
        let peer = stream.peer_cred().ok().map(|c| (c.pid(), c.uid()));
        Ok(AgentConn::new(stream, peer, self.rejected.clone()))
    }

    /// After the first connection: refuse (close) every further connection.
    pub fn reject_further_connections(self) -> (Option<Child>, Arc<AtomicU32>) {
        let rejected = self.rejected.clone();
        let listener = self.listener;
        let counter = rejected.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        (self.child, rejected)
    }
}

pub struct AgentConn {
    rx: mpsc::Receiver<Result<FromAgent, String>>,
    tx: Option<OwnedWriteHalf>,
    pub peer: Option<(Option<i32>, u32)>,
    pub rejected: Arc<AtomicU32>,
}

impl AgentConn {
    fn new(stream: UnixStream, peer: Option<(Option<i32>, u32)>, rejected: Arc<AtomicU32>) -> AgentConn {
        let (mut rd, wr) = stream.into_split();
        let (tx, rx) = mpsc::channel(4096);
        tokio::spawn(async move {
            loop {
                match read_frame::<_, FromAgent>(&mut rd).await {
                    Ok(Some(m)) => {
                        if tx.send(Ok(m)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string())).await;
                        break;
                    }
                }
            }
        });
        AgentConn { rx, tx: Some(wr), peer, rejected }
    }

    /// Next message; `None` when agentd closed the connection. `Some(Err)` is a protocol
    /// violation (the link is unusable afterwards).
    pub async fn recv(&mut self) -> Option<Result<FromAgent, String>> {
        self.rx.recv().await
    }

    pub async fn send(&mut self, m: &ToAgent) -> Result<(), IpcError> {
        match self.tx.as_mut() {
            Some(w) => write_frame(w, m).await,
            None => Err(IpcError::Io(std::io::Error::new(std::io::ErrorKind::NotConnected, "link closed"))),
        }
    }

    /// Close our side: agentd sees end-of-stream and terminates.
    pub fn close(&mut self) {
        self.tx.take();
    }

    pub fn rejected_connections(&self) -> u32 {
        self.rejected.load(Ordering::SeqCst)
    }
}

/// Wait for a spawned agentd to exit, then kill its process group (stragglers included).
pub async fn reap_spawned(child: Option<Child>, wait: Duration) {
    let Some(mut c) = child else { return };
    let pgid = c.id().map(|p| nix::unistd::Pid::from_raw(p as i32));
    if tokio::time::timeout(wait, c.wait()).await.is_err() {
        let _ = c.start_kill();
    }
    if let Some(pg) = pgid {
        let _ = nix::sys::signal::killpg(pg, nix::sys::signal::Signal::SIGKILL);
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
}
