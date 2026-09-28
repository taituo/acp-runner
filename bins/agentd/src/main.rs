//! agentd — the untrusted half of an attempt.
//!
//! agentd runs in the agent container (Kubernetes) next to runnerd, sharing only
//! `/workspace`, `/home/agent` and `/run/acp-runner`. It never sees the attempt Secret, the
//! controller URL or the attempt token. It:
//!
//! 1. connects to runnerd's Unix socket (`/run/acp-runner/agentd.sock`) and says `Hello`
//!    (with a self-check of its own container),
//! 2. waits for `Launch` (a sanitized [`AgentLaunchSpec`]),
//! 3. reads (and deletes) credentials runnerd staged for environment delivery, and sets
//!    them for the CLI process only — only after the untrusted bootstrap finished
//!    (runnerd places them on BootstrapDone, agentd reads them after Proceed);
//!    without bootstrap the order is unchanged,
//! 4. one-shot: prepares/probes/spawns the driver (unchanged `acp-runner-drivers`: ACP for
//!    fake and Codex, stream-json for Claude Code), opens the session and sends the prompt;
//!    forwards normalized events, honours `Cancel` (graceful cancel -> grace -> SIGTERM ->
//!    SIGKILL of the CLI process group), and reports `Exit`,
//! 5. environment mode (`raw_acp`): starts the harness as an ACP stdio agent (Claude Code
//!    through the in-tree bridge, `agentd claude-acp-bridge`) and copies bytes between its
//!    stdio and runnerd's data socket — the remote caller is the ACP client; agentd only
//!    supervises the process (`Finish`/`Cancel` terminate it, an exit is reported).
//!
//! agentd is treated as compromised-by-default: everything it sends is a claim. It cannot
//! report a terminal attempt state, upload artifacts or heartbeat to the controller — those
//! are runnerd's. If runnerd disappears, agentd terminates the CLI and exits.

use acp_runner_core::events::{SessionStartedData, truncate_utf8};
use acp_runner_core::failure::FailureReason;
use acp_runner_drivers::process::ManagedChild;
use acp_runner_drivers::{AgentDriver, AgentProcess, AuthState, DriverContext, DriverEvent, ExitInfo, driver_for};
use acp_runner_ipc::{
    AgentEvent, AgentExit, AgentLaunchSpec, AgentOutcome, AgentPosture, DATA_SOCKET_FILE, FromAgent, PROTOCOL_VERSION,
    ToAgent, read_frame, write_frame,
};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

mod reap;

#[derive(Parser)]
#[command(name = "agentd", version, about = "acp-runner untrusted agent executor")]
struct Cli {
    /// runnerd's socket.
    #[arg(long, env = "ACP_AGENTD_SOCKET", default_value = "/run/acp-runner/agentd.sock")]
    socket: PathBuf,
    /// How long to wait for runnerd's socket to appear.
    #[arg(long, env = "ACP_AGENTD_CONNECT_TIMEOUT", default_value_t = 900)]
    connect_timeout: u64,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve one attempt for runnerd (default).
    Run,
    /// Probe a driver (executable, version, auth state) and print JSON. Never prints secrets.
    Probe {
        #[arg(long)]
        driver: String,
        #[arg(long, default_value = "{}")]
        config: String,
        #[arg(long)]
        home: Option<PathBuf>,
        /// Credential files to expose as env (KEY=FILE, e.g. CLAUDE_CODE_OAUTH_TOKEN=/path).
        #[arg(long = "credential-env")]
        credential_env: Vec<String>,
    },
    /// ACP stdio agent wrapping the Claude Code CLI (started by agentd itself in environment
    /// mode; configured through the environment).
    ClaudeAcpBridge,
}

pub const ATTEMPT_SECRET_DIR: &str = "/var/run/acp-runner/attempt";
const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("AGENTD_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    // Credentials staged for env delivery live in this process' memory; the CLI (a child,
    // same uid) must not be able to read them from /proc/<agentd>/{mem,environ}.
    let _ = nix::sys::prctl::set_dumpable(false);
    let cli = Cli::parse();
    let res = match cli.cmd.unwrap_or(Cmd::Run) {
        Cmd::Run => serve(&cli.socket, Duration::from_secs(cli.connect_timeout)).await,
        Cmd::Probe { driver, config, home, credential_env } => probe(driver, config, home, credential_env).await,
        Cmd::ClaudeAcpBridge => claude_bridge().await,
    };
    match res {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "agentd failed");
            std::process::ExitCode::from(2)
        }
    }
}

async fn claude_bridge() -> anyhow::Result<()> {
    use acp_runner_drivers::claude_acp::{BridgeConfig, CONFIG_ENV, run_bridge};
    let cfg: BridgeConfig = serde_json::from_str(
        &std::env::var(CONFIG_ENV).map_err(|_| anyhow::anyhow!("{CONFIG_ENV} is not set (started outside agentd?)"))?,
    )?;
    // The bridge was started with the harness environment; each claude turn inherits it.
    let env: Vec<(String, String)> = std::env::vars().filter(|(k, _)| k != CONFIG_ENV).collect();
    run_bridge(tokio::io::stdin(), tokio::io::stdout(), cfg, env).await?;
    Ok(())
}

async fn probe(driver: String, config: String, home: Option<PathBuf>, cred: Vec<String>) -> anyhow::Result<()> {
    let home = home.unwrap_or_else(|| std::env::temp_dir().join(format!("agentd-probe-{}", std::process::id())));
    std::fs::create_dir_all(&home)?;
    let mut credential_env = vec![];
    for kv in cred {
        let (k, f) = kv.split_once('=').ok_or_else(|| anyhow::anyhow!("expected KEY=FILE"))?;
        credential_env.push((k.to_string(), std::fs::read_to_string(f)?.trim().to_string()));
    }
    let ctx = DriverContext {
        attempt_id: uuid::Uuid::new_v4(),
        ordinal: 1,
        workspace: std::env::current_dir()?,
        home,
        tmp: std::env::temp_dir(),
        config: serde_json::from_str(&config)?,
        class_env: Default::default(),
        credential_env,
        permissions: Default::default(),
        egress: Default::default(),
        record_raw: false,
        path_env: std::env::var("PATH").ok(),
        extra_ca_file: None,
        bridge_exe: std::env::current_exe().ok(),
    };
    let d = driver_for(&driver)?;
    d.prepare(&ctx).await?;
    let report = d.probe(&ctx).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

// ---------------------------------------------------------------------------------------

fn self_posture() -> AgentPosture {
    let runnerd_visible = std::fs::read_dir("/proc")
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit())
                    && std::fs::read_to_string(e.path().join("comm")).map(|c| c.trim() == "runnerd").unwrap_or(false)
            })
        })
        .unwrap_or(false);
    AgentPosture {
        uid: nix::unistd::getuid().as_raw(),
        attempt_secret_visible: Path::new(ATTEMPT_SECRET_DIR).exists(),
        ingest_env_present: std::env::vars_os().any(|(k, _)| k.to_string_lossy().starts_with("ACP_RUNNER_")),
        service_account_token_present: Path::new(SA_TOKEN_PATH).exists(),
        runnerd_process_visible: runnerd_visible,
    }
}

async fn connect(socket: &Path, timeout: Duration) -> anyhow::Result<UnixStream> {
    let deadline = Instant::now() + timeout;
    loop {
        match UnixStream::connect(socket).await {
            Ok(s) => return Ok(s),
            Err(e) if Instant::now() >= deadline => {
                anyhow::bail!("runnerd socket {} not reachable within {timeout:?}: {e}", socket.display())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

/// Outbound message queue (a writer task owns the socket's write half).
#[derive(Clone)]
struct Out(mpsc::Sender<FromAgent>);

impl Out {
    async fn send(&self, m: FromAgent) {
        let _ = self.0.send(m).await;
    }
    async fn event(&self, event: AgentEvent) {
        self.send(FromAgent::Event { event }).await
    }
    async fn progress(&self, category: &str, message: &str, detail: Value) {
        let data = acp_runner_core::events::ProgressData::new(category, message).with_detail(detail);
        self.event(AgentEvent::Progress { data, raw: None }).await
    }
}

enum Ctl {
    Cancel(String),
    Gone,
}

async fn serve(socket: &Path, connect_timeout: Duration) -> anyhow::Result<()> {
    // Fail closed: without the subreaper flag, orphaned bootstrap grandchildren
    // would reparent to init and the per-step sweep could not see them.
    reap::ensure_subreaper()?;
    let stream = connect(socket, connect_timeout).await?;
    let (mut rd, mut wr) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::channel::<FromAgent>(1024);
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if let Err(e) = write_frame(&mut wr, &m).await {
                tracing::warn!(error = %e, "writing to runnerd failed");
                break;
            }
        }
    });
    let (in_tx, mut inbox) = mpsc::channel::<ToAgent>(16);
    tokio::spawn(async move {
        loop {
            match read_frame::<_, ToAgent>(&mut rd).await {
                Ok(Some(m)) => {
                    if in_tx.send(m).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(acp_runner_ipc::IpcError::Io(e)) => {
                    tracing::info!(error = %e, "runnerd closed the connection");
                    break;
                }
                Err(e) => {
                    tracing::error!(error = %e, "malformed message from runnerd");
                    break;
                }
            }
        }
    });
    let out = Out(out_tx);
    out.send(FromAgent::Hello {
        protocol: PROTOCOL_VERSION,
        agentd_version: env!("CARGO_PKG_VERSION").into(),
        pid: std::process::id(),
        posture: self_posture(),
    })
    .await;
    let spec = match inbox.recv().await {
        Some(ToAgent::Launch { spec }) => spec,
        Some(_) | None => {
            tracing::info!("runnerd ended the attempt before launch");
            return Ok(());
        }
    };
    tracing::info!(attempt_id = %spec.attempt_id, driver = %spec.driver, raw_acp = spec.raw_acp, "launching agent");
    let data_socket =
        socket.parent().map(|d| d.join(DATA_SOCKET_FILE)).unwrap_or_else(|| PathBuf::from(DATA_SOCKET_FILE));
    if let Some(exit) = run(&spec, &out, &mut inbox, &data_socket).await {
        out.send(FromAgent::Exit { exit }).await;
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(10), writer).await;
    Ok(())
}

/// Await `fut`, unless runnerd cancels or disappears first.
async fn or_ctl<F: Future>(inbox: &mut mpsc::Receiver<ToAgent>, fut: F) -> Result<F::Output, Ctl> {
    tokio::pin!(fut);
    loop {
        tokio::select! {
            r = &mut fut => return Ok(r),
            m = inbox.recv() => match m {
                Some(ToAgent::Cancel { reason }) => return Err(Ctl::Cancel(reason)),
                Some(ToAgent::Finish) => return Err(Ctl::Cancel("finish during startup".into())),
                Some(ToAgent::Launch { .. }) | Some(ToAgent::Proceed) => tracing::warn!("unexpected control message ignored"),
                None => return Err(Ctl::Gone),
            },
        }
    }
}

fn failed(reason: FailureReason) -> AgentExit {
    AgentExit { outcome: AgentOutcome::Failed { reason }, exit_code: None, signal: None, stderr_tail: String::new() }
}

fn cancelled_before_start() -> AgentExit {
    AgentExit {
        outcome: AgentOutcome::Cancelled { acknowledged: true, stop_reason: None },
        exit_code: None,
        signal: None,
        stderr_tail: String::new(),
    }
}

fn ctl_exit(c: Ctl) -> Option<AgentExit> {
    match c {
        Ctl::Cancel(reason) => {
            tracing::info!(%reason, "cancelled before the agent started");
            Some(cancelled_before_start())
        }
        Ctl::Gone => None,
    }
}

fn to_agent_event(ev: DriverEvent) -> Option<AgentEvent> {
    Some(match ev {
        DriverEvent::SessionStarted { info, raw } => AgentEvent::SessionStarted {
            data: SessionStartedData {
                provider_session_id: info.provider_session_id,
                protocol: info.protocol,
                agent_name: info.agent_name,
                agent_version: info.agent_version,
                model: info.model,
                capabilities: info.capabilities,
            },
            raw,
        },
        DriverEvent::AgentOutput { channel, text, raw: _ } => AgentEvent::Output { channel: channel.into(), text },
        DriverEvent::ToolCall { data, raw } => AgentEvent::ToolCall { data, raw },
        DriverEvent::ToolResult { data, raw } => AgentEvent::ToolResult { data, raw },
        DriverEvent::PermissionRequest { data, raw } => AgentEvent::PermissionRequest { data, raw },
        DriverEvent::Progress { data, raw } => AgentEvent::Progress { data, raw },
        DriverEvent::TurnEnded { .. } | DriverEvent::Failure { .. } | DriverEvent::Exited { .. } => return None,
    })
}

/// Read and delete the credentials runnerd staged for environment delivery.
fn take_staged_credentials(spec: &AgentLaunchSpec) -> Result<Vec<(String, String)>, FailureReason> {
    let mut out = vec![];
    for c in &spec.credential_env {
        let v = std::fs::read_to_string(&c.path).map_err(|e| FailureReason::Internal {
            detail: format!("staged credential for {} unreadable: {e}", c.env_name),
        })?;
        let _ = std::fs::remove_file(&c.path);
        out.push((c.env_name.clone(), v.trim().to_string()));
    }
    if let Some(dir) = spec.credential_env.first().and_then(|c| c.path.parent()) {
        let _ = std::fs::remove_dir(dir);
    }
    Ok(out)
}

/// Outcome of driving one prompt turn.
enum TurnEnd {
    Ended {
        success: bool,
        stop_reason: String,
        detail: String,
        summary: Option<String>,
    },
    Failure(FailureReason),
    Crashed(ExitInfo, String),
    /// runnerd asked to cancel the current turn (harness stays alive in interactive mode).
    Cancelled {
        reason: String,
        acknowledged: bool,
        stop_reason: Option<String>,
    },
    /// runnerd asked to finish the session (cancel the turn, then end).
    FinishRequested,
    /// runnerd disappeared.
    Gone,
}

async fn build_context(spec: &AgentLaunchSpec) -> Result<DriverContext, FailureReason> {
    // Credential values are NOT read here: with an untrusted bootstrap they do
    // not exist yet (runnerd places them after BootstrapDone) and must never
    // be readable during bootstrap. `run` fills `credential_env` via
    // `take_staged_credentials` at the right point (after Proceed, or now when
    // there is no bootstrap). Paths are carried in the launch spec instead.
    let _ = std::fs::create_dir_all(&spec.tmp);
    let base_path = spec.path_env.clone().or_else(|| std::env::var("PATH").ok());
    let path_env = if spec.path_prepend.is_empty() {
        base_path
    } else {
        let mut parts: Vec<String> = spec.path_prepend.iter().map(|p| p.to_string_lossy().to_string()).collect();
        parts.push(base_path.unwrap_or_else(|| acp_runner_drivers::env::DEFAULT_PATH.to_string()));
        Some(parts.join(":"))
    };
    Ok(DriverContext {
        attempt_id: spec.attempt_id,
        ordinal: spec.ordinal,
        // the harness (probe, process, tools) runs in the workdir
        workspace: spec.workdir.clone().unwrap_or_else(|| spec.workspace.clone()),
        home: spec.home.clone(),
        tmp: spec.tmp.clone(),
        config: spec.driver_config.clone(),
        class_env: spec.env.clone(),
        credential_env: vec![],
        permissions: spec.permissions,
        egress: spec.egress.clone(),
        record_raw: spec.record_raw,
        path_env,
        extra_ca_file: spec.extra_ca_file.clone(),
        bridge_exe: std::env::current_exe().ok(),
    })
}

const DEFAULT_EXEC_TIMEOUT: Duration = Duration::from_secs(600);

/// Run the untrusted bootstrap commands: plain `execve(command, argv, env)` — no shell, no
/// DSL — in the agent container, before the harness starts.
///
/// Ordering vs credentials: the steps run BEFORE runnerd places the credential
/// copies (placement happens on BootstrapDone, before Proceed), and the staged
/// files are read only after Proceed — so a step can neither receive credential
/// variables (the environment is the scrubbed agent base plus the step's own
/// variables) nor read the files from the HOME. The step `cwd` is entered via
/// an `O_NOFOLLOW` walk + `fchdir` just before `execve` (no runnerd-side
/// pre-check: an earlier step could swap a symlink between check and exec).
/// After every step, leftover descendants are killed and reaped; anything still
/// alive fails the bootstrap — it would otherwise still be running when the
/// credentials land.
async fn run_bootstrap(
    spec: &AgentLaunchSpec,
    ctx: &DriverContext,
    out: &Out,
    inbox: &mut mpsc::Receiver<ToAgent>,
) -> Result<(), Option<AgentExit>> {
    let mut base = ctx.clone();
    base.credential_env.clear();
    for (i, step) in spec.bootstrap.iter().enumerate() {
        let name = step.command.rsplit('/').next().unwrap_or(&step.command).to_string();
        let label = format!("exec[{i}] {name}");
        let fail = |detail: String| Err(Some(failed(FailureReason::BootstrapFailed { step: label.clone(), detail })));
        // (workspace root, rel) for the secure enter; the joined `cwd` is only
        // used to resolve a relative `command` to an absolute program path.
        let (root, rel) = match &step.cwd {
            Some(c) => match acp_runner_core::environment::normalize_workdir(c) {
                Ok(rel) => (spec.workspace.clone(), rel),
                Err(e) => return fail(e.to_string()),
            },
            None => match ctx.workspace.strip_prefix(&spec.workspace) {
                Ok(rel) => (spec.workspace.clone(), rel.to_string_lossy().to_string()),
                Err(_) => {
                    return fail(format!(
                        "workdir {} is not below the workspace",
                        ctx.workspace.display()
                    ));
                }
            },
        };
        let cwd = spec.workspace.join(&rel);
        let env: Vec<(String, String)> = step.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let env = match acp_runner_drivers::env::compose(&base, &env) {
            Ok(e) => e,
            Err(e) => return fail(e.to_string()),
        };
        let program = if step.command.contains('/') && !step.command.starts_with('/') {
            cwd.join(&step.command).to_string_lossy().to_string()
        } else {
            step.command.clone()
        };
        let started = Instant::now();
        let mut child = match ManagedChild::spawn(&acp_runner_drivers::process::SpawnSpec {
            program,
            args: step.args.clone(),
            env,
            cwd,
            secure_cwd: Some(acp_runner_drivers::process::SecureCwd { root, rel }),
        }) {
            Ok(c) => c,
            Err(e) => return fail(e.to_string()),
        };
        drop(child.take_stdin());
        let stdout_tail = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        if let Some(mut so) = child.take_stdout() {
            let tail = stdout_tail.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut so, &mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut t = tail.lock().expect("tail");
                    t.extend_from_slice(&buf[..n]);
                    let len = t.len();
                    if len > 8192 {
                        t.drain(..len - 8192);
                    }
                }
            });
        }
        let limit = step.timeout_seconds.map(Duration::from_secs).unwrap_or(DEFAULT_EXEC_TIMEOUT);
        let exit = tokio::select! {
            e = child.wait() => Ok(e),
            _ = tokio::time::sleep(limit) => Err(format!("timed out after {limit:?}")),
            m = inbox.recv() => match m {
                Some(ToAgent::Cancel { .. }) | Some(ToAgent::Finish) => {
                    child.terminate(Duration::from_secs(2)).await;
                    return Err(Some(cancelled_before_start()));
                }
                None => {
                    child.terminate(Duration::from_secs(2)).await;
                    return Err(None);
                }
                Some(_) => Err("unexpected control message during bootstrap".into()),
            },
        };
        let exit = match exit {
            Ok(e) => e,
            Err(why) => {
                child.terminate(Duration::from_secs(2)).await;
                return fail(why);
            }
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Kill and reap anything the step left behind (orphans reparent to us:
        // agentd is a child subreaper). Leftovers are SIGKILLed even when the
        // step itself failed — they must not survive into the harness lifetime,
        // when the credentials land in the HOME.
        let leftovers = reap::kill_and_reap_descendants();
        let stderr = truncate_utf8(child.stderr_tail().trim(), 2000).0;
        let stdout = truncate_utf8(String::from_utf8_lossy(&stdout_tail.lock().expect("tail")).trim(), 2000).0;
        out.progress(
            "bootstrap_exec",
            &label,
            json!({"step": i, "command": name, "exitCode": exit.code, "signal": exit.signal,
                   "seconds": started.elapsed().as_secs_f64(), "stdoutTail": stdout, "stderrTail": stderr}),
        )
        .await;
        if !exit.success() {
            return fail(format!(
                "exit code {:?} signal {:?}: {}",
                exit.code,
                exit.signal,
                truncate_utf8(&stderr, 500).0
            ));
        }
        if !leftovers.is_empty() {
            return fail(format!("left background processes (pids {leftovers:?}); they were killed"));
        }
    }
    Ok(())
}

async fn run(
    spec: &AgentLaunchSpec,
    out: &Out,
    inbox: &mut mpsc::Receiver<ToAgent>,
    data_socket: &Path,
) -> Option<AgentExit> {
    let mut ctx = match build_context(spec).await {
        Ok(c) => c,
        Err(r) => return Some(failed(r)),
    };
    if spec.bootstrap.is_empty() {
        // No untrusted bootstrap: the old order (credentials already placed by
        // runnerd, read before prepare/probe).
        match take_staged_credentials(spec) {
            Ok(c) => ctx.credential_env = c,
            Err(r) => return Some(failed(r)),
        }
    }
    let grace = Duration::from_secs(spec.timeouts.grace_seconds);
    let startup = Duration::from_secs(spec.timeouts.startup_seconds.max(30));
    let status_secs = spec.timeouts.status_seconds.max(1);
    let driver = match driver_for(&spec.driver) {
        Ok(d) => d,
        Err(e) => return Some(failed(e.to_failure(&spec.driver))),
    };
    let driver_name = driver.name().to_string();
    match or_ctl(inbox, driver.prepare(&ctx)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Some(failed(e.to_failure(&driver_name))),
        Err(c) => return ctl_exit(c),
    }
    if !spec.bootstrap.is_empty() {
        if let Err(exit) = run_bootstrap(spec, &ctx, out, inbox).await {
            return exit;
        }
        out.send(FromAgent::BootstrapDone { steps: spec.bootstrap.len() as u32 }).await;
        loop {
            match inbox.recv().await {
                Some(ToAgent::Proceed) => break,
                Some(ToAgent::Cancel { .. }) | Some(ToAgent::Finish) => return Some(cancelled_before_start()),
                Some(ToAgent::Launch { .. }) => tracing::warn!("duplicate Launch ignored"),
                None => return None,
            }
        }
        // runnerd placed the credential copies only after BootstrapDone: read
        // (and delete) the staged files now — the bootstrap never saw them.
        match take_staged_credentials(spec) {
            Ok(c) => ctx.credential_env = c,
            Err(r) => return Some(failed(r)),
        }
    }
    let mut program = driver_name.clone();
    if !spec.skip_probe {
        match or_ctl(inbox, driver.probe(&ctx)).await {
            Ok(Ok(p)) => {
                if let Some(exe) = &p.executable {
                    program = exe.rsplit('/').next().unwrap_or(exe).to_string();
                }
                out.send(FromAgent::Probe {
                    report: serde_json::to_value(&p).unwrap_or(Value::Null),
                    executable: p.executable.clone(),
                    cli_version: p.cli_version.clone(),
                    adapter_version: p.adapter_version.clone(),
                })
                .await;
                match &p.auth {
                    AuthState::EnrollmentRequired { detail } => {
                        return Some(failed(FailureReason::AuthEnrollmentRequired {
                            provider: driver_name.clone(),
                            detail: detail.clone(),
                        }));
                    }
                    AuthState::PolicyViolation { detail } => {
                        return Some(failed(FailureReason::AuthPolicyViolation { detail: detail.clone() }));
                    }
                    _ => {}
                }
            }
            Ok(Err(e)) => return Some(failed(e.to_failure(&driver_name))),
            Err(c) => return ctl_exit(c),
        }
    }
    if spec.raw_acp {
        return raw_session(driver.as_ref(), &ctx, &program, out, inbox, data_socket, grace, status_secs).await;
    }
    let mut process: Box<dyn AgentProcess> = match driver.spawn(&ctx).await {
        Ok(p) => p,
        Err(e) => return Some(failed(e.to_failure(&driver_name))),
    };
    out.send(FromAgent::Started { program, pid: process.health().pid }).await;

    // ---- session init ------------------------------------------------------------------
    match or_ctl(inbox, tokio::time::timeout(startup, process.initialize_session())).await {
        Ok(Ok(Ok(_))) => {}
        Ok(Ok(Err(e))) => {
            let stderr = truncate_utf8(&process.stderr_tail(), 4000).0;
            let mut reason = e.to_failure(&driver_name);
            if let FailureReason::ProcessCrashed { detail, .. } = &mut reason {
                detail.push_str(&format!(" | stderr: {}", truncate_utf8(&stderr, 2000).0));
            }
            let exit = process.shutdown(grace).await;
            return Some(AgentExit {
                outcome: AgentOutcome::Failed { reason },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: stderr,
            });
        }
        Ok(Err(_)) => {
            process.shutdown(grace).await;
            return Some(failed(FailureReason::ProtocolError {
                detail: format!("session initialization exceeded {startup:?}"),
            }));
        }
        Err(Ctl::Cancel(reason)) => {
            tracing::info!(%reason, "cancelled during session initialization");
            let exit = process.shutdown(grace).await;
            return Some(AgentExit { exit_code: exit.code, signal: exit.signal, ..cancelled_before_start() });
        }
        Err(Ctl::Gone) => {
            process.shutdown(Duration::from_secs(2)).await;
            return None;
        }
    }

    one_shot(spec, process, &driver_name, out, inbox, grace, status_secs).await
}

/// Drive one prompt turn to completion, forwarding events and honouring Cancel/Finish.
async fn run_turn(
    process: &mut dyn AgentProcess,
    out: &Out,
    inbox: &mut mpsc::Receiver<ToAgent>,
    status_secs: u64,
) -> TurnEnd {
    let mut status = tokio::time::interval(Duration::from_secs(status_secs));
    status.tick().await;
    loop {
        tokio::select! {
            ev = process.next_event() => {
                let Some(ev) = ev else {
                    return TurnEnd::Crashed(ExitInfo::default(), "agent event stream ended".into());
                };
                match ev {
                    DriverEvent::TurnEnded { success, stop_reason, detail, summary, raw } => {
                        if raw.is_some() {
                            out.event(AgentEvent::Progress {
                                data: acp_runner_core::events::ProgressData::new("turn_ended", stop_reason.clone()),
                                raw,
                            }).await;
                        }
                        return TurnEnd::Ended { success, stop_reason, detail, summary };
                    }
                    DriverEvent::Failure { reason } => return TurnEnd::Failure(reason),
                    DriverEvent::Exited { exit, stderr_tail } => return TurnEnd::Crashed(exit, stderr_tail),
                    other => {
                        if let Some(e) = to_agent_event(other) {
                            out.event(e).await;
                        }
                    }
                }
            }
            m = inbox.recv() => match m {
                Some(ToAgent::Cancel { reason }) => {
                    let (acknowledged, stop_reason) = cancel_turn(out, process, Duration::from_secs(status_secs.max(5))).await;
                    return TurnEnd::Cancelled { reason, acknowledged, stop_reason };
                }
                Some(ToAgent::Finish) => {
                    let _ = cancel_turn(out, process, Duration::from_secs(status_secs.max(5))).await;
                    return TurnEnd::FinishRequested;
                }
                Some(ToAgent::Launch { .. }) | Some(ToAgent::Proceed) => tracing::warn!("unexpected control message ignored"),
                None => return TurnEnd::Gone,
            },
            _ = status.tick() => {
                let h = process.health();
                out.send(FromAgent::Status { agent_alive: h.alive, agent_pid: h.pid }).await;
            }
        }
    }
}

async fn one_shot(
    spec: &AgentLaunchSpec,
    mut process: Box<dyn AgentProcess>,
    driver_name: &str,
    out: &Out,
    inbox: &mut mpsc::Receiver<ToAgent>,
    grace: Duration,
    status_secs: u64,
) -> Option<AgentExit> {
    let prompt = spec.prompt.clone().unwrap_or_default();
    if let Err(e) = process.send_prompt(&prompt).await {
        let reason = e.to_failure(driver_name);
        process.shutdown(grace).await;
        return Some(failed(reason));
    }
    out.send(FromAgent::InputSent { bytes: prompt.len() }).await;
    let end = run_turn(process.as_mut(), out, inbox, status_secs).await;
    match end {
        TurnEnd::Ended { success, stop_reason, detail, summary } => {
            let exit = process.shutdown(grace).await;
            Some(AgentExit {
                outcome: AgentOutcome::TurnEnded { success, stop_reason, detail, summary },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: String::new(),
            })
        }
        TurnEnd::Failure(reason) => {
            let stderr = truncate_utf8(&process.stderr_tail(), 4000).0;
            let exit = process.shutdown(grace).await;
            Some(AgentExit {
                outcome: AgentOutcome::Failed { reason },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: stderr,
            })
        }
        TurnEnd::Crashed(exit, stderr_tail) => {
            process.shutdown(Duration::from_millis(100)).await;
            Some(AgentExit {
                outcome: AgentOutcome::Crashed { detail: "agent process exited unexpectedly".into() },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: truncate_utf8(stderr_tail.trim(), 4000).0,
            })
        }
        TurnEnd::Cancelled { reason, acknowledged, stop_reason } => {
            tracing::info!(%reason, "cancel requested by runnerd");
            let exit = process.shutdown(grace).await;
            out.progress("agent_terminated", "agent process stopped", json!({"exit": exit})).await;
            Some(AgentExit {
                outcome: AgentOutcome::Cancelled { acknowledged, stop_reason },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: String::new(),
            })
        }
        TurnEnd::FinishRequested => {
            let exit = process.shutdown(grace).await;
            Some(AgentExit {
                outcome: AgentOutcome::Cancelled { acknowledged: true, stop_reason: None },
                exit_code: exit.code,
                signal: exit.signal,
                stderr_tail: String::new(),
            })
        }
        TurnEnd::Gone => {
            tracing::warn!("runnerd disappeared; terminating the agent");
            process.shutdown(Duration::from_secs(2)).await;
            None
        }
    }
}

/// Environment mode: run the harness as an ACP stdio agent and splice its stdio onto the
/// data socket. agentd is not the ACP client here — the caller is (through runnerd's
/// gateway). agentd only supervises the process.
#[allow(clippy::too_many_arguments)]
async fn raw_session(
    driver: &dyn AgentDriver,
    ctx: &DriverContext,
    program: &str,
    out: &Out,
    inbox: &mut mpsc::Receiver<ToAgent>,
    data_socket: &Path,
    grace: Duration,
    status_secs: u64,
) -> Option<AgentExit> {
    let driver_name = driver.name().to_string();
    let spawn = match driver.acp_spawn(ctx) {
        Ok(s) => s,
        Err(e) => return Some(failed(e.to_failure(&driver_name))),
    };
    let mut child = match ManagedChild::spawn(&spawn) {
        Ok(c) => c,
        Err(e) => return Some(failed(e.to_failure(&driver_name))),
    };
    out.send(FromAgent::Started { program: program.to_string(), pid: Some(child.pid) }).await;
    let data = match connect(data_socket, Duration::from_secs(30)).await {
        Ok(s) => s,
        Err(e) => {
            child.terminate(Duration::from_secs(2)).await;
            return Some(failed(FailureReason::Internal { detail: format!("data link: {e}") }));
        }
    };
    let (mut data_rd, mut data_wr) = data.into_split();
    let (Some(mut stdin), Some(mut stdout)) = (child.take_stdin(), child.take_stdout()) else {
        child.terminate(Duration::from_secs(2)).await;
        return Some(failed(FailureReason::Internal { detail: "harness stdio unavailable".into() }));
    };
    // Byte copies in both directions; framing (newline-delimited JSON-RPC) is untouched.
    let to_caller = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stdout, &mut data_wr).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut data_wr).await;
    });
    let to_harness = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut data_rd, &mut stdin).await;
    });
    out.send(FromAgent::Ready).await;
    let mut exit_rx = child.exit_watch();
    let mut status = tokio::time::interval(Duration::from_secs(status_secs));
    status.tick().await;
    enum End {
        Finish,
        Cancel(String),
        Exited,
        Gone,
    }
    let end = loop {
        tokio::select! {
            m = inbox.recv() => match m {
                Some(ToAgent::Finish) => break End::Finish,
                Some(ToAgent::Cancel { reason }) => break End::Cancel(reason),
                Some(ToAgent::Launch { .. }) | Some(ToAgent::Proceed) => tracing::warn!("unexpected control message ignored"),
                None => break End::Gone,
            },
            _ = exit_rx.changed() => break End::Exited,
            _ = status.tick() => {
                out.send(FromAgent::Status { agent_alive: child.is_alive(), agent_pid: Some(child.pid) }).await;
            }
        }
    };
    let exit = match end {
        End::Exited => {
            // let the last bytes reach the caller
            let _ = tokio::time::timeout(Duration::from_secs(2), to_caller).await;
            let e = child.wait().await;
            child.signal_group(nix::sys::signal::Signal::SIGKILL);
            to_harness.abort();
            return Some(AgentExit {
                outcome: AgentOutcome::Crashed { detail: "harness exited".into() },
                exit_code: e.code,
                signal: e.signal,
                stderr_tail: truncate_utf8(child.stderr_tail().trim(), 4000).0,
            });
        }
        End::Gone => {
            child.terminate(Duration::from_secs(2)).await;
            return None;
        }
        End::Finish | End::Cancel(_) => child.terminate(grace).await,
    };
    to_harness.abort();
    to_caller.abort();
    let outcome = match end {
        End::Cancel(reason) => {
            tracing::info!(%reason, "environment cancelled");
            AgentOutcome::Cancelled { acknowledged: true, stop_reason: None }
        }
        _ => AgentOutcome::TurnEnded {
            success: true,
            stop_reason: "session_finished".into(),
            detail: "environment finished".into(),
            summary: None,
        },
    };
    Some(AgentExit { outcome, exit_code: exit.code, signal: exit.signal, stderr_tail: String::new() })
}

/// Cancel the current turn WITHOUT terminating the process (interactive mode): send the
/// harness cancel, then drain until the turn ends or a bounded wait elapses.
async fn cancel_turn(out: &Out, process: &mut dyn AgentProcess, wait: Duration) -> (bool, Option<String>) {
    let _ = process.cancel().await;
    let deadline = Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return (false, None);
        }
        match tokio::time::timeout(remaining, process.next_event()).await {
            Ok(Some(DriverEvent::TurnEnded { stop_reason, .. })) => return (true, Some(stop_reason)),
            Ok(Some(DriverEvent::Exited { .. })) | Ok(None) => return (true, None),
            Ok(Some(DriverEvent::Failure { .. })) => {}
            Ok(Some(other)) => {
                if let Some(e) = to_agent_event(other) {
                    out.event(e).await;
                }
            }
            Err(_) => return (false, None),
        }
    }
}
