use acp_runner_core::AttemptSpec;
use acp_runner_core::attempt_spec::TOKEN_FILE_NAME;
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use runnerd::agent_link::default_agentd_program;
use runnerd::sink::{FileSink, IngestSink};
use runnerd::{AgentView, AgentdLaunch, RunnerDirs, SupervisorOptions, run_attempt};
use std::path::PathBuf;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

#[derive(Parser)]
#[command(name = "runnerd", version, about = "acp-runner trusted in-sandbox attempt supervisor")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the attempt described by the controller (default; configured via environment).
    Pod,
    /// Run one attempt locally from a spec file, writing events/artifacts to a directory.
    /// runnerd starts agentd itself (same trust domain; development and compatibility
    /// testing only).
    Local(Box<LocalArgs>),
}

#[derive(clap::Args)]
struct LocalArgs {
    #[arg(long)]
    spec: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    workspace: Option<PathBuf>,
    #[arg(long)]
    home: Option<PathBuf>,
    #[arg(long)]
    tmp: Option<PathBuf>,
    #[arg(long)]
    run_dir: Option<PathBuf>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    secret_dir: Option<PathBuf>,
    /// agentd binary (default: next to runnerd, then PATH).
    #[arg(long)]
    agentd: Option<PathBuf>,
    #[arg(long)]
    skip_probe: bool,
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var(name).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(default))
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name).map(|v| matches!(v.as_str(), "1" | "true" | "yes")).unwrap_or(default)
}

fn cancel_on_sigterm() -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = term.recv() => {},
            _ = int.recv() => {},
        }
        tracing::warn!("termination signal received; cancelling attempt gracefully");
        let _ = tx.send(true);
    });
    rx
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Exactly one rustls provider, installed before any TLS client is built:
    // reqwest uses `rustls-no-provider`, and `ring` is the shared provider
    // (kube enables it elsewhere in the tree). Without this, Client::build
    // panics at startup.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("RUNNERD_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    // runnerd holds the attempt token: same-uid processes (agentd, the CLI in local modes)
    // must not read /proc/<runnerd>/{mem,environ,fd}.
    let _ = nix::sys::prctl::set_dumpable(false);
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Pod) {
        Cmd::Pod => pod().await,
        Cmd::Local(a) => {
            let LocalArgs { spec, out, workspace, home, tmp, run_dir, state_dir, secret_dir, agentd, skip_probe } = *a;
            let spec: AttemptSpec = serde_json::from_slice(&std::fs::read(&spec).context("reading spec")?)?;
            let mut dirs = RunnerDirs::under(&out.join("sandbox"), secret_dir);
            if let Some(w) = workspace {
                dirs.workspace = w.clone();
                dirs.agent.workspace = w;
            }
            if let Some(h) = home {
                dirs.home = h.clone();
                dirs.agent.home = h;
            }
            if let Some(t) = tmp {
                dirs.tmp = t.join("runnerd");
                dirs.agent.tmp = t.join("agent");
            }
            if let Some(r) = run_dir {
                dirs.run_dir = r;
            }
            if let Some(s) = state_dir {
                dirs.state = s;
            }
            let mut sink = FileSink::new(out.clone())?;
            let opts = SupervisorOptions {
                skip_probe,
                agent_path_env: std::env::var("PATH").ok(),
                agentd: AgentdLaunch::Spawn { program: agentd.unwrap_or_else(default_agentd_program), env: vec![] },
                ..Default::default()
            };
            let res = run_attempt(spec, dirs, &mut sink, opts, cancel_on_sigterm()).await;
            std::fs::write(out.join("result.json"), serde_json::to_vec_pretty(&res)?)?;
            println!("{}", serde_json::to_string_pretty(&res)?);
            Ok(())
        }
    }
}

async fn pod() -> anyhow::Result<()> {
    let ingest = std::env::var("ACP_RUNNER_INGEST_URL").context("ACP_RUNNER_INGEST_URL not set")?;
    let secret_dir = env_path("ACP_RUNNER_SECRET_DIR", "/var/run/acp-runner/attempt");
    let token =
        std::fs::read_to_string(secret_dir.join(TOKEN_FILE_NAME)).context("reading attempt token")?.trim().to_string();
    if token.len() < 32 {
        bail!("attempt token is malformed");
    }
    let mut sink = IngestSink::new(&ingest, token.clone())?;
    let spec = match sink.fetch_spec().await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "could not fetch attempt spec");
            std::process::exit(2);
        }
    };
    if spec.wire_version != acp_runner_core::WIRE_VERSION {
        tracing::error!(expected = acp_runner_core::WIRE_VERSION, got = spec.wire_version, "wire version mismatch");
        std::process::exit(2);
    }
    tracing::info!(run_id = %spec.run_id, attempt_id = %spec.attempt_id, driver = %spec.driver.name, ordinal = spec.ordinal, "starting attempt");
    let workspace = env_path("ACP_RUNNER_WORKSPACE", "/workspace");
    let home = env_path("ACP_RUNNER_HOME", "/home/agent");
    let dirs = RunnerDirs {
        agent: AgentView {
            workspace: std::env::var("ACP_RUNNER_AGENT_WORKSPACE").map(PathBuf::from).unwrap_or(workspace.clone()),
            home: std::env::var("ACP_RUNNER_AGENT_HOME").map(PathBuf::from).unwrap_or(home.clone()),
            tmp: env_path("ACP_RUNNER_AGENT_TMP", "/tmp"),
            harness: std::env::var("ACP_RUNNER_AGENT_HARNESS")
                .map(PathBuf::from)
                .unwrap_or_else(|_| env_path("ACP_RUNNER_HARNESS_DIR", acp_runner_core::harness::HARNESS_ROOT)),
        },
        harness: env_path("ACP_RUNNER_HARNESS_DIR", acp_runner_core::harness::HARNESS_ROOT),
        workspace,
        home,
        run_dir: env_path("ACP_RUNNER_RUN_DIR", "/run/acp-runner"),
        state: env_path("ACP_RUNNER_STATE_DIR", "/var/lib/acp-runner"),
        tmp: env_path("ACP_RUNNER_TMP", "/tmp"),
        secret_dir: Some(secret_dir),
    };
    let agentd = match std::env::var("ACP_RUNNER_AGENTD").as_deref() {
        Ok("spawn") => AgentdLaunch::Spawn { program: default_agentd_program(), env: vec![] },
        Ok("external") | Err(_) => AgentdLaunch::External,
        Ok(other) => bail!("ACP_RUNNER_AGENTD must be external or spawn, not {other:?}"),
    };
    let opts = SupervisorOptions {
        strict_posture: env_bool("ACP_RUNNER_STRICT_POSTURE", false),
        skip_probe: env_bool("ACP_RUNNER_SKIP_PROBE", false),
        agent_path_env: std::env::var("ACP_RUNNER_AGENT_PATH").ok(),
        extra_ca_file: std::env::var("ACP_RUNNER_EXTRA_CA_FILE").ok(),
        extra_secrets: vec![token],
        agentd,
        controller_watchdog: env_bool("ACP_RUNNER_CONTROLLER_WATCHDOG", true),
    };
    let (run_id, attempt_id, driver) = (spec.run_id, spec.attempt_id, spec.driver.name.clone());
    if matches!(spec.session, acp_runner_core::attempt_spec::SessionMode::Environment { .. }) {
        let res = runnerd::run_environment(spec, dirs, &mut sink, opts, cancel_on_sigterm()).await;
        tracing::info!(%run_id, %attempt_id, %driver, phase = %res.phase, reason = ?res.reason.as_ref().map(|r| r.code()), "environment finished");
        return Ok(());
    }
    let res = run_attempt(spec, dirs, &mut sink, opts, cancel_on_sigterm()).await;
    tracing::info!(%run_id, %attempt_id, %driver, phase = %res.phase, reason = ?res.reason.as_ref().map(|r| r.code()), "attempt finished");
    Ok(())
}
