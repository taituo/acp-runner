//! acp-runnerctl — administrator CLI.
//!
//! ```text
//! acp-runnerctl auth enroll codex personal-1      # human completes ChatGPT device login
//! acp-runnerctl auth enroll claude max-1          # human runs `claude setup-token`
//! acp-runnerctl auth list
//! acp-runnerctl auth inspect personal-1           # never prints credential values
//! acp-runnerctl run list | get | events | artifact
//! ```

mod auth;
mod runs;

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "acp-runnerctl", version, about = "acp-runner administration CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
// Parse-time dispatch enum: variant size is irrelevant.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Credential profiles (enrollment, inspection).
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Runs, attempts, journal events and artifacts (reads PostgreSQL).
    #[command(subcommand)]
    Run(RunCmd),
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum StoreKind {
    /// Kubernetes Secrets (namespace --namespace).
    K8s,
    /// Local directory (development / dev-run).
    File,
}

#[derive(Args, Clone, Debug)]
pub struct StoreArgs {
    #[arg(long, value_enum, default_value = "k8s", env = "ACP_RUNNER_CREDENTIAL_STORE")]
    pub store: StoreKind,
    /// Namespace of the credential Secrets (controller namespace).
    #[arg(long, short = 'n', default_value = "acp-runner-system", env = "ACP_RUNNER_CREDENTIAL_NAMESPACE")]
    pub namespace: String,
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_DIR")]
    pub credential_dir: Option<PathBuf>,
    /// Optional: show profile status and leases from the journal.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Runtime {
    /// Run the CLI installed on this machine with an isolated temporary HOME.
    Local,
    /// Run the CLI inside the runner image with `docker run -it`.
    Docker,
    /// Run the CLI in a temporary pod (`kubectl exec -it`).
    Kubectl,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Method {
    /// codex: `codex login --device-auth` (headless-friendly; enable device code login in ChatGPT settings)
    Device,
    /// codex: `codex login` browser flow (callback on localhost:1455; use SSH port forwarding when remote)
    Browser,
    /// codex: workspace access token via `codex login --with-access-token` (Enterprise workspaces)
    AccessToken,
    /// claude: run `claude setup-token`, then paste the printed token
    SetupToken,
}

#[derive(Subcommand)]
pub enum AuthCmd {
    /// Enroll a credential profile through the provider's own login flow.
    Enroll(auth::EnrollArgs),
    /// List credential profiles (metadata only).
    List {
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long, short = 'o', default_value = "table")]
        output: String,
    },
    /// Show non-secret facts about a profile. Never prints credential values.
    Inspect {
        profile: String,
        #[command(flatten)]
        store: StoreArgs,
        #[arg(long, short = 'o', default_value = "yaml")]
        output: String,
    },
    /// Disable a profile in the journal (no new leases).
    Disable {
        profile: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Re-enable a disabled / needs_reauth profile.
    Enable {
        profile: String,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    /// Delete a profile's stored material.
    Delete {
        profile: String,
        #[command(flatten)]
        store: StoreArgs,
    },
    /// Grant a profile's usage policy (V2 trust boundary): namespaces and
    /// runner classes allowed to lease it. Replaces the policy (empty clears).
    Allow {
        profile: String,
        #[command(flatten)]
        store: StoreArgs,
        /// Namespaces allowed to lease this profile (repeatable).
        #[arg(long = "allow-namespace")]
        allow_namespaces: Vec<String>,
        /// Runner classes allowed to lease this profile (repeatable).
        #[arg(long = "allow-class")]
        allow_classes: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum RunCmd {
    List {
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        #[arg(long, default_value_t = 30)]
        limit: i64,
    },
    Get {
        run: String,
        #[arg(long, short = 'n')]
        namespace: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },
    Events {
        run: String,
        #[arg(long, short = 'n')]
        namespace: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Keep polling for new events.
        #[arg(long, short = 'f')]
        follow: bool,
        /// Include raw provider payloads.
        #[arg(long)]
        raw: bool,
        #[arg(long, short = 'o', default_value = "text")]
        output: String,
    },
    Artifact {
        run: String,
        #[arg(long, short = 'n')]
        namespace: Option<String>,
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
        /// Write the patch here (default: stdout).
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
        /// Artifact id (default: the run's result artifact, else the latest).
        #[arg(long)]
        id: Option<uuid::Uuid>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ACP_RUNNERCTL_LOG").unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Auth(c) => auth::run(c).await,
        Cmd::Run(c) => runs::run(c).await,
    }
}
