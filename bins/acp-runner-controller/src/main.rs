//! acp-runner controller.
//!
//! * `run` (default): Kubernetes controller for `ACPRun`, runnerd ingest API, metrics.
//! * `crdgen`: print the CRDs as YAML.
//! * `dev-run`: execute one ACPRun manifest locally (engine + ingest + LocalProcessBackend),
//!   no Kubernetes needed — used for development and demos with the fake driver.

mod controller;
mod dev;
mod env_controller;

use acp_runner_engine::backend::SandboxBackend;
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, sync_profiles};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig};
use acp_runner_journal::{ArtifactStore, BlobStore, FsBlobStore, Journal, PgArtifactStore};
use acp_runner_k8s::backends::{AgentSandboxBackend, PodBackend};
use acp_runner_k8s::pod::PodConfig;
use acp_runner_k8s::secret_store::K8sSecretStore;
use anyhow::Context;
use axum::Router;
use axum::routing::get;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "acp-runner-controller", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the controller (default).
    Run(Box<RunArgs>),
    /// Print CustomResourceDefinitions (YAML).
    Crdgen,
    /// Execute one ACPRun manifest locally without Kubernetes.
    DevRun(dev::DevRunArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum BackendKind {
    Pod,
    AgentSandbox,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum CredStoreKind {
    K8s,
    File,
}

#[derive(Args, Clone, Debug)]
pub struct CommonArgs {
    /// PostgreSQL URL.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,
    /// Max PostgreSQL connections.
    #[arg(long, env = "ACP_RUNNER_DB_MAX_CONNECTIONS", default_value_t = 16)]
    pub db_max_connections: u32,
    /// Patches up to this size are stored inline in PostgreSQL.
    #[arg(long, env = "ACP_RUNNER_ARTIFACT_INLINE_LIMIT", default_value_t = 8 * 1024 * 1024)]
    pub artifact_inline_limit: u64,
    /// Optional directory for larger artifacts (FsBlobStore). S3 can be added behind BlobStore.
    #[arg(long, env = "ACP_RUNNER_ARTIFACT_DIR")]
    pub artifact_dir: Option<PathBuf>,
    /// Record raw provider payloads (redacted, capped) in the journal.
    #[arg(long, env = "ACP_RUNNER_RECORD_RAW", default_value_t = true, action = clap::ArgAction::Set)]
    pub record_raw: bool,
}

#[derive(Args, Clone, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// URL runnerd uses to reach this controller's ingest API.
    #[arg(long, env = "ACP_RUNNER_INGEST_URL")]
    pub ingest_url: String,
    #[arg(long, env = "ACP_RUNNER_INGEST_LISTEN", default_value = "0.0.0.0:8081")]
    pub ingest_listen: String,
    #[arg(long, env = "ACP_RUNNER_METRICS_LISTEN", default_value = "0.0.0.0:8080")]
    pub metrics_listen: String,
    /// Unique controller instance id (defaults to POD_NAME / hostname).
    #[arg(long, env = "POD_NAME")]
    pub controller_id: Option<String>,
    #[arg(long, env = "ACP_RUNNER_BACKEND", value_enum, default_value = "pod")]
    pub backend: BackendKind,
    /// Run sandboxes in this namespace instead of the ACPRun's namespace.
    #[arg(long, env = "ACP_RUNNER_AGENT_NAMESPACE")]
    pub agent_namespace: Option<String>,
    /// Only watch ACPRuns in this namespace (default: all namespaces).
    #[arg(long, env = "ACP_RUNNER_WATCH_NAMESPACE")]
    pub watch_namespace: Option<String>,
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_STORE", value_enum, default_value = "k8s")]
    pub credential_store: CredStoreKind,
    /// Namespace holding credential profile Secrets.
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_NAMESPACE", default_value = "acp-runner-system")]
    pub credential_namespace: String,
    #[arg(long, env = "ACP_RUNNER_CREDENTIAL_DIR")]
    pub credential_dir: Option<PathBuf>,
    /// Fail attempts whose sandbox posture is violated (root, SA token, writable rootfs, ...).
    #[arg(long, env = "ACP_RUNNER_STRICT_POSTURE", default_value_t = true, action = clap::ArgAction::Set)]
    pub strict_posture: bool,
    /// DEVELOPMENT ONLY: allow runner classes with subscription credentials to run with
    /// `egress.mode: direct` (unrestricted public egress).
    #[arg(long, env = "ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS", default_value_t = false, action = clap::ArgAction::Set)]
    pub allow_direct_credential_egress: bool,
    /// V2: exact runner images (`repo@sha256:<hex>`) allowed for credentialed
    /// runner classes. Empty denies all credentialed images (fail closed).
    #[arg(long, env = "ACP_RUNNER_ALLOWED_IMAGES", value_delimiter = ',')]
    pub allowed_images: Vec<String>,
    /// V2: service accounts credentialed runner classes may use.
    #[arg(long, env = "ACP_RUNNER_ALLOWED_SERVICE_ACCOUNTS", value_delimiter = ',', default_value = "acp-runner-agent")]
    pub allowed_service_accounts: Vec<String>,
    /// Enable controller-verified Codex write-back (V1a): the controller
    /// refreshes ChatGPT tokens itself against the pinned provider endpoint.
    /// Disable only if the controller has no egress to auth.openai.com.
    #[arg(long, env = "ACP_RUNNER_CODEX_REFRESH", default_value_t = true, action = clap::ArgAction::Set)]
    pub codex_refresh: bool,
    /// Route the Codex token refresh through an HTTP CONNECT proxy (the
    /// allowlisting egress proxy) instead of direct egress. Required when the
    /// controller has no general public egress (see networkpolicy.yaml).
    #[arg(long, env = "ACP_RUNNER_CODEX_REFRESH_PROXY")]
    pub codex_refresh_proxy: Option<String>,
    /// V10a: manage `AgentEnvironment` objects (reconcile/status/finalizer) with
    /// the durable environment provider. Disable only for run-only controllers.
    #[arg(long, env = "ACP_RUNNER_MANAGE_ENVIRONMENTS", default_value_t = true, action = clap::ArgAction::Set)]
    pub manage_environments: bool,
    /// V10a/b: connection-ticket master key file (mounted Secret; raw or hex).
    /// Missing file falls back to an ephemeral key (dev only: live environments
    /// do not survive a restart) with a warning.
    #[arg(long, env = "ACP_RUNNER_TICKET_KEY_FILE")]
    pub ticket_key_file: Option<PathBuf>,
    /// V10b: previous master key file, kept only during rotation so
    /// environments created under it stay connectable until they end.
    #[arg(long, env = "ACP_RUNNER_TICKET_KEY_PREV_FILE")]
    pub ticket_key_prev_file: Option<PathBuf>,
    /// V10a: address runnerd binds the ACP gateway on inside environment
    /// sandboxes. Must carry an explicit port for the gateway Service
    /// (`0.0.0.0:<port>` for pods; `127.0.0.1:0` for local development).
    #[arg(long, env = "ACP_RUNNER_ENV_GATEWAY_LISTEN", default_value = "0.0.0.0:4713")]
    pub env_gateway_listen: String,
    /// V10a: runner image for environment sandboxes (pod backend). Credentialed
    /// environments additionally require an allowlisted digest-pinned image.
    #[arg(long, env = "ACP_RUNNER_ENV_RUNNER_IMAGE", default_value = "acp-runner/runner:dev")]
    pub env_runner_image: String,
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,kube=warn,sqlx=warn,hyper=warn".into()),
        )
        .init();
}

pub async fn build_artifacts(journal: &Journal, common: &CommonArgs) -> Arc<dyn ArtifactStore> {
    let external: Option<Arc<dyn BlobStore>> =
        common.artifact_dir.clone().map(|root| Arc::new(FsBlobStore { root }) as Arc<dyn BlobStore>);
    Arc::new(PgArtifactStore::new(journal.clone(), common.artifact_inline_limit, external))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Exactly one rustls provider before any TLS client (refresh Client,
    // kube client) is built; see runnerd main for rationale.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Crdgen) => {
            print!("{}", acp_runner_k8s::crds_yaml());
            Ok(())
        }
        Some(Cmd::DevRun(args)) => {
            init_tracing();
            dev::dev_run(args).await
        }
        Some(Cmd::Run(args)) => {
            init_tracing();
            run(*args).await
        }
        None => {
            init_tracing();
            #[derive(Parser)]
            struct EnvOnly {
                #[command(flatten)]
                args: RunArgs,
            }
            let parsed =
                EnvOnly::try_parse_from(["acp-runner-controller"]).context("configure via environment variables")?;
            run(parsed.args).await
        }
    }
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    let controller_id = args
        .controller_id
        .clone()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_else(|| format!("acp-runner-controller-{}", std::process::id()));
    let journal = Journal::connect(&args.common.database_url, args.common.db_max_connections)
        .await
        .context("connecting to PostgreSQL")?;
    journal.migrate().await.context("migrating journal")?;
    let client = kube::Client::try_default().await.context("kubernetes client")?;
    let pod_cfg = PodConfig {
        agent_namespace: args.agent_namespace.clone(),
        strict_posture: args.strict_posture,
        // Single source of truth is the operator env var (V8.3): the same
        // value that gates `RepositoryInput::validate` in this process is
        // propagated into the runnerd containers this controller builds.
        // Never sourced from RunSpec caller input.
        allow_file_repos: acp_runner_core::spec::allow_file_repos(),
        ..Default::default()
    };
    let backend: Arc<dyn SandboxBackend> = match args.backend {
        BackendKind::Pod => Arc::new(PodBackend { client: client.clone(), cfg: pod_cfg }),
        BackendKind::AgentSandbox => Arc::new(AgentSandboxBackend { client: client.clone(), cfg: pod_cfg }),
    };
    let creds: Arc<dyn CredentialStore> = match args.credential_store {
        CredStoreKind::K8s => {
            Arc::new(K8sSecretStore { client: client.clone(), namespace: args.credential_namespace.clone() })
        }
        CredStoreKind::File => Arc::new(FileCredentialStore {
            root: args.credential_dir.clone().context("--credential-dir required for the file store")?,
        }),
    };
    let artifacts = build_artifacts(&journal, &args.common).await;
    let metrics = Arc::new(Metrics::new());
    let engine = Arc::new(Engine {
        journal: journal.clone(),
        backend: backend.clone(),
        creds: creds.clone(),
        artifacts: artifacts.clone(),
        metrics: metrics.clone(),
        cfg: EngineConfig {
            controller_id: controller_id.clone(),
            ingest_url: args.ingest_url.clone(),
            record_raw_payloads: args.common.record_raw,
            require_egress_proxy_for_credentials: !args.allow_direct_credential_egress,
            allowed_images: args.allowed_images.clone(),
            allowed_service_accounts: args.allowed_service_accounts.clone(),
            ..Default::default()
        },
    });
    if args.allow_direct_credential_egress {
        tracing::warn!(
            "ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS=true: credentialed runner classes may run without the egress proxy"
        );
    }
    tracing::info!(controller_id = %controller_id, backend = ?args.backend, "starting acp-runner controller");

    // ingest API (runnerd -> controller)
    let mut ingest_state =
        IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None);
    // V1a: the controller needs egress to the pinned Codex token endpoint to
    // verify write-backs (see deploy/controller/networkpolicy.yaml). The
    // endpoint stays pinned to https://auth.openai.com — overrides outside
    // that URL fail startup instead of sending tokens elsewhere.
    if args.codex_refresh {
        let mut cfg = acp_runner_engine::codex_refresh::CodexRefreshConfig::from_env_or_default();
        if let Some(proxy) = args.codex_refresh_proxy.clone() {
            cfg.proxy_url = Some(proxy);
        }
        let refresher = acp_runner_engine::codex_refresh::HttpCodexRefresher::new(cfg)
            .map_err(|detail| anyhow::anyhow!("invalid codex refresh config: {detail}"))?;
        tracing::info!("codex verifying write-back enabled");
        ingest_state.codex_refresher = Some(std::sync::Arc::new(refresher));
    } else {
        tracing::warn!("codex verifying write-back disabled: chatgpt write-backs will be rejected");
    }
    let ingest_state = Arc::new(ingest_state);

    // V10a: durable environment provider (shares the live ingest state so
    // control-plane directives reach runnerd's heartbeats; all state lives in
    // PostgreSQL, so finish/cancel/destroy survive controller restarts).
    let gateway_port: i32 = args
        .env_gateway_listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .filter(|p| *p > 0)
        .with_context(|| {
            format!(
                "--env-gateway-listen {:?} must carry an explicit port for the gateway Service",
                args.env_gateway_listen
            )
        })?;
    let ticket_keys = match &args.ticket_key_file {
        Some(path) if !path.exists() => {
            // The Secret volume is optional until ticket-key-secret.yaml is
            // applied with real key material: same fallback as unset.
            tracing::warn!(
                key_file = %path.display(),
                "ticket key file missing: ephemeral ticket key; live environments do not survive a restart"
            );
            acp_runner_engine::environment::TicketKeyRing::ephemeral()
        }
        Some(path) => {
            use acp_runner_engine::environment::{TicketKey, TicketKeyRing};
            let key = TicketKey::from_file(path)
                .with_context(|| format!("reading ticket key {}", path.display()))?;
            let mut ring = TicketKeyRing::new(key);
            if let Some(prev_path) = &args.ticket_key_prev_file {
                let prev = TicketKey::from_file(prev_path)
                    .with_context(|| format!("reading previous ticket key {}", prev_path.display()))?;
                ring = ring.with_previous(prev);
                tracing::info!("ticket key rotation in progress: previous key still mints for old environments");
            }
            tracing::info!(key_file = %path.display(), version = ring.current().0, "ticket master key loaded from file");
            ring
        }
        None => {
            tracing::warn!(
                "ACP_RUNNER_TICKET_KEY_FILE unset: ephemeral ticket key; live environments do not survive a restart"
            );
            acp_runner_engine::environment::TicketKeyRing::ephemeral()
        }
    };
    let provider = Arc::new(acp_runner_engine::environment::EnvironmentProvider::new(
        journal.clone(),
        backend.clone(),
        creds.clone(),
        artifacts.clone(),
        ingest_state.clone(),
        acp_runner_engine::environment::EnvironmentConfig {
            controller_id: controller_id.clone(),
            ingest_url: args.ingest_url.clone(),
            gateway_listen: args.env_gateway_listen.clone(),
            require_egress_proxy_for_credentials: !args.allow_direct_credential_egress,
            runner_image: args.env_runner_image.clone(),
            allowed_images: args.allowed_images.clone(),
            allowed_service_accounts: args.allowed_service_accounts.clone(),
            ticket_keys,
            ticket_ttl_seconds: acp_runner_core::ticket::DEFAULT_TICKET_TTL_SECONDS,
        },
    ));
    let ingest_listener = tokio::net::TcpListener::bind(&args.ingest_listen).await?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(ingest_listener, router(ingest_state)).await {
            tracing::error!(error = %e, "ingest server stopped");
        }
    });

    // metrics + health
    let m = metrics.clone();
    let j = journal.clone();
    let ops = Router::new()
        .route(
            "/metrics",
            get(move || {
                let m = m.clone();
                async move { m.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let j = j.clone();
                async move {
                    match j.ping().await {
                        Ok(()) => (axum::http::StatusCode::OK, "ready"),
                        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "database unavailable"),
                    }
                }
            }),
        );
    let ops_listener = tokio::net::TcpListener::bind(&args.metrics_listen).await?;
    tokio::spawn(async move {
        let _ = axum::serve(ops_listener, ops).await;
    });

    // credential profile records (non-secret) and gauges
    let (e2, c2) = (engine.clone(), creds.clone());
    tokio::spawn(async move {
        loop {
            match sync_profiles(c2.as_ref(), &e2.journal).await {
                Ok(n) => tracing::debug!(profiles = n, "credential profiles synced"),
                Err(e) => tracing::warn!(error = %e, "credential profile sync failed"),
            }
            if let Err(e) = e2.refresh_gauges().await {
                tracing::warn!(error = %e, "refreshing gauges failed");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });

    if args.manage_environments {
        tracing::info!("AgentEnvironment management enabled");
        let (c2, p2, ns2) = (client.clone(), provider.clone(), args.watch_namespace.clone());
        tokio::spawn(async move { env_controller::run(c2, p2, gateway_port, ns2).await });
    } else {
        tracing::warn!("AgentEnvironment management disabled: AgentEnvironment objects are ignored");
    }
    controller::run(client, engine, args.watch_namespace.clone()).await;
    Ok(())
}
