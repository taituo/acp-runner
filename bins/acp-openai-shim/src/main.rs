//! `acp-openai-shim --listen 0.0.0.0:8090 --connections /etc/acp-shim/connections.json`
//!
//! Serves a subset of the OpenAI Responses API on top of AgentEnvironment ACP gateways. The
//! connections file maps a model name (an environment) to `{gateway, ticket}` and is re-read
//! on every (re)connect, so a sidecar can keep the short-lived tickets fresh.

use acp_openai_shim::{FileConnectionSource, ShimState, router};
use acp_runner_client::Transport;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "acp-openai-shim", version, about = "OpenAI Responses shim over ACP")]
struct Cli {
    #[arg(long, env = "ACP_SHIM_LISTEN", default_value = "127.0.0.1:8090")]
    listen: String,
    #[arg(long, env = "ACP_SHIM_CONNECTIONS")]
    connections: std::path::PathBuf,
    /// Gateway transport: raw (acp-ndjson) or websocket.
    #[arg(long, default_value = "raw")]
    transport: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let transport = match cli.transport.as_str() {
        "raw" => Transport::Raw,
        "websocket" | "ws" => Transport::WebSocket,
        other => anyhow::bail!("unknown transport {other:?}"),
    };
    let state = ShimState::new(Arc::new(FileConnectionSource { path: cli.connections }), transport);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(listen = %cli.listen, "acp-openai-shim listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
