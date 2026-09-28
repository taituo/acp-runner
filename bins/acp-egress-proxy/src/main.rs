use acp_egress_proxy::{Allowlist, ProxyConfig, loopback_up, relay, serve_tcp, serve_unix};
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "acp-egress-proxy", version, about = "Allowlisting HTTP CONNECT egress proxy for acp-runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the proxy.
    Serve {
        /// TCP listen address.
        #[arg(long, env = "ACP_EGRESS_LISTEN", default_value = "0.0.0.0:3128")]
        listen: String,
        /// Additionally/instead listen on a Unix socket.
        #[arg(long)]
        listen_unix: Option<PathBuf>,
        /// Allowed host (`api.anthropic.com`) or domain (`.openai.com`). Repeatable.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// File with one pattern per line (`#` comments).
        #[arg(long, env = "ACP_EGRESS_ALLOW_FILE")]
        allow_file: Option<PathBuf>,
        /// Allowed destination ports (default 443). Repeatable.
        #[arg(long = "allow-port")]
        allow_port: Vec<u16>,
        /// Permit loopback/private destinations (tests only; never in a cluster).
        #[arg(long)]
        allow_private_destinations: bool,
        #[arg(long, default_value_t = 1024)]
        max_connections: usize,
        #[arg(long, default_value_t = 21600)]
        max_tunnel_seconds: u64,
    },
    /// TCP -> Unix socket relay (local isolation harness).
    Relay {
        #[arg(long)]
        listen: String,
        #[arg(long)]
        unix: PathBuf,
        /// Bring the loopback interface of this network namespace up first.
        #[arg(long)]
        lo_up: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ACP_EGRESS_LOG").unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Serve {
            listen,
            listen_unix,
            allow,
            allow_file,
            allow_port,
            allow_private_destinations,
            max_connections,
            max_tunnel_seconds,
        } => {
            let mut patterns = allow;
            if let Some(f) = allow_file {
                let text = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
                patterns.extend(text.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_string()));
            }
            let allowlist = Allowlist::parse(patterns).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(!allowlist.is_empty(), "empty allowlist: nothing would be reachable");
            let mut cfg = ProxyConfig::new(allowlist);
            if !allow_port.is_empty() {
                cfg.ports = allow_port;
            }
            cfg.allow_private = allow_private_destinations;
            cfg.max_connections = max_connections;
            cfg.max_tunnel = Duration::from_secs(max_tunnel_seconds);
            if cfg.allow_private {
                tracing::warn!("private destinations are allowed (test mode)");
            }
            let cfg = Arc::new(cfg);
            let mut tasks = vec![];
            if let Some(p) = listen_unix {
                let _ = std::fs::remove_file(&p);
                let l = tokio::net::UnixListener::bind(&p)?;
                tracing::info!(socket = %p.display(), "listening");
                tasks.push(tokio::spawn(serve_unix(l, cfg.clone())));
            }
            if listen != "none" {
                let l = tokio::net::TcpListener::bind(&listen).await?;
                tracing::info!(listen = %l.local_addr()?, "listening");
                tasks.push(tokio::spawn(serve_tcp(l, cfg.clone())));
            }
            for t in tasks {
                t.await?;
            }
            Ok(())
        }
        Cmd::Relay { listen, unix, lo_up } => {
            if lo_up {
                loopback_up().context("bringing loopback up")?;
            }
            let l = tokio::net::TcpListener::bind(&listen).await?;
            relay(l, &unix).await;
            Ok(())
        }
    }
}
