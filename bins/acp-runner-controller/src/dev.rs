//! `dev-run`: execute one ACPRun manifest locally — the same engine, ingest API and runnerd
//! as in the cluster, with `LocalProcessBackend` instead of pods. No isolation: use only
//! with the fake driver or on a machine you are happy to let the agent modify.

use crate::controller::to_status;
use crate::{CommonArgs, build_artifacts};
use acp_runner_engine::backend::{LocalProcessBackend, RunKey};
use acp_runner_engine::creds::{FileCredentialStore, sync_profiles};
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_engine::{Engine, EngineConfig, RunInput};
use acp_runner_journal::Journal;
use acp_runner_k8s::crds::{ACPRun, ACPRunnerClass};
use anyhow::{Context, bail};
use clap::Args;
use kube::ResourceExt;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Args, Clone, Debug)]
pub struct DevRunArgs {
    #[command(flatten)]
    pub common: CommonArgs,
    /// ACPRun manifest (YAML).
    #[arg(short = 'f', long = "run")]
    pub run: PathBuf,
    /// ACPRunnerClass manifests (YAML, multi-document allowed).
    #[arg(long = "classes", required = true)]
    pub classes: Vec<PathBuf>,
    /// runnerd binary (default: next to this executable).
    #[arg(long)]
    pub runnerd: Option<PathBuf>,
    #[arg(long, default_value = ".acp-runner-dev")]
    pub work_dir: PathBuf,
    /// FileCredentialStore directory (default: <work-dir>/credentials).
    #[arg(long)]
    pub credential_dir: Option<PathBuf>,
    #[arg(long, default_value_t = 900)]
    pub timeout_seconds: u64,
    /// Keep sandbox directories for inspection.
    #[arg(long)]
    pub keep: bool,
    /// Allow credentialed runner classes with `egress.mode: direct` (local development;
    /// dev-run is not an isolation boundary anyway).
    #[arg(long)]
    pub allow_direct_credential_egress: bool,
}

fn load_docs<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> anyhow::Result<Vec<T>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = vec![];
    for doc in serde_yaml::Deserializer::from_str(&text) {
        let v = serde_yaml::Value::deserialize(doc)?;
        if v.is_null() {
            continue;
        }
        out.push(serde_yaml::from_value(v)?);
    }
    Ok(out)
}

pub async fn dev_run(args: DevRunArgs) -> anyhow::Result<()> {
    let journal = Journal::connect(&args.common.database_url, 8).await?;
    journal.migrate().await?;
    let runs: Vec<ACPRun> = load_docs(&args.run)?;
    let run = runs.into_iter().next().context("no ACPRun in manifest")?;
    let mut all_classes: Vec<ACPRunnerClass> = vec![];
    for f in &args.classes {
        all_classes.extend(load_docs::<ACPRunnerClass>(f)?);
    }
    let mut classes = vec![];
    for name in run.spec.class_names() {
        let c = all_classes
            .iter()
            .find(|c| c.name_any() == name)
            .with_context(|| format!("runner class {name} not provided"))?;
        classes.push(c.spec.to_core(&name));
    }
    std::fs::create_dir_all(&args.work_dir)?;
    let work = std::fs::canonicalize(&args.work_dir)?;
    let runnerd = match args.runnerd.clone() {
        Some(p) => p,
        None => std::env::current_exe()?.parent().context("exe dir")?.join("runnerd"),
    };
    if !runnerd.exists() {
        bail!("runnerd not found at {} (build it with `cargo build -p runnerd` or pass --runnerd)", runnerd.display());
    }
    let creds =
        Arc::new(FileCredentialStore { root: args.credential_dir.clone().unwrap_or_else(|| work.join("credentials")) });
    sync_profiles(creds.as_ref(), &journal).await?;
    let artifacts = build_artifacts(&journal, &args.common).await;
    let metrics = Arc::new(Metrics::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let state = Arc::new(IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics.clone(), None));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    let mut backend =
        LocalProcessBackend::new(runnerd, work.join("sandboxes"), std::env::var("PATH").unwrap_or_default());
    backend.keep_dirs = args.keep;
    let engine = Engine {
        journal: journal.clone(),
        backend: Arc::new(backend),
        creds,
        artifacts: artifacts.clone(),
        metrics: metrics.clone(),
        cfg: EngineConfig {
            controller_id: format!("dev-run-{}", std::process::id()),
            ingest_url: format!("http://{addr}"),
            active_requeue: Duration::from_millis(500),
            waiting_requeue: Duration::from_secs(2),
            record_raw_payloads: args.common.record_raw,
            require_egress_proxy_for_credentials: !args.allow_direct_credential_egress,
            ..Default::default()
        },
    };
    let key = RunKey {
        namespace: run.namespace().unwrap_or_else(|| "default".into()),
        name: run.name_any(),
        uid: run.uid().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
    };
    let input = RunInput { key, spec: run.spec.to_core(classes), cancel: false };
    eprintln!("dev-run: {} (ingest {addr})", run.name_any());
    let start = Instant::now();
    let mut seen: i64 = 0;
    let view = loop {
        let v = engine.reconcile(&input).await?;
        for e in journal.events_for_run(v.run_id, seen, 1000).await? {
            seen = e.id;
            let d = e.data.to_string();
            let d = if d.len() > 160 {
                format!("{}…", &d[..d.char_indices().nth(160).map(|x| x.0).unwrap_or(d.len())])
            } else {
                d
            };
            eprintln!("  {:>5} {:<17} {}", e.id, e.kind, d);
        }
        if v.phase.is_terminal() {
            break v;
        }
        if start.elapsed() > Duration::from_secs(args.timeout_seconds) {
            engine.cancel(&input.key, "dev-run timeout").await?;
            bail!("dev-run timed out");
        }
        tokio::time::sleep(v.requeue_after.unwrap_or(Duration::from_millis(500))).await;
    };
    let status = to_status(&view, None);
    println!("{}", serde_yaml::to_string(&serde_json::json!({"status": status}))?);
    if let Some(a) = &view.artifact {
        let bytes = artifacts.get_content(a.id).await?;
        let out = work.join(format!("{}.patch", run.name_any()));
        std::fs::write(&out, bytes)?;
        eprintln!("patch artifact written to {}", out.display());
    }
    Ok(())
}
