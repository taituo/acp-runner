//! Run inspection from the PostgreSQL journal.

use crate::RunCmd;
use acp_runner_journal::{ArtifactStore, Journal, PgArtifactStore, RunRow};
use anyhow::{Context, bail};
use std::io::Write;
use std::time::Duration;

async fn find(j: &Journal, run: &str, ns: Option<&str>) -> anyhow::Result<RunRow> {
    let mut rows = j.find_runs(run, ns).await?;
    match rows.len() {
        0 => bail!("no run matches {run:?}"),
        1 => Ok(rows.remove(0)),
        n => {
            eprintln!("{n} runs match {run:?}; showing the most recent (use the run id to disambiguate)");
            Ok(rows.remove(0))
        }
    }
}

pub async fn run(cmd: RunCmd) -> anyhow::Result<()> {
    match cmd {
        RunCmd::List { database_url, limit } => {
            let j = Journal::connect(&database_url, 2).await?;
            println!(
                "{:<38} {:<14} {:<28} {:<10} {:<4} {:<20}",
                "RUN ID", "NAMESPACE", "NAME", "PHASE", "ATT", "CREATED"
            );
            for r in j.list_runs(limit).await? {
                println!(
                    "{:<38} {:<14} {:<28} {:<10} {:<4} {:<20}",
                    r.id,
                    r.k8s_namespace,
                    r.k8s_name,
                    r.phase,
                    r.attempt_count,
                    r.created_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
            Ok(())
        }
        RunCmd::Get { run, namespace, database_url } => {
            let j = Journal::connect(&database_url, 2).await?;
            let r = find(&j, &run, namespace.as_deref()).await?;
            let attempts = j.attempts_for_run(r.id).await?;
            let v = serde_json::json!({
                "runId": r.id, "namespace": r.k8s_namespace, "name": r.k8s_name, "taskId": r.task_id,
                "phase": r.phase, "failureReason": r.failure_reason, "artifactId": r.artifact_id,
                "waiting": r.waiting_reason, "createdAt": r.created_at, "startedAt": r.started_at, "finishedAt": r.finished_at,
                "attempts": attempts.iter().map(|a| serde_json::json!({
                    "ordinal": a.ordinal, "id": a.id, "runnerClass": a.runner_class, "driver": a.driver,
                    "phase": a.phase, "credentialProfile": a.credential_profile, "sandbox": a.sandbox_ref,
                    "driverVersion": a.driver_version, "baseRevision": a.base_revision,
                    "failureReason": a.failure_reason, "outcome": a.outcome,
                    "createdAt": a.created_at, "startedAt": a.started_at, "finishedAt": a.finished_at,
                    "lastHeartbeatAt": a.last_heartbeat_at, "lastProgressAt": a.last_progress_at,
                    "supervisor": a.lease_owner,
                })).collect::<Vec<_>>(),
            });
            print!("{}", serde_yaml::to_string(&v)?);
            Ok(())
        }
        RunCmd::Events { run, namespace, database_url, follow, raw, output } => {
            let j = Journal::connect(&database_url, 2).await?;
            let r = find(&j, &run, namespace.as_deref()).await?;
            let attempts = j.attempts_for_run(r.id).await?;
            let ordinal = |id: Option<uuid::Uuid>| {
                id.and_then(|id| attempts.iter().find(|a| a.id == id).map(|a| a.ordinal.to_string()))
                    .unwrap_or_else(|| "-".into())
            };
            let mut after = 0i64;
            loop {
                let evs = j.events_for_run(r.id, after, 500).await?;
                for e in &evs {
                    after = e.id;
                    if output == "json" {
                        let mut v = serde_json::json!({"id": e.id, "attemptId": e.attempt_id, "seq": e.seq, "ts": e.ts,
                                                       "kind": e.kind, "source": e.source, "data": e.data});
                        if raw {
                            v["raw"] = e.raw.clone().unwrap_or_default();
                        }
                        println!("{v}");
                    } else {
                        let mut d = e.data.to_string();
                        if d.len() > 220 {
                            let cut = d.char_indices().nth(220).map(|x| x.0).unwrap_or(d.len());
                            d.truncate(cut);
                            d.push('…');
                        }
                        println!(
                            "{} a{:<2} {:<10} {:<17} {}",
                            e.ts.format("%H:%M:%S%.3f"),
                            ordinal(e.attempt_id),
                            e.source,
                            e.kind,
                            d
                        );
                        if raw && let Some(rv) = &e.raw {
                            println!("      raw: {rv}");
                        }
                    }
                }
                if !follow {
                    break;
                }
                let current = j.get_run(r.id).await?;
                if current.phase().is_terminal() && evs.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(())
        }
        RunCmd::Artifact { run, namespace, database_url, out, id } => {
            let j = Journal::connect(&database_url, 2).await?;
            let r = find(&j, &run, namespace.as_deref()).await?;
            let store = PgArtifactStore::new(j.clone(), u64::MAX, None);
            let aid = match id.or(r.artifact_id) {
                Some(a) => a,
                None => store.latest_for_run(r.id).await?.context("run has no artifact")?.id,
            };
            let meta = store.get_meta(aid).await?;
            let bytes = store.get_content(aid).await?;
            eprintln!(
                "artifact {} kind={} base={} sha256={} size={} driver={} ({})",
                meta.id,
                meta.kind,
                meta.base_revision,
                meta.sha256,
                meta.size_bytes,
                meta.driver,
                meta.driver_version.unwrap_or_default()
            );
            match out {
                Some(p) => std::fs::write(&p, &bytes).with_context(|| format!("writing {}", p.display()))?,
                None => std::io::stdout().write_all(&bytes)?,
            }
            Ok(())
        }
    }
}
