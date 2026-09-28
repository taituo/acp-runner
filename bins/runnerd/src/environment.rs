//! Environment-mode supervisor: trusted bootstrap → harness launched as an ACP stdio agent →
//! Ready → authenticated **raw ACP** through the gateway until `finish()`, with non-terminal
//! snapshots. Reuses the same trusted bootstrap as the one-shot supervisor (workspace +
//! private git dir, synthetic HOME + credentials, agentd link) and the same authoritative
//! patch collector.
//!
//! Authoritative actions stay on runnerd's side: the caller speaks ACP to the harness through
//! the gateway (untrusted, ticket-authenticated, relayed verbatim); snapshot/finish/cancel
//! are provider operations delivered on the control channel (heartbeat directives); the
//! workspace changeset and terminal state are computed here, never by the agent.

use crate::agent_link::{AgentListener, AgentdLaunch, DataListener, reap_spawned};
use crate::gateway::{Caller, Gateway, GatewayConfig, GatewayEvent};
use crate::home::{PreparedHome, changed_writeback_files, place_credentials, prepare_home, prepare_home_base, staged_env_rels};
use crate::sink::{ArtifactUpload, EventSink};
use crate::supervisor::{RunnerDirs, SupervisorOptions};
use crate::tap::{AcpTap, Observed};
use acp_runner_core::AttemptSpec;
use acp_runner_core::attempt_spec::SessionMode;
use acp_runner_core::environment::EnvironmentPhase;
use acp_runner_core::events::{
    AgentStartedData, ArtifactCreatedData, EventEnvelope, EventKind, EventSource, HeartbeatData, InputSentData,
    ProgressData, RunnerDirective, truncate_utf8,
};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::harness::{merge_config, substitute_root};
use acp_runner_core::redact::Redactor;
use acp_runner_ipc::{
    AgentEvent, AgentExit, AgentLaunchSpec, AgentOutcome, AgentTimeouts, FromAgent, PROTOCOL_VERSION,
    StagedCredentialEnv, ToAgent,
};
use acp_runner_workspace::{
    CollectOptions, GitWorkspace, changed_between, collect_patch, fingerprint, prepare_empty, prepare_with_env,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentResult {
    pub phase: EnvironmentPhase,
    pub reason: Option<FailureReason>,
    pub base_revision: Option<String>,
    pub final_artifact_id: Option<Uuid>,
    pub changed_paths: usize,
    pub turns: u32,
    pub snapshots: u32,
}

struct Em<'a> {
    sink: &'a mut dyn EventSink,
    redactor: Redactor,
    record_raw: bool,
}

impl Em<'_> {
    async fn emit(&mut self, kind: EventKind, source: EventSource, data: impl Serialize) {
        let mut data = serde_json::to_value(data).unwrap_or(Value::Null);
        self.redactor.redact_json(&mut data);
        self.sink.emit(EventEnvelope::new(kind, source, data)).await;
    }
    async fn progress(&mut self, category: &str, message: &str, detail: Value) {
        self.emit(EventKind::Progress, EventSource::Runnerd, ProgressData::new(category, message).with_detail(detail))
            .await
    }
    fn cap_raw(&self, raw: Option<Value>) -> Option<Value> {
        if !self.record_raw {
            return None;
        }
        let mut raw = raw?;
        self.redactor.redact_json(&mut raw);
        let len = serde_json::to_vec(&raw).map(|v| v.len()).unwrap_or(0);
        if len > 32 * 1024 { Some(json!({"truncated": true, "bytes": len})) } else { Some(raw) }
    }
    /// Journal an agent event (source=agent) and return the version to forward to the caller.
    async fn agent_event(&mut self, ev: AgentEvent) {
        let (kind, data, raw): (EventKind, Value, Option<Value>) = match &ev {
            AgentEvent::SessionStarted { data, raw } => {
                (EventKind::SessionStarted, serde_json::to_value(data).unwrap_or(Value::Null), raw.clone())
            }
            AgentEvent::Output { channel, text } => {
                (EventKind::AgentOutput, json!({"channel": channel, "text": truncate_utf8(text, 16 * 1024).0}), None)
            }
            AgentEvent::ToolCall { data, raw } => {
                (EventKind::ToolCall, serde_json::to_value(data).unwrap_or(Value::Null), raw.clone())
            }
            AgentEvent::ToolResult { data, raw } => {
                (EventKind::ToolResult, serde_json::to_value(data).unwrap_or(Value::Null), raw.clone())
            }
            AgentEvent::PermissionRequest { data, raw } => {
                (EventKind::PermissionRequest, serde_json::to_value(data).unwrap_or(Value::Null), raw.clone())
            }
            AgentEvent::Progress { data, raw } => {
                // Reserved categories are runnerd's trust domain: quarantine the
                // agent claim under `agent.<category>` and leave a marker.
                let mut owned = data.clone();
                if acp_runner_core::events::is_reserved_agent_category(&owned.category) {
                    let original = std::mem::take(&mut owned.category);
                    owned.category = format!("agent.{original}");
                    self.progress(
                        "protocol_warning",
                        &format!("agent sent reserved progress category {original:?}; renamed"),
                        json!({"category": original}),
                    )
                    .await;
                }
                (EventKind::Progress, serde_json::to_value(owned).unwrap_or(Value::Null), raw.clone())
            }
        };
        let mut data = data;
        self.redactor.redact_json(&mut data);
        let raw = self.cap_raw(raw);
        self.sink.emit(EventEnvelope::new(kind, EventSource::Agent, data).with_raw(raw)).await;
    }
}

fn bad(reason: FailureReason) -> EnvironmentResult {
    EnvironmentResult {
        phase: EnvironmentPhase::Failed,
        reason: Some(reason),
        base_revision: None,
        final_artifact_id: None,
        changed_paths: 0,
        turns: 0,
        snapshots: 0,
    }
}

async fn emit_credentials_placed(
    em: &mut Em<'_>,
    layout: Option<&acp_runner_core::attempt_spec::CredentialLayout>,
    message: &str,
) {
    if let Some(l) = layout {
        em.progress(
            "credentials_placed",
            message,
            json!({"provider": l.provider, "profile": l.profile, "files": l.files.iter().map(|f| &f.target).collect::<Vec<_>>(),
                   "stagedEnv": l.env.iter().map(|e| &e.env_name).collect::<Vec<_>>()}),
        )
        .await;
    }
}

/// Read `K_env` (hex) from the per-attempt secret mount.
fn read_gateway_key(dirs: &RunnerDirs) -> Result<[u8; 32], String> {
    use acp_runner_core::attempt_spec::GATEWAY_KEY_FILE_NAME;
    let dir = dirs.secret_dir.as_ref().ok_or("no secret mount (gateway key missing)")?;
    let text = std::fs::read_to_string(dir.join(GATEWAY_KEY_FILE_NAME)).map_err(|e| format!("gateway key: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|_| "gateway key is not hex".to_string())?;
    bytes.try_into().map_err(|_| "gateway key must be 32 bytes".to_string())
}

/// Run one environment end-to-end.
pub async fn run_environment(
    spec: AttemptSpec,
    dirs: RunnerDirs,
    sink: &mut dyn EventSink,
    opts: SupervisorOptions,
    mut external_cancel: watch::Receiver<bool>,
) -> EnvironmentResult {
    let SessionMode::Environment { environment_id, gateway_listen, idle_timeout_seconds, max_lifetime_seconds } =
        spec.session.clone()
    else {
        return bad(FailureReason::Internal { detail: "run_environment called for a one-shot attempt".into() });
    };
    let started_at = Instant::now();
    let mut redactor = Redactor::new();
    for s in &opts.extra_secrets {
        redactor.add_secret(s);
    }
    let gateway_key = match read_gateway_key(&dirs) {
        Ok(k) => k,
        Err(detail) => return bad(FailureReason::Internal { detail }),
    };
    redactor.add_secret(&hex::encode(gateway_key));
    let mut em = Em { sink, redactor, record_raw: spec.record_raw_payloads };
    let grace = Duration::from_secs(spec.timeouts.grace_seconds);
    let startup = Duration::from_secs(spec.timeouts.startup_seconds.max(30));
    let hb_every = Duration::from_secs(spec.timeouts.heartbeat_seconds.max(1));

    for d in [&dirs.workspace, &dirs.home, &dirs.run_dir, &dirs.state, &dirs.tmp] {
        let _ = std::fs::create_dir_all(d);
    }
    let plan = spec.bootstrap.clone();
    // ---- agentd link ------------------------------------------------------------------
    let mut listener = match AgentListener::bind(&dirs.run_dir) {
        Ok(l) => l,
        Err(e) => return bad(FailureReason::Internal { detail: format!("binding agentd socket: {e}") }),
    };
    let data_listener = match DataListener::bind(&dirs.run_dir) {
        Ok(l) => l,
        Err(e) => return bad(FailureReason::Internal { detail: format!("binding data socket: {e}") }),
    };
    if let AgentdLaunch::Spawn { program, env } = &opts.agentd {
        let mut env = env.clone();
        env.push(("HOME".into(), dirs.agent.home.to_string_lossy().to_string()));
        if let Err(e) = listener.spawn_agentd(program, &env) {
            return bad(FailureReason::Unsupported { detail: format!("cannot start agentd: {e}") });
        }
    }
    // ---- TRUSTED bootstrap -----------------------------------------------------------------
    // 1. resolve harness: fetch + digest-verify + extract the pinned artifact
    let mut driver_config = spec.driver.config.clone();
    let mut path_prepend = vec![];
    if let Some(h) = &plan.harness {
        match crate::bootstrap::materialize_harness(&mut *em.sink, h, &dirs.harness, &dirs.state.join("harness-dl"))
            .await
        {
            Ok(files) => {
                let root = dirs.agent.harness.to_string_lossy().to_string();
                driver_config = merge_config(&driver_config, &substitute_root(&h.driver_config, &root));
                path_prepend = h.path.iter().map(|p| dirs.agent.harness.join(p)).collect();
                em.progress(
                    "harness_materialized",
                    &format!("{} {}", h.name, h.version),
                    json!({"digest": h.digest, "files": files, "adapter": h.adapter}),
                )
                .await;
            }
            Err(reason) => return bad(reason),
        }
    }
    // 2. checkout BASE (or the deterministic empty base)
    let net_env: Vec<(String, String)> = spec
        .egress
        .https_proxy
        .iter()
        .flat_map(|p| [("HTTPS_PROXY".to_string(), p.clone()), ("HTTP_PROXY".to_string(), p.clone())])
        .chain(spec.egress.no_proxy.iter().map(|n| ("NO_PROXY".to_string(), n.clone())))
        .collect();
    let prepared = if plan.empty_source {
        tokio::time::timeout(startup, prepare_empty(&dirs.workspace, &dirs.state)).await
    } else {
        tokio::time::timeout(startup, prepare_with_env(&dirs.workspace, &dirs.state, &spec.repository, &net_env)).await
    };
    let ws: GitWorkspace = match prepared {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            return bad(FailureReason::WorkspacePrepareFailed { detail: em.redactor.redact_string(&e.to_string()) });
        }
        Err(_) => {
            return bad(FailureReason::WorkspacePrepareFailed { detail: "git fetch/checkout timed out".into() });
        }
    };
    em.progress(
        "workspace_ready",
        "workspace prepared",
        json!({"baseRevision": ws.base_sha, "sparse": ws.sparse, "emptySource": plan.empty_source}),
    )
    .await;
    let mut collect = CollectCfg {
        max_bytes: spec.output.max_patch_bytes,
        allowed_paths: spec.output.allowed_paths.clone(),
        exclude: vec![],
        produce_artifact: plan.produce_artifact,
        allow_submodules: spec.output.allow_submodules,
    };
    macro_rules! fail_early {
        ($reason:expr) => {
            return finish_now(&mut em, EnvironmentPhase::Failed, Some($reason), &ws, &dirs, None, &collect, 0, 0).await
        };
    }
    // 3. apply workspace overlays (inherited work: part of the artifact)
    match crate::bootstrap::apply_overlays(&mut *em.sink, &plan, &ws).await {
        Ok(applied) => {
            for (id, files) in applied {
                em.progress("overlay_applied", "workspace overlay applied", json!({"artifactId": id, "files": files}))
                    .await;
            }
        }
        Err(reason) => fail_early!(reason),
    }
    // 4. materialize configs/agents/skills (runtime configuration: excluded by default)
    match crate::bootstrap::place_bundles(&mut *em.sink, &plan, &dirs.workspace, &dirs.home).await {
        Ok((excluded, placed)) => {
            collect.exclude.extend(excluded);
            if !placed.is_empty() {
                em.progress("bundles_placed", "bundles verified and placed", json!({"bundles": placed})).await;
            }
        }
        Err(reason) => fail_early!(reason),
    }
    // 5. lease + synthetic HOME base. Credential copies land only after the
    //    untrusted bootstrap finished (on BootstrapDone, before Proceed) — or
    //    right here when there is no bootstrap — so bootstrap steps can never
    //    read them. The lease itself is held from here for the lifetime.
    let defer_credentials = !plan.exec.is_empty() && spec.credentials.is_some();
    let mut prepared_home = if defer_credentials {
        match prepare_home_base(&dirs.home) {
            Ok(()) => PreparedHome::default(),
            Err(reason) => fail_early!(reason),
        }
    } else {
        match prepare_home(&dirs.home, spec.credentials.as_ref(), dirs.secret_dir.as_deref(), &mut em.redactor) {
            Ok(h) => {
                emit_credentials_placed(&mut em, spec.credentials.as_ref(), "credential copies placed").await;
                h
            }
            Err(reason) => fail_early!(reason),
        }
    };
    let mut credentials_placed = !defer_credentials;
    macro_rules! fail {
        ($reason:expr) => {
            return finish_now(&mut em, EnvironmentPhase::Failed, Some($reason), &ws, &dirs, Some(&prepared_home), &collect, 0, 0).await
        };
    }
    // 6. validate the workdir (real directory below the workspace, no symlinks)
    let workdir_agent_view =
        match crate::bootstrap::validate_workdir(&dirs.workspace, &dirs.agent.workspace, &plan.workdir) {
            Ok(p) => p,
            Err(reason) => fail!(reason),
        };
    // State before the untrusted bootstrap, to attribute its workspace changes.
    let before_exec = if !plan.exec.is_empty() && !plan.include_exec_changes {
        match fingerprint(&ws, &collect.exclude).await {
            Ok(f) => Some(f),
            Err(e) => fail!(FailureReason::Internal { detail: format!("workspace fingerprint: {e}") }),
        }
    } else {
        None
    };

    // ---- connect agentd ----------------------------------------------------------------
    let mut conn = match listener.accept(startup).await {
        Ok(c) => c,
        Err(e) => fail!(FailureReason::SandboxFailed { detail: format!("agentd: {e}") }),
    };
    let (mut child, _) = listener.reject_further_connections();
    match tokio::time::timeout(Duration::from_secs(30), conn.recv()).await {
        Ok(Some(Ok(FromAgent::Hello { protocol, posture, .. }))) => {
            if protocol != PROTOCOL_VERSION {
                conn.close();
                reap_spawned(child.take(), grace).await;
                fail!(FailureReason::Unsupported { detail: "agentd protocol mismatch".into() });
            }
            if opts.strict_posture
                && !opts.agentd.is_spawn()
                && (posture.attempt_secret_visible || posture.ingest_env_present || posture.runnerd_process_visible)
            {
                conn.close();
                reap_spawned(child.take(), grace).await;
                fail!(FailureReason::SandboxFailed { detail: "agent isolation violated".into() });
            }
        }
        _ => {
            conn.close();
            reap_spawned(child.take(), grace).await;
            fail!(FailureReason::ProtocolError { detail: "agentd sent no Hello".into() });
        }
    }
    // ---- UNTRUSTED bootstrap + harness launch (agentd) -------------------------------------
    // 7. agentd runs bootstrap.exec, then starts the harness as an ACP stdio agent.
    let launch = AgentLaunchSpec {
        attempt_id: spec.attempt_id,
        ordinal: spec.ordinal,
        driver: spec.driver.name.clone(),
        driver_config,
        prompt: None,
        raw_acp: true,
        workspace: dirs.agent.workspace.clone(),
        workdir: Some(workdir_agent_view.clone()),
        bootstrap: plan.exec.clone(),
        path_prepend,
        home: dirs.agent.home.clone(),
        tmp: dirs.agent.tmp.clone(),
        env: spec.env.clone(),
        // Staged paths are derived from the layout, not from placed files: with
        // deferred credentials the files only exist after BootstrapDone, but
        // agentd reads them after Proceed in either case.
        credential_env: spec
            .credentials
            .as_ref()
            .map(staged_env_rels)
            .unwrap_or_default()
            .iter()
            .map(|s| StagedCredentialEnv { env_name: s.env_name.clone(), path: dirs.agent.home.join(&s.rel) })
            .collect(),
        permissions: spec.permissions,
        egress: spec.egress.clone(),
        record_raw: spec.record_raw_payloads,
        timeouts: AgentTimeouts {
            startup_seconds: spec.timeouts.startup_seconds,
            grace_seconds: spec.timeouts.grace_seconds,
            status_seconds: spec.timeouts.heartbeat_seconds.max(1),
        },
        skip_probe: opts.skip_probe,
        path_env: opts.agent_path_env.clone(),
        extra_ca_file: opts.extra_ca_file.clone(),
    };
    if conn.send(&ToAgent::Launch { spec: Box::new(launch) }).await.is_err() {
        conn.close();
        reap_spawned(child.take(), grace).await;
        fail!(FailureReason::ProcessCrashed { exit_code: None, signal: None, detail: "agentd link lost".into() });
    }
    // Wait for Ready (harness started, data link connected), journaling startup events.
    let mut driver_version: Option<String> = None;
    let exec_budget: u64 = plan.exec.iter().map(|x| x.timeout_seconds.unwrap_or(600)).sum();
    let ready_wait = startup + Duration::from_secs(exec_budget);
    loop {
        match tokio::time::timeout(ready_wait, conn.recv()).await {
            Ok(Some(Ok(FromAgent::Ready))) => break,
            Ok(Some(Ok(FromAgent::BootstrapDone { steps }))) => {
                // Credentials land only now that the untrusted bootstrap is done —
                // before Proceed, so the harness (and only the harness) sees them.
                if !credentials_placed {
                    match place_credentials(
                        &dirs.home,
                        spec.credentials.as_ref(),
                        dirs.secret_dir.as_deref(),
                        &mut em.redactor,
                    ) {
                        Ok(h) => {
                            prepared_home = h;
                            credentials_placed = true;
                            emit_credentials_placed(
                                &mut em,
                                spec.credentials.as_ref(),
                                "credential copies placed after bootstrap",
                            )
                            .await;
                        }
                        Err(reason) => {
                            conn.close();
                            reap_spawned(child.take(), grace).await;
                            fail!(reason);
                        }
                    }
                }
                // Attribute workspace changes of the untrusted setup; keep them out of the
                // artifact (runtime state, not work) unless the spec says otherwise.
                if let Some(before) = &before_exec {
                    match fingerprint(&ws, &collect.exclude).await {
                        Ok(after) => {
                            let changed = changed_between(before, &after);
                            em.progress(
                                "bootstrap_exec_done",
                                "bootstrap commands finished",
                                json!({"steps": steps, "excludedPaths": changed.len()}),
                            )
                            .await;
                            collect.exclude.extend(changed);
                        }
                        Err(e) => {
                            conn.close();
                            reap_spawned(child.take(), grace).await;
                            fail!(FailureReason::Internal { detail: format!("workspace fingerprint: {e}") });
                        }
                    }
                } else {
                    em.progress("bootstrap_exec_done", "bootstrap commands finished", json!({"steps": steps})).await;
                }
                if conn.send(&ToAgent::Proceed).await.is_err() {
                    conn.close();
                    reap_spawned(child.take(), grace).await;
                    fail!(FailureReason::ProcessCrashed {
                        exit_code: None,
                        signal: None,
                        detail: "agentd link lost".into()
                    });
                }
            }
            Ok(Some(Ok(FromAgent::Probe { cli_version, adapter_version, .. }))) => {
                driver_version = join_versions(&cli_version, &adapter_version);
            }
            Ok(Some(Ok(FromAgent::Started { program, pid }))) => {
                em.emit(
                    EventKind::AgentStarted,
                    EventSource::Runnerd,
                    AgentStartedData {
                        driver: spec.driver.name.clone(),
                        program: truncate_utf8(&program, 128).0,
                        pid,
                        cli_version: driver_version.clone(),
                        adapter_version: None,
                    },
                )
                .await;
            }
            Ok(Some(Ok(FromAgent::Event { event }))) => em.agent_event(event).await,
            Ok(Some(Ok(FromAgent::Status { .. }))) => {}
            Ok(Some(Ok(FromAgent::Exit { exit }))) => {
                let reason = exit_reason(&spec, exit, &mut em.redactor);
                conn.close();
                reap_spawned(child.take(), grace).await;
                fail!(reason);
            }
            _ => {
                conn.close();
                reap_spawned(child.take(), grace).await;
                fail!(FailureReason::ProtocolError { detail: "harness did not reach Ready".into() });
            }
        }
    }
    let data = match data_listener.accept(Duration::from_secs(10)).await {
        Ok(d) => d,
        Err(e) => {
            conn.close();
            reap_spawned(child.take(), grace).await;
            fail!(FailureReason::ProtocolError { detail: format!("agentd data link: {e}") });
        }
    };
    let (mut agent_rx, agent_tx) = spawn_data_link(data);
    em.progress("environment_ready", "environment is idle; the ACP gateway accepts callers", json!({"phase": "Idle"}))
        .await;

    // ---- gateway -----------------------------------------------------------------------
    let gw = match Gateway::bind(GatewayConfig {
        listen: gateway_listen.clone(),
        environment_id,
        key: gateway_key,
        workdir: workdir_agent_view.to_string_lossy().to_string(),
    })
    .await
    {
        Ok(g) => g,
        Err(e) => {
            conn.close();
            reap_spawned(child.take(), grace).await;
            fail!(FailureReason::Internal { detail: format!("gateway bind: {e}") });
        }
    };
    if let Ok(addr) = gw.local_addr() {
        em.progress("gateway_listening", "ACP gateway is accepting callers", json!({"addr": addr.to_string()})).await;
    }
    let (phase_tx, phase_rx) = watch::channel(EnvironmentPhase::Idle);
    let (gw_tx, mut gw_rx) = mpsc::channel::<GatewayEvent>(16);
    let gw_task = gw.spawn(phase_rx, gw_tx);

    // ---- main loop ---------------------------------------------------------------------
    let mut state = EnvState {
        phase: EnvironmentPhase::Idle,
        caller: None,
        turns: 0,
        snapshots: 0,
        idle_since: Instant::now(),
        tap: AcpTap::default(),
        agent_open: true,
        pending_acks: vec![],
        seen_snapshot_ids: std::collections::HashSet::new(),
        heartbeat_deadline: None,
    };
    let idle_timeout = idle_timeout_seconds.map(Duration::from_secs);
    let max_lifetime = max_lifetime_seconds.map(Duration::from_secs);
    let mut hb = tokio::time::interval(hb_every);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let result = loop {
        tokio::select! {
            biased;
            m = conn.recv() => match m {
                None => break Finish::AgentGone,
                Some(Err(e)) => break Finish::Protocol(e),
                Some(Ok(FromAgent::Event { event })) => em.agent_event(event).await,
                Some(Ok(FromAgent::Exit { exit })) => break Finish::AgentFailed(exit_reason(&spec, exit, &mut em.redactor)),
                Some(Ok(_)) => {}
            },
            line = agent_rx.recv(), if state.agent_open => match line {
                None => state.agent_open = false,
                Some(line) => on_agent_line(&mut em, &mut state, &phase_tx, &agent_tx, line).await,
            },
            ev = gw_rx.recv() => match ev {
                Some(GatewayEvent::Attached(c)) => {
                    let replaced = state.caller.replace(c).is_some();
                    let t = state.caller.as_ref().map(|c| c.transport).unwrap_or("");
                    em.progress("caller_attached", "a caller attached to the environment", json!({"transport": t, "replacedPrevious": replaced})).await;
                }
                Some(GatewayEvent::Rejected(r)) => {
                    em.progress("caller_rejected", &r.reason, json!({"status": r.status})).await;
                }
                None => {}
            },
            msg = recv_caller(&mut state) => match msg {
                Some(line) => {
                    for o in state.tap.caller_message(&line) {
                        if let Observed::PromptStarted { bytes, preview } = o {
                            em.emit(EventKind::InputSent, EventSource::Runnerd, InputSentData { bytes, sha256: String::new(), preview, has_resume_capsule: false }).await;
                            if state.phase != EnvironmentPhase::Busy {
                                state.phase = EnvironmentPhase::Busy;
                                let _ = phase_tx.send(EnvironmentPhase::Busy);
                                em.progress("environment_busy", "prompt turn started", json!({"phase": "Busy"})).await;
                            }
                        }
                    }
                    let _ = agent_tx.send(line).await;
                }
                None => {
                    if state.caller.take().is_some() {
                        em.progress("caller_detached", "the caller disconnected from the environment", Value::Null).await;
                        state.idle_since = Instant::now();
                    }
                }
            },
            _ = hb.tick() => {
                let hb = HeartbeatData {
                    agent_alive: state.agent_open,
                    agent_pid: None,
                    seconds_since_progress: None,
                    stage: state.phase.as_str().to_string(),
                    // V5a: ack every consumed directive; cleared only when the
                    // POST succeeds (a failed POST keeps them for the retry,
                    // redelivery + dedupe below cover the rest).
                    acked_directives: state.pending_acks.clone(),
                };
                // Provider operations (snapshot/finish/cancel) arrive on the heartbeat reply
                // (controller -> runnerd); they never travel on the ACP dataplane.
                match em.sink.heartbeat(&hb).await {
                    Ok(reply) => {
                        state.pending_acks.clear();
                        // V10c: a success resets the continuous-failure clock;
                        // the deadline tracks the lease's remaining lifetime.
                        state.heartbeat_deadline =
                            heartbeat_deadline_from_reply(Instant::now(), em.sink.last_lease_expires_at());
                        if let Some(directive) = reply {
                            let did = em.sink.take_directive_id();
                            let mut ack = |id: Option<Uuid>| {
                                if let Some(id) = id {
                                    state.pending_acks.push(id);
                                }
                            };
                            match directive {
                                // Terminal directives end the loop (no more
                                // heartbeats): nothing left to ack with.
                                RunnerDirective::Finish => break Finish::Finish,
                                RunnerDirective::Cancel { reason } => break Finish::Cancel(reason.message()),
                                RunnerDirective::Snapshot { snapshot_id, label } => {
                                    let id = snapshot_id.unwrap_or_else(Uuid::now_v7);
                                    // Redelivered (unacked) directives must not
                                    // upload twice: same snapshotId, one artifact.
                                    if state.seen_snapshot_ids.contains(&id) {
                                        em.progress(
                                            "snapshot_duplicate_ignored",
                                            "redelivered snapshot directive already processed",
                                            json!({"snapshotId": id}),
                                        )
                                        .await;
                                    } else if state.phase == EnvironmentPhase::Idle {
                                        snapshot(&mut em, &ws, &spec, &collect, id, label, driver_version.clone())
                                            .await;
                                        state.snapshots += 1;
                                        state.seen_snapshot_ids.insert(id);
                                    } else {
                                        em.progress("snapshot_rejected", "snapshot requested while Busy; ignored (retry at Idle)", json!({"snapshotId": id})).await;
                                    }
                                    ack(did);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // V10c: heartbeats failing continuously past the
                        // credential lease's remaining lifetime mean the
                        // controller side is gone — stop the agent instead of
                        // running unsupervised on a lapsed lease.
                        if state.heartbeat_deadline.is_some_and(|d| Instant::now() >= d) {
                            break Finish::Cancel(
                                "heartbeats failed continuously past the credential lease expiry".into(),
                            );
                        }
                        tracing::warn!(error = %e, "heartbeat failed; directive acks kept for the retry");
                    }
                }
            }
            _ = tick.tick() => {
                if *external_cancel.borrow() {
                    break Finish::Cancel("runnerd received SIGTERM".into());
                }
                if let Some(t) = idle_timeout
                    && state.phase == EnvironmentPhase::Idle
                    && state.caller.is_none()
                    && state.idle_since.elapsed() > t
                {
                    break Finish::IdleTimeout;
                }
                if let Some(t) = max_lifetime && started_at.elapsed() > t {
                    break Finish::MaxLifetime;
                }
            }
            _ = external_cancel.changed() => {
                if *external_cancel.borrow() { break Finish::Cancel("runnerd received SIGTERM".into()); }
            }
        }
    };

    // ---- finish ------------------------------------------------------------------------
    let _ = phase_tx.send(EnvironmentPhase::Finishing);
    gw_task.abort();
    state.caller = None; // closes the caller's connection
    let _ = conn.send(&ToAgent::Finish).await;
    let _ = tokio::time::timeout(grace * 2 + Duration::from_secs(5), async {
        while let Some(Ok(m)) = conn.recv().await {
            if let FromAgent::Exit { .. } = m {
                break;
            }
        }
    })
    .await;
    conn.close();
    reap_spawned(child.take(), grace).await;
    let (phase, reason) = match result {
        Finish::Finish | Finish::IdleTimeout | Finish::MaxLifetime => (EnvironmentPhase::Completed, None),
        Finish::Cancel(detail) => (EnvironmentPhase::Failed, Some(FailureReason::Cancelled { detail })),
        Finish::AgentGone => (
            EnvironmentPhase::Failed,
            Some(FailureReason::ProcessCrashed { exit_code: None, signal: None, detail: "agentd disconnected".into() }),
        ),
        Finish::Protocol(e) => {
            (EnvironmentPhase::Failed, Some(FailureReason::ProtocolError { detail: format!("agentd: {e}") }))
        }
        Finish::AgentFailed(r) => (EnvironmentPhase::Failed, Some(r)),
    };
    let mut res =
        finish_now(&mut em, phase, reason, &ws, &dirs, Some(&prepared_home), &collect, state.turns, state.snapshots)
            .await;
    res.base_revision = Some(ws.base_sha.clone());
    res
}

/// Split agentd's data connection into a line reader (harness → caller) and a writer
/// (caller → harness). Lines are relayed verbatim.
fn spawn_data_link(data: tokio::net::UnixStream) -> (mpsc::Receiver<String>, mpsc::Sender<String>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    let (rd, mut wr) = data.into_split();
    let (in_tx, in_rx) = mpsc::channel::<String>(4096);
    let (out_tx, mut out_rx) = mpsc::channel::<String>(1024);
    tokio::spawn(async move {
        let max = acp_runner_ipc::gateway::MAX_MESSAGE_BYTES;
        let mut rd = tokio::io::BufReader::new(rd);
        loop {
            let mut buf = Vec::new();
            match (&mut rd).take(max as u64 + 1).read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) if n > max => break,
                Ok(_) => {}
            }
            let line = String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']).to_string();
            if line.trim().is_empty() {
                continue;
            }
            if in_tx.send(line).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(mut m) = out_rx.recv().await {
            m.push('\n');
            if wr.write_all(m.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    (in_rx, out_tx)
}

/// A message from the harness: observe, journal, relay to the caller.
async fn on_agent_line(
    em: &mut Em<'_>,
    state: &mut EnvState,
    phase_tx: &watch::Sender<EnvironmentPhase>,
    agent_tx: &mpsc::Sender<String>,
    line: String,
) {
    for o in state.tap.agent_message(&line) {
        match o {
            Observed::Agent(ev) => em.agent_event(ev).await,
            Observed::PromptEnded { stop_reason, error, text } => {
                if !text.trim().is_empty() {
                    em.agent_event(AgentEvent::Output { channel: "message".into(), text }).await;
                }
                state.turns += 1;
                if !state.tap.busy() {
                    state.phase = EnvironmentPhase::Idle;
                    state.idle_since = Instant::now();
                    let _ = phase_tx.send(EnvironmentPhase::Idle);
                }
                em.progress(
                    "turn_ended",
                    &stop_reason,
                    json!({"success": stop_reason == "end_turn", "error": error, "phase": state.phase.as_str()}),
                )
                .await;
            }
            Observed::PromptStarted { .. } => {}
        }
    }
    let delivered = match &state.caller {
        Some(c) => c.send(line.clone()).await,
        None => false,
    };
    if !delivered && let Some(id) = AcpTap::is_request(&line) {
        // Nobody can answer a harness request while no client is attached; answer with a
        // generic JSON-RPC error so the harness does not wait forever.
        let err = json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32001, "message": "no ACP client is attached to this environment"}});
        let _ = agent_tx.send(err.to_string()).await;
    }
}

#[allow(clippy::enum_variant_names)]
enum Finish {
    Finish,
    Cancel(String),
    IdleTimeout,
    MaxLifetime,
    AgentGone,
    Protocol(String),
    AgentFailed(FailureReason),
}

struct EnvState {
    phase: EnvironmentPhase,
    caller: Option<Caller>,
    turns: u32,
    snapshots: u32,
    idle_since: Instant,
    tap: AcpTap,
    agent_open: bool,
    /// Consumed directive ids, acked on the next successful heartbeat (V5a).
    pending_acks: Vec<Uuid>,
    /// Processed snapshot ids: redelivered directives must not upload twice.
    seen_snapshot_ids: std::collections::HashSet<Uuid>,
    /// Monotonic deadline for continuous heartbeat failure (V10c): recomputed
    /// from the lease expiry on every successful heartbeat; when heartbeats
    /// keep failing past it, the agent is stopped. `None` without a lease.
    heartbeat_deadline: Option<Instant>,
}

/// V10c: recompute the stop deadline from a heartbeat reply's lease expiry
/// (unix seconds). Pure, unit-tested.
fn heartbeat_deadline_from_reply(now: Instant, lease_expires_at: Option<i64>) -> Option<Instant> {
    let exp = lease_expires_at?;
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some(now + std::time::Duration::from_secs(exp.saturating_sub(unix).max(0) as u64))
}

async fn recv_caller(state: &mut EnvState) -> Option<String> {
    match &mut state.caller {
        Some(c) => c.rx.recv().await,
        None => std::future::pending().await,
    }
}

fn exit_reason(spec: &AttemptSpec, exit: AgentExit, r: &mut Redactor) -> FailureReason {
    let stderr = r.redact_string(&truncate_utf8(exit.stderr_tail.trim(), 2000).0);
    match exit.outcome {
        AgentOutcome::Failed { reason } if acp_runner_ipc::agent_may_claim(&reason) => reason,
        AgentOutcome::Failed { reason } => {
            FailureReason::ProtocolError { detail: format!("agent claimed {}", reason.code()) }
        }
        AgentOutcome::Crashed { detail } => FailureReason::ProcessCrashed {
            exit_code: exit.exit_code,
            signal: exit.signal,
            detail: format!("{detail} | stderr: {stderr}"),
        },
        AgentOutcome::TurnEnded { .. } => FailureReason::ProcessCrashed {
            exit_code: exit.exit_code,
            signal: exit.signal,
            detail: format!("harness exited: {} | stderr: {stderr}", spec.driver.name),
        },
        AgentOutcome::Cancelled { .. } => FailureReason::Cancelled { detail: "harness exited on cancel".into() },
    }
}

fn join_versions(cli: &Option<String>, adapter: &Option<String>) -> Option<String> {
    let v: Vec<String> = [cli, adapter].iter().filter_map(|x| x.as_ref().cloned()).collect();
    (!v.is_empty()).then(|| v.join(" / "))
}

/// How the authoritative collector builds artifacts for this environment.
struct CollectCfg {
    max_bytes: u64,
    allowed_paths: Vec<String>,
    /// Runtime configuration and setup output (never part of the artifact).
    exclude: Vec<String>,
    /// Output policy `none` → no final artifact.
    produce_artifact: bool,
    /// Submodule opt-in from the attempt output spec (V6).
    allow_submodules: bool,
}

impl CollectCfg {
    fn options(&self) -> CollectOptions {
        CollectOptions {
            max_bytes: self.max_bytes,
            allowed_paths: self.allowed_paths.clone(),
            reject_symlink_escape: true,
            exclude_paths: self.exclude.clone(),
            allow_submodules: self.allow_submodules,
        }
    }
}

/// Collect a non-terminal snapshot against the base and upload it.
async fn snapshot(
    em: &mut Em<'_>,
    ws: &GitWorkspace,
    spec: &AttemptSpec,
    collect: &CollectCfg,
    snapshot_id: Uuid,
    label: Option<String>,
    driver_version: Option<String>,
) {
    match collect_patch(ws, &collect.options()).await {
        Ok(p) => {
            let art = ArtifactUpload {
                kind: "snapshot".into(),
                base_revision: p.base_sha.clone(),
                sha256: p.sha256.clone(),
                changed_paths: p.changed_paths.clone(),
                driver: spec.driver.name.clone(),
                driver_version,
                patch_b64: base64_encode(&p.patch),
            };
            match em.sink.upload_artifact(&art).await {
                Ok(acc) => {
                    em.emit(
                        EventKind::ArtifactCreated,
                        EventSource::Runnerd,
                        ArtifactCreatedData {
                            artifact_id: acc.artifact_id,
                            kind: "snapshot".into(),
                            base_revision: p.base_sha.clone(),
                            sha256: p.sha256.clone(),
                            size_bytes: p.size_bytes(),
                            changed_paths: p.changed_paths.clone(),
                            storage: acc.storage,
                        },
                    )
                    .await;
                    em.progress("snapshot_created", "workspace snapshot collected", json!({"snapshotId": snapshot_id, "label": label, "changedPaths": p.changed_paths.len(), "artifactId": acc.artifact_id})).await;
                }
                Err(e) => em.progress("snapshot_failed", &e.to_string(), json!({"snapshotId": snapshot_id})).await,
            }
        }
        Err(e) => em.progress("snapshot_failed", &e.to_string(), json!({"snapshotId": snapshot_id})).await,
    }
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[allow(clippy::too_many_arguments)]
async fn finish_now(
    em: &mut Em<'_>,
    phase: EnvironmentPhase,
    reason: Option<FailureReason>,
    ws: &GitWorkspace,
    dirs: &RunnerDirs,
    home: Option<&PreparedHome>,
    collect: &CollectCfg,
    turns: u32,
    snapshots: u32,
) -> EnvironmentResult {
    let mut res = EnvironmentResult {
        phase,
        reason: reason.clone(),
        base_revision: Some(ws.base_sha.clone()),
        final_artifact_id: None,
        changed_paths: 0,
        turns,
        snapshots,
    };
    // credential write-back (validated by the controller)
    if let Some(h) = home {
        for (key, bytes) in changed_writeback_files(&dirs.home, h) {
            // The refreshed values are new secrets: redact them from now on (V8.1).
            if let Ok(s) = std::str::from_utf8(&bytes) {
                em.redactor.add_secret(s);
            }
            match em.sink.writeback(&key, &bytes).await {
                Ok(()) => {
                    em.progress("credential_writeback", &format!("refreshed {key} handed back"), Value::Null).await
                }
                Err(e) => em.progress("credential_writeback_failed", &format!("{key}: {e}"), Value::Null).await,
            }
        }
    }
    // final changeset (both on completion and, best-effort, on failure) — cumulative
    // against the original base, whatever overlays the environment started from.
    if collect.produce_artifact {
        match collect_patch(ws, &collect.options()).await {
            Ok(p) if !p.is_empty() => {
                res.changed_paths = p.changed_paths.len();
                let kind = if phase == EnvironmentPhase::Completed { "final" } else { "partial_final" };
                let art = ArtifactUpload {
                    kind: kind.into(),
                    base_revision: p.base_sha.clone(),
                    sha256: p.sha256.clone(),
                    changed_paths: p.changed_paths.clone(),
                    driver: String::new(),
                    driver_version: None,
                    patch_b64: base64_encode(&p.patch),
                };
                if let Ok(acc) = em.sink.upload_artifact(&art).await {
                    res.final_artifact_id = Some(acc.artifact_id);
                    em.emit(
                        EventKind::ArtifactCreated,
                        EventSource::Runnerd,
                        ArtifactCreatedData {
                            artifact_id: acc.artifact_id,
                            kind: kind.into(),
                            base_revision: p.base_sha.clone(),
                            sha256: p.sha256.clone(),
                            size_bytes: p.size_bytes(),
                            changed_paths: p.changed_paths.clone(),
                            storage: acc.storage,
                        },
                    )
                    .await;
                }
            }
            _ => {}
        }
    }
    let reason = reason.map(|r| {
        let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
        em.redactor.redact_json(&mut v);
        serde_json::from_value(v).unwrap_or(r)
    });
    res.reason = reason.clone();
    let kind =
        if phase == EnvironmentPhase::Completed { EventKind::AttemptCompleted } else { EventKind::AttemptFailed };
    em.emit(
        kind,
        EventSource::Runnerd,
        json!({
            "environmentPhase": phase.as_str(),
            "reason": reason,
            "finalArtifactId": res.final_artifact_id,
            "turns": turns,
            "snapshots": snapshots,
        }),
    )
    .await;
    let _ = em.sink.flush().await;
    let _ = dirs;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
    }

    #[test]
    fn heartbeat_deadline_tracks_lease_expiry() {
        let now = Instant::now();
        // no lease, no deadline: failures only warn
        assert_eq!(heartbeat_deadline_from_reply(now, None), None);
        // expiry a minute out: deadline ~a minute out
        let d = heartbeat_deadline_from_reply(now, Some(unix() + 60)).unwrap();
        assert!(d > now + Duration::from_secs(50) && d <= now + Duration::from_secs(61), "{d:?}");
        // already-lapsed expiry: deadline is now (stop on the next failure)
        let d0 = heartbeat_deadline_from_reply(now, Some(0)).unwrap();
        assert!(d0 <= now + Duration::from_millis(500), "{d0:?}");
    }
}
