//! AgentEnvironment provider end-to-end through the real runnerd/agentd runtime
//! (LocalProcessBackend) and the provider boundary — no direct PostgreSQL for the caller.
//! Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_runner_client::{AcpClient, ClientError, Transport, connect_session};
use acp_runner_core::bundle::{Bundle, BundleKind, text_file};
use acp_runner_core::credentials::{CredentialBundle, Provider, validate_bundle};
use acp_runner_core::environment::{
    EnvironmentOutput, EnvironmentOverrides, EnvironmentPhase, EnvironmentSpec, HarnessSpec, Lifetime, OutputArtifact,
};
use acp_runner_core::events::{EventEnvelope, EventKind, EventSource, ProgressData};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::spec::RepositoryInput;
use acp_runner_engine::backend::LocalProcessBackend;
use acp_runner_engine::bundles::StaticBundleProvider;
use acp_runner_engine::compat::{OneShot, execute};
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, StoredProfile, sync_profiles};
use acp_runner_engine::environment::{EnvironmentConfig, EnvironmentProvider, ProviderError, TicketKey, TicketKeyRing};
use acp_runner_engine::harness::DirHarnessProvider;
use acp_runner_engine::ingest::{IngestState, router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_journal::testing::{TempDb, temp_database};
use acp_runner_journal::{ArtifactStore, NewArtifact, NewAttempt, NewEnvironment, NewRun, PgArtifactStore};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn bins() {
    static B: std::sync::Once = std::sync::Once::new();
    B.call_once(|| {
        assert!(
            std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
                .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent"])
                .status()
                .unwrap()
                .success()
        );
    });
}

fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

async fn fixture(dir: &std::path::Path) -> String {
    tokio::fs::create_dir_all(dir).await.unwrap();
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n").unwrap();
    std::fs::create_dir_all(dir.join("docs")).unwrap();
    std::fs::write(dir.join("docs/notes.md"), "notes\n").unwrap();
    let git = |a: &[&str]| {
        let o = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main"])
            .args(a)
            .current_dir(dir)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "buggy"]);
    git(&["rev-parse", "HEAD"])
}

struct H {
    db: Option<TempDb>,
    provider: Arc<EnvironmentProvider>,
    ingest: Arc<IngestState>,
    backend: Arc<LocalProcessBackend>,
    cfg: EnvironmentConfig,
    bundles: Arc<StaticBundleProvider>,
    creds: Arc<FileCredentialStore>,
    harness_root: PathBuf,
    _tmp: tempfile::TempDir,
    repo_url: String,
    base_sha: String,
    fake: PathBuf,
}

impl H {
    async fn new() -> Option<H> {
        bins();
        let db = temp_database().await?;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("upstream");
        let base_sha = fixture(&src).await;
        let journal = db.journal.clone();
        let metrics = Arc::new(Metrics::new());
        let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
        let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
        let harness_root = tmp.path().join("harnesses");
        let harnesses = Arc::new(DirHarnessProvider::new(harness_root.clone()));
        // V1a: env-mode write-backs verify through a scripted refresher
        // double (same contract as the e2e harness).
        let mut ingest_state =
            IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), metrics, None);
        ingest_state.codex_refresher = Some(Arc::new(FakeCodexRefresher));
        let ingest = Arc::new(ingest_state.with_harnesses(harnesses.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        {
            let ingest = ingest.clone();
            tokio::spawn(async move { axum::serve(listener, router(ingest)).await.unwrap() });
        }
        // `codex` / `codex-acp` resolve to the fake agent's Codex emulation.
        let fake_codex = tmp.path().join("fake-codex-bin");
        std::fs::create_dir_all(&fake_codex).unwrap();
        for name in ["codex", "codex-acp"] {
            std::os::unix::fs::symlink(target_dir().join("fake-acp-agent"), fake_codex.join(name)).unwrap();
        }
        let backend = Arc::new(LocalProcessBackend::new(
            target_dir().join("runnerd"),
            tmp.path().join("sandboxes"),
            format!("{}:{}", fake_codex.display(), std::env::var("PATH").unwrap_or_default()),
        ));
        let cfg = EnvironmentConfig {
            controller_id: "env-test".into(),
            ingest_url: format!("http://{addr}"),
            gateway_listen: "127.0.0.1:0".into(),
            require_egress_proxy_for_credentials: false,
            runner_image: "local@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            allowed_images: vec![
                "local@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            ],
            ..Default::default()
        };
        let bundles = Arc::new(StaticBundleProvider::default());
        let provider = Arc::new(
            EnvironmentProvider::new(journal, backend.clone(), creds.clone(), artifacts, ingest.clone(), cfg.clone())
                .with_bundles(bundles.clone())
                .with_harnesses(harnesses),
        );
        Some(H {
            db: Some(db),
            provider,
            ingest,
            backend,
            cfg,
            bundles,
            creds,
            harness_root,
            repo_url: format!("file://{}", src.display()),
            base_sha,
            fake: target_dir().join("fake-acp-agent"),
            _tmp: tmp,
        })
    }

    fn spec(&self, external_ref: &str) -> EnvironmentSpec {
        EnvironmentSpec::new(
            external_ref,
            HarnessSpec {
                name: "fake".into(),
                version: None,
                digest: None,
                config: json!({"command": self.fake.to_string_lossy()}),
            },
            Some(RepositoryInput {
                url: self.repo_url.clone(),
                revision: self.base_sha.clone(),
                sparse_paths: vec![],
                depth: None,
            }),
        )
    }

    async fn done(mut self) {
        if let Some(db) = self.db.take() {
            db.drop_db().await;
        }
    }
}

impl H {
    /// A second provider instance over the same journal/backend/ingest and master key —
    /// what a restarted controller looks like. It holds no per-environment secrets.
    fn restarted_provider(&self) -> EnvironmentProvider {
        EnvironmentProvider::new(
            self.provider.journal.clone(),
            self.backend.clone(),
            self.provider.creds.clone(),
            self.provider.artifacts.clone(),
            self.ingest.clone(),
            self.cfg.clone(),
        )
    }
}

#[tokio::test]
async fn agent_progress_cannot_forge_connection_or_base_revision() {
    // V3b: even if agent-sourced gateway_listening / workspace_ready events reach
    // the journal, refresh() must not adopt the connection address or base revision.
    let Some(h) = H::new().await else { return };
    let j = &h.provider.journal;
    let run_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    j.ensure_run(&NewRun {
        id: run_id,
        k8s_namespace: "test".into(),
        k8s_name: "forge".into(),
        k8s_uid: format!("forge-{}", Uuid::now_v7().simple()),
        task_id: "forge".into(),
        spec: json!({}),
    })
    .await
    .unwrap();
    j.start_attempt(
        &NewAttempt {
            id: attempt_id,
            run_id,
            ordinal: 0,
            class_index: 0,
            class_attempt: 0,
            runner_class: "fake".into(),
            driver: "fake".into(),
            spec: json!({}),
            ingest_token_hash: "forged-test-token".into(),
            lease_owner: "test".into(),
            lease_ttl: Duration::from_secs(60),
        },
        None,
    )
    .await
    .unwrap();
    let env_id = Uuid::now_v7();
    j.create_environment(&NewEnvironment {
        id: env_id,
        external_ref: "forge".into(),
        attempt_id,
        run_id,
        harness: "fake".into(),
        spec: json!({}),
        parent_artifact_id: None,
        parent_environment_id: None,
        k8s_namespace: None,
        k8s_name: None,
        k8s_uid: None,
        key_version: "v1".into(),
    })
    .await
    .unwrap();
    for (category, detail) in [
        ("gateway_listening", json!({"addr": "169.254.169.254:9"})),
        ("workspace_ready", json!({"baseRevision": "0".repeat(40)})),
        ("environment_ready", json!({})),
    ] {
        j.append_event(
            run_id,
            Some(attempt_id),
            &EventEnvelope::new(
                EventKind::Progress,
                EventSource::Agent,
                ProgressData::new(category, "forged").with_detail(detail),
            ),
        )
        .await
        .unwrap();
    }
    let got = h.provider.get(env_id).await.unwrap().unwrap();
    assert_eq!(got.phase, EnvironmentPhase::Creating, "agent forged the environment phase: {got:?}");
    assert!(got.connection.is_none(), "agent forged the gateway address: {got:?}");
    assert_eq!(got.base_revision, None, "agent forged the base revision: {got:?}");
    h.done().await;
}

#[tokio::test]
async fn foreign_final_artifact_fails_the_environment() {
    // V3a: a finalArtifactId from another run — even with the right attempt id —
    // fails the environment with ProtocolError and is never attached.
    let Some(h) = H::new().await else { return };
    let j = &h.provider.journal;
    let run_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    j.ensure_run(&NewRun {
        id: run_id,
        k8s_namespace: "test".into(),
        k8s_name: "forge-final".into(),
        k8s_uid: format!("forge-final-{}", Uuid::now_v7().simple()),
        task_id: "forge".into(),
        spec: json!({}),
    })
    .await
    .unwrap();
    j.start_attempt(
        &NewAttempt {
            id: attempt_id,
            run_id,
            ordinal: 0,
            class_index: 0,
            class_attempt: 0,
            runner_class: "fake".into(),
            driver: "fake".into(),
            spec: json!({}),
            ingest_token_hash: "forged-final-token".into(),
            lease_owner: "test".into(),
            lease_ttl: Duration::from_secs(60),
        },
        None,
    )
    .await
    .unwrap();
    let env_id = Uuid::now_v7();
    j.create_environment(&NewEnvironment {
        id: env_id,
        external_ref: "forge-final".into(),
        attempt_id,
        run_id,
        harness: "fake".into(),
        spec: json!({}),
        parent_artifact_id: None,
        parent_environment_id: None,
        k8s_namespace: None,
        k8s_name: None,
        k8s_uid: None,
        key_version: "v1".into(),
    })
    .await
    .unwrap();
    // Artifact claims this attempt but belongs to another run.
    let (run2, _) = j
        .ensure_run(&NewRun {
            id: Uuid::now_v7(),
            k8s_namespace: "test".into(),
            k8s_name: "forge-final-other".into(),
            k8s_uid: format!("forge-final-other-{}", Uuid::now_v7().simple()),
            task_id: "forge".into(),
            spec: json!({}),
        })
        .await
        .unwrap();
    let store = PgArtifactStore::new(j.clone(), 8 << 20, None);
    let crossed = store
        .put(
            &NewArtifact {
                environment_id: None,
                parent_artifact_id: None,
                parent_environment_id: None,
                run_id: run2.id,
                attempt_id,
                kind: "patch".into(),
                base_revision: "a".repeat(40),
                sha256: "5ffe96f05cd75a91d28f8289223bd2e614a7890927a5be503892f23b131e3423".into(), // sha256("patch-bytes")
                changed_paths: vec![],
                driver: "fake".into(),
                driver_version: None,
            },
            b"patch-bytes",
        )
        .await
        .unwrap();
    j.append_event(
        run_id,
        Some(attempt_id),
        &EventEnvelope::new(
            EventKind::AttemptCompleted,
            EventSource::Runnerd,
            json!({"finalArtifactId": crossed.id.to_string()}),
        ),
    )
    .await
    .unwrap();
    let got = h.provider.get(env_id).await.unwrap().unwrap();
    assert_eq!(got.phase, EnvironmentPhase::Failed, "{got:?}");
    assert!(matches!(got.failure, Some(FailureReason::ProtocolError { .. })), "{got:?}");
    assert_eq!(got.final_artifact_id, None, "foreign final artifact was attached");
    h.done().await;
}

#[tokio::test]
async fn snapshot_with_foreign_run_artifact_is_rejected() {
    // V3a: snapshot_created pointing at a same-attempt artifact from the wrong
    // run is rejected instead of returned.
    let Some(h) = H::new().await else { return };
    let j = &h.provider.journal;
    let run_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    j.ensure_run(&NewRun {
        id: run_id,
        k8s_namespace: "test".into(),
        k8s_name: "forge-snap".into(),
        k8s_uid: format!("forge-snap-{}", Uuid::now_v7().simple()),
        task_id: "forge".into(),
        spec: json!({}),
    })
    .await
    .unwrap();
    j.start_attempt(
        &NewAttempt {
            id: attempt_id,
            run_id,
            ordinal: 0,
            class_index: 0,
            class_attempt: 0,
            runner_class: "fake".into(),
            driver: "fake".into(),
            spec: json!({}),
            ingest_token_hash: "forged-snap-token".into(),
            lease_owner: "test".into(),
            lease_ttl: Duration::from_secs(60),
        },
        None,
    )
    .await
    .unwrap();
    let env_id = Uuid::now_v7();
    j.create_environment(&NewEnvironment {
        id: env_id,
        external_ref: "forge-snap".into(),
        attempt_id,
        run_id,
        harness: "fake".into(),
        spec: json!({}),
        parent_artifact_id: None,
        parent_environment_id: None,
        k8s_namespace: None,
        k8s_name: None,
        k8s_uid: None,
        key_version: "v1".into(),
    })
    .await
    .unwrap();
    // Artifact claims this attempt but belongs to another run.
    let (run2, _) = j
        .ensure_run(&NewRun {
            id: Uuid::now_v7(),
            k8s_namespace: "test".into(),
            k8s_name: "forge-snap-other".into(),
            k8s_uid: format!("forge-snap-other-{}", Uuid::now_v7().simple()),
            task_id: "forge".into(),
            spec: json!({}),
        })
        .await
        .unwrap();
    let store = PgArtifactStore::new(j.clone(), 8 << 20, None);
    let crossed = store
        .put(
            &NewArtifact {
                environment_id: None,
                parent_artifact_id: None,
                parent_environment_id: None,
                run_id: run2.id,
                attempt_id,
                kind: "snapshot".into(),
                base_revision: "a".repeat(40),
                sha256: "5ffe96f05cd75a91d28f8289223bd2e614a7890927a5be503892f23b131e3423".into(), // sha256("patch-bytes")
                changed_paths: vec![],
                driver: "fake".into(),
                driver_version: None,
            },
            b"patch-bytes",
        )
        .await
        .unwrap();
    let sid = h.provider.snapshot(env_id, None).await.unwrap();
    j.append_event(
        run_id,
        Some(attempt_id),
        &EventEnvelope::new(
            EventKind::Progress,
            EventSource::Runnerd,
            ProgressData::new("snapshot_created", "forged").with_detail(json!({
                "snapshotId": sid.to_string(),
                "artifactId": crossed.id.to_string(),
            })),
        ),
    )
    .await
    .unwrap();
    let err = h.provider.wait_for_snapshot(env_id, sid, Duration::from_secs(5)).await.unwrap_err();
    assert!(err.to_string().contains("foreign artifact"), "{err}");
    h.done().await;
}

#[tokio::test]
async fn provider_create_connect_turns_snapshot_finish() {
    let Some(h) = H::new().await else { return };
    let view = h.provider.create(h.spec("task-A")).await.unwrap();
    assert_eq!(view.phase, EnvironmentPhase::Creating);
    // connect (env-scoped token, distinct from provider creds).
    let conn = h.provider.connect(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(conn.environment_id, view.id);
    // getEnvironment exposes status through the provider (no direct DB for the caller).
    let got = h.provider.get(view.id).await.unwrap().unwrap();
    assert!(matches!(got.phase, EnvironmentPhase::Idle));
    assert_eq!(got.connection.as_ref().unwrap().gateway, conn.gateway);
    assert_eq!(got.base_revision.as_deref(), Some(h.base_sha.as_str()));

    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.expect("attach");
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix add.sh").await.unwrap().stop_reason, "end_turn");
    // snapshot at Idle, environment stays alive.
    let snap1 = h.provider.snapshot(view.id, Some("s1".into())).await.unwrap();
    let _ = snap1;
    wait_snapshots(&h.provider, view.id, 1).await;
    // a second turn modifies a new file; a second snapshot reflects it.
    assert_eq!(client.prompt(&session, "[[fake:touch:extra.txt]] add file").await.unwrap().stop_reason, "end_turn");
    h.provider.snapshot(view.id, Some("s2".into())).await.unwrap();
    let got = wait_snapshots(&h.provider, view.id, 2).await;
    assert!(got.snapshots.last().unwrap().changed_paths >= 2, "{:?}", got.snapshots);

    // finish → final artifact, environment destroyed.
    let done = h.provider.finish(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    let art_id = done.final_artifact_id.expect("final artifact");
    let content = h.provider.artifacts.get_content(art_id).await.unwrap();
    let text = String::from_utf8_lossy(&content);
    assert!(text.contains("add.sh") && text.contains("extra.txt"), "final patch missing files");
    h.done().await;
}

#[tokio::test]
async fn provider_denies_cross_environment_ticket() {
    let Some(h) = H::new().await else { return };
    let a = h.provider.create(h.spec("A")).await.unwrap();
    let b = h.provider.create(h.spec("B")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let cb = h.provider.connect(b.id, Duration::from_secs(60)).await.unwrap();
    // A's ticket cannot open B's gateway.
    let cross = AcpClient::connect(&cb.gateway, &ca.ticket, Transport::Raw).await;
    assert!(matches!(cross, Err(ClientError::Rejected { .. })), "cross-environment ticket accepted");
    // and the matching tickets still work.
    let _ = AcpClient::connect(&ca.gateway, &ca.ticket, Transport::Raw).await.expect("A attaches");
    let _ = AcpClient::connect(&cb.gateway, &cb.ticket, Transport::WebSocket).await.expect("B attaches");
    // the connection view never carries the ticket
    let v = serde_json::to_string(&h.provider.get(a.id).await.unwrap().unwrap()).unwrap();
    assert!(!v.contains(&ca.ticket));
    h.provider.cancel(a.id, "test", Duration::from_secs(60)).await.unwrap();
    h.provider.cancel(b.id, "test", Duration::from_secs(60)).await.unwrap();
    h.done().await;
}

#[tokio::test]
async fn provider_restart_keeps_the_environment_connectable() {
    let Some(h) = H::new().await else { return };
    let view = h.provider.create(h.spec("survivor")).await.unwrap();
    let first = h.provider.connect(view.id, Duration::from_secs(60)).await.unwrap();
    // "restart": a fresh provider instance with the same master key and durable state only.
    let p2 = h.restarted_provider();
    let conn = p2.connect(view.id, Duration::from_secs(10)).await.unwrap();
    assert_ne!(conn.ticket, first.ticket);
    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::WebSocket).await.unwrap();
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");
    // a provider with a different master key refuses to mint (V10b: a clear
    // retired-key error, never a wrong-key ticket the gateway would 401).
    let other = EnvironmentProvider::new(
        h.provider.journal.clone(),
        h.backend.clone(),
        h.provider.creds.clone(),
        h.provider.artifacts.clone(),
        h.ingest.clone(),
        EnvironmentConfig { ticket_keys: acp_runner_engine::environment::TicketKeyRing::ephemeral(), ..h.cfg.clone() },
    );
    let err = other.connect(view.id, Duration::from_secs(10)).await.unwrap_err().to_string();
    assert!(err.contains("retired"), "unexpected error: {err}");
    let done = p2.finish(view.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed);
    h.done().await;
}

#[tokio::test]
async fn shared_key_file_mints_across_provider_instances() {
    // V10b acceptance: a second replica (same Secret file, no shared memory)
    // mints working tickets for an environment the first replica created.
    let Some(h) = H::new().await else { return };
    let key_file = h._tmp.path().join("ticket.key");
    std::fs::write(&key_file, h.cfg.ticket_keys.current().1.bytes()).unwrap();
    let cfg_for = |ring: TicketKeyRing| EnvironmentConfig { ticket_keys: ring, ..h.cfg.clone() };
    let p1 = EnvironmentProvider::new(
        h.provider.journal.clone(),
        h.backend.clone(),
        h.provider.creds.clone(),
        h.provider.artifacts.clone(),
        h.ingest.clone(),
        cfg_for(TicketKeyRing::new(TicketKey::from_file(&key_file).unwrap())),
    );
    let p2 = EnvironmentProvider::new(
        h.provider.journal.clone(),
        h.backend.clone(),
        h.provider.creds.clone(),
        h.provider.artifacts.clone(),
        h.ingest.clone(),
        cfg_for(TicketKeyRing::new(TicketKey::from_file(&key_file).unwrap())),
    );
    let view = p1.create(h.spec("shared")).await.unwrap();
    let conn = p2.connect(view.id, Duration::from_secs(60)).await.unwrap();
    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.expect("attach");
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");
    p2.cancel(view.id, "test", Duration::from_secs(60)).await.unwrap();
    h.done().await;
}

#[tokio::test]
async fn rotation_keeps_old_environments_working_until_they_end() {
    // V10b: ring [new, old] mints for both generations (runnerd verifies with
    // the derived key it already holds); a lone new key refuses the old
    // generation with a clear error instead of a wrong-key ticket.
    use acp_runner_core::ticket;
    let Some(h) = H::new().await else { return };
    let old = TicketKey::from_bytes(vec![7u8; 48]).unwrap();
    let new = TicketKey::from_bytes(vec![9u8; 48]).unwrap();
    let cfg_for = |ring: TicketKeyRing| EnvironmentConfig { ticket_keys: ring, ..h.cfg.clone() };
    let mk = |ring| {
        EnvironmentProvider::new(
            h.provider.journal.clone(),
            h.backend.clone(),
            h.provider.creds.clone(),
            h.provider.artifacts.clone(),
            h.ingest.clone(),
            cfg_for(ring),
        )
    };
    let p_old = mk(TicketKeyRing::new(old.clone()));
    let p_rot = mk(TicketKeyRing::new(new.clone()).with_previous(old.clone()));
    let p_new = mk(TicketKeyRing::new(new.clone()));

    let a = p_old.create(h.spec("gen-old")).await.unwrap();
    let old_id = TicketKeyRing::id_for(&old);
    let new_id = TicketKeyRing::id_for(&new);
    assert_ne!(old_id, new_id);
    let row = h.provider.journal.get_environment(a.id).await.unwrap().unwrap();
    assert_eq!(row.key_version, old_id);

    // rotating provider mints for the old environment and the gateway accepts it.
    let conn = p_rot.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let derived_old = ticket::derive_env_key(old.bytes(), a.id).unwrap();
    ticket::verify(&derived_old, &conn.ticket, a.id, ticket::GATEWAY_AUDIENCE, chrono::Utc::now().timestamp())
        .expect("rotating provider mints with the old key");
    let (mut client, session) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.expect("attach");
    assert_eq!(client.prompt(&session, "[[fake:fix]] fix").await.unwrap().stop_reason, "end_turn");

    // new environments use the new key.
    let b = p_rot.create(h.spec("gen-new")).await.unwrap();
    assert_eq!(h.provider.journal.get_environment(b.id).await.unwrap().unwrap().key_version, new_id);

    // retired key: clear error, never a wrong-key ticket.
    let err = p_new.connect(a.id, Duration::from_secs(10)).await.unwrap_err().to_string();
    assert!(err.contains("retired"), "unexpected error: {err}");
    let conn_b = p_new.connect(b.id, Duration::from_secs(60)).await.unwrap();
    let derived_new = ticket::derive_env_key(new.bytes(), b.id).unwrap();
    ticket::verify(&derived_new, &conn_b.ticket, b.id, ticket::GATEWAY_AUDIENCE, chrono::Utc::now().timestamp())
        .expect("new key mints for the new environment");

    p_rot.cancel(a.id, "test", Duration::from_secs(60)).await.unwrap();
    p_rot.cancel(b.id, "test", Duration::from_secs(60)).await.unwrap();
    h.done().await;
}

#[tokio::test]
async fn compat_wrapper_runs_one_shot_and_produces_the_patch() {
    let Some(h) = H::new().await else { return };
    let req = OneShot {
        external_ref: "oneshot".into(),
        harness: HarnessSpec {
            name: "fake".into(),
            version: None,
            digest: None,
            config: json!({"command": h.fake.to_string_lossy()}),
        },
        repository: RepositoryInput {
            url: h.repo_url.clone(),
            revision: h.base_sha.clone(),
            sparse_paths: vec![],
            depth: None,
        },
        credential_profile: None,
        prompt: "[[fake:fix]] fix add.sh".into(),
    };
    let view = execute(&h.provider, req, Duration::from_secs(60)).await.unwrap();
    assert_eq!(view.phase, EnvironmentPhase::Completed, "{view:?}");
    let content = h.provider.artifacts.get_content(view.final_artifact_id.expect("artifact")).await.unwrap();
    assert!(String::from_utf8_lossy(&content).contains("add.sh"));
    h.done().await;
}

async fn wait_snapshots(
    p: &EnvironmentProvider,
    id: Uuid,
    n: usize,
) -> acp_runner_engine::environment::EnvironmentView {
    let start = std::time::Instant::now();
    loop {
        let v = p.get(id).await.unwrap().unwrap();
        if v.snapshots.len() >= n {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "snapshots {}<{n}", v.snapshots.len());
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// implement → snapshot S1 → review (short branch: overlay S1, reviewer config, no output
/// artifact) → fix (branch of S1) → final artifact cumulative against the original base with
/// lineage S1/A. The orchestrator never handles patch bytes.
#[tokio::test]
async fn implement_review_fix_is_just_branching() {
    let Some(h) = H::new().await else { return };
    h.bundles.insert(
        Bundle::new(
            BundleKind::Config,
            "reviewer-config",
            vec![text_file("CLAUDE.md", "REVIEW RULES: be strict\n")],
            json!({}),
        )
        .unwrap(),
    );
    h.bundles.insert(
        Bundle::new(BundleKind::Skill, "review-rules", vec![text_file("SKILL.md", "# review")], json!({})).unwrap(),
    );
    // implementation environment A
    let a = h.provider.create(h.spec("impl-1")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut client, session) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    client.prompt(&session, "[[fake:fix]] implement").await.unwrap();
    let s1 = h.provider.snapshot_and_wait(a.id, Some("S1".into()), Duration::from_secs(30)).await.unwrap();

    // review = short branch of S1 (A stays alive)
    let review = h
        .provider
        .branch(
            s1,
            EnvironmentOverrides {
                configs: Some(vec!["reviewer-config".into()]),
                skills: Some(vec!["review-rules".into()]),
                lifetime: Some(Lifetime { idle_seconds: Some(300), max_seconds: Some(600) }),
                output: Some(EnvironmentOutput { artifact: OutputArtifact::None }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(review.lineage.parent_artifact_id, Some(s1));
    assert_eq!(review.lineage.parent_environment_id, Some(a.id));
    let cr = h.provider.connect(review.id, Duration::from_secs(60)).await.unwrap();
    let (mut rc, rs) = connect_session(&cr.gateway, &cr.ticket, Transport::WebSocket).await.unwrap();
    let seen = rc.prompt(&rs, "[[fake:read:add.sh]] review the change").await.unwrap();
    assert!(seen.text.contains("$(( $1 + $2 ))"), "reviewer does not see S1: {seen:?}");
    let rules = rc.prompt(&rs, "[[fake:read:CLAUDE.md]]").await.unwrap();
    assert!(rules.text.contains("REVIEW RULES"), "{rules:?}");
    let done = h.provider.finish(review.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed);
    assert!(done.final_artifact_id.is_none(), "review with output none produced an artifact");

    // fix = another branch of S1 (with the same injected config, which must not leak into the patch)
    let fix = h
        .provider
        .branch(s1, EnvironmentOverrides { configs: Some(vec!["reviewer-config".into()]), ..Default::default() })
        .await
        .unwrap();
    let cf = h.provider.connect(fix.id, Duration::from_secs(60)).await.unwrap();
    let (mut fc, fs) = connect_session(&cf.gateway, &cf.ticket, Transport::Raw).await.unwrap();
    fc.prompt(&fs, "[[fake:touch:fix.txt]] address findings").await.unwrap();
    let fixed = h.provider.finish(fix.id, Duration::from_secs(60)).await.unwrap();
    let f1 = fixed.final_artifact_id.expect("fix artifact");
    let meta = h.provider.artifacts.get_meta(f1).await.unwrap();
    // cumulative against the ORIGINAL base, lineage recorded as metadata
    assert_eq!(meta.base_revision, h.base_sha);
    assert_eq!(meta.parent_artifact_id, Some(s1));
    assert_eq!(meta.parent_environment_id, Some(a.id));
    assert_eq!(meta.environment_id, Some(fix.id));
    let patch = String::from_utf8_lossy(&h.provider.artifacts.get_content(f1).await.unwrap()).to_string();
    assert!(patch.contains("add.sh") && patch.contains("fix.txt"), "{patch}");
    assert!(!patch.contains("CLAUDE.md"), "provider-injected config leaked into the artifact");
    // finishing A still yields its own cumulative artifact
    let fa = h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    assert!(fa.final_artifact_id.is_some());
    h.done().await;
}

#[tokio::test]
async fn provider_verifies_overlay_hash_and_base() {
    let Some(h) = H::new().await else { return };
    let a = h.provider.create(h.spec("A")).await.unwrap();
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:fix]] fix").await.unwrap();
    let s1 = h.provider.snapshot_and_wait(a.id, None, Duration::from_secs(30)).await.unwrap();
    h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    // explicit source with another revision than the artifact's base → refused
    let mut spec = h.spec("B");
    if let Some(acp_runner_core::environment::WorkspaceSource::Git(r)) = &mut spec.workspace.source {
        r.revision = "1111111111111111111111111111111111111111".into();
    }
    spec.workspace.overlays = vec![acp_runner_core::environment::WorkspaceOverlay::PatchArtifact { artifact_id: s1 }];
    let e = h.provider.create(spec).await.unwrap_err();
    assert!(e.to_string().contains("is not the overlays' base"), "{e}");
    // tampered stored content → refused (hash verification)
    sqlx::query("UPDATE artifacts SET content = content || '\n'::bytea WHERE id = $1")
        .bind(s1)
        .execute(h.provider.journal.pool())
        .await
        .unwrap();
    let e = h.provider.branch(s1, Default::default()).await.unwrap_err();
    assert!(e.to_string().contains("sha256"), "{e}");
    // unknown artifact
    assert!(h.provider.branch(Uuid::now_v7(), Default::default()).await.is_err());
    h.done().await;
}

#[tokio::test]
async fn workdir_is_the_harness_cwd_through_the_provider() {
    let Some(h) = H::new().await else { return };
    let mut spec = h.spec("wd");
    spec.workspace.workdir = Some("./docs/".into());
    let v = h.provider.create(spec).await.unwrap();
    assert_eq!(v.workdir, "docs");
    let conn = h.provider.connect(v.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.unwrap();
    assert!(c.info.workdir.as_deref().unwrap().ends_with("/docs"), "{:?}", c.info.workdir);
    c.prompt(&s, "[[fake:touch:in-docs.txt]]").await.unwrap();
    let done = h.provider.finish(v.id, Duration::from_secs(60)).await.unwrap();
    let patch = h.provider.artifacts.get_content(done.final_artifact_id.unwrap()).await.unwrap();
    assert!(String::from_utf8_lossy(&patch).contains("b/docs/in-docs.txt"));
    // an escaping workdir never gets past validation
    let mut bad = h.spec("wd-bad");
    bad.workspace.workdir = Some("../etc".into());
    assert!(matches!(
        h.provider.create(bad).await.unwrap_err().downcast_ref::<ProviderError>(),
        Some(ProviderError::InvalidSpec(_))
    ));
    h.done().await;
}

fn fake_id_jwt(account: &str) -> String {
    use base64::Engine as _;
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let claims = json!({"email":"a@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"plus","chatgpt_account_id":account}});
    format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
}

/// V1a scripted provider double (mirrors the e2e harness one).
struct FakeCodexRefresher;

#[async_trait::async_trait]
impl acp_runner_engine::codex_refresh::CodexRefresher for FakeCodexRefresher {
    async fn refresh(
        &self,
        refresh_token: &str,
    ) -> Result<acp_runner_engine::codex_refresh::RefreshedTokens, acp_runner_engine::codex_refresh::RefreshError>
    {
        use acp_runner_engine::codex_refresh::{RefreshError, RefreshedTokens};
        if refresh_token != "rt_test_refresh_token_value_0000000000" {
            return Err(RefreshError::Permanent { reason: "invalid_grant".into() });
        }
        Ok(RefreshedTokens {
            access_token: "access-e2e-rotated".into(),
            id_token: fake_id_jwt("acct-1"),
            refresh_token: Some("rt_test_refresh_token_value_0000000001".into()),
            account_id: "acct-1".into(),
        })
    }
}

fn fake_codex_auth(account: &str) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let jwt = |claims: serde_json::Value| {
        format!("{}.{}.{}", b64(json!({"alg":"none"})), b64(claims), b64(json!("sig-000000000")))
    };
    json!({
        "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
        "tokens": {"id_token": jwt(json!({"email":"a@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"plus","chatgpt_account_id":account}})),
                   "access_token": jwt(json!({"exp": 1900000000})), "refresh_token": "rt_test_refresh_token_value_0000000000", "account_id": account},
        "last_refresh": "2026-09-20T00:00:00Z"
    })
    .to_string()
    .into_bytes()
}

/// Subscription credentials are leased for the environment's lifetime (not per turn),
/// exclusively, renewed by heartbeats, and released only after the validated write-back.
#[tokio::test]
async fn environment_holds_an_exclusive_credential_lease_for_its_lifetime() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-1".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 3,
                metadata: md,
                allowed_namespaces: vec!["environments".into()],
                allowed_classes: vec!["env-codex".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.provider.journal).await.unwrap();
    let codex_spec = |r: &str| {
        let mut s = h.spec(r);
        s.harness = HarnessSpec::named("codex");
        s.credentials.profile = Some("codex-1".into());
        s
    };
    let a = h.provider.create(codex_spec("A")).await.unwrap();
    let leases = h.provider.journal.active_leases().await.unwrap();
    assert_eq!(leases.len(), 1);
    let initial_expiry = leases[0].expires_at;
    // V10c: the lease spans the sandbox's hard deadline (same bound as the
    // pod's activeDeadlineSeconds), not a fixed short window.
    let ttl = (leases[0].expires_at - leases[0].acquired_at).to_std().unwrap();
    assert_eq!(
        ttl,
        acp_runner_core::spec::TimeoutPolicy::default().hard_deadline(),
        "credential lease must equal the sandbox hard deadline"
    );
    // a second environment on the same exclusive profile is refused while A lives
    let e = h.provider.create(codex_spec("B")).await.unwrap_err();
    assert!(matches!(e.downcast_ref::<ProviderError>(), Some(ProviderError::CredentialBusy { .. })), "{e}");
    // the lease outlives turns: two turns, one of them refreshes the token
    let ca = h.provider.connect(a.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&ca.gateway, &ca.ticket, Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:noop]] first turn").await.unwrap();
    c.prompt(&s, "[[fake:refresh-credential]] second turn").await.unwrap();
    assert_eq!(h.provider.journal.active_leases().await.unwrap().len(), 1, "lease must span turns");
    // heartbeats keep extending the lease
    tokio::time::sleep(Duration::from_secs(3)).await;
    let renewed = h.provider.journal.active_leases().await.unwrap()[0].expires_at;
    assert!(renewed >= initial_expiry, "{renewed} < {initial_expiry}");
    let done = h.provider.finish(a.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    // V1a: controller-built write-back happened before the release; the lease is gone
    let (_, stored) = h.creds.load("codex-1").await.unwrap();
    let stored_json: serde_json::Value = serde_json::from_slice(&stored["auth.json"]).unwrap();
    assert_eq!(stored_json["tokens"]["refresh_token"], json!("rt_test_refresh_token_value_0000000001"));
    assert_eq!(stored_json["tokens"]["account_id"], json!("acct-1"));
    assert!(h.provider.journal.active_leases().await.unwrap().is_empty());
    // now the profile is free again
    let b = h.provider.create(codex_spec("B2")).await.unwrap();
    h.provider.cancel(b.id, "test", Duration::from_secs(60)).await.unwrap();
    assert!(h.provider.journal.active_leases().await.unwrap().is_empty());
    // credential values never reach the journal
    let all = sqlx::query_scalar::<_, String>("SELECT data::text FROM session_events")
        .fetch_all(h.provider.journal.pool())
        .await
        .unwrap()
        .join("\n");
    assert!(!all.contains("rt_test_refresh_token_value"));
    h.done().await;
}

/// Publish `fake-acp-agent` as harness `fake@<version>` (tar.gz + manifest with the pin).
fn publish_fake_harness(h: &H, version: &str) -> (PathBuf, String) {
    use sha2::Digest;
    let bin = std::fs::read(&h.fake).unwrap();
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let mut hd = tar::Header::new_gnu();
    hd.set_size(bin.len() as u64);
    hd.set_mode(0o755);
    hd.set_entry_type(tar::EntryType::Regular);
    hd.set_cksum();
    b.append_data(&mut hd, "bin/fake-acp-agent", bin.as_slice()).unwrap();
    let bytes = b.into_inner().unwrap().finish().unwrap();
    let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&bytes)));
    let dir = h.harness_root.join("fake").join(version);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("harness.tar.gz"), &bytes).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        json!({"digest": digest, "archive": "harness.tar.gz", "executable": "bin/fake-acp-agent", "adapter": "fake",
               "driverConfig": {"command": "{harness}/bin/fake-acp-agent"}, "path": ["bin"]})
        .to_string(),
    )
    .unwrap();
    (dir.join("harness.tar.gz"), digest)
}

/// One runtime image; the harness is a pinned, digest-verified artifact materialized at
/// bootstrap (resolve(name, version) → digest, executable, adapter, manifest).
#[tokio::test]
async fn harness_provider_materializes_pinned_artifacts() {
    let Some(h) = H::new().await else { return };
    let (archive, digest) = publish_fake_harness(&h, "1.0.0");
    let harness = |version: &str, digest: Option<String>| HarnessSpec {
        name: "fake".into(),
        version: Some(version.into()),
        digest,
        config: json!({}),
    };
    let mut spec = h.spec("harness-1");
    spec.harness = harness("1.0.0", Some(digest.clone()));
    let v = h.provider.create(spec).await.unwrap();
    let conn = h.provider.connect(v.id, Duration::from_secs(60)).await.unwrap();
    let (mut c, s) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.unwrap();
    assert_eq!(c.prompt(&s, "[[fake:fix]]").await.unwrap().stop_reason, "end_turn");
    let done = h.provider.finish(v.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    let evs = sqlx::query_scalar::<_, String>(
        "SELECT data::text FROM session_events WHERE data->>'category' = 'harness_materialized'",
    )
    .fetch_all(h.provider.journal.pool())
    .await
    .unwrap();
    assert_eq!(evs.len(), 1);
    assert!(evs[0].contains(&digest));
    // a different pin, an unknown version, and a tampered archive are all refused
    let mut spec = h.spec("harness-2");
    spec.harness = harness("1.0.0", Some(format!("sha256:{}", "0".repeat(64))));
    assert!(h.provider.create(spec).await.unwrap_err().to_string().contains("pins"));
    let mut spec = h.spec("harness-3");
    spec.harness = harness("9.9.9", None);
    assert!(h.provider.create(spec).await.is_err());
    std::fs::write(&archive, b"tampered").unwrap();
    let mut spec = h.spec("harness-4");
    spec.harness = harness("1.0.0", None);
    let e = h.provider.create(spec).await.unwrap_err().to_string();
    assert!(e.contains("does not match the pinned"), "{e}");
    h.done().await;
}

fn bootstrap_step(script: &str) -> acp_runner_core::environment::BootstrapExec {
    acp_runner_core::environment::BootstrapExec {
        command: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: None,
        env: Default::default(),
        timeout_seconds: Some(60),
    }
}

/// A process whose argv contains `marker` (excluding this test process itself).
fn proc_with_marker(marker: &str) -> bool {
    let me = std::process::id().to_string();
    let Ok(rd) = std::fs::read_dir("/proc") else { return false };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.chars().all(|c| c.is_ascii_digit()) || name == me {
            continue;
        }
        let cmd = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
        let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
        if cmd.split_whitespace().any(|a| a == marker) {
            return true;
        }
    }
    false
}

/// V4: bootstrap steps run before the credential copies land in the HOME — a
/// step looking for them finds nothing, while the harness (after Proceed)
/// still gets the leased profile.
#[tokio::test]
async fn bootstrap_cannot_see_credentials_placed_after_it() {
    let Some(h) = H::new().await else { return };
    let mut bundle = CredentialBundle::new();
    bundle.insert("auth.json".into(), fake_codex_auth("acct-1"));
    let md = validate_bundle(Provider::Codex, &bundle).unwrap();
    h.creds
        .save(
            &StoredProfile {
                name: "codex-1".into(),
                provider: Provider::Codex,
                max_concurrent_leases: 3,
                metadata: md,
                allowed_namespaces: vec!["environments".into()],
                allowed_classes: vec!["env-codex".into()],
                store_ref: String::new(),
            },
            &bundle,
        )
        .await
        .unwrap();
    sync_profiles(h.creds.as_ref(), &h.provider.journal).await.unwrap();
    let mut s = h.spec("boot-creds");
    s.harness = HarnessSpec::named("codex");
    s.credentials.profile = Some("codex-1".into());
    s.bootstrap.exec = vec![bootstrap_step(
        "test ! -e \"$HOME/.codex/auth.json\" && test ! -e \"$HOME/.acp-credentials/oauth-token\"",
    )];
    let v = h.provider.create(s).await.unwrap();
    // the lease is held from the start even though the bootstrap sees no files
    assert_eq!(h.provider.journal.active_leases().await.unwrap().len(), 1);
    let conn = h.provider.connect(v.id, Duration::from_secs(120)).await.unwrap();
    let (mut c, sess) = connect_session(&conn.gateway, &conn.ticket, Transport::Raw).await.unwrap();
    c.prompt(&sess, "[[fake:noop]] turn after bootstrap").await.unwrap();
    let done = h.provider.finish(v.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(done.phase, EnvironmentPhase::Completed, "{done:?}");
    assert!(h.provider.journal.active_leases().await.unwrap().is_empty());
    h.done().await;
}

/// V4: a bootstrap step that backgrounds work fails the environment with
/// BootstrapFailed, and the stray process is killed — it never survives to
/// see the credentials land.
#[tokio::test]
async fn bootstrap_background_process_fails_and_is_reaped() {
    let Some(h) = H::new().await else { return };
    assert!(!proc_with_marker("46137"), "stale marker sleep running");
    let mut s = h.spec("boot-bg");
    s.bootstrap.exec = vec![bootstrap_step("sleep 46137 &")];
    let v = h.provider.create(s).await.unwrap();
    // the harness never reaches Ready: the environment must fail
    let mut failed = None;
    for _ in 0..240 {
        let got = h.provider.get(v.id).await.unwrap().unwrap();
        if matches!(got.phase, EnvironmentPhase::Failed) {
            failed = Some(got);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let got = failed.expect("environment never failed after backgrounding bootstrap");
    match &got.failure {
        Some(FailureReason::BootstrapFailed { step, detail }) => {
            assert!(step.starts_with("exec[0]"), "{got:?}");
            assert!(detail.contains("left background processes"), "{got:?}");
        }
        other => panic!("expected BootstrapFailed, got {other:?}"),
    }
    // the stray sleep was killed by agentd's sweep, not left lingering
    for _ in 0..20 {
        if !proc_with_marker("46137") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(!proc_with_marker("46137"), "background sleep survived the sweep");
    assert!(h.provider.connect(v.id, Duration::from_secs(5)).await.is_err());
    h.done().await;
}
