//! v3 bootstrap through the real runnerd/agentd runtime (deterministic fake harness):
//!
//! * trusted placement of verified bundles (workspace + HOME), `artifactPolicy: exclude`,
//! * `workspace.workdir` as the harness cwd (probe, bootstrap exec, session, tools),
//! * untrusted `bootstrap.exec` = execve in agentd (never runnerd), without credentials,
//!   its workspace side effects kept out of the artifact,
//! * overlays: sha256 + base verification, cumulative artifacts,
//! * refusals: tampered bundle, tampered overlay, wrong base, bad workdir, failing exec,
//! * inference-only environments on the deterministic empty base.

mod common;

use acp_runner_client::{Transport, connect_session};
use acp_runner_core::attempt_spec::{BundleMount, OverlayRef};
use acp_runner_core::bundle::{Bundle, BundleFile, BundleKind, text_file};
use acp_runner_core::environment::{BootstrapExec, EnvironmentPhase};
use acp_runner_core::events::RunnerDirective;
use acp_runner_core::failure::FailureReason;
use acp_runner_core::harness::PlacementRoot;
use common::env_mode::*;
use common::*;
use runnerd::sink::MemorySink;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

fn bundle(kind: BundleKind, name: &str, files: Vec<BundleFile>) -> Bundle {
    Bundle::new(kind, name, files, serde_json::json!({"source": "test"})).unwrap()
}

fn serve_bundle(sink: &MemorySink, b: &Bundle) {
    sink.bundles.lock().unwrap().insert(b.digest.clone(), b.clone());
}

fn mount(b: &Bundle, root: PlacementRoot, dir: &str, file: Option<&str>) -> BundleMount {
    BundleMount {
        digest: b.digest.clone(),
        kind: b.kind,
        name: b.name.clone(),
        root,
        dir: dir.into(),
        file: file.map(str::to_string),
        exclude_from_artifact: true,
    }
}

fn exec(command: &str, args: &[&str], cwd: Option<&str>) -> BootstrapExec {
    BootstrapExec {
        command: command.into(),
        args: args.iter().map(|a| a.to_string()).collect(),
        cwd: cwd.map(str::to_string),
        env: BTreeMap::from([("SETUP_FLAVOR".to_string(), "coding".to_string())]),
        timeout_seconds: Some(60),
    }
}

fn reason(res: &runnerd::EnvironmentResult) -> String {
    serde_json::to_string(&res.reason).unwrap()
}

#[tokio::test]
async fn workdir_bundles_and_untrusted_exec() {
    let mut env = TestEnv::new(&Target::fake_acp()).await;
    // a credential the harness receives by env var — bootstrap commands must not.
    env.add_env_credential("claude", "oauth-token", "CLAUDE_CODE_OAUTH_TOKEN", FAKE_CLAUDE_TOKEN.as_bytes());
    let sink = MemorySink::default();
    let cfg = bundle(BundleKind::Config, "reviewer-config", vec![text_file("CLAUDE.md", "REVIEW RULES v1\n")]);
    let skill = bundle(
        BundleKind::Skill,
        "rust",
        vec![
            text_file("SKILL.md", "# rust"),
            BundleFile { path: "bin/check".into(), mode: 0o755, content: b"#!/bin/sh\n".to_vec() },
        ],
    );
    serve_bundle(&sink, &cfg);
    serve_bundle(&sink, &skill);
    let r = Running::start_with_sink(
        &env,
        |s| {
            s.bootstrap.workdir = "docs".into();
            s.bootstrap.bundles = vec![
                mount(&cfg, PlacementRoot::Workspace, "", Some("docs/CLAUDE.md")),
                mount(&skill, PlacementRoot::Home, ".acp/skills/rust", None),
            ];
            s.bootstrap.exec = vec![
                // default cwd = workdir
                exec("touch", &["exec-marker.txt"], None),
                // who ran me, and with which environment? (/bin/sh is the user's explicit
                // choice here; the bootstrap itself is plain execve)
                exec("/bin/sh", &["-c", "cat /proc/$PPID/comm > parent.txt; env > env.txt"], Some("")),
            ];
        },
        sink,
    )
    .await;
    // the harness runs in the workdir: the gateway announces it, the session uses it
    let (mut client, session) = connect_session(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    assert!(client.info.workdir.as_deref().unwrap().ends_with("/workspace/docs"), "{:?}", client.info.workdir);
    let t = client.prompt(&session, "[[fake:read:CLAUDE.md]] what are the rules?").await.unwrap();
    assert!(t.text.contains("REVIEW RULES v1"), "{t:?}");
    let t = client.prompt(&session, "[[fake:read:exec-marker.txt]]").await.unwrap();
    assert!(!t.text.contains("MISSING"), "bootstrap exec did not run in the workdir: {t:?}");
    client.prompt(&session, "[[fake:touch:agent.txt]] work").await.unwrap();
    r.directive(RunnerDirective::Snapshot { snapshot_id: Some(Uuid::now_v7()), label: None });
    wait_event_n(&r.sink, "snapshot_created", 1).await;
    // runtime configuration and setup output are not work: only the agent's file counts
    let snap: Vec<String> = latest_snapshot(&r.sink).unwrap().iter().map(|c| c.path.clone()).collect();
    assert_eq!(snap, vec!["docs/agent.txt".to_string()]);
    let dirs = r.dirs.clone();
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed, "{res:?}");
    let rec = sink.snapshot();
    let fin = rec.artifacts.iter().find(|a| a.kind == "final").unwrap();
    assert_eq!(fin.changed_paths.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(), vec!["docs/agent.txt"]);
    // placement: skill in HOME (exec bit kept), config in the workdir
    assert_eq!(std::fs::read_to_string(dirs.home.join(".acp/skills/rust/SKILL.md")).unwrap(), "# rust");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dirs.home.join(".acp/skills/rust/bin/check")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    // bootstrap exec ran under agentd (the untrusted executor), not runnerd, and without the
    // credential; its own env was passed.
    assert_eq!(std::fs::read_to_string(dirs.workspace.join("parent.txt")).unwrap().trim(), "agentd");
    let envtxt = std::fs::read_to_string(dirs.workspace.join("env.txt")).unwrap();
    assert!(!envtxt.contains("CLAUDE_CODE_OAUTH_TOKEN") && !envtxt.contains(FAKE_CLAUDE_TOKEN));
    assert!(envtxt.contains("SETUP_FLAVOR=coding"));
    assert!(!envtxt.contains("ACP_RUNNER_"));
    // journal: bundles placed + each exec step reported (source = agent)
    assert!(progress(&rec, "bundles_placed") && progress(&rec, "bootstrap_exec_done"));
    let steps =
        rec.events.iter().filter(|e| e.data.get("category").and_then(|c| c.as_str()) == Some("bootstrap_exec")).count();
    assert_eq!(steps, 2);
    assert!(!all_text(&rec).contains(FAKE_CLAUDE_TOKEN));
}

/// Collect a snapshot/final of a first environment, then start a second environment from it.
#[tokio::test]
async fn overlays_are_verified_and_artifacts_stay_cumulative() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    // A: fix add.sh
    let a = Running::start(&env, |_| {}).await;
    let (mut c, s) = connect_session(&a.gateway, &a.ticket(), Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:fix]] fix").await.unwrap();
    let (res_a, sink_a) = a.finish().await;
    assert_eq!(res_a.phase, EnvironmentPhase::Completed);
    let s1 = sink_a.snapshot().artifacts.into_iter().find(|x| x.kind == "final").unwrap();
    let s1_bytes = s1.patch_bytes().unwrap();
    let s1_id = Uuid::now_v7();
    let overlay = OverlayRef {
        artifact_id: s1_id,
        sha256: hex::encode(Sha256::digest(&s1_bytes)),
        base_revision: s1.base_revision.clone(),
        size_bytes: s1_bytes.len() as u64,
    };
    // B: base + S1, then a new file
    let sink = MemorySink::default();
    sink.overlays.lock().unwrap().insert(s1_id, s1_bytes.clone());
    let ov = overlay.clone();
    let b = Running::start_with_sink(&env, move |sp| sp.bootstrap.overlays = vec![ov], sink).await;
    let (mut c, s) = connect_session(&b.gateway, &b.ticket(), Transport::WebSocket).await.unwrap();
    let t = c.prompt(&s, "[[fake:read:add.sh]]").await.unwrap();
    assert!(t.text.contains("$(( $1 + $2 ))"), "overlay not applied: {t:?}");
    c.prompt(&s, "[[fake:touch:b.txt]]").await.unwrap();
    let (res_b, sink_b) = b.finish().await;
    assert_eq!(res_b.phase, EnvironmentPhase::Completed, "{res_b:?}");
    let b1 = sink_b.snapshot().artifacts.into_iter().find(|x| x.kind == "final").unwrap();
    // B1 = diff(base, state B), not diff(S1, B)
    assert_eq!(b1.base_revision, env.base_sha);
    let paths: Vec<&str> = b1.changed_paths.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, vec!["add.sh", "b.txt"]);
    env.assert_patch_applies_and_fixes(&b1.patch_bytes().unwrap()).await;
    assert!(progress(&sink_b.snapshot(), "overlay_applied"));

    // tampered overlay content → refused before the harness starts
    let sink = MemorySink::default();
    let mut evil = s1_bytes.clone();
    evil.extend_from_slice(b"\n");
    sink.overlays.lock().unwrap().insert(s1_id, evil);
    let ov = overlay.clone();
    let (res, _) = Running::launch(&env, move |sp| sp.bootstrap.overlays = vec![ov], sink).result().await;
    assert_eq!(res.phase, EnvironmentPhase::Failed);
    assert!(reason(&res).contains("sha256 mismatch"), "{res:?}");
    // overlay relative to another base → refused
    let sink = MemorySink::default();
    sink.overlays.lock().unwrap().insert(s1_id, s1_bytes.clone());
    let mut ov = overlay.clone();
    ov.base_revision = "1111111111111111111111111111111111111111".into();
    let (res, _) = Running::launch(&env, move |sp| sp.bootstrap.overlays = vec![ov], sink).result().await;
    assert!(matches!(res.reason, Some(FailureReason::BootstrapFailed { .. })), "{res:?}");
    assert!(reason(&res).contains("does not match the checked-out base"), "{res:?}");
}

#[tokio::test]
async fn tampered_bundles_bad_workdirs_and_failing_exec_are_refused() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    // bundle content does not match its digest
    let good = bundle(BundleKind::Config, "cfg", vec![text_file("AGENTS.md", "rules")]);
    let mut served = good.clone();
    served.files[0].content = b"evil rules".to_vec();
    let sink = MemorySink::default();
    sink.bundles.lock().unwrap().insert(good.digest.clone(), served);
    let m = mount(&good, PlacementRoot::Workspace, "", None);
    let (res, _) = Running::launch(&env, move |s| s.bootstrap.bundles = vec![m], sink).result().await;
    assert!(reason(&res).contains("digest mismatch"), "{res:?}");
    // a bundle target outside its root is refused
    let sink = MemorySink::default();
    serve_bundle(&sink, &good);
    let m = mount(&good, PlacementRoot::Home, ".", Some("../escape.md"));
    let (res, _) = Running::launch(&env, move |s| s.bootstrap.bundles = vec![m], sink).result().await;
    assert_eq!(res.phase, EnvironmentPhase::Failed, "{res:?}");
    // workdir must be a real directory inside the workspace
    for bad in ["missing", "../outside", "add.sh"] {
        let (res, _) =
            Running::launch(&env, |s| s.bootstrap.workdir = bad.into(), MemorySink::default()).result().await;
        assert!(reason(&res).contains("workdir"), "{bad}: {res:?}");
    }
    // a failing bootstrap command fails the environment with BootstrapFailed
    let (res, sink) =
        Running::launch(&env, |s| s.bootstrap.exec = vec![exec("false", &[], None)], MemorySink::default())
            .result()
            .await;
    assert!(
        matches!(&res.reason, Some(FailureReason::BootstrapFailed { step, .. }) if step.contains("exec[0]")),
        "{res:?}"
    );
    assert!(!progress(&sink.snapshot(), "gateway_listening"));
    // a command that does not exist, too (no shell fallback)
    let (res, _) = Running::launch(
        &env,
        |s| s.bootstrap.exec = vec![exec("definitely-not-a-command", &["x; rm -rf /"], None)],
        MemorySink::default(),
    )
    .result()
    .await;
    assert!(matches!(res.reason, Some(FailureReason::BootstrapFailed { .. })), "{res:?}");
}

#[tokio::test]
async fn inference_only_environment_uses_the_deterministic_empty_base() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let r = Running::start(&env, |s| {
        s.bootstrap.empty_source = true;
        s.repository.url = "empty:".into();
    })
    .await;
    let (mut c, s) = connect_session(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:touch:answer.md]]").await.unwrap();
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed, "{res:?}");
    let fin = sink.snapshot().artifacts.into_iter().find(|a| a.kind == "final").unwrap();
    assert_eq!(fin.changed_paths.len(), 1);
    // the same empty base everywhere → branchable
    let tmp = tempfile::tempdir().unwrap();
    let ws = acp_runner_workspace::prepare_empty(&tmp.path().join("w"), &tmp.path().join("s")).await.unwrap();
    assert_eq!(ws.base_sha, fin.base_revision);
    ws.apply_patch(&fin.patch_bytes().unwrap()).await.unwrap();
    assert!(ws.dir.join("answer.md").exists());
}

#[tokio::test]
async fn output_policy_none_produces_no_final_artifact() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let r = Running::start(&env, |s| s.bootstrap.produce_artifact = false).await;
    let (mut c, s) = connect_session(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    c.prompt(&s, "[[fake:fix]] review and fix").await.unwrap();
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed);
    assert!(res.final_artifact_id.is_none());
    assert!(sink.snapshot().artifacts.iter().all(|a| a.kind != "final"));
}

/// A tar.gz whose only executable is a copy of the fake ACP agent.
fn harness_archive(dir: &std::path::Path) -> (std::path::PathBuf, String, u64) {
    let bin = std::fs::read(fake_agent_bin()).unwrap();
    let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
    let mut h = tar::Header::new_gnu();
    h.set_size(bin.len() as u64);
    h.set_mode(0o755);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    b.append_data(&mut h, "bin/acp-agent", bin.as_slice()).unwrap();
    let bytes = b.into_inner().unwrap().finish().unwrap();
    let p = dir.join("harness.tar.gz");
    std::fs::write(&p, &bytes).unwrap();
    (p, format!("sha256:{}", hex::encode(Sha256::digest(&bytes))), bytes.len() as u64)
}

#[tokio::test]
async fn pinned_harness_artifact_is_verified_and_materialized() {
    let env = TestEnv::new(&Target::fake_acp()).await;
    let (archive, digest, size) = harness_archive(env.tmp.path());
    let href = acp_runner_core::harness::HarnessArtifactRef {
        name: "fake".into(),
        version: "1.0.0".into(),
        digest: digest.clone(),
        size_bytes: size,
        executable: "bin/acp-agent".into(),
        adapter: "fake".into(),
        driver_config: serde_json::json!({"command": "{harness}/bin/acp-agent"}),
        path: vec!["bin".into()],
        manifest: serde_json::Value::Null,
    };
    let sink = MemorySink::default();
    sink.harnesses.lock().unwrap().insert(digest.clone(), archive.clone());
    let h = href.clone();
    let r = Running::start_with_sink(
        &env,
        move |s| {
            s.bootstrap.harness = Some(h);
            // nothing in the environment names a binary: it comes from the artifact
            s.driver.config = serde_json::json!({});
        },
        sink,
    )
    .await;
    let (mut c, s) = connect_session(&r.gateway, &r.ticket(), Transport::Raw).await.unwrap();
    assert_eq!(c.init.as_ref().unwrap().agent_info.name.as_deref(), Some("fake-acp-agent"));
    assert_eq!(c.prompt(&s, "[[fake:fix]]").await.unwrap().stop_reason, "end_turn");
    let dirs = r.dirs.clone();
    let (res, sink) = r.finish().await;
    assert_eq!(res.phase, EnvironmentPhase::Completed, "{res:?}");
    assert!(progress(&sink.snapshot(), "harness_materialized"));
    let started = sink
        .snapshot()
        .events
        .iter()
        .find(|e| e.kind == acp_runner_core::EventKind::AgentStarted)
        .map(|e| e.data.to_string())
        .unwrap();
    assert!(started.contains("acp-agent"), "{started}");
    assert!(dirs.harness.join("bin/acp-agent").is_file());
    // same pin, different bytes → refused before anything runs
    let other = env.tmp.path().join("other.tar.gz");
    std::fs::write(&other, b"not the pinned archive").unwrap();
    let sink = MemorySink::default();
    sink.harnesses.lock().unwrap().insert(digest.clone(), other);
    let (res, _) = Running::launch(&env, move |s| s.bootstrap.harness = Some(href), sink).result().await;
    assert!(matches!(&res.reason, Some(FailureReason::BootstrapFailed { step, .. }) if step == "harness"), "{res:?}");
}
