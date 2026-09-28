//! OpenAI Responses shim → ACP gateway → a real environment (LocalProcessBackend, fake
//! harness). Requires `ACP_TEST_DATABASE_URL`; skipped otherwise.

use acp_openai_shim::{ConnectionSource, ShimState, router};
use acp_runner_client::Transport;
use acp_runner_core::environment::{EnvironmentPhase, EnvironmentSpec, HarnessSpec};
use acp_runner_core::spec::RepositoryInput;
use acp_runner_engine::backend::LocalProcessBackend;
use acp_runner_engine::creds::FileCredentialStore;
use acp_runner_engine::environment::{EnvironmentConfig, EnvironmentProvider};
use acp_runner_engine::ingest::{IngestState, router as ingest_router};
use acp_runner_engine::metrics::Metrics;
use acp_runner_journal::{ArtifactStore, PgArtifactStore};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn target_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_path_buf()
}

struct ProviderSource(Arc<EnvironmentProvider>);

#[async_trait::async_trait]
impl ConnectionSource for ProviderSource {
    async fn connect(&self, model: &str) -> anyhow::Result<(String, String)> {
        let c = self.0.connect(model.parse()?, Duration::from_secs(60)).await?;
        Ok((c.gateway, c.ticket))
    }
}

fn fixture(dir: &std::path::Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("add.sh"), "#!/bin/sh\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n").unwrap();
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

/// Parse an SSE body into (event, data) pairs.
fn sse_events(body: &str) -> Vec<(String, Value)> {
    body.split("\n\n")
        .filter_map(|block| {
            let ev = block.lines().find_map(|l| l.strip_prefix("event:"))?.trim().to_string();
            let data = block.lines().find_map(|l| l.strip_prefix("data:"))?.trim();
            Some((ev, serde_json::from_str(data).ok()?))
        })
        .collect()
}

#[tokio::test]
async fn openai_responses_over_acp() {
    // Exactly one rustls provider before Client::new (reqwest is no-provider;
    // this graph has no kube-supplied ring).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let Some(db) = acp_runner_journal::testing::temp_database().await else { return };
    assert!(
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["build", "-q", "-p", "runnerd", "-p", "agentd", "-p", "fake-acp-agent"])
            .status()
            .unwrap()
            .success()
    );
    let tmp = tempfile::tempdir().unwrap();
    let base = fixture(&tmp.path().join("upstream"));
    let journal = db.journal.clone();
    let artifacts: Arc<dyn ArtifactStore> = Arc::new(PgArtifactStore::new(journal.clone(), 8 << 20, None));
    let creds = Arc::new(FileCredentialStore { root: tmp.path().join("creds") });
    let ingest =
        Arc::new(IngestState::new(journal.clone(), artifacts.clone(), creds.clone(), Arc::new(Metrics::new()), None));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingest_addr = l.local_addr().unwrap();
    {
        let ingest = ingest.clone();
        tokio::spawn(async move { axum::serve(l, ingest_router(ingest)).await.unwrap() });
    }
    let backend = Arc::new(LocalProcessBackend::new(
        target_dir().join("runnerd"),
        tmp.path().join("sandboxes"),
        std::env::var("PATH").unwrap_or_default(),
    ));
    let provider = Arc::new(EnvironmentProvider::new(
        journal,
        backend,
        creds,
        artifacts,
        ingest,
        EnvironmentConfig {
            ingest_url: format!("http://{ingest_addr}"),
            require_egress_proxy_for_credentials: false,
            ..Default::default()
        },
    ));
    let env = provider
        .create(EnvironmentSpec::new(
            "shim",
            HarnessSpec {
                name: "fake".into(),
                version: None,
                digest: None,
                config: json!({"command": target_dir().join("fake-acp-agent")}),
            },
            Some(RepositoryInput {
                url: format!("file://{}", tmp.path().join("upstream").display()),
                revision: base,
                sparse_paths: vec![],
                depth: None,
            }),
        ))
        .await
        .unwrap();
    // the shim: a separate ACP client, holding no provider key
    let shim = ShimState::new(Arc::new(ProviderSource(provider.clone())), Transport::WebSocket);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, router(shim)).await.unwrap() });
    let http = reqwest::Client::new();
    let model = env.id.to_string();

    // 1. plain request → completed response with the agent's text
    let r: Value = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": [{"role": "user", "content": [{"type": "input_text", "text": "[[fake:fix]] fix add.sh"}]}]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["object"], "response");
    let text = r["output"][0]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("Fixed add.sh"), "{r}");
    assert_eq!(r["metadata"]["acp_stop_reason"], "end_turn");
    let session = r["metadata"]["acp_session_id"].clone();

    // 2. streamed continuation of the same conversation (same ACP session)
    let body = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": "[[fake:touch:second.txt]] more", "stream": true,
                      "previous_response_id": r["id"]}))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let evs = sse_events(&body);
    let kinds: Vec<&str> = evs.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(kinds.first(), Some(&"response.created"), "{kinds:?}");
    assert!(kinds.contains(&"response.output_text.delta"), "{kinds:?}");
    assert_eq!(kinds.last(), Some(&"response.completed"), "{kinds:?}");
    let done = &evs.last().unwrap().1["response"];
    assert_eq!(done["metadata"]["acp_session_id"], session, "continuation used another ACP session");
    assert_eq!(done["previous_response_id"], r["id"]);
    let seqs: Vec<u64> = evs.iter().map(|(_, v)| v["sequence_number"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));

    // 3. client function tools are refused (v1), unknown continuation is 404
    let res = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": "x", "tools": [{"type": "function", "name": "f", "parameters": {}}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(res.json::<Value>().await.unwrap()["error"]["code"], "unsupported_tools");
    let res = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": "x", "previous_response_id": "resp_nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // 4. cancel an in-flight streamed response → ACP session/cancel → response.cancelled
    let mut res = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": "[[fake:hang]] wait", "stream": true}))
        .send()
        .await
        .unwrap();
    let mut body = String::new();
    let id = loop {
        let chunk =
            tokio::time::timeout(Duration::from_secs(30), res.chunk()).await.unwrap().unwrap().expect("stream ended");
        body.push_str(&String::from_utf8_lossy(&chunk));
        if let Some((_, v)) = sse_events(&body).into_iter().find(|(k, _)| k == "response.in_progress") {
            break v["response"]["id"].as_str().unwrap().to_string();
        }
    };
    let running: Value = http.get(format!("{url}/v1/responses/{id}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(running["status"], "in_progress");
    let c: Value = http.post(format!("{url}/v1/responses/{id}/cancel")).send().await.unwrap().json().await.unwrap();
    assert_eq!(c["status"], "cancelling");
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(30), res.chunk()).await.unwrap().unwrap() {
        body.push_str(&String::from_utf8_lossy(&chunk));
    }
    let evs = sse_events(&body);
    assert_eq!(evs.last().map(|(k, _)| k.as_str()), Some("response.cancelled"), "{body}");
    let stored: Value = http.get(format!("{url}/v1/responses/{id}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(stored["status"], "cancelled");
    // the environment is still alive and usable after a cancelled turn
    let r: Value = http
        .post(format!("{url}/v1/responses"))
        .json(&json!({"model": model, "input": "[[fake:noop]] ok?"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["status"], "completed", "{r}");

    let fin = provider.finish(env.id, Duration::from_secs(60)).await.unwrap();
    assert_eq!(fin.phase, EnvironmentPhase::Completed);
    let patch = provider.artifacts.get_content(fin.final_artifact_id.unwrap()).await.unwrap();
    let patch = String::from_utf8_lossy(&patch);
    assert!(patch.contains("add.sh") && patch.contains("second.txt"));
    db.drop_db().await;
}
