//! Where runnerd sends events, heartbeats, artifacts and credential write-backs.
//!
//! * [`IngestSink`] — the controller's ingest API (in-cluster HTTP, per-attempt bearer token).
//! * [`FileSink`] — local directory (`runnerd local`, compatibility suite).
//! * [`MemorySink`] — tests.

use acp_runner_core::bundle::Bundle;
use acp_runner_core::events::{ChangedPath, EventEnvelope, HeartbeatData, HeartbeatReply, RunnerDirective};
use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("ingest rejected request ({status}): {body}")]
    Rejected { status: u16, body: String },
    #[error("ingest unreachable: {0}")]
    Unreachable(String),
    #[error("i/o: {0}")]
    Io(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactUpload {
    /// `patch` or `partial_patch`.
    pub kind: String,
    pub base_revision: String,
    pub sha256: String,
    pub changed_paths: Vec<ChangedPath>,
    pub driver: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    pub patch_b64: String,
}

impl ArtifactUpload {
    pub fn patch_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.patch_b64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactAccepted {
    pub artifact_id: Uuid,
    pub storage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CredentialWriteback {
    pub key: String,
    pub content_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventBatch {
    pub events: Vec<EventEnvelope>,
}

#[async_trait]
pub trait EventSink: Send {
    /// Buffer an event (sequence numbers are assigned by the sink).
    async fn emit(&mut self, ev: EventEnvelope);
    /// Liveness report; the controller may answer with a directive (e.g. cancel the agent).
    async fn heartbeat(&mut self, hb: &HeartbeatData) -> Result<Option<RunnerDirective>, SinkError>;
    /// Durable-queue row id of the directive returned by the last `heartbeat`
    /// call (V5a explicit acks). `None` when the last reply carried no id
    /// (test sinks, older ingests, or no directive).
    fn take_directive_id(&mut self) -> Option<Uuid> {
        None
    }
    /// Credential lease expiry (unix seconds) from the last `heartbeat` reply
    /// (V10c). `None` when the attempt holds no lease or the ingest is older.
    fn last_lease_expires_at(&self) -> Option<i64> {
        None
    }
    async fn upload_artifact(&mut self, art: &ArtifactUpload) -> Result<ArtifactAccepted, SinkError>;
    async fn writeback(&mut self, key: &str, bytes: &[u8]) -> Result<(), SinkError>;
    async fn flush(&mut self) -> Result<(), SinkError>;
    /// Environment bootstrap: bytes of an overlay patch artifact listed in the attempt spec
    /// (the caller verifies the sha256).
    async fn fetch_overlay(&mut self, artifact_id: Uuid) -> Result<Vec<u8>, SinkError> {
        Err(SinkError::Io(format!("this sink cannot fetch overlay {artifact_id}")))
    }
    /// Environment bootstrap: a bundle listed in the attempt spec (the caller verifies it).
    async fn fetch_bundle(&mut self, digest: &str) -> Result<Bundle, SinkError> {
        Err(SinkError::Io(format!("this sink cannot fetch bundle {digest}")))
    }
    /// Environment bootstrap: download the harness artifact pinned in the attempt spec to
    /// `dest` (the caller verifies the digest).
    async fn fetch_harness(&mut self, digest: &str, dest: &std::path::Path) -> Result<u64, SinkError> {
        let _ = dest;
        Err(SinkError::Io(format!("this sink cannot fetch harness {digest}")))
    }
}

// ---------------------------------------------------------------------------------------

pub struct IngestSink {
    client: reqwest::Client,
    base: String,
    token: String,
    seq: u64,
    buffer: Vec<EventEnvelope>,
    last_flush: Instant,
    last_directive_id: Option<Uuid>,
    last_lease_expires_at: Option<i64>,
}

pub const WIRE_HEADER: &str = "x-acp-runner-wire-version";

impl IngestSink {
    pub fn new(base_url: &str, token: String) -> Result<IngestSink, SinkError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(|e| SinkError::Unreachable(e.to_string()))?;
        Ok(IngestSink {
            client,
            base: base_url.trim_end_matches('/').to_string(),
            token,
            seq: 0,
            buffer: vec![],
            last_flush: Instant::now(),
            last_directive_id: None,
            last_lease_expires_at: None,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Fetch the attempt spec.
    pub async fn fetch_spec(&self) -> Result<acp_runner_core::AttemptSpec, SinkError> {
        let mut delay = Duration::from_millis(250);
        for attempt in 0..8 {
            match self
                .client
                .get(self.url("/v1/attempt"))
                .bearer_auth(&self.token)
                .header(WIRE_HEADER, acp_runner_core::WIRE_VERSION.to_string())
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    return r.json().await.map_err(|e| SinkError::Io(e.to_string()));
                }
                Ok(r) if r.status().is_client_error() => {
                    let status = r.status().as_u16();
                    return Err(SinkError::Rejected { status, body: r.text().await.unwrap_or_default() });
                }
                Ok(r) => tracing::warn!(status = %r.status(), attempt, "fetching attempt spec"),
                Err(e) => tracing::warn!(error = %e, attempt, "fetching attempt spec"),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(8));
        }
        Err(SinkError::Unreachable("GET /v1/attempt failed repeatedly".into()))
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response, SinkError> {
        let mut delay = Duration::from_millis(250);
        let mut last = String::new();
        for _ in 0..6 {
            match self
                .client
                .get(self.url(path))
                .bearer_auth(&self.token)
                .header(WIRE_HEADER, acp_runner_core::WIRE_VERSION.to_string())
                .timeout(Duration::from_secs(600))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => return Ok(r),
                Ok(r) if r.status().is_client_error() => {
                    let status = r.status().as_u16();
                    return Err(SinkError::Rejected { status, body: r.text().await.unwrap_or_default() });
                }
                Ok(r) => last = format!("status {}", r.status()),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
        Err(SinkError::Unreachable(format!("GET {path}: {last}")))
    }

    async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
        retries: u32,
    ) -> Result<reqwest::Response, SinkError> {
        let mut delay = Duration::from_millis(200);
        let mut last = String::new();
        for _ in 0..=retries {
            match self
                .client
                .post(self.url(path))
                .bearer_auth(&self.token)
                .header(WIRE_HEADER, acp_runner_core::WIRE_VERSION.to_string())
                .json(body)
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => return Ok(r),
                Ok(r) if r.status().is_client_error() => {
                    let status = r.status().as_u16();
                    return Err(SinkError::Rejected { status, body: r.text().await.unwrap_or_default() });
                }
                Ok(r) => last = format!("status {}", r.status()),
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
        }
        Err(SinkError::Unreachable(format!("POST {path}: {last}")))
    }
}

#[async_trait]
impl EventSink for IngestSink {
    async fn emit(&mut self, mut ev: EventEnvelope) {
        self.seq += 1;
        ev.seq = Some(self.seq);
        let terminal = ev.kind.is_attempt_terminal();
        self.buffer.push(ev);
        if (terminal || self.buffer.len() >= 32 || self.last_flush.elapsed() > Duration::from_millis(500))
            && let Err(e) = self.flush().await
        {
            tracing::warn!(error = %e, "event flush failed; will retry");
        }
    }

    async fn heartbeat(&mut self, hb: &HeartbeatData) -> Result<Option<RunnerDirective>, SinkError> {
        if !self.buffer.is_empty() {
            let _ = self.flush().await;
        }
        let r = self.post("/v1/attempt/heartbeat", hb, 2).await?;
        if r.status() == reqwest::StatusCode::NO_CONTENT {
            self.last_directive_id = None;
            self.last_lease_expires_at = None;
            return Ok(None);
        }
        let body = r.bytes().await.map_err(|e| SinkError::Io(e.to_string()))?;
        if body.is_empty() {
            self.last_directive_id = None;
            self.last_lease_expires_at = None;
            return Ok(None);
        }
        let reply =
            serde_json::from_slice::<HeartbeatReply>(&body).map_err(|e| SinkError::Io(e.to_string()))?;
        self.last_directive_id = reply.directive_id;
        self.last_lease_expires_at = reply.lease_expires_at;
        Ok(reply.directive)
    }

    fn take_directive_id(&mut self) -> Option<Uuid> {
        self.last_directive_id.take()
    }

    fn last_lease_expires_at(&self) -> Option<i64> {
        self.last_lease_expires_at
    }

    async fn upload_artifact(&mut self, art: &ArtifactUpload) -> Result<ArtifactAccepted, SinkError> {
        self.flush().await?;
        let r = self.post("/v1/attempt/artifact", art, 5).await?;
        r.json().await.map_err(|e| SinkError::Io(e.to_string()))
    }

    async fn writeback(&mut self, key: &str, bytes: &[u8]) -> Result<(), SinkError> {
        let body = CredentialWriteback {
            key: key.to_string(),
            content_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        };
        self.post("/v1/attempt/credential", &body, 5).await.map(|_| ())
    }

    async fn fetch_overlay(&mut self, artifact_id: Uuid) -> Result<Vec<u8>, SinkError> {
        let r = self.get(&format!("/v1/attempt/overlay/{artifact_id}")).await?;
        Ok(r.bytes().await.map_err(|e| SinkError::Io(e.to_string()))?.to_vec())
    }

    async fn fetch_bundle(&mut self, digest: &str) -> Result<Bundle, SinkError> {
        let r = self.get(&format!("/v1/attempt/bundle/{digest}")).await?;
        r.json().await.map_err(|e| SinkError::Io(e.to_string()))
    }

    async fn fetch_harness(&mut self, digest: &str, dest: &std::path::Path) -> Result<u64, SinkError> {
        use tokio::io::AsyncWriteExt;
        let mut r = self.get(&format!("/v1/attempt/harness/{digest}")).await?;
        let mut f = tokio::fs::File::create(dest).await.map_err(|e| SinkError::Io(e.to_string()))?;
        let mut n = 0u64;
        while let Some(chunk) = r.chunk().await.map_err(|e| SinkError::Io(e.to_string()))? {
            n += chunk.len() as u64;
            f.write_all(&chunk).await.map_err(|e| SinkError::Io(e.to_string()))?;
        }
        f.flush().await.map_err(|e| SinkError::Io(e.to_string()))?;
        Ok(n)
    }

    async fn flush(&mut self) -> Result<(), SinkError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let batch = EventBatch { events: std::mem::take(&mut self.buffer) };
        match self.post("/v1/attempt/events", &batch, 6).await {
            Ok(_) => {
                self.last_flush = Instant::now();
                Ok(())
            }
            Err(e @ SinkError::Rejected { .. }) => Err(e),
            Err(e) => {
                // keep for a later retry (ingest de-duplicates by seq)
                let mut events = batch.events;
                events.append(&mut self.buffer);
                self.buffer = events;
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------------------

/// Writes `events.jsonl`, `heartbeats.jsonl`, `patch.diff`, `artifact.json` and
/// `writeback/<key>` into a directory.
pub struct FileSink {
    dir: PathBuf,
    seq: u64,
}

impl FileSink {
    pub fn new(dir: PathBuf) -> std::io::Result<FileSink> {
        std::fs::create_dir_all(&dir)?;
        Ok(FileSink { dir, seq: 0 })
    }

    fn append(&self, file: &str, line: &str) -> Result<(), SinkError> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(file))
            .map_err(|e| SinkError::Io(e.to_string()))?;
        writeln!(f, "{line}").map_err(|e| SinkError::Io(e.to_string()))
    }
}

#[async_trait]
impl EventSink for FileSink {
    async fn emit(&mut self, mut ev: EventEnvelope) {
        self.seq += 1;
        ev.seq = Some(self.seq);
        let _ = self.append("events.jsonl", &serde_json::to_string(&ev).unwrap_or_default());
    }
    async fn heartbeat(&mut self, hb: &HeartbeatData) -> Result<Option<RunnerDirective>, SinkError> {
        self.append("heartbeats.jsonl", &serde_json::to_string(hb).unwrap_or_default()).map(|_| None)
    }
    async fn upload_artifact(&mut self, art: &ArtifactUpload) -> Result<ArtifactAccepted, SinkError> {
        let bytes = art.patch_bytes().map_err(|e| SinkError::Io(e.to_string()))?;
        let name = if art.kind == "patch" { "patch.diff" } else { "partial.patch.diff" };
        std::fs::write(self.dir.join(name), bytes).map_err(|e| SinkError::Io(e.to_string()))?;
        let mut meta = art.clone();
        meta.patch_b64 = String::new();
        std::fs::write(self.dir.join(format!("{name}.json")), serde_json::to_vec_pretty(&meta).unwrap_or_default())
            .map_err(|e| SinkError::Io(e.to_string()))?;
        Ok(ArtifactAccepted { artifact_id: Uuid::new_v4(), storage: "file".into() })
    }
    async fn writeback(&mut self, key: &str, bytes: &[u8]) -> Result<(), SinkError> {
        let d = self.dir.join("writeback");
        std::fs::create_dir_all(&d).map_err(|e| SinkError::Io(e.to_string()))?;
        std::fs::write(d.join(key), bytes).map_err(|e| SinkError::Io(e.to_string()))
    }
    async fn flush(&mut self) -> Result<(), SinkError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct MemoryRecord {
    pub events: Vec<EventEnvelope>,
    pub heartbeats: Vec<HeartbeatData>,
    pub artifacts: Vec<ArtifactUpload>,
    pub writebacks: Vec<(String, Vec<u8>)>,
}

#[derive(Clone, Default)]
pub struct MemorySink {
    pub record: Arc<Mutex<MemoryRecord>>,
    /// Directives returned by successive heartbeats (tests: simulated controller decisions).
    pub directives: Arc<Mutex<std::collections::VecDeque<RunnerDirective>>>,
    /// Content served to `fetch_*` (tests: what the controller would serve).
    pub overlays: Arc<Mutex<std::collections::HashMap<Uuid, Vec<u8>>>>,
    pub bundles: Arc<Mutex<std::collections::HashMap<String, Bundle>>>,
    pub harnesses: Arc<Mutex<std::collections::HashMap<String, PathBuf>>>,
    seq: u64,
}

impl MemorySink {
    pub fn snapshot(&self) -> MemoryRecord {
        self.record.lock().expect("lock").clone()
    }
}

#[async_trait]
impl EventSink for MemorySink {
    async fn emit(&mut self, mut ev: EventEnvelope) {
        self.seq += 1;
        ev.seq = Some(self.seq);
        self.record.lock().expect("lock").events.push(ev);
    }
    async fn heartbeat(&mut self, hb: &HeartbeatData) -> Result<Option<RunnerDirective>, SinkError> {
        self.record.lock().expect("lock").heartbeats.push(hb.clone());
        Ok(self.directives.lock().expect("lock").pop_front())
    }
    async fn upload_artifact(&mut self, art: &ArtifactUpload) -> Result<ArtifactAccepted, SinkError> {
        self.record.lock().expect("lock").artifacts.push(art.clone());
        Ok(ArtifactAccepted { artifact_id: Uuid::new_v4(), storage: "memory".into() })
    }
    async fn writeback(&mut self, key: &str, bytes: &[u8]) -> Result<(), SinkError> {
        self.record.lock().expect("lock").writebacks.push((key.to_string(), bytes.to_vec()));
        Ok(())
    }
    async fn flush(&mut self) -> Result<(), SinkError> {
        Ok(())
    }
    async fn fetch_overlay(&mut self, artifact_id: Uuid) -> Result<Vec<u8>, SinkError> {
        self.overlays
            .lock()
            .expect("lock")
            .get(&artifact_id)
            .cloned()
            .ok_or(SinkError::Rejected { status: 404, body: "unknown overlay".into() })
    }
    async fn fetch_bundle(&mut self, digest: &str) -> Result<Bundle, SinkError> {
        self.bundles
            .lock()
            .expect("lock")
            .get(digest)
            .cloned()
            .ok_or(SinkError::Rejected { status: 404, body: "unknown bundle".into() })
    }
    async fn fetch_harness(&mut self, digest: &str, dest: &std::path::Path) -> Result<u64, SinkError> {
        let src = self
            .harnesses
            .lock()
            .expect("lock")
            .get(digest)
            .cloned()
            .ok_or(SinkError::Rejected { status: 404, body: "unknown harness".into() })?;
        std::fs::copy(src, dest).map_err(|e| SinkError::Io(e.to_string()))
    }
}
