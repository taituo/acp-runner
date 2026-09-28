//! Artifact storage.
//!
//! Patches up to `inline_limit` bytes are stored in PostgreSQL (`artifacts.content`).
//! Larger ones go to an optional [`BlobStore`] (filesystem implementation provided; an S3
//! implementation can be added behind the same trait) or are rejected.

use crate::{Journal, JournalError, Result};
use acp_runner_core::events::ChangedPath;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NewArtifact {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    /// `patch` | `partial_patch`
    pub kind: String,
    pub base_revision: String,
    pub sha256: String,
    pub changed_paths: Vec<ChangedPath>,
    pub driver: String,
    pub driver_version: Option<String>,
    /// Lineage (environment artifacts): the environment that produced it, and the artifact /
    /// environment its workspace was branched from. The patch itself is always cumulative
    /// against `base_revision`.
    pub environment_id: Option<Uuid>,
    pub parent_artifact_id: Option<Uuid>,
    pub parent_environment_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StoredArtifact {
    pub id: Uuid,
    pub storage: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub kind: String,
    pub base_revision: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub changed_paths: serde_json::Value,
    pub driver: String,
    pub driver_version: Option<String>,
    pub storage: String,
    pub external_uri: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub environment_id: Option<Uuid>,
    pub parent_artifact_id: Option<Uuid>,
    pub parent_environment_id: Option<Uuid>,
}

#[async_trait]
pub trait BlobStore: Send + Sync {
    fn name(&self) -> &'static str;
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<String>;
    async fn get(&self, uri: &str) -> Result<Vec<u8>>;
}

#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn put(&self, meta: &NewArtifact, content: &[u8]) -> Result<StoredArtifact>;
    async fn get_meta(&self, id: Uuid) -> Result<ArtifactRow>;
    async fn get_content(&self, id: Uuid) -> Result<Vec<u8>>;
    async fn latest_for_run(&self, run_id: Uuid) -> Result<Option<ArtifactRow>>;
}

pub struct PgArtifactStore {
    journal: Journal,
    inline_limit: u64,
    external: Option<Arc<dyn BlobStore>>,
}

impl PgArtifactStore {
    pub fn new(journal: Journal, inline_limit: u64, external: Option<Arc<dyn BlobStore>>) -> Self {
        PgArtifactStore { journal, inline_limit, external }
    }

    /// Largest artifact accepted at all.
    pub fn max_accepted(&self) -> u64 {
        if self.external.is_some() { u64::MAX } else { self.inline_limit }
    }
}

#[async_trait]
impl ArtifactStore for PgArtifactStore {
    async fn put(&self, meta: &NewArtifact, content: &[u8]) -> Result<StoredArtifact> {
        let size = content.len() as u64;
        let actual = hex::encode(Sha256::digest(content));
        if actual != meta.sha256 {
            return Err(JournalError::Invalid(format!("sha256 mismatch: declared {} actual {actual}", meta.sha256)));
        }
        let id = Uuid::now_v7();
        let (storage, inline, uri) = if size <= self.inline_limit {
            ("postgres".to_string(), Some(content), None)
        } else if let Some(ext) = &self.external {
            let uri = ext.put(&format!("{}/{}/{id}.patch", meta.run_id, meta.attempt_id), content).await?;
            (ext.name().to_string(), None, Some(uri))
        } else {
            return Err(JournalError::TooLarge { size, limit: self.inline_limit });
        };
        sqlx::query(
            "INSERT INTO artifacts (id, run_id, attempt_id, kind, base_revision, sha256, size_bytes, changed_paths,
                                    driver, driver_version, storage, content, external_uri,
                                    environment_id, parent_artifact_id, parent_environment_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(id)
        .bind(meta.run_id)
        .bind(meta.attempt_id)
        .bind(&meta.kind)
        .bind(&meta.base_revision)
        .bind(&meta.sha256)
        .bind(size as i64)
        .bind(serde_json::to_value(&meta.changed_paths).unwrap_or_default())
        .bind(&meta.driver)
        .bind(&meta.driver_version)
        .bind(&storage)
        .bind(inline)
        .bind(uri)
        .bind(meta.environment_id)
        .bind(meta.parent_artifact_id)
        .bind(meta.parent_environment_id)
        .execute(self.journal.pool())
        .await?;
        Ok(StoredArtifact { id, storage, size_bytes: size })
    }

    async fn get_meta(&self, id: Uuid) -> Result<ArtifactRow> {
        sqlx::query_as(
            "SELECT id, run_id, attempt_id, kind, base_revision, sha256, size_bytes, changed_paths, driver, driver_version,
                    storage, external_uri, created_at, environment_id, parent_artifact_id, parent_environment_id
             FROM artifacts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.journal.pool())
        .await?
        .ok_or_else(|| JournalError::NotFound(format!("artifact {id}")))
    }

    async fn get_content(&self, id: Uuid) -> Result<Vec<u8>> {
        let row: Option<(String, Option<Vec<u8>>, Option<String>, String)> =
            sqlx::query_as("SELECT storage, content, external_uri, sha256 FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_optional(self.journal.pool())
                .await?;
        let (storage, content, uri, sha) = row.ok_or_else(|| JournalError::NotFound(format!("artifact {id}")))?;
        let bytes = match (storage.as_str(), content, uri) {
            ("postgres", Some(c), _) => c,
            (_, _, Some(uri)) => match &self.external {
                Some(ext) => ext.get(&uri).await?,
                None => {
                    return Err(JournalError::Blob(format!(
                        "artifact stored externally at {uri}; no blob store configured"
                    )));
                }
            },
            _ => return Err(JournalError::Invalid(format!("artifact {id} has no content"))),
        };
        if hex::encode(Sha256::digest(&bytes)) != sha {
            return Err(JournalError::Invalid(format!("artifact {id} content does not match its sha256")));
        }
        Ok(bytes)
    }

    async fn latest_for_run(&self, run_id: Uuid) -> Result<Option<ArtifactRow>> {
        Ok(sqlx::query_as(
            "SELECT id, run_id, attempt_id, kind, base_revision, sha256, size_bytes, changed_paths, driver, driver_version,
                    storage, external_uri, created_at, environment_id, parent_artifact_id, parent_environment_id
             FROM artifacts WHERE run_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(run_id)
        .fetch_optional(self.journal.pool())
        .await?)
    }
}

/// Filesystem blob store (development / single-node). Keys are sanitized.
pub struct FsBlobStore {
    pub root: PathBuf,
}

#[async_trait]
impl BlobStore for FsBlobStore {
    fn name(&self) -> &'static str {
        "fs"
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<String> {
        let safe: String =
            key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c } else { '_' }).collect();
        let path = self.root.join(safe);
        tokio::fs::create_dir_all(&self.root).await.map_err(|e| JournalError::Blob(e.to_string()))?;
        tokio::fs::write(&path, bytes).await.map_err(|e| JournalError::Blob(e.to_string()))?;
        Ok(format!("file://{}", path.display()))
    }

    async fn get(&self, uri: &str) -> Result<Vec<u8>> {
        let p = uri.strip_prefix("file://").ok_or_else(|| JournalError::Blob(format!("unsupported uri {uri}")))?;
        let path = PathBuf::from(p);
        if !path.starts_with(&self.root) {
            return Err(JournalError::Blob("uri outside blob root".into()));
        }
        tokio::fs::read(path).await.map_err(|e| JournalError::Blob(e.to_string()))
    }
}
