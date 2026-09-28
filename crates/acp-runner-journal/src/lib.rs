//! PostgreSQL journal.
//!
//! Tables: `runs`, `attempts`, `session_events` (append-only, enforced by trigger),
//! `artifacts`, `credential_profiles`, `credential_leases`. See `migrations/`.
//!
//! Concurrency model:
//! * every reconcile of a run holds a transaction-scoped advisory lock on the run
//!   ([`Journal::try_lock_run`]) so two controller replicas never act on the same run
//!   concurrently; a crashed controller's lock disappears with its connection;
//! * attempts carry a *supervision lease* (`lease_owner`, `lease_expires_at`) renewed by the
//!   supervising controller; an expired lease is taken over by another instance;
//! * credential leases are acquired under `SELECT ... FOR UPDATE` on the profile rows and
//!   expire (`expires_at`) so a crashed controller cannot hold a credential forever.

pub mod artifacts;
pub mod testing;

use acp_runner_core::events::{EventEnvelope, EventKind, EventSource};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::{AttemptPhase, RunPhase};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::{PgPool, Transaction};
use std::time::Duration;
use uuid::Uuid;

pub use artifacts::{ArtifactRow, ArtifactStore, BlobStore, FsBlobStore, NewArtifact, PgArtifactStore, StoredArtifact};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid stored data: {0}")]
    Invalid(String),
    #[error("artifact too large: {size} > {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("blob store error: {0}")]
    Blob(String),
}

pub type Result<T> = std::result::Result<T, JournalError>;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RunRow {
    pub id: Uuid,
    pub k8s_namespace: String,
    pub k8s_name: String,
    pub k8s_uid: String,
    pub task_id: String,
    pub spec: Value,
    pub phase: String,
    pub current_attempt_id: Option<Uuid>,
    pub attempt_count: i32,
    pub failure_reason: Option<Value>,
    pub artifact_id: Option<Uuid>,
    pub waiting_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

impl RunRow {
    pub fn phase(&self) -> RunPhase {
        self.phase.parse().unwrap_or(RunPhase::Pending)
    }
    pub fn failure(&self) -> Option<FailureReason> {
        self.failure_reason.clone().and_then(|v| serde_json::from_value(v).ok())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AttemptRow {
    pub id: Uuid,
    pub run_id: Uuid,
    pub ordinal: i32,
    pub class_index: i32,
    pub class_attempt: i32,
    pub runner_class: String,
    pub driver: String,
    pub phase: String,
    pub spec: Value,
    pub sandbox_ref: Option<Value>,
    pub ingest_token_hash: Option<String>,
    pub credential_profile: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub sandbox_created_at: Option<DateTime<Utc>>,
    pub sandbox_released_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub last_progress_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub failure_reason: Option<Value>,
    pub outcome: Option<Value>,
    pub driver_version: Option<String>,
    pub base_revision: Option<String>,
    pub artifact_id: Option<Uuid>,
    /// Controller asked runnerd to cancel the agent (delivered with the heartbeat reply).
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub cancel_reason: Option<Value>,
}

impl AttemptRow {
    pub fn phase(&self) -> AttemptPhase {
        self.phase.parse().unwrap_or(AttemptPhase::Failed)
    }
    pub fn failure(&self) -> Option<FailureReason> {
        self.failure_reason.clone().and_then(|v| serde_json::from_value(v).ok())
    }
    pub fn cancel_request(&self) -> Option<FailureReason> {
        self.cancel_reason.clone().and_then(|v| serde_json::from_value(v).ok())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventRow {
    pub id: i64,
    pub run_id: Uuid,
    pub attempt_id: Option<Uuid>,
    pub seq: Option<i64>,
    pub ts: DateTime<Utc>,
    pub recorded_at: DateTime<Utc>,
    pub kind: String,
    pub source: String,
    pub data: Value,
    pub raw: Option<Value>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProfileRow {
    pub name: String,
    pub provider: String,
    pub store: String,
    pub status: String,
    pub max_concurrent_leases: i32,
    pub metadata: Value,
    /// Namespaces whose attempts may lease this profile (V2, deny by default).
    pub allowed_namespaces: Vec<String>,
    /// Runner classes (by name) that may lease this profile (V2, deny by default).
    pub allowed_classes: Vec<String>,
    pub material_fingerprint: Option<String>,
    pub generation: i64,
    pub last_error: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LeaseRow {
    pub id: Uuid,
    pub profile_name: String,
    pub attempt_id: Uuid,
    pub holder: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct NewRun {
    pub id: Uuid,
    pub k8s_namespace: String,
    pub k8s_name: String,
    pub k8s_uid: String,
    pub task_id: String,
    pub spec: Value,
}

#[derive(Debug, Clone)]
pub struct NewAttempt {
    pub id: Uuid,
    pub run_id: Uuid,
    pub ordinal: i32,
    pub class_index: i32,
    pub class_attempt: i32,
    pub runner_class: String,
    pub driver: String,
    pub spec: Value,
    pub ingest_token_hash: String,
    pub lease_owner: String,
    pub lease_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct LeaseRequest {
    pub provider: String,
    /// Candidate profiles in preference order.
    pub candidates: Vec<String>,
    pub holder: String,
    pub ttl: Duration,
}

#[derive(Debug)]
pub enum StartAttempt {
    Started {
        attempt: Box<AttemptRow>,
        lease: Option<LeaseRow>,
    },
    /// All candidate profiles are busy (retry later).
    NoCredentialAvailable {
        detail: String,
    },
    /// No candidate profile is usable at all (disabled / needs re-enrollment / missing).
    CredentialUnusable {
        detail: String,
    },
}

#[derive(Debug, Clone)]
pub struct ProfileUpsert {
    pub name: String,
    pub provider: String,
    pub store: String,
    pub max_concurrent_leases: i32,
    pub metadata: Value,
    pub material_fingerprint: String,
    pub allowed_namespaces: Vec<String>,
    pub allowed_classes: Vec<String>,
}

/// True iff the profile may be leased to an attempt of `namespace`/`class`.
/// Empty lists deny everything (deny by default, including pre-V2 rows).
pub fn profile_policy_allows(p: &ProfileRow, namespace: &str, class: &str) -> bool {
    p.allowed_namespaces.iter().any(|n| n == namespace) && p.allowed_classes.iter().any(|c| c == class)
}

async fn upsert_profile_inner<'e, E>(ex: E, p: &ProfileUpsert) -> Result<()>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query(
        "INSERT INTO credential_profiles (name, provider, store, max_concurrent_leases, metadata, material_fingerprint,
                                          allowed_namespaces, allowed_classes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (name) DO UPDATE SET
            provider = EXCLUDED.provider, store = EXCLUDED.store,
            max_concurrent_leases = EXCLUDED.max_concurrent_leases, metadata = EXCLUDED.metadata,
            allowed_namespaces = EXCLUDED.allowed_namespaces, allowed_classes = EXCLUDED.allowed_classes,
            status = CASE WHEN credential_profiles.status = 'needs_reauth'
                           AND credential_profiles.material_fingerprint IS DISTINCT FROM EXCLUDED.material_fingerprint
                          THEN 'active' ELSE credential_profiles.status END,
            last_error = CASE WHEN credential_profiles.material_fingerprint IS DISTINCT FROM EXCLUDED.material_fingerprint
                          THEN NULL ELSE credential_profiles.last_error END,
            material_fingerprint = EXCLUDED.material_fingerprint,
            generation = credential_profiles.generation
                + CASE WHEN credential_profiles.material_fingerprint IS DISTINCT FROM EXCLUDED.material_fingerprint THEN 1 ELSE 0 END,
            updated_at = now()",
    )
    .bind(&p.name)
    .bind(&p.provider)
    .bind(&p.store)
    .bind(p.max_concurrent_leases.max(1))
    .bind(&p.metadata)
    .bind(&p.material_fingerprint)
    .bind(&p.allowed_namespaces)
    .bind(&p.allowed_classes)
    .execute(ex)
    .await?;
    Ok(())
}

/// Held across one profile sync: the profile row stays locked from before the
/// store is (re)loaded until the upsert commits, so the upsert can never be
/// built from a stale pre-lock snapshot.
pub struct ProfileSyncGuard {
    tx: Transaction<'static, Postgres>,
}

impl ProfileSyncGuard {
    pub async fn commit(mut self, p: &ProfileUpsert) -> Result<()> {
        upsert_profile_inner(&mut *self.tx, p).await?;
        self.tx.commit().await?;
        Ok(())
    }
}

/// Held across a credential write-back: the lease row stays locked from the
/// usability check until the profile metadata update commits.
pub struct WritebackGuard {
    tx: Transaction<'static, Postgres>,
    pub lease: LeaseRow,
    /// Profile row as locked (also `FOR UPDATE`): read enrollment facts from
    /// this, never from an unlocked re-read, so they cannot change mid-flight.
    pub profile: ProfileRow,
}

impl WritebackGuard {
    /// Record the new profile metadata/fingerprint and commit, releasing the
    /// row lock. Call only after the credential store write succeeded.
    pub async fn commit_metadata(mut self, profile: &str, metadata: &Value, fingerprint: &str) -> Result<()> {
        sqlx::query(
            "UPDATE credential_profiles SET metadata = $2, material_fingerprint = $3, generation = generation + 1,
                 updated_at = now() WHERE name = $1",
        )
        .bind(profile)
        .bind(metadata)
        .bind(fingerprint)
        .execute(&mut *self.tx)
        .await?;
        self.tx.commit().await?;
        Ok(())
    }
}

/// Held for the duration of one reconcile; released on commit or drop.
pub struct RunLock {
    tx: Transaction<'static, Postgres>,
}

impl RunLock {
    pub async fn release(self) -> Result<()> {
        self.tx.commit().await?;
        Ok(())
    }
}

fn lock_key(id: Uuid) -> i64 {
    let (hi, lo) = id.as_u64_pair();
    (hi ^ lo) as i64
}

fn interval(d: Duration) -> String {
    format!("{} milliseconds", d.as_millis())
}

#[derive(Clone)]
pub struct Journal {
    pool: PgPool,
}

impl Journal {
    pub async fn connect(url: &str, max_connections: u32) -> Result<Journal> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await?;
        Ok(Journal { pool })
    }

    pub fn from_pool(pool: PgPool) -> Journal {
        Journal { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    // ------------------------------------------------------------------ locks

    /// Non-blocking, transaction-scoped advisory lock on a run.
    pub async fn try_lock_run(&self, run_id: Uuid) -> Result<Option<RunLock>> {
        let mut tx = self.pool.begin().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(lock_key(run_id))
            .fetch_one(&mut *tx)
            .await?;
        if got { Ok(Some(RunLock { tx })) } else { Ok(None) }
    }

    // ------------------------------------------------------------------ runs

    /// Insert the run if unknown (idempotent). Emits `RunCreated` exactly once.
    pub async fn ensure_run(&self, new: &NewRun) -> Result<(RunRow, bool)> {
        if let Some(r) = self.run_by_uid(&new.k8s_uid).await? {
            return Ok((r, false));
        }
        let mut tx = self.pool.begin().await?;
        let inserted: Option<RunRow> = sqlx::query_as(
            "INSERT INTO runs (id, k8s_namespace, k8s_name, k8s_uid, task_id, spec, phase)
             VALUES ($1, $2, $3, $4, $5, $6, 'Pending')
             ON CONFLICT (k8s_uid) DO NOTHING RETURNING *",
        )
        .bind(new.id)
        .bind(&new.k8s_namespace)
        .bind(&new.k8s_name)
        .bind(&new.k8s_uid)
        .bind(&new.task_id)
        .bind(&new.spec)
        .fetch_optional(&mut *tx)
        .await?;
        match inserted {
            Some(row) => {
                let ev = EventEnvelope::new(
                    EventKind::RunCreated,
                    EventSource::Controller,
                    serde_json::json!({"taskId": new.task_id, "namespace": new.k8s_namespace, "name": new.k8s_name}),
                );
                insert_event(&mut tx, row.id, None, &ev).await?;
                tx.commit().await?;
                Ok((row, true))
            }
            None => {
                tx.rollback().await?;
                let r =
                    self.run_by_uid(&new.k8s_uid).await?.ok_or_else(|| JournalError::NotFound(new.k8s_uid.clone()))?;
                Ok((r, false))
            }
        }
    }

    pub async fn run_by_uid(&self, uid: &str) -> Result<Option<RunRow>> {
        Ok(sqlx::query_as("SELECT * FROM runs WHERE k8s_uid = $1").bind(uid).fetch_optional(&self.pool).await?)
    }

    pub async fn get_run(&self, id: Uuid) -> Result<RunRow> {
        sqlx::query_as("SELECT * FROM runs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| JournalError::NotFound(format!("run {id}")))
    }

    pub async fn find_runs(&self, name_or_id: &str, namespace: Option<&str>) -> Result<Vec<RunRow>> {
        if let Ok(id) = Uuid::parse_str(name_or_id) {
            return Ok(sqlx::query_as("SELECT * FROM runs WHERE id = $1 OR k8s_uid = $2")
                .bind(id)
                .bind(name_or_id)
                .fetch_all(&self.pool)
                .await?);
        }
        Ok(sqlx::query_as(
            "SELECT * FROM runs WHERE (k8s_name = $1 OR task_id = $1) AND ($2::text IS NULL OR k8s_namespace = $2)
             ORDER BY created_at DESC",
        )
        .bind(name_or_id)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_runs(&self, limit: i64) -> Result<Vec<RunRow>> {
        Ok(sqlx::query_as("SELECT * FROM runs ORDER BY created_at DESC LIMIT $1")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn set_run_phase(
        &self,
        id: Uuid,
        phase: RunPhase,
        failure: Option<&FailureReason>,
        artifact_id: Option<Uuid>,
    ) -> Result<()> {
        let failure = failure.map(|f| serde_json::to_value(f).unwrap_or(Value::Null));
        sqlx::query(
            "UPDATE runs SET phase = $2,
                failure_reason = COALESCE($3, failure_reason),
                artifact_id = COALESCE($4, artifact_id),
                started_at = CASE WHEN $2 = 'Running' AND started_at IS NULL THEN now() ELSE started_at END,
                finished_at = CASE WHEN $2 IN ('Succeeded','Failed','Cancelled') AND finished_at IS NULL THEN now() ELSE finished_at END,
                waiting_reason = CASE WHEN $2 = 'Pending' THEN waiting_reason ELSE NULL END,
                updated_at = now()
             WHERE id = $1 AND phase NOT IN ('Succeeded','Failed','Cancelled')",
        )
        .bind(id)
        .bind(phase.as_str())
        .bind(failure)
        .bind(artifact_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_run_waiting(&self, id: Uuid, reason: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE runs SET waiting_reason = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(reason)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ------------------------------------------------------------------ attempts

    /// Atomically create the attempt row and (optionally) acquire a credential lease.
    pub async fn start_attempt(&self, new: &NewAttempt, lease: Option<&LeaseRequest>) -> Result<StartAttempt> {
        let mut tx = self.pool.begin().await?;
        let attempt: AttemptRow = sqlx::query_as(
            "INSERT INTO attempts (id, run_id, ordinal, class_index, class_attempt, runner_class, driver, phase, spec,
                                   ingest_token_hash, lease_owner, lease_expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'Pending',$8,$9,$10, now() + $11::interval) RETURNING *",
        )
        .bind(new.id)
        .bind(new.run_id)
        .bind(new.ordinal)
        .bind(new.class_index)
        .bind(new.class_attempt)
        .bind(&new.runner_class)
        .bind(&new.driver)
        .bind(&new.spec)
        .bind(&new.ingest_token_hash)
        .bind(&new.lease_owner)
        .bind(interval(new.lease_ttl))
        .fetch_one(&mut *tx)
        .await?;

        let mut lease_row = None;
        if let Some(req) = lease {
            // V2 trust boundary: the attempt's namespace owns the decision.
            let run_ns: String = sqlx::query_scalar("SELECT k8s_namespace FROM runs WHERE id = $1")
                .bind(new.run_id)
                .fetch_one(&mut *tx)
                .await?;
            let profiles: Vec<ProfileRow> =
                sqlx::query_as("SELECT * FROM credential_profiles WHERE name = ANY($1) ORDER BY name FOR UPDATE")
                    .bind(&req.candidates)
                    .fetch_all(&mut *tx)
                    .await?;
            let mut busy = vec![];
            let mut unusable = vec![];
            for cand in &req.candidates {
                let Some(p) = profiles.iter().find(|p| &p.name == cand) else {
                    unusable.push(format!("{cand}: not enrolled"));
                    continue;
                };
                if p.provider != req.provider {
                    unusable.push(format!("{cand}: provider {} != {}", p.provider, req.provider));
                    continue;
                }
                if p.status != "active" {
                    unusable.push(format!("{cand}: status {}", p.status));
                    continue;
                }
                // V2: explicit admin grant required (namespace × class);
                // missing grants deny, never retry-later.
                if !profile_policy_allows(p, &run_ns, &new.runner_class) {
                    unusable.push(format!("{cand}: not granted for namespace {run_ns} class {}", new.runner_class));
                    continue;
                }
                let active: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM credential_leases WHERE profile_name = $1 AND released_at IS NULL AND expires_at > now()",
                )
                .bind(&p.name)
                .fetch_one(&mut *tx)
                .await?;
                if active >= p.max_concurrent_leases as i64 {
                    busy.push(format!("{cand}: {active}/{} leases in use", p.max_concurrent_leases));
                    continue;
                }
                let l: LeaseRow = sqlx::query_as(
                    "INSERT INTO credential_leases (id, profile_name, attempt_id, holder, expires_at)
                     VALUES ($1, $2, $3, $4, now() + $5::interval) RETURNING *",
                )
                .bind(Uuid::now_v7())
                .bind(&p.name)
                .bind(new.id)
                .bind(&req.holder)
                .bind(interval(req.ttl))
                .fetch_one(&mut *tx)
                .await?;
                sqlx::query("UPDATE credential_profiles SET last_used_at = now() WHERE name = $1")
                    .bind(&p.name)
                    .execute(&mut *tx)
                    .await?;
                sqlx::query("UPDATE attempts SET credential_profile = $2 WHERE id = $1")
                    .bind(new.id)
                    .bind(&p.name)
                    .execute(&mut *tx)
                    .await?;
                lease_row = Some(l);
                break;
            }
            if lease_row.is_none() {
                tx.rollback().await?;
                return Ok(if busy.is_empty() {
                    StartAttempt::CredentialUnusable { detail: unusable.join("; ") }
                } else {
                    StartAttempt::NoCredentialAvailable {
                        detail: busy.into_iter().chain(unusable).collect::<Vec<_>>().join("; "),
                    }
                });
            }
        }
        sqlx::query(
            "UPDATE runs SET current_attempt_id = $2, attempt_count = GREATEST(attempt_count, $3),
                 phase = 'Running', waiting_reason = NULL,
                 started_at = COALESCE(started_at, now()), updated_at = now()
             WHERE id = $1",
        )
        .bind(new.run_id)
        .bind(new.id)
        .bind(new.ordinal)
        .execute(&mut *tx)
        .await?;
        let attempt =
            sqlx::query_as("SELECT * FROM attempts WHERE id = $1").bind(attempt.id).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(StartAttempt::Started { attempt: Box::new(attempt), lease: lease_row })
    }

    pub async fn attempts_for_run(&self, run_id: Uuid) -> Result<Vec<AttemptRow>> {
        Ok(sqlx::query_as("SELECT * FROM attempts WHERE run_id = $1 ORDER BY ordinal")
            .bind(run_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn get_attempt(&self, id: Uuid) -> Result<AttemptRow> {
        sqlx::query_as("SELECT * FROM attempts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| JournalError::NotFound(format!("attempt {id}")))
    }

    pub async fn attempt_by_token_hash(&self, hash: &str) -> Result<Option<AttemptRow>> {
        Ok(sqlx::query_as("SELECT * FROM attempts WHERE ingest_token_hash = $1")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn update_attempt_spec(&self, id: Uuid, spec: &Value) -> Result<()> {
        sqlx::query("UPDATE attempts SET spec = $2 WHERE id = $1").bind(id).bind(spec).execute(&self.pool).await?;
        Ok(())
    }

    /// Rotate the ingest token (before (re)creating a sandbox for a Pending attempt).
    pub async fn set_attempt_token(&self, id: Uuid, token_hash: &str) -> Result<()> {
        sqlx::query("UPDATE attempts SET ingest_token_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record the created sandbox (Pending -> Starting).
    pub async fn set_attempt_sandbox(&self, id: Uuid, sandbox_ref: &Value) -> Result<()> {
        sqlx::query(
            "UPDATE attempts SET sandbox_ref = $2, sandbox_created_at = now(),
                 phase = CASE WHEN phase = 'Pending' THEN 'Starting' ELSE phase END
             WHERE id = $1",
        )
        .bind(id)
        .bind(sandbox_ref)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Conditional phase transition; returns false if the attempt was not in one of `from`.
    pub async fn transition_attempt(
        &self,
        id: Uuid,
        from: &[AttemptPhase],
        to: AttemptPhase,
        failure: Option<&FailureReason>,
        outcome: Option<&Value>,
    ) -> Result<bool> {
        let from: Vec<&str> = from.iter().map(|p| p.as_str()).collect();
        let failure = failure.map(|f| serde_json::to_value(f).unwrap_or(Value::Null));
        let r = sqlx::query(
            "UPDATE attempts SET phase = $3,
                 failure_reason = COALESCE($4, failure_reason),
                 outcome = COALESCE($5, outcome),
                 started_at = CASE WHEN $3 = 'Running' AND started_at IS NULL THEN now() ELSE started_at END,
                 finished_at = CASE WHEN $3 IN ('Succeeded','Failed','TimedOut','Cancelled') THEN COALESCE(finished_at, now()) ELSE finished_at END
             WHERE id = $1 AND phase = ANY($2)",
        )
        .bind(id)
        .bind(&from)
        .bind(to.as_str())
        .bind(failure)
        .bind(outcome)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn set_attempt_details(
        &self,
        id: Uuid,
        driver_version: Option<&str>,
        base_revision: Option<&str>,
        artifact_id: Option<Uuid>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE attempts SET driver_version = COALESCE($2, driver_version), base_revision = COALESCE($3, base_revision),
                 artifact_id = COALESCE($4, artifact_id) WHERE id = $1",
        )
        .bind(id)
        .bind(driver_version)
        .bind(base_revision)
        .bind(artifact_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_sandbox_released(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE attempts SET sandbox_released_at = COALESCE(sandbox_released_at, now()) WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clear the sandbox reference of a Pending attempt whose sandbox creation must be redone.
    pub async fn reset_attempt_sandbox(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE attempts SET sandbox_ref = NULL, sandbox_created_at = NULL WHERE id = $1 AND phase = 'Pending'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ask runnerd (via the next heartbeat reply) to cancel the agent. Idempotent: returns
    /// true only for the first request of an active attempt.
    pub async fn request_attempt_cancel(&self, id: Uuid, reason: &FailureReason) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE attempts SET cancel_requested_at = now(), cancel_reason = $2
             WHERE id = $1 AND cancel_requested_at IS NULL AND phase IN ('Pending','Starting','Running')",
        )
        .bind(id)
        .bind(serde_json::to_value(reason).unwrap_or(Value::Null))
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn touch_heartbeat(&self, id: Uuid) -> Result<()> {
        sqlx::query("UPDATE attempts SET last_heartbeat_at = now() WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn touch_progress(&self, id: Uuid, at: DateTime<Utc>) -> Result<()> {
        sqlx::query(
            "UPDATE attempts SET last_progress_at = GREATEST(COALESCE(last_progress_at, $2), $2) WHERE id = $1",
        )
        .bind(id)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Renew (or take over an expired) supervision lease. Returns the previous owner when
    /// a stale lease of another controller instance was taken over, `Err`-free `None`
    /// otherwise. Returns `Ok(Err(owner))` when another live instance holds it.
    pub async fn renew_supervision_lease(
        &self,
        id: Uuid,
        owner: &str,
        ttl: Duration,
    ) -> Result<std::result::Result<Option<String>, String>> {
        let mut tx = self.pool.begin().await?;
        type LeaseState = (Option<String>, Option<DateTime<Utc>>, DateTime<Utc>);
        let row: Option<LeaseState> =
            sqlx::query_as("SELECT lease_owner, lease_expires_at, now() FROM attempts WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some((cur, exp, now)) = row else {
            return Err(JournalError::NotFound(format!("attempt {id}")));
        };
        let taken_over = match (&cur, exp) {
            (Some(o), Some(e)) if o != owner && e > now => {
                tx.rollback().await?;
                return Ok(Err(o.clone()));
            }
            (Some(o), _) if o != owner => Some(o.clone()),
            _ => None,
        };
        sqlx::query("UPDATE attempts SET lease_owner = $2, lease_expires_at = now() + $3::interval WHERE id = $1")
            .bind(id)
            .bind(owner)
            .bind(interval(ttl))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Ok(taken_over))
    }

    pub async fn active_attempt_counts(&self) -> Result<Vec<(String, i64)>> {
        Ok(sqlx::query_as(
            "SELECT driver, count(*) FROM attempts WHERE phase IN ('Pending','Starting','Running') GROUP BY driver",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn db_now(&self) -> Result<DateTime<Utc>> {
        Ok(sqlx::query_scalar("SELECT now()").fetch_one(&self.pool).await?)
    }

    // ------------------------------------------------------------------ events

    pub async fn append_event(&self, run_id: Uuid, attempt_id: Option<Uuid>, ev: &EventEnvelope) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let inserted = insert_event(&mut tx, run_id, attempt_id, ev).await?;
        tx.commit().await?;
        Ok(inserted)
    }

    /// Append a batch (idempotent per `(attempt_id, seq)`). Returns number of new rows.
    pub async fn append_events(&self, run_id: Uuid, attempt_id: Option<Uuid>, evs: &[EventEnvelope]) -> Result<usize> {
        let mut tx = self.pool.begin().await?;
        let mut n = 0;
        for ev in evs {
            if insert_event(&mut tx, run_id, attempt_id, ev).await? {
                n += 1;
            }
        }
        tx.commit().await?;
        Ok(n)
    }

    pub async fn events_for_run(&self, run_id: Uuid, after_id: i64, limit: i64) -> Result<Vec<EventRow>> {
        Ok(sqlx::query_as("SELECT * FROM session_events WHERE run_id = $1 AND id > $2 ORDER BY id LIMIT $3")
            .bind(run_id)
            .bind(after_id)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn events_for_attempt(&self, attempt_id: Uuid, kinds: &[EventKind], limit: i64) -> Result<Vec<EventRow>> {
        let kinds: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        Ok(sqlx::query_as(
            "SELECT * FROM session_events WHERE attempt_id = $1 AND (cardinality($2::text[]) = 0 OR kind = ANY($2))
             ORDER BY id DESC LIMIT $3",
        )
        .bind(attempt_id)
        .bind(&kinds)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map(|mut v: Vec<EventRow>| {
            v.reverse();
            v
        })?)
    }

    pub async fn count_events(&self, attempt_id: Uuid, kind: EventKind) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM session_events WHERE attempt_id = $1 AND kind = $2")
            .bind(attempt_id)
            .bind(kind.as_str())
            .fetch_one(&self.pool)
            .await?)
    }

    // ------------------------------------------------- targeted progress reads (V5b)

    /// Latest runnerd `Progress` event per requested category (one row per
    /// category at most). Indexed; replaces full-attempt scans in `refresh()`.
    pub async fn latest_runner_progress(
        &self,
        attempt_id: Uuid,
        categories: &[&str],
    ) -> Result<Vec<EventRow>> {
        Ok(sqlx::query_as(
            "SELECT DISTINCT ON ((data ->> 'category')) * FROM session_events
             WHERE attempt_id = $1 AND kind = 'Progress' AND source = 'runnerd'
               AND (data ->> 'category') = ANY($2)
             ORDER BY (data ->> 'category'), id DESC",
        )
        .bind(attempt_id)
        .bind(categories)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Earliest runnerd `Progress` event of one category (connection/base revision).
    pub async fn earliest_runner_progress(&self, attempt_id: Uuid, category: &str) -> Result<Option<EventRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM session_events
             WHERE attempt_id = $1 AND kind = 'Progress' AND source = 'runnerd'
               AND (data ->> 'category') = $2
             ORDER BY id ASC LIMIT 1",
        )
        .bind(attempt_id)
        .bind(category)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Latest terminal event (`AttemptCompleted`/`AttemptFailed`/`AttemptTimedOut`).
    pub async fn latest_terminal_event(&self, attempt_id: Uuid) -> Result<Option<EventRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM session_events
             WHERE attempt_id = $1 AND kind = ANY($2)
             ORDER BY id DESC LIMIT 1",
        )
        .bind(attempt_id)
        .bind(["AttemptCompleted", "AttemptFailed", "AttemptTimedOut"])
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Latest runnerd `Progress` event with `data.detail.<key> == value`
    /// (e.g. `snapshotId` for `wait_for_snapshot`). Progress payloads nest
    /// their fields under `detail`; narrowed by attempt+kind first.
    pub async fn progress_by_detail(
        &self,
        attempt_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<Option<EventRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM session_events
             WHERE attempt_id = $1 AND kind = 'Progress' AND source = 'runnerd'
               AND (data -> 'detail' ->> $2) = $3
             ORDER BY id DESC LIMIT 1",
        )
        .bind(attempt_id)
        .bind(key)
        .bind(value)
        .fetch_optional(&self.pool)
        .await?)
    }

    // ------------------------------------------- environment directives (V5a)

    /// Queue a provider directive for the attempt's sandbox. Returns the row id
    /// (used for ack + redelivery).
    pub async fn push_env_directive(
        &self,
        attempt_id: Uuid,
        directive: &acp_runner_core::events::RunnerDirective,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO environment_directives (id, attempt_id, directive) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(attempt_id)
            .bind(serde_json::to_value(directive).unwrap_or(Value::Null))
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    /// Oldest unacked directive due for delivery: never delivered, or delivered
    /// over `redeliver_after` ago without an ack (runnerd died mid-directive).
    /// Marks `delivered_at` atomically; `FOR UPDATE SKIP LOCKED` keeps parallel
    /// controller replicas from delivering the same row twice.
    pub async fn next_env_directive(
        &self,
        attempt_id: Uuid,
        redeliver_after: Duration,
    ) -> Result<Option<(Uuid, acp_runner_core::events::RunnerDirective)>> {
        let row: Option<(Uuid, Value)> = sqlx::query_as(
            "UPDATE environment_directives SET delivered_at = now()
             WHERE id = (
                 SELECT id FROM environment_directives
                 WHERE attempt_id = $1 AND acked_at IS NULL
                   AND (delivered_at IS NULL OR delivered_at < now() - $2::interval)
                 ORDER BY created_at, id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, directive",
        )
        .bind(attempt_id)
        .bind(interval(redeliver_after))
        .fetch_optional(&self.pool)
        .await?;
        row.map(|(id, v)| {
            serde_json::from_value(v)
                .map(|d| (id, d))
                .map_err(|e| JournalError::Invalid(format!("directive {id} is not valid JSON: {e}")))
        })
        .transpose()
    }

    /// Ack a delivered directive. Returns true when this call acked it.
    pub async fn ack_env_directive(&self, id: Uuid) -> Result<bool> {
        let r = sqlx::query("UPDATE environment_directives SET acked_at = now() WHERE id = $1 AND acked_at IS NULL")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Ack everything pending for the attempt (terminal hygiene: no redelivery
    /// to a sandbox that will never heartbeat again).
    pub async fn ack_env_directives_for_attempt(&self, attempt_id: Uuid) -> Result<u64> {
        let r = sqlx::query(
            "UPDATE environment_directives SET acked_at = now() WHERE attempt_id = $1 AND acked_at IS NULL",
        )
        .bind(attempt_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected())
    }

    /// Atomically claim the throttled journaled-heartbeat slot. Returns true
    /// when this caller won (replaces the ingest in-memory `hb_last` map, so
    /// the throttle works across controller replicas).
    pub async fn claim_heartbeat_journal(&self, attempt_id: Uuid, every: Duration) -> Result<bool> {
        let row: Option<Uuid> = sqlx::query_scalar(
            "UPDATE attempts SET last_heartbeat_journaled_at = now()
             WHERE id = $1
               AND (last_heartbeat_journaled_at IS NULL
                    OR last_heartbeat_journaled_at < now() - $2::interval)
             RETURNING id",
        )
        .bind(attempt_id)
        .bind(interval(every))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    // ------------------------------------------------------------------ credentials

    /// Insert or update a profile's non-secret record. A changed material fingerprint (re-
    /// enrollment) re-activates a profile flagged `needs_reauth`.
    pub async fn upsert_profile(&self, p: &ProfileUpsert) -> Result<()> {
        upsert_profile_inner(&self.pool, p).await
    }

    /// Open a profile-sync guard: lock the profile row (`FOR UPDATE`) so the
    /// caller can load fresh store data *after* the lock is held, then commit
    /// with [`ProfileSyncGuard::commit`]. Absent rows are inserted at commit.
    /// Lock order is profile-only (never lease-after-profile here), matching
    /// the profile-before-lease order of [`Journal::start_attempt`] and
    /// [`Journal::begin_writeback`].
    pub async fn begin_profile_sync(&self, name: &str) -> Result<ProfileSyncGuard> {
        let mut tx = self.pool.begin().await?;
        let _existing: Option<ProfileRow> =
            sqlx::query_as("SELECT * FROM credential_profiles WHERE name = $1 FOR UPDATE")
                .bind(name)
                .fetch_optional(&mut *tx)
                .await?;
        Ok(ProfileSyncGuard { tx })
    }

    pub async fn list_profiles(&self) -> Result<Vec<ProfileRow>> {
        Ok(sqlx::query_as("SELECT * FROM credential_profiles ORDER BY name").fetch_all(&self.pool).await?)
    }

    pub async fn get_profile(&self, name: &str) -> Result<Option<ProfileRow>> {
        Ok(sqlx::query_as("SELECT * FROM credential_profiles WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Admin assignment for V2 trust boundary: replace the profile's usage
    /// policy (namespaces × classes). Empty lists deny everything.
    pub async fn set_profile_policy(&self, name: &str, namespaces: &[String], classes: &[String]) -> Result<()> {
        sqlx::query(
            "UPDATE credential_profiles SET allowed_namespaces = $2, allowed_classes = $3, updated_at = now() WHERE name = $1",
        )
        .bind(name)
        .bind(namespaces)
        .bind(classes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_profile_status(&self, name: &str, status: &str, last_error: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE credential_profiles SET status = $2, last_error = $3, updated_at = now() WHERE name = $1")
            .bind(name)
            .bind(status)
            .bind(last_error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_profile(&self, name: &str) -> Result<()> {
        sqlx::query("UPDATE credential_profiles SET status = 'disabled', updated_at = now() WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_writeback(&self, name: &str, metadata: &Value, fingerprint: &str) -> Result<()> {
        sqlx::query(
            "UPDATE credential_profiles SET metadata = $2, material_fingerprint = $3, generation = generation + 1,
                 updated_at = now() WHERE name = $1",
        )
        .bind(name)
        .bind(metadata)
        .bind(fingerprint)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn lease_for_attempt(&self, attempt_id: Uuid) -> Result<Option<LeaseRow>> {
        Ok(sqlx::query_as("SELECT * FROM credential_leases WHERE attempt_id = $1")
            .bind(attempt_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Open a write-back guard: lock the profile row and then the attempt's
    /// lease row (both `FOR UPDATE`), returning them iff the attempt still
    /// holds an unexpired lease and the profile still exists. Lock order is
    /// profile-before-lease, matching [`Journal::start_attempt`], so a
    /// concurrent lease acquisition can never deadlock against a write-back.
    /// Both locks are held until [`WritebackGuard::commit_metadata`], so a
    /// concurrent lease release blocks instead of slipping between the check
    /// and the store update — and a concurrent `sync_profiles`/admin write
    /// cannot interleave a stale profile metadata/material_fingerprint over
    /// the committed write-back (lost update). Returns `Ok(None)` when there
    /// is no usable lease or the profile is gone.
    pub async fn begin_writeback(&self, attempt_id: Uuid, profile: &str) -> Result<Option<WritebackGuard>> {
        let mut tx = self.pool.begin().await?;
        let enrolled: Option<ProfileRow> =
            sqlx::query_as("SELECT * FROM credential_profiles WHERE name = $1 FOR UPDATE")
                .bind(profile)
                .fetch_optional(&mut *tx)
                .await?;
        let lease: Option<LeaseRow> =
            sqlx::query_as("SELECT * FROM credential_leases WHERE attempt_id = $1 FOR UPDATE")
                .bind(attempt_id)
                .fetch_optional(&mut *tx)
                .await?;
        let usable = lease.as_ref().is_some_and(|l| l.released_at.is_none() && l.expires_at > Utc::now());
        if !usable || enrolled.is_none() {
            tx.rollback().await?;
            return Ok(None);
        }
        Ok(Some(WritebackGuard { tx, lease: lease.expect("checked"), profile: enrolled.expect("checked") }))
    }

    /// Extend an active lease to at least `now + window` (never shortens it),
    /// capped at `cap` (V10c: a heartbeat must never push a lease past the
    /// sandbox's hard deadline). No cap (`None`) keeps the legacy behavior.
    pub async fn extend_lease(
        &self,
        attempt_id: Uuid,
        window: Duration,
        cap: Option<DateTime<Utc>>,
    ) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE credential_leases
             SET expires_at = LEAST(GREATEST(expires_at, now() + $2::interval), COALESCE($3, 'infinity'::timestamptz))
             WHERE attempt_id = $1 AND released_at IS NULL AND expires_at > now()",
        )
        .bind(attempt_id)
        .bind(interval(window))
        .bind(cap)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// All unreleased leases for a profile, newest first — including expired
    /// ones (V10c fencing inspects exactly those).
    pub async fn leases_for_profile(&self, profile: &str) -> Result<Vec<LeaseRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM credential_leases WHERE profile_name = $1 AND released_at IS NULL ORDER BY acquired_at DESC",
        )
        .bind(profile)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn release_lease(&self, attempt_id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE credential_leases SET released_at = now() WHERE attempt_id = $1 AND released_at IS NULL",
        )
        .bind(attempt_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn active_leases(&self) -> Result<Vec<LeaseRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM credential_leases WHERE released_at IS NULL AND expires_at > now() ORDER BY acquired_at",
        )
        .fetch_all(&self.pool)
        .await?)
    }
}

async fn insert_event(
    tx: &mut Transaction<'static, Postgres>,
    run_id: Uuid,
    attempt_id: Option<Uuid>,
    ev: &EventEnvelope,
) -> Result<bool> {
    let r = sqlx::query(
        "INSERT INTO session_events (run_id, attempt_id, seq, ts, kind, source, data, raw)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (attempt_id, seq) WHERE seq IS NOT NULL DO NOTHING",
    )
    .bind(run_id)
    .bind(attempt_id)
    .bind(ev.seq.map(|s| s as i64))
    .bind(ev.ts)
    .bind(ev.kind.as_str())
    .bind(ev.source.as_str())
    .bind(&ev.data)
    .bind(&ev.raw)
    .execute(&mut **tx)
    .await?;
    Ok(r.rows_affected() == 1)
}

#[cfg(test)]
mod tests;

// ---- environments (AgentEnvironment handles) ------------------------------------------

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EnvironmentRow {
    pub id: Uuid,
    pub external_ref: String,
    pub attempt_id: Uuid,
    pub run_id: Uuid,
    pub harness: String,
    pub phase: String,
    pub spec: Value,
    /// Unused since v3 (tickets are signed, not stored); kept for v2 rows.
    pub gateway_token_sha256: Option<String>,
    pub connection_ref: Option<Value>,
    pub base_revision: Option<String>,
    pub final_artifact_id: Option<Uuid>,
    pub failure_reason: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub parent_artifact_id: Option<Uuid>,
    pub parent_environment_id: Option<Uuid>,
    /// V10a: owning AgentEnvironment object, if controller-managed.
    pub k8s_namespace: Option<String>,
    pub k8s_name: Option<String>,
    pub k8s_uid: Option<String>,
    /// V10b: ticket master key version this environment's tickets use.
    pub key_version: String,
}

impl EnvironmentRow {
    pub fn phase(&self) -> acp_runner_core::EnvironmentPhase {
        self.phase.parse().unwrap_or(acp_runner_core::EnvironmentPhase::Failed)
    }
    pub fn failure(&self) -> Option<FailureReason> {
        self.failure_reason.clone().and_then(|v| serde_json::from_value(v).ok())
    }
}

#[derive(Debug, Clone)]
pub struct NewEnvironment {
    pub id: Uuid,
    pub external_ref: String,
    pub attempt_id: Uuid,
    pub run_id: Uuid,
    pub harness: String,
    pub spec: Value,
    pub parent_artifact_id: Option<Uuid>,
    pub parent_environment_id: Option<Uuid>,
    /// V10a: owning AgentEnvironment object (all three set together, or all None).
    pub k8s_namespace: Option<String>,
    pub k8s_name: Option<String>,
    pub k8s_uid: Option<String>,
    /// V10b: ticket master key version for this environment's tickets.
    pub key_version: String,
}

impl Journal {
    pub async fn create_environment(&self, new: &NewEnvironment) -> Result<EnvironmentRow> {
        Ok(sqlx::query_as(
            "INSERT INTO environments (id, external_ref, attempt_id, run_id, harness, phase, spec,
                                       parent_artifact_id, parent_environment_id,
                                       k8s_namespace, k8s_name, k8s_uid, key_version)
             VALUES ($1,$2,$3,$4,$5,'Creating',$6,$7,$8,$9,$10,$11,$12) RETURNING *",
        )
        .bind(new.id)
        .bind(&new.external_ref)
        .bind(new.attempt_id)
        .bind(new.run_id)
        .bind(&new.harness)
        .bind(&new.spec)
        .bind(new.parent_artifact_id)
        .bind(new.parent_environment_id)
        .bind(&new.k8s_namespace)
        .bind(&new.k8s_name)
        .bind(&new.k8s_uid)
        .bind(&new.key_version)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Live (non-terminal) controller-managed environment for a K8s object, if any (V10a).
    pub async fn live_environment_by_k8s(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<EnvironmentRow>> {
        Ok(sqlx::query_as(
            "SELECT * FROM environments
             WHERE k8s_namespace = $1 AND k8s_name = $2 AND phase NOT IN ('Completed', 'Failed')",
        )
        .bind(namespace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Delete an environment row (only after its sandbox and lease are released, e.g. a
    /// stale row for a deleted-then-recreated object; events and artifacts stay).
    pub async fn delete_environment(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM environments WHERE id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// The environment backed by `attempt_id`, if any.
    pub async fn environment_by_attempt(&self, attempt_id: Uuid) -> Result<Option<EnvironmentRow>> {
        Ok(sqlx::query_as("SELECT * FROM environments WHERE attempt_id = $1")
            .bind(attempt_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Store a resolved bundle (content-addressed; idempotent).
    pub async fn put_bundle(&self, b: &acp_runner_core::bundle::Bundle) -> Result<()> {
        sqlx::query(
            "INSERT INTO bundles (digest, kind, name, metadata, manifest, size_bytes, content)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (digest) DO NOTHING",
        )
        .bind(&b.digest)
        .bind(b.kind.as_str())
        .bind(&b.name)
        .bind(&b.metadata)
        .bind(b.manifest())
        .bind(b.size_bytes() as i64)
        .bind(serde_json::to_value(b).map_err(|e| JournalError::Invalid(e.to_string()))?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_bundle(&self, digest: &str) -> Result<Option<acp_runner_core::bundle::Bundle>> {
        let v: Option<(Value,)> = sqlx::query_as("SELECT content FROM bundles WHERE digest = $1")
            .bind(digest)
            .fetch_optional(&self.pool)
            .await?;
        v.map(|(v,)| serde_json::from_value(v).map_err(|e| JournalError::Invalid(format!("stored bundle: {e}"))))
            .transpose()
    }

    /// Artifacts produced by an environment's backing attempt(s), oldest first.
    pub async fn artifacts_for_environment(&self, environment_id: Uuid) -> Result<Vec<crate::ArtifactRow>> {
        Ok(sqlx::query_as(
            "SELECT id, run_id, attempt_id, kind, base_revision, sha256, size_bytes, changed_paths, driver, driver_version,
                    storage, external_uri, created_at, environment_id, parent_artifact_id, parent_environment_id
             FROM artifacts WHERE environment_id = $1 ORDER BY created_at",
        )
        .bind(environment_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get_environment(&self, id: Uuid) -> Result<Option<EnvironmentRow>> {
        Ok(sqlx::query_as("SELECT * FROM environments WHERE id = $1").bind(id).fetch_optional(&self.pool).await?)
    }

    pub async fn set_environment_phase(&self, id: Uuid, phase: &str, failure: Option<&FailureReason>) -> Result<()> {
        let failure = failure.map(|f| serde_json::to_value(f).unwrap_or(Value::Null));
        sqlx::query(
            "UPDATE environments SET phase = $2, failure_reason = COALESCE($3, failure_reason),
                 finished_at = CASE WHEN $2 IN ('Completed','Failed') THEN COALESCE(finished_at, now()) ELSE finished_at END,
                 updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(phase)
        .bind(failure)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_environment_connection(
        &self,
        id: Uuid,
        connection: &Value,
        base_revision: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE environments SET connection_ref = $2, base_revision = COALESCE($3, base_revision), updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(connection)
        .bind(base_revision)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_environment_final_artifact(
        &self,
        id: Uuid,
        artifact_id: Uuid,
        base_revision: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE environments SET final_artifact_id = $2, base_revision = COALESCE($3, base_revision), updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(artifact_id)
        .bind(base_revision)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
