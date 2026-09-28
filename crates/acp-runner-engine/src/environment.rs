//! The **agent environment provider**: `create / get / connect / snapshot / finish / cancel`.
//!
//! An environment is backed by one long-lived attempt (the execution unit, reused unchanged):
//! the engine writes an `AttemptSpec` with [`SessionMode::Environment`], creates a sandbox that
//! runs `runnerd` in environment mode, and tracks a durable [`EnvironmentRow`] handle.
//!
//! * **Data plane**: the caller speaks raw ACP to the harness through runnerd's gateway,
//!   authenticated with a signed, short-lived connection ticket from [`EnvironmentProvider::connect`]
//!   (see `acp_runner_core::ticket`). Tickets are derived from the provider master key and
//!   never stored: a restarted provider issues new tickets for environments that outlived it.
//! * **Control plane**: snapshot / branch / finish / cancel are provider operations, delivered
//!   to runnerd on the heartbeat channel.
//!
//! The caller never sees Kubernetes objects, PostgreSQL, the ingest token or provider
//! credentials.

use crate::backend::{RunKey, SandboxBackend, SandboxRequest, sandbox_name};
use crate::bundles::BundleProvider;
use crate::creds::CredentialStore;
use crate::harness::HarnessProvider;
use crate::ingest::IngestState;
use crate::{new_token, token_hash};
use acp_runner_core::attempt_spec::{
    AttemptOutput, AttemptSpec, BootstrapPlan, BundleMount, CredentialEnvLayout, CredentialFileLayout,
    CredentialLayout, DriverSpec, Lineage, OverlayRef, SessionMode,
};
use acp_runner_core::bundle::BundleKind;
use acp_runner_core::credentials::{CredentialMetadata, Provider};
use acp_runner_core::environment::{
    ArtifactPolicy, EnvironmentOverrides, EnvironmentPhase, EnvironmentSpec, WorkspaceOverlay, WorkspaceSource,
};
use acp_runner_core::events::{EventKind, EventSource, RunnerDirective};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::harness::{HarnessArtifactRef, bundle_placement, credential_provider};
use acp_runner_core::spec::{OutputKind, RepositoryInput, TimeoutPolicy};
use acp_runner_core::ticket;
use acp_runner_core::{RunPhase, WIRE_VERSION};
use acp_runner_journal::{
    ArtifactRow, ArtifactStore, Journal, LeaseRequest, NewAttempt, NewEnvironment, NewRun, StartAttempt,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub type Result<T> = anyhow::Result<T>;

/// Configuration for the provider.
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    pub controller_id: String,
    pub ingest_url: String,
    /// Address runnerd binds the gateway on inside the sandbox. `127.0.0.1:0` (local backend,
    /// runnerd reports the bound port) or `0.0.0.0:<port>` (pod, exposed by a Service).
    pub gateway_listen: String,
    pub require_egress_proxy_for_credentials: bool,
    /// Runner image for the pod backend (ignored by the local backend).
    pub runner_image: String,
    /// V2: exact image strings allowed when the environment holds credentials.
    pub allowed_images: Vec<String>,
    /// V2: service accounts credentialed environments may use.
    pub allowed_service_accounts: Vec<String>,
    /// Master keys for connection tickets. Keep them stable across provider
    /// restarts (a Secret) so live environments stay connectable.
    pub ticket_keys: TicketKeyRing,
    /// Lifetime of issued connection tickets.
    pub ticket_ttl_seconds: i64,
}

/// The provider's ticket master key (never printed).
#[derive(Clone)]
pub struct TicketKey(Arc<Vec<u8>>);

impl TicketKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<TicketKey> {
        anyhow::ensure!(
            bytes.len() >= ticket::MIN_MASTER_KEY_BYTES,
            "ticket master key must be at least {} bytes",
            ticket::MIN_MASTER_KEY_BYTES
        );
        Ok(TicketKey(Arc::new(bytes)))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    /// Load the master key from a file (e.g. a mounted Secret; raw bytes or hex).
    pub fn from_file(path: &std::path::Path) -> Result<TicketKey> {
        let raw = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&raw);
        let bytes = match hex::decode(text.trim()) {
            Ok(b) if !b.is_empty() => b,
            _ => raw,
        };
        Self::from_bytes(bytes)
    }
}

impl std::fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TicketKey(<redacted>)")
    }
}

/// A random master key (tests / single-process development; not restart-safe).
pub fn random_ticket_key() -> TicketKey {
    let mut k = Uuid::new_v4().as_bytes().to_vec();
    k.extend_from_slice(Uuid::new_v4().as_bytes());
    k.extend_from_slice(Uuid::new_v4().as_bytes());
    TicketKey(Arc::new(k))
}

/// Ticket master key ring (V10b): `current` mints tickets for new environments;
/// `previous` (at most one, only during rotation) still mints for environments
/// created under it. runnerd only ever sees the derived per-environment key, so
/// rotation is transparent to running sandboxes: existing environments keep
/// working until they end, and only the retired key stops minting.
#[derive(Debug, Clone)]
pub struct TicketKeyRing {
    current: (String, TicketKey),
    previous: Option<(String, TicketKey)>,
}

impl TicketKeyRing {
    /// Deterministic version id: first 8 hex chars of sha256(master), so every
    /// replica loading the same Secret files agrees on versions without config.
    pub fn id_for(key: &TicketKey) -> String {
        hex::encode(Sha256::digest(key.bytes()))[..16].to_string()
    }

    pub fn new(current: TicketKey) -> Self {
        let id = Self::id_for(&current);
        TicketKeyRing { current: (id, current), previous: None }
    }

    /// Single-key ring for tests / development (a random key, not restart-safe).
    pub fn ephemeral() -> Self {
        Self::new(random_ticket_key())
    }

    /// Rotation: keep minting for environments created under `prev`. A `prev`
    /// identical to `current` is ignored.
    pub fn with_previous(mut self, prev: TicketKey) -> Self {
        let id = Self::id_for(&prev);
        if id != self.current.0 {
            self.previous = Some((id, prev));
        }
        self
    }

    pub fn current(&self) -> (&str, &TicketKey) {
        (self.current.0.as_str(), &self.current.1)
    }

    pub fn key_for(&self, version: &str) -> Option<&TicketKey> {
        if version == self.current.0 {
            return Some(&self.current.1);
        }
        self.previous.as_ref().filter(|(id, _)| id == version).map(|(_, k)| k)
    }
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        EnvironmentConfig {
            controller_id: "acp-runner-env".into(),
            ingest_url: "http://127.0.0.1:8081".into(),
            gateway_listen: "127.0.0.1:0".into(),
            require_egress_proxy_for_credentials: true,
            runner_image: "acp-runner/runner:dev".into(),
            allowed_images: vec![],
            allowed_service_accounts: vec![
                acp_runner_core::spec::DEFAULT_AGENT_SERVICE_ACCOUNT.to_string(),
            ],
            ticket_keys: TicketKeyRing::ephemeral(),
            ticket_ttl_seconds: ticket::DEFAULT_TICKET_TTL_SECONDS,
        }
    }
}

pub struct EnvironmentProvider {
    pub journal: Journal,
    pub backend: Arc<dyn SandboxBackend>,
    pub creds: Arc<dyn CredentialStore>,
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Shared with the running ingest server so directives reach runnerd's heartbeats.
    pub ingest: Arc<IngestState>,
    pub cfg: EnvironmentConfig,
    /// Resolves `configs` / `agents` / `skills` / `bootstrap.files` references.
    pub bundles: Option<Arc<dyn BundleProvider>>,
    /// Resolves pinned harness artifacts (one runtime image; harness materialized at bootstrap).
    pub harnesses: Option<Arc<dyn HarnessProvider>>,
}

/// Typed provider errors callers may want to branch on.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The exclusive credential profile is leased by another live environment/attempt.
    #[error("credential profile {profile} is in use: {detail}")]
    CredentialBusy { profile: String, detail: String },
    #[error("invalid environment spec: {0}")]
    InvalidSpec(String),
}

/// The caller-visible view of an environment (no secret material).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentView {
    pub id: Uuid,
    pub external_ref: String,
    pub harness: String,
    pub phase: EnvironmentPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    /// Harness working directory relative to the workspace root (`""` = root).
    pub workdir: String,
    /// Reference only — where the gateway is reachable; never a ticket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionRef>,
    #[serde(skip_serializing_if = "Lineage::is_empty")]
    pub lineage: Lineage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_artifact_id: Option<Uuid>,
    pub snapshots: Vec<SnapshotRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureReason>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionRef {
    /// `host:port` of the ACP gateway.
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRef {
    pub artifact_id: Uuid,
    pub sha256: String,
    pub changed_paths: usize,
}

/// What `connect` returns: where the gateway is and a signed, short-lived ticket for it —
/// distinct from the ingest token and from provider (Claude/Codex) credentials.
#[derive(Clone)]
pub struct Connection {
    pub environment_id: Uuid,
    /// `host:port` of the gateway.
    pub gateway: String,
    /// Connection ticket (`Authorization: Bearer`), single-use, expires at `expires_at`.
    pub ticket: String,
    /// Unix seconds.
    pub expires_at: i64,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("environment_id", &self.environment_id)
            .field("gateway", &self.gateway)
            .field("ticket", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Artifact kinds that may be used as workspace overlays (all cumulative vs. their base).
const OVERLAY_KINDS: &[&str] = &["snapshot", "final", "partial_final", "patch", "partial_patch"];

/// Resolved workspace: original source (None = empty base), verified overlays, lineage.
struct ResolvedWorkspace {
    source: Option<RepositoryInput>,
    overlays: Vec<OverlayRef>,
    lineage: Lineage,
}

/// Owning Kubernetes object for a controller-managed environment (V10a): the
/// sandbox runs in the object's namespace and the journal row is mapped by
/// (namespace, name) with the UID guarding against name reuse.
#[derive(Debug, Clone)]
pub struct K8sOwner {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

impl EnvironmentProvider {
    pub fn new(
        journal: Journal,
        backend: Arc<dyn SandboxBackend>,
        creds: Arc<dyn CredentialStore>,
        artifacts: Arc<dyn ArtifactStore>,
        ingest: Arc<IngestState>,
        cfg: EnvironmentConfig,
    ) -> Self {
        EnvironmentProvider { journal, backend, creds, artifacts, ingest, cfg, bundles: None, harnesses: None }
    }

    pub fn with_bundles(mut self, b: Arc<dyn BundleProvider>) -> Self {
        self.bundles = Some(b);
        self
    }

    /// The same provider must also be given to the ingest server
    /// ([`IngestState::with_harnesses`]) so runnerd can download the pinned artifact.
    pub fn with_harnesses(mut self, h: Arc<dyn HarnessProvider>) -> Self {
        self.harnesses = Some(h);
        self
    }

    fn env_key(&self, env_id: Uuid) -> Result<[u8; 32]> {
        let (_, key) = self.cfg.ticket_keys.current();
        ticket::derive_env_key(key.bytes(), env_id).map_err(|e| anyhow::anyhow!("ticket key: {e}"))
    }

    /// Issue a fresh connection ticket for a live environment (no provider state involved).
    pub fn issue_ticket(&self, env_id: Uuid) -> Result<(String, i64)> {
        let now = chrono::Utc::now().timestamp();
        let claims = ticket::claims_for(env_id, now, self.cfg.ticket_ttl_seconds);
        let exp = claims.exp;
        Ok((ticket::issue(&self.env_key(env_id)?, &claims), exp))
    }

    /// Mint with the master key version the environment was created under (V10b):
    /// existing environments keep working across rotation; a retired version is a
    /// clear error (recreate the environment), never a wrong-key ticket.
    fn issue_ticket_for_version(&self, env_id: Uuid, version: &str) -> Result<(String, i64)> {
        let key = self.cfg.ticket_keys.key_for(version).ok_or_else(|| {
            anyhow::anyhow!("ticket key version {version} is retired; recreate the environment")
        })?;
        let derived =
            ticket::derive_env_key(key.bytes(), env_id).map_err(|e| anyhow::anyhow!("ticket key: {e}"))?;
        let now = chrono::Utc::now().timestamp();
        let claims = ticket::claims_for(env_id, now, self.cfg.ticket_ttl_seconds);
        let exp = claims.exp;
        Ok((ticket::issue(&derived, &claims), exp))
    }

    fn runner_class(&self, spec: &EnvironmentSpec, driver: &str) -> acp_runner_core::spec::RunnerClassSpec {
        acp_runner_core::spec::RunnerClassSpec {
            name: format!("env-{}", spec.harness.name),
            driver: driver.to_string(),
            driver_config: spec.harness.config.clone(),
            image: self.cfg.runner_image.clone(),
            image_pull_policy: None,
            runtime_class_name: spec.runtime_class_name.clone(),
            resources: spec.resources.clone(),
            credentials: acp_runner_core::spec::CredentialRequirement {
                provider: spec.credentials.profile.as_ref().map(|_| spec.harness.name.clone()),
                profiles: spec.credentials.profile.clone().into_iter().collect(),
                file_targets: spec.credentials.file_targets.clone(),
            },
            workspace: spec.workspace.policy.clone(),
            timeouts: Self::timeouts(spec),
            permissions: spec.permissions,
            egress: spec.egress.clone(),
            env: spec.env.clone(),
            // Environment callers set the harness config directly; there is no
            // run-overrides layer in the environment API (V9.3).
            allow_run_overrides: false,
            run_as_user: None,
            service_account_name: None,
        }
    }

    fn timeouts(spec: &EnvironmentSpec) -> TimeoutPolicy {
        let mut t = TimeoutPolicy::default().with_overrides(&spec.timeouts);
        // An environment lives as long as its lifetime policy says; the hard timeout is only
        // a backstop above it.
        if let Some(max) = spec.lifetime.max_seconds {
            t.hard_seconds = t.hard_seconds.max(max + t.grace_seconds);
        }
        t
    }

    fn credential_layout(spec: &EnvironmentSpec, provider: Provider, profile: &str) -> CredentialLayout {
        let s = provider.spec();
        CredentialLayout {
            provider: provider.as_str().to_string(),
            profile: profile.to_string(),
            files: s
                .files
                .iter()
                .map(|f| CredentialFileLayout {
                    key: f.key.to_string(),
                    target: spec
                        .credentials
                        .file_targets
                        .get(f.key)
                        .cloned()
                        .unwrap_or_else(|| f.default_target.to_string()),
                    mode: f.mode,
                    writeback: f.writeback,
                })
                .collect(),
            env: s
                .env
                .iter()
                .map(|e| CredentialEnvLayout { key: e.key.to_string(), env_name: e.env_name.to_string() })
                .collect(),
        }
    }

    /// 1. resolve harness: a pinned, digest-verified artifact when a harness provider knows
    ///    `name@version`; otherwise the harness installed in the runtime image.
    async fn resolve_harness(&self, spec: &EnvironmentSpec) -> Result<Option<HarnessArtifactRef>> {
        let h = &spec.harness;
        let resolved = match (&self.harnesses, &h.version) {
            (Some(hp), Some(v)) => Some(hp.resolve(&h.name, v).await?),
            _ => None,
        };
        match (&resolved, &h.digest) {
            (Some(r), Some(pin)) if &r.digest != pin => {
                anyhow::bail!("harness {} {:?} resolved to {} but the spec pins {pin}", h.name, h.version, r.digest)
            }
            (None, Some(pin)) => {
                anyhow::bail!("harness digest {pin} is pinned but no harness provider can resolve {}", h.name)
            }
            _ => Ok(resolved),
        }
    }

    /// Original source + base of an artifact (the environment or run that produced it).
    async fn origin_of(&self, meta: &ArtifactRow) -> Result<(Option<RepositoryInput>, Option<Uuid>)> {
        if let Some(env) = self.journal.environment_by_attempt(meta.attempt_id).await? {
            let spec: EnvironmentSpec = serde_json::from_value(env.spec.clone())?;
            return Ok((spec.source_repository().cloned(), Some(env.id)));
        }
        let run = self.journal.get_run(meta.run_id).await?;
        let rs: acp_runner_core::spec::RunSpec = serde_json::from_value(run.spec.clone())
            .map_err(|e| anyhow::anyhow!("artifact {} has no resolvable origin: {e}", meta.id))?;
        Ok((Some(rs.repository), None))
    }

    /// 2+3. checkout BASE + overlays: fetch artifact metadata, verify the content hash,
    ///      resolve the original repository/base, pin the source to that base.
    async fn resolve_workspace(&self, spec: &EnvironmentSpec) -> Result<ResolvedWorkspace> {
        if spec.workspace.overlays.is_empty() {
            return Ok(ResolvedWorkspace {
                source: spec.source_repository().cloned(),
                overlays: vec![],
                lineage: Lineage::default(),
            });
        }
        let mut overlays = vec![];
        let mut origin: Option<(Option<RepositoryInput>, String)> = None;
        let mut lineage = Lineage::default();
        for o in &spec.workspace.overlays {
            let id = o.artifact_id();
            let meta = self.artifacts.get_meta(id).await.map_err(|e| anyhow::anyhow!("overlay {id}: {e}"))?;
            anyhow::ensure!(
                OVERLAY_KINDS.contains(&meta.kind.as_str()),
                "overlay {id}: artifact kind {} cannot be overlaid",
                meta.kind
            );
            // get_content verifies the stored content against the recorded sha256.
            let content = self.artifacts.get_content(id).await.map_err(|e| anyhow::anyhow!("overlay {id}: {e}"))?;
            anyhow::ensure!(hex::encode(Sha256::digest(&content)) == meta.sha256, "overlay {id}: hash mismatch");
            let (src, parent_env) = self.origin_of(&meta).await?;
            match &origin {
                None => origin = Some((src, meta.base_revision.clone())),
                Some((_, base)) => anyhow::ensure!(
                    base.eq_ignore_ascii_case(&meta.base_revision),
                    "overlays are relative to different bases ({base} vs {})",
                    meta.base_revision
                ),
            }
            lineage = Lineage { parent_artifact_id: Some(id), parent_environment_id: parent_env };
            overlays.push(OverlayRef {
                artifact_id: id,
                sha256: meta.sha256.clone(),
                base_revision: meta.base_revision.clone(),
                size_bytes: meta.size_bytes.max(0) as u64,
            });
        }
        let (origin_src, base) = origin.expect("at least one overlay");
        let source = match (spec.source_repository(), origin_src) {
            (Some(explicit), _) => {
                anyhow::ensure!(
                    explicit.revision.eq_ignore_ascii_case(&base),
                    "workspace.source revision {} is not the overlays' base {base}",
                    explicit.revision
                );
                Some(explicit.clone())
            }
            // pin the original repository to the exact base the artifacts are relative to
            (None, Some(mut r)) => {
                r.revision = base;
                Some(r)
            }
            (None, None) => None, // empty-base origin (inference-only environment)
        };
        Ok(ResolvedWorkspace { source, overlays, lineage })
    }

    /// 4. configs/agents/skills + bootstrap.files: resolve, store (content-addressed), place
    ///    per the harness layout.
    async fn resolve_bundles(&self, spec: &EnvironmentSpec, layout: &str, workdir: &str) -> Result<Vec<BundleMount>> {
        let mut refs: Vec<(BundleKind, String)> = vec![];
        refs.extend(spec.configs.iter().map(|n| (BundleKind::Config, n.clone())));
        refs.extend(spec.agents.iter().map(|n| (BundleKind::Agent, n.clone())));
        refs.extend(spec.skills.iter().map(|n| (BundleKind::Skill, n.clone())));
        if refs.is_empty() && spec.bootstrap.files.is_empty() {
            return Ok(vec![]);
        }
        let bp = self
            .bundles
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("bundles referenced but no bundle provider configured"))?;
        let mut mounts = vec![];
        for (kind, name) in refs {
            let b = bp.resolve(kind, &name).await?;
            self.journal.put_bundle(&b).await?;
            let p = bundle_placement(layout, kind, &name, workdir);
            mounts.push(BundleMount {
                digest: b.digest,
                kind,
                name,
                root: p.root,
                dir: p.dir,
                file: None,
                exclude_from_artifact: true,
            });
        }
        for f in &spec.bootstrap.files {
            let kind = f.kind.unwrap_or(BundleKind::Config);
            let b = bp.resolve(kind, &f.bundle).await?;
            self.journal.put_bundle(&b).await?;
            let single = b.files.len() == 1;
            mounts.push(BundleMount {
                digest: b.digest,
                kind,
                name: f.bundle.clone(),
                root: f.target.root,
                dir: if single { String::new() } else { f.target.path.clone() },
                file: single.then(|| f.target.path.clone()),
                exclude_from_artifact: f.artifact_policy == ArtifactPolicy::Exclude,
            });
        }
        Ok(mounts)
    }

    /// Create and bootstrap an environment. Returns immediately with phase `Creating`.
    ///
    /// Bootstrap order (trusted steps here and in runnerd, untrusted in agentd):
    /// resolve harness → checkout BASE → apply overlays → materialize configs/agents/skills →
    /// lease + materialize credentials → validate workdir → untrusted `bootstrap.exec` →
    /// launch harness → Ready → authenticated raw ACP.
    pub async fn create(&self, spec: EnvironmentSpec) -> Result<EnvironmentView> {
        self.create_inner(spec, None).await
    }

    /// `create` for a controller-managed `AgentEnvironment`: the sandbox (and its
    /// gateway Service/NetworkPolicy) lives in the object's namespace.
    pub async fn create_namespaced(
        &self,
        spec: EnvironmentSpec,
        owner: K8sOwner,
    ) -> Result<EnvironmentView> {
        self.create_inner(spec, Some(owner)).await
    }

    async fn create_inner(&self, spec: EnvironmentSpec, owner: Option<K8sOwner>) -> Result<EnvironmentView> {
        spec.validate().map_err(|e| ProviderError::InvalidSpec(e.to_string()))?;
        if self.cfg.require_egress_proxy_for_credentials
            && spec.uses_credentials()
            && spec.egress.effective_mode() != acp_runner_core::spec::EgressMode::Proxy
        {
            anyhow::bail!(
                "environment uses persistent credentials but egress.mode is not proxy; set egress.mode: proxy"
            );
        }
        // V2 trust boundary (admission, before any lease): credentialed
        // environments run only on an allowlisted digest-pinned image.
        if spec.credentials.profile.is_some() {
            acp_runner_core::spec::validate_credentialed_image(&self.cfg.runner_image, &self.cfg.allowed_images)
                .map_err(|e| anyhow::anyhow!("credentialed environment: {e}"))?;
            acp_runner_core::spec::resolve_service_account(None, &self.cfg.allowed_service_accounts)
                .map_err(|e| anyhow::anyhow!("credentialed environment: {e}"))?;
        }
        let workdir = spec.workdir()?;
        let harness = self.resolve_harness(&spec).await?;
        let driver = harness.as_ref().map(|h| h.adapter.clone()).unwrap_or_else(|| spec.harness.name.clone());
        let ws = self.resolve_workspace(&spec).await?;
        let mounts = self.resolve_bundles(&spec, &driver, &workdir).await?;
        let provider = match spec.credentials.profile.as_deref() {
            Some(_) => Some(
                credential_provider(&driver)
                    .ok_or_else(|| anyhow::anyhow!("harness {driver} has no credential layout"))?,
            ),
            None => None,
        };
        // The stored spec records the resolved origin (source pinned to the overlays' base).
        let mut stored = spec.clone();
        stored.repository = None;
        stored.workspace.source = ws.source.clone().map(WorkspaceSource::Git);

        let env_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let ingest_token = new_token();
        let gateway_key = self.env_key(env_id)?;
        let t = Self::timeouts(&spec);
        // V10a: controller-managed environments are keyed by their owning object.
        // Every `create` mints a fresh run row (`uid/env_id`): a failed create
        // (backend error, crash) leaves an orphan run behind, and the
        // controller's retry must not collide with its attempt ordinals.
        // Adoption after a restart uses the environment row, never the run.
        // Direct API use keeps the synthetic `environments` scope.
        let (run_ns, run_name, run_uid) = match &owner {
            Some(o) => (o.namespace.clone(), o.name.clone(), format!("{}/{}", o.uid, env_id)),
            None => (
                "environments".to_string(),
                format!("env-{}", &env_id.simple().to_string()[..12]),
                env_id.to_string(),
            ),
        };
        let (run, _) = self
            .journal
            .ensure_run(&NewRun {
                id: Uuid::now_v7(),
                k8s_namespace: run_ns.clone(),
                k8s_name: run_name,
                k8s_uid: run_uid,
                task_id: spec.external_ref.clone(),
                spec: serde_json::to_value(&stored)?,
            })
            .await?;
        let empty_source = ws.source.is_none();
        let plan = BootstrapPlan {
            workdir: workdir.clone(),
            empty_source,
            overlays: ws.overlays,
            bundles: mounts,
            exec: spec.bootstrap.exec.clone(),
            include_exec_changes: spec.bootstrap.exec_artifact_policy == ArtifactPolicy::Include,
            harness: harness.clone(),
            lineage: ws.lineage,
            produce_artifact: spec.produces_artifact(),
        };
        let mut attempt_spec = AttemptSpec {
            wire_version: WIRE_VERSION,
            run_id: run.id,
            attempt_id,
            task_id: spec.external_ref.clone(),
            ordinal: 1,
            class_attempt: 1,
            runner_class: format!("env-{}", spec.harness.name),
            driver: DriverSpec { name: driver.clone(), config: spec.harness.config.clone() },
            repository: ws.source.clone().unwrap_or_else(|| RepositoryInput {
                url: "empty:".into(),
                revision: "empty".into(),
                sparse_paths: vec![],
                depth: None,
            }),
            prompt: String::new(),
            capsule: None,
            apply_patch_b64: None,
            output: AttemptOutput {
                kind: if spec.produces_artifact() { OutputKind::Patch } else { OutputKind::None },
                require_changes: false,
                max_patch_bytes: spec.workspace.policy.max_patch_bytes,
                allowed_paths: spec.workspace.policy.allowed_paths.clone(),
                // Environment specs have no per-run submodule knob: deny by default (V6).
                allow_submodules: false,
            },
            timeouts: t,
            permissions: spec.permissions,
            egress: spec.egress.clone(),
            credentials: provider.map(|p| Self::credential_layout(&spec, p, "<leased>")),
            record_raw_payloads: spec.record_raw_payloads,
            env: spec.env.clone(),
            session: SessionMode::Environment {
                environment_id: env_id,
                gateway_listen: self.cfg.gateway_listen.clone(),
                idle_timeout_seconds: spec.idle_seconds(),
                max_lifetime_seconds: spec.lifetime.max_seconds,
            },
            bootstrap: plan,
        };
        // Credential lease for the environment's lifetime (not per turn): acquired now,
        // renewed by runnerd's heartbeats, released after the validated write-back at the end.
        let lease = provider.map(|p| LeaseRequest {
            provider: p.as_str().to_string(),
            candidates: spec.credentials.profile.clone().into_iter().collect(),
            holder: format!("{}/env/{env_id}", self.cfg.controller_id),
            // V10c: the lease spans the sandbox's hard deadline (heartbeat only
            // extends it optimistically, capped at the deadline in extend_lease).
            ttl: t.hard_deadline(),
        });
        let new_attempt = NewAttempt {
            id: attempt_id,
            run_id: run.id,
            ordinal: 1,
            class_index: 0,
            class_attempt: 1,
            runner_class: attempt_spec.runner_class.clone(),
            driver: driver.clone(),
            spec: serde_json::to_value(&attempt_spec)?,
            ingest_token_hash: token_hash(&ingest_token),
            lease_owner: self.cfg.controller_id.clone(),
            lease_ttl: Duration::from_secs(t.hard_seconds + t.startup_seconds + 3 * t.grace_seconds + 600),
        };
        let leased_profile = match self.journal.start_attempt(&new_attempt, lease.as_ref()).await? {
            StartAttempt::Started { lease, .. } => lease.map(|l| l.profile_name),
            StartAttempt::NoCredentialAvailable { detail } => {
                let _ = self.journal.set_run_phase(run.id, RunPhase::Failed, None, None).await;
                return Err(ProviderError::CredentialBusy {
                    profile: spec.credentials.profile.clone().unwrap_or_default(),
                    detail,
                }
                .into());
            }
            StartAttempt::CredentialUnusable { detail } => {
                let _ = self.journal.set_run_phase(run.id, RunPhase::Failed, None, None).await;
                anyhow::bail!("credential profile unusable: {detail}");
            }
        };
        // V10c fencing: an exclusive profile is not shared with a live
        // sandbox — a previous holder whose lease lapsed but whose sandbox is
        // still observed live is terminated first (fail closed on doubt).
        if let Some(profile) = &leased_profile
            && let Err(e) =
                crate::backend::fence_exclusive_lease(&self.journal, self.backend.as_ref(), profile, attempt_id)
                    .await
        {
            let _ = self.journal.release_lease(attempt_id).await;
            let reason = FailureReason::CredentialUnavailable { detail: e.to_string() };
            let _ = self
                .journal
                .transition_attempt(
                    attempt_id,
                    &acp_runner_core::AttemptPhase::ACTIVE,
                    acp_runner_core::AttemptPhase::Failed,
                    Some(&reason),
                    None,
                )
                .await;
            return Err(ProviderError::CredentialBusy { profile: profile.clone(), detail: e.to_string() }.into());
        }
        if let (Some(p), Some(profile)) = (provider, &leased_profile) {
            let mut layout = Self::credential_layout(&spec, p, profile);
            // 1c: only the `chatgpt` mode writes back (see engine lib.rs).
            if p == Provider::Codex {
                let writable = self
                    .journal
                    .get_profile(profile)
                    .await?
                    .and_then(|pr| serde_json::from_value::<CredentialMetadata>(pr.metadata).ok())
                    .is_some_and(|md| md.auth_kind == "chatgpt");
                if !writable {
                    for f in &mut layout.files {
                        f.writeback = false;
                    }
                }
            }
            attempt_spec.credentials = Some(layout);
            self.journal.update_attempt_spec(attempt_id, &serde_json::to_value(&attempt_spec)?).await?;
        }
        self.journal
            .transition_attempt(
                attempt_id,
                &[acp_runner_core::AttemptPhase::Pending],
                acp_runner_core::AttemptPhase::Running,
                None,
                None,
            )
            .await?;
        let env_row = self
            .journal
            .create_environment(&NewEnvironment {
                id: env_id,
                external_ref: spec.external_ref.clone(),
                attempt_id,
                run_id: run.id,
                harness: spec.harness.name.clone(),
                spec: serde_json::to_value(&stored)?,
                parent_artifact_id: attempt_spec.bootstrap.lineage.parent_artifact_id,
                parent_environment_id: attempt_spec.bootstrap.lineage.parent_environment_id,
                k8s_namespace: owner.as_ref().map(|o| o.namespace.clone()),
                k8s_name: owner.as_ref().map(|o| o.name.clone()),
                k8s_uid: owner.as_ref().map(|o| o.uid.clone()),
                key_version: self.cfg.ticket_keys.current().0.to_string(),
            })
            .await?;

        // Credential material (the leased profile) and the sandbox running runnerd env mode.
        let mut credential_files = BTreeMap::new();
        if let Some(profile) = &leased_profile {
            match self.creds.load(profile).await {
                Ok((_p, bundle)) => credential_files = bundle,
                Err(e) => {
                    let reason = FailureReason::CredentialUnavailable { detail: format!("{profile}: {e}") };
                    self.journal.set_environment_phase(env_id, "Failed", Some(&reason)).await?;
                    self.finalize(&env_row).await;
                    anyhow::bail!("loading credential profile {profile}: {e}");
                }
            }
        }
        let req = SandboxRequest {
            run_key: RunKey { namespace: run_ns, name: run.k8s_name.clone(), uid: env_id.to_string() },
            run_id: run.id,
            attempt_id,
            ordinal: 1,
            name: sandbox_name(&run.k8s_name, 1, attempt_id),
            class: self.runner_class(&spec, &driver),
            ingest_url: self.cfg.ingest_url.clone(),
            token: ingest_token,
            credential_files,
            runner_secret_files: BTreeMap::from([(
                acp_runner_core::attempt_spec::GATEWAY_KEY_FILE_NAME.to_string(),
                hex::encode(gateway_key).into_bytes(),
            )]),
            timeouts: t,
        };
        match self.backend.create(&req).await {
            Ok(sref) => self.journal.set_attempt_sandbox(attempt_id, &serde_json::to_value(&sref)?).await?,
            Err(e) => {
                let reason = FailureReason::SandboxFailed { detail: e.to_string() };
                self.journal.set_environment_phase(env_id, "Failed", Some(&reason)).await?;
                self.finalize(&env_row).await;
                anyhow::bail!("creating the environment sandbox: {e}");
            }
        }
        self.view_from(env_row).await
    }

    /// `branch(artifact, overrides)`: a new environment whose workspace is the original
    /// base + that artifact, with the origin environment's configuration unless overridden.
    /// Convenience over `create` with `workspace.overlays: [{type: patchArtifact, …}]`.
    pub async fn branch(&self, artifact_id: Uuid, overrides: EnvironmentOverrides) -> Result<EnvironmentView> {
        let meta =
            self.artifacts.get_meta(artifact_id).await.map_err(|e| anyhow::anyhow!("artifact {artifact_id}: {e}"))?;
        let base = match self.journal.environment_by_attempt(meta.attempt_id).await? {
            Some(env) => serde_json::from_value::<EnvironmentSpec>(env.spec)?,
            None => {
                let harness = overrides
                    .harness
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("branching a run artifact needs overrides.harness"))?;
                EnvironmentSpec::new(&format!("run-{}", meta.run_id), harness, None)
            }
        };
        let short = &artifact_id.simple().to_string()[24..];
        let mut spec = base.clone().with_overrides(&overrides);
        if overrides.external_ref.is_none() {
            spec.external_ref = format!("{}~{short}", base.external_ref);
        }
        spec.repository = None;
        spec.workspace.source = None; // resolved from the artifact's origin and pinned to its base
        spec.workspace.overlays = vec![WorkspaceOverlay::PatchArtifact { artifact_id }];
        self.create(spec).await
    }

    /// Release what an ended environment holds: sandbox and credential lease (after the
    /// validated write-back, which runnerd performs before reporting the terminal state).
    async fn finalize(&self, env: &acp_runner_journal::EnvironmentRow) {
        if let Ok(a) = self.journal.get_attempt(env.attempt_id).await
            && a.sandbox_released_at.is_none()
            && let Some(sref) = a.sandbox_ref.clone()
            && let Ok(sref) = serde_json::from_value(sref)
        {
            let _ = self.backend.terminate(&sref, Duration::from_secs(env_terminate_grace())).await;
            let _ = self.journal.mark_sandbox_released(env.attempt_id).await;
        }
        if let Ok(true) = self.journal.release_lease(env.attempt_id).await {
            tracing::debug!(environment_id = %env.id, "credential lease released");
        }
    }

    /// Derive the environment phase from the journal (events) and persist it.
    async fn refresh(&self, env_id: Uuid) -> Result<()> {
        let Some(env) = self.journal.get_environment(env_id).await? else { return Ok(()) };
        if env.phase().is_terminal() {
            self.finalize(&env).await;
            return Ok(());
        }
        // Targeted indexed reads (V5b): no full-attempt scan. Earliest-match
        // for connection/base (same as the old first-match scan), latest for
        // terminal/phase (same as the old last-match scan).
        // connection ref: from the runnerd-sourced gateway_listening event only (V3b).
        if env.connection_ref.is_none()
            && let Some(row) = self.journal.earliest_runner_progress(env.attempt_id, "gateway_listening").await?
            && let Some(addr) = gateway_addr(&row.data)
        {
            let base = self
                .journal
                .earliest_runner_progress(env.attempt_id, "workspace_ready")
                .await?
                .and_then(|r| base_revision(&r.data));
            self.journal.set_environment_connection(env_id, &json!({"gateway": addr}), base.as_deref()).await?;
        }
        // terminal?
        if let Some(term) = self.journal.latest_terminal_event(env.attempt_id).await? {
            let mut phase = if term.kind == "AttemptCompleted" { "Completed" } else { "Failed" };
            let mut reason =
                term.data.get("reason").and_then(|r| serde_json::from_value::<FailureReason>(r.clone()).ok());
            if let Some(id) = term.data.get("finalArtifactId").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()) {
                // V3a: the final artifact must belong to this attempt (attempt and run).
                match self.artifacts.get_meta(id).await {
                    Ok(meta) if meta.attempt_id == env.attempt_id && meta.run_id == env.run_id => {
                        self.journal.set_environment_final_artifact(env_id, id, None).await?;
                    }
                    _ => {
                        tracing::warn!(environment_id = %env_id, artifact_id = %id, "final artifact does not belong to this environment attempt");
                        phase = "Failed";
                        reason = Some(FailureReason::ProtocolError {
                            detail: format!("final artifact {id} does not belong to this environment attempt"),
                        });
                    }
                }
            }
            self.journal.set_environment_phase(env_id, phase, reason.as_ref()).await?;
            // Terminal hygiene: no redelivery to a sandbox that will never
            // heartbeat again (V5a).
            let _ = self.journal.ack_env_directives_for_attempt(env.attempt_id).await;
            let _ = self
                .journal
                .transition_attempt(
                    env.attempt_id,
                    &acp_runner_core::AttemptPhase::ACTIVE,
                    if phase == "Completed" {
                        acp_runner_core::AttemptPhase::Succeeded
                    } else {
                        acp_runner_core::AttemptPhase::Failed
                    },
                    reason.as_ref(),
                    None,
                )
                .await;
            self.finalize(&env).await;
            return Ok(());
        }
        // live phase from the last relevant runnerd progress event (V3b).
        let rows =
            self.journal.latest_runner_progress(env.attempt_id, &["environment_ready", "turn_ended", "environment_busy"]).await?;
        let mut phase = "Creating";
        if let Some(latest) = rows.iter().max_by_key(|r| r.id) {
            match latest.data.get("category").and_then(|c| c.as_str()) {
                Some("environment_ready") | Some("turn_ended") => phase = "Idle",
                Some("environment_busy") => phase = "Busy",
                _ => {}
            }
        }
        self.journal.set_environment_phase(env_id, phase, None).await?;
        Ok(())
    }

    pub async fn get(&self, env_id: Uuid) -> Result<Option<EnvironmentView>> {
        self.refresh(env_id).await?;
        match self.journal.get_environment(env_id).await? {
            Some(env) => Ok(Some(self.view_from(env).await?)),
            None => Ok(None),
        }
    }

    async fn view_from(&self, env: acp_runner_journal::EnvironmentRow) -> Result<EnvironmentView> {
        let snapshots = self
            .journal
            .events_for_attempt(env.attempt_id, &[EventKind::ArtifactCreated], 10_000)
            .await?
            .iter()
            .filter(|e| e.source == EventSource::Runnerd.as_str())
            .filter(|e| e.data.get("kind").and_then(|k| k.as_str()) == Some("snapshot"))
            .filter_map(|e| {
                Some(SnapshotRef {
                    artifact_id: e.data.get("artifactId").and_then(|v| v.as_str())?.parse().ok()?,
                    sha256: e.data.get("sha256").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                    changed_paths: e.data.get("changedPaths").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                })
            })
            .collect();
        let workdir = serde_json::from_value::<EnvironmentSpec>(env.spec.clone())
            .ok()
            .and_then(|s| s.workdir().ok())
            .unwrap_or_default();
        Ok(EnvironmentView {
            id: env.id,
            external_ref: env.external_ref.clone(),
            harness: env.harness.clone(),
            phase: env.phase(),
            base_revision: env.base_revision.clone(),
            workdir,
            connection: env
                .connection_ref
                .as_ref()
                .and_then(|c| c.get("gateway").and_then(|g| g.as_str()))
                .map(|g| ConnectionRef { gateway: g.to_string() }),
            lineage: Lineage {
                parent_artifact_id: env.parent_artifact_id,
                parent_environment_id: env.parent_environment_id,
            },
            final_artifact_id: env.final_artifact_id,
            snapshots,
            failure: env.failure(),
        })
    }

    /// Wait until the environment is reachable (a gateway is listening) and issue a
    /// connection ticket. Works for any live environment, also after a provider restart.
    pub async fn connect(&self, env_id: Uuid, timeout: Duration) -> Result<Connection> {
        let deadline = Instant::now() + timeout;
        loop {
            self.refresh(env_id).await?;
            let env =
                self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
            if env.phase().is_terminal() {
                let why = env.failure().map(|f| format!(": {}", f.message())).unwrap_or_default();
                anyhow::bail!("environment is {} and cannot be connected{why}", env.phase());
            }
            if let Some(gw) = env.connection_ref.as_ref().and_then(|c| c.get("gateway")).and_then(|g| g.as_str()) {
                let (ticket, expires_at) = self.issue_ticket_for_version(env_id, &env.key_version)?;
                return Ok(Connection { environment_id: env_id, gateway: gw.to_string(), ticket, expires_at });
            }
            if Instant::now() >= deadline {
                anyhow::bail!("environment did not become reachable within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// Request a non-terminal snapshot; returns the snapshot id (the artifact appears async).
    pub async fn snapshot(&self, env_id: Uuid, label: Option<String>) -> Result<Uuid> {
        let env = self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
        anyhow::ensure!(!env.phase().is_terminal(), "environment is terminal");
        let snapshot_id = Uuid::now_v7();
        self.ingest
            .push_env_directive(env.attempt_id, RunnerDirective::Snapshot { snapshot_id: Some(snapshot_id), label })
            .await?;
        Ok(snapshot_id)
    }

    /// `snapshot()` and wait for its artifact (the id to `branch` from).
    pub async fn snapshot_and_wait(&self, env_id: Uuid, label: Option<String>, timeout: Duration) -> Result<Uuid> {
        let sid = self.snapshot(env_id, label).await?;
        self.wait_for_snapshot(env_id, sid, timeout).await
    }

    /// Wait for the artifact of an already-issued snapshot `sid` (see `snapshot()`).
    pub async fn wait_for_snapshot(&self, env_id: Uuid, sid: Uuid, timeout: Duration) -> Result<Uuid> {
        let env = self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
        let deadline = Instant::now() + timeout;
        loop {
            // V5b: single indexed lookup instead of a 100k Progress scan.
            // V3: only runnerd-sourced events are authoritative for snapshots
            // (enforced in the query).
            if let Some(e) = self.journal.progress_by_detail(env.attempt_id, "snapshotId", &sid.to_string()).await? {
                let cat = e.data.get("category").and_then(|c| c.as_str());
                match cat {
                    Some("snapshot_created") => {
                        let artifact: Uuid = e
                            .data
                            .pointer("/detail/artifactId")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok())
                            .ok_or_else(|| anyhow::anyhow!("snapshot event without artifact id"))?;
                        // V3a: the snapshot artifact must belong to this attempt (attempt and run).
                        match self.artifacts.get_meta(artifact).await {
                            Ok(meta) if meta.attempt_id == env.attempt_id && meta.run_id == env.run_id => {
                                return Ok(artifact);
                            }
                            _ => {
                                tracing::warn!(environment_id = %env_id, artifact_id = %artifact, "snapshot artifact does not belong to this environment attempt");
                                anyhow::bail!("snapshot {sid} references foreign artifact {artifact}")
                            }
                        }
                    }
                    Some(c @ ("snapshot_rejected" | "snapshot_failed")) => anyhow::bail!("snapshot {sid}: {c}"),
                    _ => {}
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "snapshot {sid} did not complete within {timeout:?}");
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// Finish the environment: authoritative final changeset, then destroy. Waits for the
    /// terminal state and returns the final view.
    pub async fn finish(&self, env_id: Uuid, timeout: Duration) -> Result<EnvironmentView> {
        self.terminate(env_id, RunnerDirective::Finish, timeout).await
    }

    pub async fn cancel(&self, env_id: Uuid, reason: &str, timeout: Duration) -> Result<EnvironmentView> {
        self.terminate(
            env_id,
            RunnerDirective::Cancel { reason: FailureReason::Cancelled { detail: reason.into() } },
            timeout,
        )
        .await
    }

    /// `destroy()`: cancel, without waiting for a graceful end beyond `timeout`, then
    /// release everything the environment holds.
    pub async fn destroy(&self, env_id: Uuid, timeout: Duration) -> Result<()> {
        let env = self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
        if self.cancel(env_id, "destroyed", timeout).await.is_err() {
            let reason = FailureReason::Cancelled { detail: "destroyed".into() };
            self.journal.set_environment_phase(env_id, "Failed", Some(&reason)).await?;
        }
        self.finalize(&env).await;
        Ok(())
    }

    async fn terminate(&self, env_id: Uuid, directive: RunnerDirective, timeout: Duration) -> Result<EnvironmentView> {
        let env = self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
        if !env.phase().is_terminal() {
            self.ingest.push_env_directive(env.attempt_id, directive).await?;
        }
        let deadline = Instant::now() + timeout;
        loop {
            self.refresh(env_id).await?;
            let env =
                self.journal.get_environment(env_id).await?.ok_or_else(|| anyhow::anyhow!("unknown environment"))?;
            if env.phase().is_terminal() {
                self.finalize(&env).await;
                return self.view_from(env).await;
            }
            if Instant::now() >= deadline {
                anyhow::bail!("environment did not reach a terminal state within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }
}

fn env_terminate_grace() -> u64 {
    20
}

fn gateway_addr(data: &serde_json::Value) -> Option<String> {
    (data.get("category").and_then(|c| c.as_str()) == Some("gateway_listening"))
        .then(|| data.pointer("/detail/addr").and_then(|a| a.as_str()).map(str::to_string))
        .flatten()
}

fn base_revision(data: &serde_json::Value) -> Option<String> {
    (data.get("category").and_then(|c| c.as_str()) == Some("workspace_ready"))
        .then(|| data.pointer("/detail/baseRevision").and_then(|a| a.as_str()).map(str::to_string))
        .flatten()
}
