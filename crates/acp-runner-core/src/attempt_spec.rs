//! The per-attempt document runnerd receives (via the ingest API, authenticated with the
//! attempt token). It contains everything runnerd needs and nothing secret: credential
//! *material* is mounted separately (read-only) and only its *layout* is described here.

use crate::bundle::BundleKind;
use crate::capsule::ResumeCapsule;
use crate::environment::BootstrapExec;
use crate::harness::{HarnessArtifactRef, PlacementRoot};
use crate::spec::{EgressPolicy, OutputKind, PermissionPolicy, RepositoryInput, TimeoutPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptSpec {
    pub wire_version: u32,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub task_id: String,
    /// 1-based ordinal within the run.
    pub ordinal: u32,
    /// 1-based attempt number within the runner class.
    pub class_attempt: u32,
    pub runner_class: String,
    pub driver: DriverSpec,
    pub repository: RepositoryInput,
    /// Final prompt text sent to the agent (original task + rendered resume capsule).
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule: Option<ResumeCapsule>,
    /// Base64 git patch to apply before the agent starts (resume.applyPreviousPatch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_patch_b64: Option<String>,
    pub output: AttemptOutput,
    pub timeouts: TimeoutPolicy,
    pub permissions: PermissionPolicy,
    #[serde(default)]
    pub egress: EgressPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialLayout>,
    /// Preserve raw provider payloads in the journal (redacted, size-capped).
    #[serde(default = "default_true")]
    pub record_raw_payloads: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// One-shot attempt (default) or a multi-turn environment session.
    #[serde(default, skip_serializing_if = "SessionMode::is_one_shot")]
    pub session: SessionMode,
    /// Environment bootstrap plan (trusted placement + untrusted exec); empty for one-shot.
    #[serde(default, skip_serializing_if = "BootstrapPlan::is_empty")]
    pub bootstrap: BootstrapPlan,
}

/// How runnerd drives the harness.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum SessionMode {
    /// Send `prompt` once, collect the patch, terminate (the classic attempt).
    #[default]
    OneShot,
    /// Bootstrap to Ready, expose the raw ACP gateway, serve until `finish()`.
    Environment {
        /// Provider-facing environment id (what connection tickets are scoped to).
        environment_id: Uuid,
        /// Address runnerd binds the caller-facing ACP gateway on (backend-chosen).
        gateway_listen: String,
        /// Destroy the environment after this long with no active turn and no caller.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_timeout_seconds: Option<u64>,
        /// Destroy the environment after this long regardless of activity.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_lifetime_seconds: Option<u64>,
    },
}

impl SessionMode {
    pub fn is_one_shot(&self) -> bool {
        matches!(self, SessionMode::OneShot)
    }
}

/// What runnerd (trusted) and agentd (untrusted) do before the harness starts, in order:
/// materialize `harness` → checkout BASE (or an empty base) → apply `overlays` → place
/// `bundles` → credentials → validate `workdir` → agentd runs `exec` → launch the harness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapPlan {
    /// Harness working directory, workspace-relative (`""` = root). Validated by runnerd
    /// (must be a real directory reached without symlinks).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workdir: String,
    /// No repository: start from the deterministic empty base commit.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub empty_source: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<OverlayRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<BundleMount>,
    /// Untrusted setup commands (run by agentd, never by runnerd).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<BootstrapExec>,
    /// Keep workspace changes made by `exec` in the artifact (default: excluded).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub include_exec_changes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessArtifactRef>,
    #[serde(default, skip_serializing_if = "Lineage::is_empty")]
    pub lineage: Lineage,
    /// `false` = output policy `none`: no final artifact.
    #[serde(default = "default_true")]
    pub produce_artifact: bool,
}

impl Default for BootstrapPlan {
    fn default() -> Self {
        BootstrapPlan {
            workdir: String::new(),
            empty_source: false,
            overlays: vec![],
            bundles: vec![],
            exec: vec![],
            include_exec_changes: false,
            harness: None,
            lineage: Lineage::default(),
            produce_artifact: true,
        }
    }
}

impl BootstrapPlan {
    pub fn is_empty(&self) -> bool {
        *self == BootstrapPlan::default()
    }
}

/// A verified patch artifact applied on top of the base checkout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OverlayRef {
    pub artifact_id: uuid::Uuid,
    pub sha256: String,
    pub base_revision: String,
    pub size_bytes: u64,
}

/// A bundle to fetch (by digest), verify and place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleMount {
    pub digest: String,
    pub kind: BundleKind,
    pub name: String,
    pub root: PlacementRoot,
    /// Directory (relative to `root`) that receives the bundle's files.
    #[serde(default)]
    pub dir: String,
    /// Single-file placement: the bundle's only file lands exactly at this path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Keep placed workspace files out of the artifact (runtime configuration).
    #[serde(default = "default_true")]
    pub exclude_from_artifact: bool,
}

/// Where an environment's workspace came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Lineage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_artifact_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_environment_id: Option<uuid::Uuid>,
}

impl Lineage {
    pub fn is_empty(&self) -> bool {
        self.parent_artifact_id.is_none() && self.parent_environment_id.is_none()
    }
}

/// File name of the per-environment gateway ticket key (`K_env`, see [`crate::ticket`])
/// inside the per-attempt secret mount (environment mode only).
pub const GATEWAY_KEY_FILE_NAME: &str = "gateway-key";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriverSpec {
    pub name: String,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptOutput {
    pub kind: OutputKind,
    pub require_changes: bool,
    pub max_patch_bytes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
    /// Effective `.gitmodules`/submodule opt-in for this attempt (V6).
    /// Resolved from the run's `OutputExpectation`; default false.
    pub allow_submodules: bool,
}

/// Where the leased credential material appears and how the CLI receives it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialLayout {
    pub provider: String,
    pub profile: String,
    /// Credential files copied from the read-only mount into the synthetic HOME.
    #[serde(default)]
    pub files: Vec<CredentialFileLayout>,
    /// Credentials handed to the CLI process via environment variable only.
    #[serde(default)]
    pub env: Vec<CredentialEnvLayout>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialFileLayout {
    /// Key in the mounted secret (file name `cred.<key>`).
    pub key: String,
    /// Target path relative to the synthetic HOME.
    pub target: String,
    pub mode: u32,
    pub writeback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialEnvLayout {
    pub key: String,
    pub env_name: String,
}

/// File name used for a credential key inside the per-attempt secret mount.
pub fn secret_file_name(key: &str) -> String {
    format!("cred.{key}")
}

/// File name of the ingest bearer token inside the per-attempt secret mount.
pub const TOKEN_FILE_NAME: &str = "token";

fn default_true() -> bool {
    true
}
