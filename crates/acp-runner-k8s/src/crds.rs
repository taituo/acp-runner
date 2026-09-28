//! Custom resources.
//!
//! * `ACPRunnerClass` — reusable runtime class: driver + opaque driver config, image,
//!   resources, runtimeClassName (e.g. gvisor), credential profile type/candidates,
//!   workspace policy, timeout defaults, permission policy, egress mode (direct | proxy).
//! * `ACPRun` — one logical execution request: task id, runner class + fallbacks,
//!   repository/revision/sparse paths, prompt, output expectation, retry, timeouts.
//!
//! `ACPRun.status` carries operational state only (phase, attempt, sandbox reference,
//! timestamps, failure reason, artifact reference). Transcripts live in PostgreSQL.

use acp_runner_core::spec as core;
use k8s_openapi::api::core::v1::ResourceRequirements;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GROUP: &str = "acp-runner.dev";
pub const VERSION: &str = "v1alpha1";
pub const FINALIZER: &str = "acp-runner.dev/run-cleanup";

fn preserve_unknown_opt(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
    preserve_unknown(g)
}

fn preserve_unknown(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true
    })
}

// ---------------------------------------------------------------------------------------
// ACPRunnerClass
// ---------------------------------------------------------------------------------------

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema, Default)]
#[kube(
    group = "acp-runner.dev",
    version = "v1alpha1",
    kind = "ACPRunnerClass",
    plural = "acprunnerclasses",
    shortname = "arc",
    namespaced,
    printcolumn = r#"{"name":"Driver","type":"string","jsonPath":".spec.driver"}"#,
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".spec.image"}"#,
    printcolumn = r#"{"name":"RuntimeClass","type":"string","jsonPath":".spec.runtimeClassName"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ACPRunnerClassSpec {
    /// Driver name: `fake`, `codex`, `claude`.
    pub driver: String,
    /// Driver-specific configuration (see README "Driver configuration").
    #[serde(default)]
    #[schemars(schema_with = "preserve_unknown")]
    pub driver_config: serde_json::Value,
    /// Runner image containing runnerd, agentd, git and the pinned CLIs (used for both
    /// containers of the attempt pod).
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pull_policy: Option<String>,
    /// e.g. `gvisor`. Leave empty on KIND.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    #[serde(default)]
    pub credentials: ClassCredentials,
    #[serde(default)]
    pub workspace: ClassWorkspace,
    #[serde(default)]
    pub timeouts: ClassTimeouts,
    #[serde(default)]
    pub permissions: ClassPermissions,
    #[serde(default)]
    pub egress: ClassEgress,
    /// Extra non-secret environment for the agent process. API-key variables are refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvPair>,
    /// Allow per-run `overrides` for the `acp` driver launch (V9). Default false.
    #[serde(default)]
    pub allow_run_overrides: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassCredentials {
    /// `codex` or `claude`; omit for drivers without credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Enrolled credential profile names, tried in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Override credential file locations relative to the synthetic HOME.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_targets: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassWorkspace {
    /// `Memory` (default, tmpfs) or `Disk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tmp_size_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_size_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassTimeouts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_progress_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassPermissions {
    /// `AllowAll` (default; the sandbox is the boundary) or `DenyAll`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassEgress {
    /// `direct` (NetworkPolicy only: any public HTTPS endpoint) or `proxy` (the pod may reach
    /// only DNS, the ingest API and the egress proxy; the proxy allowlists hostnames).
    /// Defaults to `proxy` when `httpsProxy` is set. Classes with `credentials` must use
    /// `proxy` (the controller rejects the run otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ClassEgressMode>,
    /// Proxy reference for the agent CLI and runnerd's git fetch, e.g.
    /// `http://acp-egress-proxy.acp-egress.svc:3128`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
pub enum ClassEgressMode {
    #[serde(rename = "direct")]
    Direct,
    #[serde(rename = "proxy")]
    Proxy,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub struct EnvPair {
    pub name: String,
    pub value: String,
}

// ---------------------------------------------------------------------------------------
// ACPRun
// ---------------------------------------------------------------------------------------

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "acp-runner.dev",
    version = "v1alpha1",
    kind = "ACPRun",
    plural = "acpruns",
    shortname = "acprun",
    namespaced,
    status = "ACPRunStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Attempt","type":"integer","jsonPath":".status.currentAttempt"}"#,
    printcolumn = r#"{"name":"Class","type":"string","jsonPath":".status.runnerClass"}"#,
    printcolumn = r#"{"name":"Sandbox","type":"string","jsonPath":".status.sandboxRef.name"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.failureReason.code"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ACPRunSpec {
    /// Opaque task/session identifier owned by the orchestrator.
    pub task_id: String,
    pub runner_class_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback_runner_class_names: Vec<String>,
    pub repository: RunRepository,
    pub prompt: RunPrompt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<RunOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RunRetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<RunTimeouts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<RunResume>,
    /// Set to true to cancel the run (sandbox terminated, lease released).
    #[serde(default)]
    pub cancel: bool,
    /// Per-run launch additions for the `acp` driver (V9). Honored only when
    /// the runner class sets `allowRunOverrides`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<RunOverrides>,
}

/// Per-run launch additions (V9): `env` keys replace class keys, `files` are
/// appended after the class files. No list merging, no added arguments.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunOverrides {
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<LaunchFile>,
}

/// One trusted configuration file for the synthetic HOME (V9 `launch.files`).
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LaunchFile {
    /// Path relative to the HOME.
    pub target: String,
    pub content: String,
    /// File mode; default 0600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunRepository {
    pub url: String,
    /// Exact commit SHA (recommended) or ref.
    pub revision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sparse_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunPrompt {
    pub text: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunOutput {
    /// `Patch` (default) or `None`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_changes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    /// Opt in to `.gitmodules` changes in the patch (V6, default false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_submodules: Option<bool>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunRetry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_attempts_per_runner: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_attempts: Option<u32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunTimeouts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_progress_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunResume {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_previous_patch: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_transcript: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transcript_messages: Option<u32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ACPRunStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_attempt: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_ref: Option<SandboxRefStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_progress_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<FailureStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<ArtifactRefStatus>,
    /// Human readable note (e.g. waiting for a credential lease).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxRefStatus {
    /// `Pod`, `Sandbox` or `local`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FailureStatus {
    pub code: String,
    pub message: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactRefStatus {
    pub id: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub changed_paths: i64,
    pub base_revision: String,
    pub storage: String,
}

// ---------------------------------------------------------------------------------------
// conversion to the provider-neutral domain model
// ---------------------------------------------------------------------------------------

impl ACPRunnerClassSpec {
    pub fn to_core(&self, name: &str) -> core::RunnerClassSpec {
        let d = core::TimeoutPolicy::default();
        let w = core::WorkspacePolicy::default();
        core::RunnerClassSpec {
            name: name.to_string(),
            driver: self.driver.clone(),
            driver_config: if self.driver_config.is_null() {
                serde_json::json!({})
            } else {
                self.driver_config.clone()
            },
            image: self.image.clone(),
            image_pull_policy: self.image_pull_policy.clone(),
            runtime_class_name: self.runtime_class_name.clone().filter(|s| !s.is_empty()),
            resources: self.resources.as_ref().and_then(|r| serde_json::to_value(r).ok()),
            credentials: core::CredentialRequirement {
                provider: self.credentials.provider.clone(),
                profiles: self.credentials.profiles.clone(),
                file_targets: self.credentials.file_targets.clone(),
            },
            workspace: core::WorkspacePolicy {
                medium: match self.workspace.medium.as_deref() {
                    Some("Disk") => core::StorageMedium::Disk,
                    _ => core::StorageMedium::Memory,
                },
                size_limit: self.workspace.size_limit.clone().unwrap_or(w.size_limit),
                tmp_size_limit: self.workspace.tmp_size_limit.clone().unwrap_or(w.tmp_size_limit),
                home_size_limit: self.workspace.home_size_limit.clone().unwrap_or(w.home_size_limit),
                max_patch_bytes: self.workspace.max_patch_bytes.unwrap_or(w.max_patch_bytes),
                allowed_paths: self.workspace.allowed_paths.clone(),
            },
            timeouts: core::TimeoutPolicy {
                hard_seconds: self.timeouts.hard_seconds.unwrap_or(d.hard_seconds),
                no_progress_seconds: self.timeouts.no_progress_seconds.unwrap_or(d.no_progress_seconds),
                grace_seconds: self.timeouts.grace_seconds.unwrap_or(d.grace_seconds),
                heartbeat_seconds: self.timeouts.heartbeat_seconds.unwrap_or(d.heartbeat_seconds),
                startup_seconds: self.timeouts.startup_seconds.unwrap_or(d.startup_seconds),
            },
            permissions: core::PermissionPolicy {
                mode: match self.permissions.mode.as_deref() {
                    Some("DenyAll") => core::PermissionMode::DenyAll,
                    _ => core::PermissionMode::AllowAll,
                },
            },
            egress: core::EgressPolicy {
                mode: self.egress.mode.map(|m| match m {
                    ClassEgressMode::Direct => core::EgressMode::Direct,
                    ClassEgressMode::Proxy => core::EgressMode::Proxy,
                }),
                https_proxy: self.egress.https_proxy.clone(),
                no_proxy: self.egress.no_proxy.clone(),
            },
            env: self.env.iter().map(|e| (e.name.clone(), e.value.clone())).collect(),
            allow_run_overrides: self.allow_run_overrides,
            run_as_user: self.run_as_user,
            service_account_name: self.service_account_name.clone(),
        }
    }
}

impl ACPRunSpec {
    /// Resolve against the runner classes `[primary, fallbacks...]` (already fetched).
    pub fn to_core(&self, classes: Vec<core::RunnerClassSpec>) -> core::RunSpec {
        let out = self.output.clone().unwrap_or_default();
        let retry = self.retry.clone().unwrap_or_default();
        let t = self.timeouts.clone().unwrap_or_default();
        let r = self.resume.clone().unwrap_or_default();
        let dr = core::ResumePolicy::default();
        core::RunSpec {
            task_id: self.task_id.clone(),
            prompt: self.prompt.text.clone(),
            repository: core::RepositoryInput {
                url: self.repository.url.clone(),
                revision: self.repository.revision.clone(),
                sparse_paths: self.repository.sparse_paths.clone(),
                depth: self.repository.depth,
            },
            output: core::OutputExpectation {
                kind: match out.type_.as_deref() {
                    Some("None") => core::OutputKind::None,
                    _ => core::OutputKind::Patch,
                },
                require_changes: out.require_changes.unwrap_or(true),
                max_patch_bytes: out.max_patch_bytes,
                allow_submodules: out.allow_submodules.unwrap_or(false),
            },
            retry: core::RetryPolicy {
                max_attempts_per_runner: retry.max_attempts_per_runner.unwrap_or(1),
                max_total_attempts: retry.max_total_attempts,
            },
            timeouts: core::TimeoutOverrides {
                hard_seconds: t.hard_seconds,
                no_progress_seconds: t.no_progress_seconds,
                grace_seconds: t.grace_seconds,
            },
            resume: core::ResumePolicy {
                apply_previous_patch: r.apply_previous_patch.unwrap_or(dr.apply_previous_patch),
                include_transcript: r.include_transcript.unwrap_or(dr.include_transcript),
                max_transcript_messages: r.max_transcript_messages.unwrap_or(dr.max_transcript_messages),
            },
            runner_classes: classes,
            overrides: self
                .overrides
                .clone()
                .map(|o| core::RunOverrides {
                    env: o.env,
                    files: o
                        .files
                        .into_iter()
                        .map(|f| core::LaunchFile { target: f.target, content: f.content, mode: f.mode })
                        .collect(),
                })
                .unwrap_or_default(),
        }
    }

    pub fn class_names(&self) -> Vec<String> {
        std::iter::once(self.runner_class_name.clone())
            .chain(self.fallback_runner_class_names.iter().cloned())
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// AgentEnvironment (the general primitive; ACPRun is the one-shot compatibility resource)
// ---------------------------------------------------------------------------------------

/// Durable, caller-facing agent execution environment (v3 provider/bootstrap shape).
/// Connection tickets are never stored in status; the provider issues them on `connect`.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "acp-runner.dev",
    version = "v1alpha1",
    kind = "AgentEnvironment",
    plural = "agentenvironments",
    shortname = "agentenv",
    namespaced,
    status = "AgentEnvironmentStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Harness","type":"string","jsonPath":".status.harness.name"}"#,
    printcolumn = r#"{"name":"Revision","type":"string","jsonPath":".status.resolvedRevision"}"#,
    printcolumn = r#"{"name":"Parent","type":"string","jsonPath":".status.lineage.parentArtifactId"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.failureReason.code"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AgentEnvironmentSpec {
    /// Opaque external task/session reference owned by the caller.
    pub external_ref: String,
    pub harness: EnvHarness,
    /// Legacy alias of `workspace.source`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RunRepository>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<EnvWorkspace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<EnvBootstrap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<EnvCredentials>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
    #[serde(default, alias = "configBundles", skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<EnvLifetime>,
    /// Legacy alias of `lifetime.idleSeconds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<EnvOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_unknown_opt")]
    pub resources: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<RunTimeouts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ClassPermissions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<ClassEgress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvPair>,
    /// Explicit lifecycle request: `finish` or `cancel` the environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvHarness {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Pinned `sha256:<hex>` of the harness artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "preserve_unknown_opt")]
    pub config: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvWorkspace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<EnvSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<EnvOverlay>,
    /// Harness working directory relative to the workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EnvSourceType {
    Git,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvSource {
    #[serde(rename = "type")]
    pub type_: EnvSourceType,
    pub url: String,
    pub revision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sparse_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EnvOverlayType {
    PatchArtifact,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvOverlay {
    #[serde(rename = "type")]
    pub type_: EnvOverlayType,
    pub artifact_id: String,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvArtifactPolicy {
    Exclude,
    Include,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvRoot {
    Workspace,
    Home,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvBundleKind {
    Config,
    Agent,
    Skill,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvBootstrap {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<EnvBootstrapFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<EnvBootstrapExec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_artifact_policy: Option<EnvArtifactPolicy>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvBootstrapFile {
    pub bundle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EnvBundleKind>,
    pub target: EnvFileTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_policy: Option<EnvArtifactPolicy>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvFileTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<EnvRoot>,
    pub path: String,
}

/// `execve(command, args, env)` in the agent container before the harness starts.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvBootstrapExec {
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvPair>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvLifetime {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_seconds: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EnvOutputArtifact {
    Patch,
    None,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvOutput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<EnvOutputArtifact>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvCredentials {
    pub profile: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentEnvironmentStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<StatusHarness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_revision: Option<String>,
    /// Harness working directory as the agent sees it (pass as `cwd` to `session/new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Reference only — how to reach the ACP gateway; never secret material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<EnvConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<EnvLineage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_progress_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_ref: Option<EnvArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_artifact_ref: Option<EnvArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<FailureStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvLineage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_environment_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatusHarness {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvConnection {
    /// e.g. an in-cluster gateway Service address; tickets are issued by the provider.
    pub gateway: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EnvArtifactRef {
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
}

fn pairs(v: &[EnvPair]) -> std::collections::BTreeMap<String, String> {
    v.iter().map(|e| (e.name.clone(), e.value.clone())).collect()
}

fn policy(p: Option<EnvArtifactPolicy>) -> acp_runner_core::environment::ArtifactPolicy {
    match p {
        Some(EnvArtifactPolicy::Include) => acp_runner_core::environment::ArtifactPolicy::Include,
        _ => acp_runner_core::environment::ArtifactPolicy::Exclude,
    }
}

impl AgentEnvironmentSpec {
    /// Resolve to the provider-neutral core [`acp_runner_core::environment::EnvironmentSpec`].
    pub fn to_core(&self) -> Result<acp_runner_core::environment::EnvironmentSpec, String> {
        use acp_runner_core::bundle::BundleKind;
        use acp_runner_core::environment as e;
        use acp_runner_core::harness::PlacementRoot;
        let repo = |url: &str, revision: &str, sparse: &[String], depth: Option<u32>| core::RepositoryInput {
            url: url.to_string(),
            revision: revision.to_string(),
            sparse_paths: sparse.to_vec(),
            depth,
        };
        let ws = self.workspace.clone().unwrap_or_default();
        let mut policy_ws = core::WorkspacePolicy::default();
        if let Some(sz) = &ws.size_limit {
            policy_ws.size_limit = sz.clone();
        }
        if let Some(m) = ws.max_patch_bytes {
            policy_ws.max_patch_bytes = m;
        }
        policy_ws.allowed_paths = ws.allowed_paths.clone();
        let mut overlays = vec![];
        for o in &ws.overlays {
            let id =
                o.artifact_id.parse().map_err(|_| format!("overlay artifactId {:?} is not a UUID", o.artifact_id))?;
            overlays.push(match o.type_ {
                EnvOverlayType::PatchArtifact => e::WorkspaceOverlay::PatchArtifact { artifact_id: id },
            });
        }
        let boot = self.bootstrap.clone().unwrap_or_default();
        let spec = e::EnvironmentSpec {
            external_ref: self.external_ref.clone(),
            harness: e::HarnessSpec {
                name: self.harness.name.clone(),
                version: self.harness.version.clone(),
                digest: self.harness.digest.clone(),
                config: self.harness.config.clone().unwrap_or(serde_json::json!({})),
            },
            repository: self.repository.as_ref().map(|r| repo(&r.url, &r.revision, &r.sparse_paths, r.depth)),
            workspace: e::EnvironmentWorkspace {
                source: ws.source.as_ref().map(|s| match s.type_ {
                    EnvSourceType::Git => e::WorkspaceSource::Git(repo(&s.url, &s.revision, &s.sparse_paths, s.depth)),
                }),
                overlays,
                workdir: ws.workdir.clone(),
                policy: policy_ws,
            },
            bootstrap: e::BootstrapSpec {
                files: boot
                    .files
                    .iter()
                    .map(|f| e::BootstrapFile {
                        bundle: f.bundle.clone(),
                        kind: f.kind.map(|k| match k {
                            EnvBundleKind::Config => BundleKind::Config,
                            EnvBundleKind::Agent => BundleKind::Agent,
                            EnvBundleKind::Skill => BundleKind::Skill,
                        }),
                        target: e::FileTarget {
                            root: match f.target.root {
                                Some(EnvRoot::Home) => PlacementRoot::Home,
                                _ => PlacementRoot::Workspace,
                            },
                            path: f.target.path.clone(),
                        },
                        artifact_policy: policy(f.artifact_policy),
                    })
                    .collect(),
                exec: boot
                    .exec
                    .iter()
                    .map(|x| e::BootstrapExec {
                        command: x.command.clone(),
                        args: x.args.clone(),
                        cwd: x.cwd.clone(),
                        env: pairs(&x.env),
                        timeout_seconds: x.timeout_seconds,
                    })
                    .collect(),
                exec_artifact_policy: policy(boot.exec_artifact_policy),
            },
            credentials: e::CredentialSelection {
                profile: self.credentials.as_ref().map(|c| c.profile.clone()),
                file_targets: Default::default(),
            },
            agents: self.agents.clone(),
            skills: self.skills.clone(),
            configs: self.configs.clone(),
            lifetime: self
                .lifetime
                .as_ref()
                .map(|l| e::Lifetime { idle_seconds: l.idle_seconds, max_seconds: l.max_seconds })
                .unwrap_or_default(),
            idle_timeout_seconds: self.idle_timeout_seconds,
            output: e::EnvironmentOutput {
                artifact: match self.output.as_ref().and_then(|o| o.artifact) {
                    Some(EnvOutputArtifact::None) => e::OutputArtifact::None,
                    _ => e::OutputArtifact::Patch,
                },
            },
            resources: self.resources.clone(),
            timeouts: self
                .timeouts
                .as_ref()
                .map(|t| core::TimeoutOverrides {
                    hard_seconds: t.hard_seconds,
                    no_progress_seconds: t.no_progress_seconds,
                    grace_seconds: t.grace_seconds,
                })
                .unwrap_or_default(),
            permissions: core::PermissionPolicy {
                mode: match self.permissions.as_ref().and_then(|p| p.mode.as_deref()) {
                    Some("DenyAll") => core::PermissionMode::DenyAll,
                    _ => core::PermissionMode::AllowAll,
                },
            },
            egress: self
                .egress
                .as_ref()
                .map(|g| core::EgressPolicy {
                    mode: g.mode.map(|m| match m {
                        ClassEgressMode::Direct => core::EgressMode::Direct,
                        ClassEgressMode::Proxy => core::EgressMode::Proxy,
                    }),
                    https_proxy: g.https_proxy.clone(),
                    no_proxy: g.no_proxy.clone(),
                })
                .unwrap_or_default(),
            runtime_class_name: self.runtime_class_name.clone(),
            env: pairs(&self.env),
            record_raw_payloads: true,
        };
        spec.validate().map_err(|e| e.to_string())?;
        Ok(spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crds_generate_and_are_structural() {
        let run = serde_yaml::to_string(&ACPRun::crd()).unwrap();
        assert!(run.contains("acpruns.acp-runner.dev"));
        assert!(run.contains("subresources"));
        let class = serde_yaml::to_string(&ACPRunnerClass::crd()).unwrap();
        assert!(class.contains("x-kubernetes-preserve-unknown-fields: true"));
    }

    #[test]
    fn conversion_applies_defaults() {
        let spec: ACPRunnerClassSpec = serde_json::from_value(serde_json::json!({
            "driver": "codex", "image": "img", "credentials": {"provider": "codex", "profiles": ["p"]},
            "timeouts": {"hardSeconds": 10}
        }))
        .unwrap();
        let c = spec.to_core("codex-default");
        assert_eq!(c.timeouts.hard_seconds, 10);
        assert_eq!(c.timeouts.no_progress_seconds, 600);
        assert_eq!(c.workspace.medium, core::StorageMedium::Memory);
        let run: ACPRunSpec = serde_json::from_value(serde_json::json!({
            "taskId": "t", "runnerClassName": "codex-default", "fallbackRunnerClassNames": ["claude-default"],
            "repository": {"url": "https://x/y.git", "revision": "main"}, "prompt": {"text": "do it"},
            "retry": {"maxAttemptsPerRunner": 2}
        }))
        .unwrap();
        assert_eq!(run.class_names(), vec!["codex-default", "claude-default"]);
        let r = run.to_core(vec![c]);
        assert_eq!(r.retry.max_attempts_per_runner, 2);
        r.validate().unwrap();
    }

    #[test]
    fn agent_environment_v3_example_converts() {
        let y = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/examples/agentenvironment-review.yaml"
        ))
        .unwrap();
        let ae: AgentEnvironment = serde_yaml::from_str(&y).unwrap();
        let spec = ae.spec.to_core().unwrap();
        assert_eq!(spec.workdir().unwrap(), "packages/backend");
        assert_eq!(spec.workspace.overlays.len(), 1);
        assert_eq!(spec.bootstrap.exec[0].args, vec!["--profile".to_string(), "coding".to_string()]);
        assert!(!spec.produces_artifact());
        let crd = serde_yaml::to_string(&AgentEnvironment::crd()).unwrap();
        assert!(crd.contains("overlays") && crd.contains("workdir") && crd.contains("patchArtifact"));
    }
}
