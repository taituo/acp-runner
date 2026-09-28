//! Resolved, provider-neutral specifications.
//!
//! The Kubernetes adapter turns `ACPRun` + `ACPRunnerClass` custom resources into a
//! [`RunSpec`]. The engine snapshots that spec when the run is first seen, so edits to the
//! custom resources after the run started do not change an in-flight run.

use crate::paths::{PathError, validate_relative_path};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Upper bound on the task prompt accepted by the engine.
pub const MAX_PROMPT_BYTES: usize = 256 * 1024;
/// Default upper bound for a patch artifact.
pub const DEFAULT_MAX_PATCH_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunSpec {
    /// Opaque identifier owned by the higher-level orchestrator (task/session id).
    pub task_id: String,
    pub prompt: String,
    pub repository: RepositoryInput,
    #[serde(default)]
    pub output: OutputExpectation,
    #[serde(default)]
    pub retry: RetryPolicy,
    #[serde(default)]
    pub timeouts: TimeoutOverrides,
    #[serde(default)]
    pub resume: ResumePolicy,
    /// `[primary, fallback_1, fallback_2, ...]`, resolved and snapshotted.
    pub runner_classes: Vec<RunnerClassSpec>,
    /// Per-run launch additions for the `acp` driver (V9). Empty = none.
    #[serde(default)]
    pub overrides: RunOverrides,
}

/// Per-run additions to a runner class launch (V9): only `env` and `files`,
/// and only when the class sets `allowRunOverrides`. Env keys replace
/// class keys; files are appended after the class files (later wins per
/// target at placement). No merging of lists, no added arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunOverrides {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<LaunchFile>,
}

impl RunOverrides {
    pub fn is_empty(&self) -> bool {
        self.env.is_empty() && self.files.is_empty()
    }
}

/// One trusted configuration file for the synthetic HOME (V9 `launch.files`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchFile {
    /// Path relative to the HOME.
    pub target: String,
    pub content: String,
    /// File mode; default 0600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u64>,
}

/// Whether `file://` repository URLs are accepted (V8.3, default deny).
/// Opt in with the controller setting `ACP_RUNNER_ALLOW_FILE_REPOS=true`
/// (`scripts/dev-run.sh` and the test suite set it; production must not —
/// a `file://` URL would read the controller's own filesystem).
pub fn allow_file_repos() -> bool {
    std::env::var("ACP_RUNNER_ALLOW_FILE_REPOS").as_deref() == Ok("true")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryInput {
    /// Fetch URL. `https://`, `http://`, `ssh://` and `git://` are accepted by
    /// the validator; `file://` only when [`allow_file_repos`] holds (fixtures
    /// baked into the runner image, dev-run, tests).
    pub url: String,
    /// Exact commit SHA (preferred) or a ref name. The resolved SHA is recorded as the
    /// authoritative base revision of the attempt.
    pub revision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sparse_paths: Vec<String>,
    /// Shallow fetch depth; `None` means depth 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputKind {
    /// A git-compatible binary patch relative to the base revision.
    #[default]
    Patch,
    /// No artifact expected (analysis-only task); final agent message is journaled.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputExpectation {
    #[serde(default)]
    pub kind: OutputKind,
    /// Fail the attempt with `NoChanges` when the workspace is unchanged.
    #[serde(default = "default_true")]
    pub require_changes: bool,
    /// Overrides the runner class limit when smaller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    /// Opt in to `.gitmodules` changes and submodule content in the patch
    /// (V6). Default false: submodule changes are a policy violation.
    #[serde(default)]
    pub allow_submodules: bool,
}

impl Default for OutputExpectation {
    fn default() -> Self {
        OutputExpectation { kind: OutputKind::Patch, require_changes: true, max_patch_bytes: None, allow_submodules: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Attempts allowed on each runner class (primary and every fallback).
    #[serde(default = "one")]
    pub max_attempts_per_runner: u32,
    /// Optional cap over all classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_attempts: Option<u32>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy { max_attempts_per_runner: 1, max_total_attempts: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TimeoutOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_progress_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumePolicy {
    /// Apply the latest previous attempt's patch to the fresh workspace before starting a
    /// retry/fallback attempt. Off by default: the capsule only *describes* the patch.
    #[serde(default)]
    pub apply_previous_patch: bool,
    /// Include normalized agent messages from previous attempts in the capsule.
    #[serde(default = "default_true")]
    pub include_transcript: bool,
    #[serde(default = "default_capsule_messages")]
    pub max_transcript_messages: u32,
}

impl Default for ResumePolicy {
    fn default() -> Self {
        ResumePolicy { apply_previous_patch: false, include_transcript: true, max_transcript_messages: 12 }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerClassSpec {
    pub name: String,
    /// Driver name, e.g. `fake`, `codex`, `claude`, `acp`.
    pub driver: String,
    /// Driver-specific configuration (opaque to the controller).
    #[serde(default)]
    pub driver_config: serde_json::Value,
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pull_policy: Option<String>,
    /// e.g. `gvisor`. Omitted on KIND by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    /// Kubernetes `ResourceRequirements` as JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(default)]
    pub credentials: CredentialRequirement,
    #[serde(default)]
    pub workspace: WorkspacePolicy,
    #[serde(default)]
    pub timeouts: TimeoutPolicy,
    #[serde(default)]
    pub permissions: PermissionPolicy,
    #[serde(default)]
    pub egress: EgressPolicy,
    /// Extra non-secret environment for the driver process.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Allow per-run `overrides` (V9, `acp` driver only). Default false:
    /// runs cannot change the launch otherwise.
    #[serde(default)]
    pub allow_run_overrides: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as_user: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequirement {
    /// `codex`, `claude`, or `None` for drivers without credentials (fake).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Candidate profiles, tried in order. Each is an independently authorized login.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Override where a credential file lands, relative to the synthetic HOME
    /// (`{"auth.json": ".codex/auth.json"}`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_targets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StorageMedium {
    #[default]
    Memory,
    Disk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePolicy {
    #[serde(default)]
    pub medium: StorageMedium,
    #[serde(default = "default_ws_size")]
    pub size_limit: String,
    #[serde(default = "default_tmp_size")]
    pub tmp_size_limit: String,
    #[serde(default = "default_home_size")]
    pub home_size_limit: String,
    #[serde(default = "default_max_patch")]
    pub max_patch_bytes: u64,
    /// Repository-relative path prefixes the agent may change. Empty = whole repository.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_paths: Vec<String>,
}

impl Default for WorkspacePolicy {
    fn default() -> Self {
        WorkspacePolicy {
            medium: StorageMedium::Memory,
            size_limit: default_ws_size(),
            tmp_size_limit: default_tmp_size(),
            home_size_limit: default_home_size(),
            max_patch_bytes: default_max_patch(),
            allowed_paths: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeoutPolicy {
    #[serde(default = "default_hard")]
    pub hard_seconds: u64,
    #[serde(default = "default_no_progress")]
    pub no_progress_seconds: u64,
    #[serde(default = "default_grace")]
    pub grace_seconds: u64,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_seconds: u64,
    #[serde(default = "default_startup")]
    pub startup_seconds: u64,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        TimeoutPolicy {
            hard_seconds: default_hard(),
            no_progress_seconds: default_no_progress(),
            grace_seconds: default_grace(),
            heartbeat_seconds: default_heartbeat(),
            startup_seconds: default_startup(),
        }
    }
}

impl TimeoutPolicy {
    pub fn with_overrides(mut self, o: &TimeoutOverrides) -> Self {
        if let Some(v) = o.hard_seconds {
            self.hard_seconds = v;
        }
        if let Some(v) = o.no_progress_seconds {
            self.no_progress_seconds = v;
        }
        if let Some(v) = o.grace_seconds {
            self.grace_seconds = v;
        }
        self
    }

    /// Controller-side heartbeat staleness threshold.
    pub fn heartbeat_timeout_seconds(&self) -> u64 {
        self.heartbeat_seconds * 3 + 15
    }

    /// Kubelet-enforced sandbox lifetime and the credential-lease bound (V10c):
    /// hard timeout + startup + grace + margin. The pod's
    /// `activeDeadlineSeconds` and every credential lease TTL must equal this —
    /// heartbeat is only an optimistic extension, never the safety basis.
    pub fn hard_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.hard_seconds + self.startup_seconds + 2 * self.grace_seconds + 60,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PermissionMode {
    /// Approve every ACP permission request (the sandbox is the security boundary).
    #[default]
    AllowAll,
    /// Reject every ACP permission request.
    DenyAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PermissionPolicy {
    #[serde(default)]
    pub mode: PermissionMode,
}

/// How an attempt pod reaches the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    /// NetworkPolicy only: DNS, the ingest API and public HTTPS/HTTP. No hostname policy —
    /// the agent can reach any public endpoint.
    #[serde(alias = "Direct")]
    Direct,
    /// NetworkPolicy allows DNS, the ingest API and the egress proxy only; every HTTP(S)
    /// connection of the agent and of runnerd's git fetch goes through the allowlisting
    /// CONNECT proxy (`httpsProxy`). Required for runner classes with persistent
    /// subscription credentials.
    #[serde(alias = "Proxy")]
    Proxy,
}

impl EgressMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EgressMode::Direct => "direct",
            EgressMode::Proxy => "proxy",
        }
    }
}

/// Egress of an attempt pod. NetworkPolicy cannot filter by hostname; the proxy can.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EgressPolicy {
    /// Defaults to `proxy` when `https_proxy` is set, `direct` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<EgressMode>,
    /// The proxy reference, e.g. `http://acp-egress-proxy.acp-egress.svc:3128`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,
}

impl EgressPolicy {
    pub fn effective_mode(&self) -> EgressMode {
        self.mode.unwrap_or(if self.https_proxy.is_some() { EgressMode::Proxy } else { EgressMode::Direct })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("prompt exceeds {MAX_PROMPT_BYTES} bytes")]
    PromptTooLarge,
    #[error("repository url {0:?} is not allowed (scheme must be https, http, ssh or git; file:// needs ACP_RUNNER_ALLOW_FILE_REPOS=true; no leading '-')")]
    BadRepositoryUrl(String),
    #[error("revision {0:?} is not a safe git revision")]
    BadRevision(String),
    #[error("sparse path {path:?}: {err}")]
    BadSparsePath { path: String, err: PathError },
    #[error("allowed path {path:?}: {err}")]
    BadAllowedPath { path: String, err: PathError },
    #[error("retry.maxAttemptsPerRunner must be between 1 and 20")]
    BadRetry,
    #[error("at least one runner class is required")]
    NoRunnerClass,
    #[error("runner class {0}: {1}")]
    BadRunnerClass(String, String),
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
}

impl RunSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.task_id.trim().is_empty() {
            return Err(SpecError::Empty("taskId"));
        }
        if self.prompt.trim().is_empty() {
            return Err(SpecError::Empty("prompt"));
        }
        if self.prompt.len() > MAX_PROMPT_BYTES {
            return Err(SpecError::PromptTooLarge);
        }
        self.repository.validate()?;
        if !(1..=20).contains(&self.retry.max_attempts_per_runner) {
            return Err(SpecError::BadRetry);
        }
        if self.runner_classes.is_empty() {
            return Err(SpecError::NoRunnerClass);
        }
        for c in &self.runner_classes {
            c.validate()?;
            // An HTTP CONNECT proxy carries https:// fetches; ssh:// and git:// cannot pass.
            let url = self.repository.url.trim();
            if c.egress.effective_mode() == EgressMode::Proxy
                && !(url.starts_with("https://") || url.starts_with("file://"))
            {
                return Err(SpecError::BadRunnerClass(
                    c.name.clone(),
                    "egress.mode proxy requires an https:// (or file://) repository URL".into(),
                ));
            }
        }
        Ok(())
    }

    /// Effective timeouts for an attempt on `class`.
    pub fn effective_timeouts(&self, class: &RunnerClassSpec) -> TimeoutPolicy {
        class.timeouts.with_overrides(&self.timeouts)
    }

    /// Effective patch limit for an attempt on `class`.
    pub fn effective_max_patch_bytes(&self, class: &RunnerClassSpec) -> u64 {
        match self.output.max_patch_bytes {
            Some(v) => v.min(class.workspace.max_patch_bytes),
            None => class.workspace.max_patch_bytes,
        }
    }
}

/// Default service account for agent pods (V2: also the default allowlist).
pub const DEFAULT_AGENT_SERVICE_ACCOUNT: &str = "acp-runner-agent";

/// V2 admission for credentialed runner classes: the image must be
/// digest-pinned (`repo@sha256:<64 hex>`) and operator-allowlisted. Anything
/// else fails the run before any lease is issued, so a namespace user can
/// never steer a borrowed credential into a self-chosen image.
pub fn validate_credentialed_image(image: &str, allowed_images: &[String]) -> Result<(), String> {
    let pinned = image
        .rsplit_once('@')
        .is_some_and(|(_, d)| {
            d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
        });
    if !pinned {
        return Err(format!("image {image:?} is not digest-pinned (repo@sha256:<hex> required)"));
    }
    if !allowed_images.iter().any(|a| a == image) {
        return Err(format!("image {image:?} is not on the operator allowlist"));
    }
    Ok(())
}

/// V2 admission: resolve the effective service account and require it to be
/// operator-allowlisted.
pub fn resolve_service_account(
    configured: Option<&str>,
    allowed_service_accounts: &[String],
) -> Result<String, String> {
    let sa = configured.unwrap_or(DEFAULT_AGENT_SERVICE_ACCOUNT);
    if !allowed_service_accounts.iter().any(|a| a == sa) {
        return Err(format!("serviceAccountName {sa:?} is not on the operator allowlist"));
    }
    Ok(sa.to_string())
}

impl RepositoryInput {
    pub fn validate(&self) -> Result<(), SpecError> {
        let url = self.url.trim();
        let is_file = url.starts_with("file://");
        let ok_scheme = ["https://", "http://", "ssh://", "git://"]
            .iter()
            .any(|s| url.starts_with(s))
            || (is_file && allow_file_repos());
        if url.is_empty() || !ok_scheme || url.starts_with('-') || url.chars().any(char::is_whitespace) {
            return Err(SpecError::BadRepositoryUrl(self.url.clone()));
        }
        if !is_safe_revision(&self.revision) {
            return Err(SpecError::BadRevision(self.revision.clone()));
        }
        for p in &self.sparse_paths {
            validate_relative_path(p).map_err(|err| SpecError::BadSparsePath { path: p.clone(), err })?;
        }
        Ok(())
    }
}

impl RunnerClassSpec {
    pub fn validate(&self) -> Result<(), SpecError> {
        let bad = |m: &str| SpecError::BadRunnerClass(self.name.clone(), m.to_string());
        if self.name.trim().is_empty() {
            return Err(SpecError::Empty("runnerClass.name"));
        }
        if self.driver.trim().is_empty() {
            return Err(bad("driver must not be empty"));
        }
        if self.image.trim().is_empty() {
            return Err(bad("image must not be empty"));
        }
        if self.timeouts.hard_seconds == 0
            || self.timeouts.no_progress_seconds == 0
            || self.timeouts.heartbeat_seconds == 0
        {
            return Err(bad("timeouts must be > 0"));
        }
        if self.credentials.provider.is_some() && self.credentials.profiles.is_empty() {
            return Err(bad("credentials.provider is set but no profiles are listed"));
        }
        for (k, target) in &self.credentials.file_targets {
            validate_relative_path(target).map_err(|e| bad(&format!("credentials.fileTargets[{k}]: {e}")))?;
        }
        for p in &self.workspace.allowed_paths {
            validate_relative_path(p).map_err(|err| SpecError::BadAllowedPath { path: p.clone(), err })?;
        }
        if self.egress.effective_mode() == EgressMode::Proxy {
            match self.egress.https_proxy.as_deref() {
                None => return Err(bad("egress.mode proxy requires egress.httpsProxy")),
                Some(u)
                    if !(u.starts_with("http://") || u.starts_with("https://")) || u.contains(char::is_whitespace) =>
                {
                    return Err(bad("egress.httpsProxy must be an http:// or https:// URL"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Uses persistent subscription credentials (leased profiles).
    pub fn uses_credentials(&self) -> bool {
        self.credentials.provider.is_some()
    }
}

impl RunSpec {
    /// Runner classes that hold persistent subscription credentials but would run with
    /// unrestricted egress. The engine rejects such runs unless explicitly allowed.
    pub fn credential_egress_violations(&self) -> Vec<String> {
        self.runner_classes
            .iter()
            .filter(|c| c.uses_credentials() && c.egress.effective_mode() != EgressMode::Proxy)
            .map(|c| c.name.clone())
            .collect()
    }
}

/// Conservative git revision check: a SHA or a ref name, never something git could parse
/// as an option.
pub fn is_safe_revision(rev: &str) -> bool {
    !rev.is_empty()
        && rev.len() <= 255
        && !rev.starts_with('-')
        && !rev.contains("..")
        && rev.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '@' | '^' | '~'))
}

/// True if `rev` looks like a full 40 (SHA-1) or 64 (SHA-256) hex object id.
pub fn is_full_sha(rev: &str) -> bool {
    (rev.len() == 40 || rev.len() == 64) && rev.chars().all(|c| c.is_ascii_hexdigit())
}

fn default_true() -> bool {
    true
}
fn one() -> u32 {
    1
}
fn default_capsule_messages() -> u32 {
    12
}
fn default_ws_size() -> String {
    "2Gi".into()
}
fn default_tmp_size() -> String {
    "512Mi".into()
}
fn default_home_size() -> String {
    "1Gi".into()
}
fn default_max_patch() -> u64 {
    DEFAULT_MAX_PATCH_BYTES
}
fn default_hard() -> u64 {
    3600
}
fn default_no_progress() -> u64 {
    600
}
fn default_grace() -> u64 {
    20
}
fn default_heartbeat() -> u64 {
    10
}
fn default_startup() -> u64 {
    300
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn class(name: &str, driver: &str) -> RunnerClassSpec {
        RunnerClassSpec {
            name: name.into(),
            driver: driver.into(),
            driver_config: serde_json::json!({}),
            image: "acp-runner/runner:dev".into(),
            image_pull_policy: None,
            runtime_class_name: None,
            resources: None,
            credentials: CredentialRequirement::default(),
            workspace: WorkspacePolicy::default(),
            timeouts: TimeoutPolicy::default(),
            permissions: PermissionPolicy::default(),
            egress: EgressPolicy::default(),
            env: BTreeMap::new(),
            allow_run_overrides: false,
            run_as_user: None,
            service_account_name: None,
        }
    }

    #[test]
    fn credentialed_image_needs_digest_pin_and_allowlist() {
        let good = "reg/run@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(validate_credentialed_image(good, &[good.to_string()]).is_ok());
        assert!(validate_credentialed_image("reg/run:dev", &[good.to_string()]).is_err());
        assert!(validate_credentialed_image("reg/run:dev@sha256:zzzz", &[good.to_string()]).is_err());
        assert!(validate_credentialed_image(good, &[]).is_err());
        assert!(
            validate_credentialed_image(
                "other@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                &[good.to_string()]
            )
            .is_err()
        );
    }

    #[test]
    fn service_account_resolves_default_and_checks_allowlist() {
        assert_eq!(
            resolve_service_account(None, &[DEFAULT_AGENT_SERVICE_ACCOUNT.to_string()]).unwrap(),
            DEFAULT_AGENT_SERVICE_ACCOUNT
        );
        assert!(resolve_service_account(Some("evil-sa"), &[DEFAULT_AGENT_SERVICE_ACCOUNT.to_string()]).is_err());
        assert!(resolve_service_account(Some("custom"), &["custom".to_string()]).unwrap() == "custom");
    }

    pub fn run_spec() -> RunSpec {
        RunSpec {
            task_id: "task-1".into(),
            prompt: "fix the bug".into(),
            repository: RepositoryInput {
                url: "https://example.com/repo.git".into(),
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
                sparse_paths: vec![],
                depth: None,
            },
            output: OutputExpectation::default(),
            retry: RetryPolicy { max_attempts_per_runner: 2, max_total_attempts: None },
            timeouts: TimeoutOverrides::default(),
            resume: ResumePolicy::default(),
            runner_classes: vec![class("claude-default", "claude"), class("codex-default", "codex")],
            overrides: RunOverrides::default(),
        }
    }

    #[test]
    fn valid_spec_passes() {
        run_spec().validate().unwrap();
    }

    #[test]
    fn rejects_option_injection_in_revision_and_url() {
        let mut s = run_spec();
        s.repository.revision = "--upload-pack=/bin/sh".into();
        assert!(matches!(s.validate(), Err(SpecError::BadRevision(_))));
        let mut s = run_spec();
        s.repository.url = "-oProxyCommand=evil".into();
        assert!(matches!(s.validate(), Err(SpecError::BadRepositoryUrl(_))));
        let mut s = run_spec();
        s.repository.url = "ext::sh -c evil".into();
        assert!(matches!(s.validate(), Err(SpecError::BadRepositoryUrl(_))));
    }

    #[test]
    fn file_urls_need_an_explicit_opt_in() {
        // V8.3: default deny. Save/remove/restore the flag around the deny
        // assertion (microsecond window; no other test toggles this variable).
        let mut s = run_spec();
        s.repository.url = "file:///tmp/fixture.git".into();
        // SAFETY: test-only; the flag is toggled back before returning and no
        // other test in this binary toggles it (microsecond race window).
        unsafe {
            let saved = std::env::var("ACP_RUNNER_ALLOW_FILE_REPOS").ok();
            std::env::remove_var("ACP_RUNNER_ALLOW_FILE_REPOS");
            assert!(matches!(s.validate(), Err(SpecError::BadRepositoryUrl(_))));
            std::env::set_var("ACP_RUNNER_ALLOW_FILE_REPOS", "true");
            s.validate().unwrap();
            std::env::set_var("ACP_RUNNER_ALLOW_FILE_REPOS", "false");
            assert!(matches!(s.validate(), Err(SpecError::BadRepositoryUrl(_))));
            match saved {
                Some(v) => std::env::set_var("ACP_RUNNER_ALLOW_FILE_REPOS", v),
                None => std::env::remove_var("ACP_RUNNER_ALLOW_FILE_REPOS"),
            }
        }
    }

    #[test]
    fn rejects_traversal_in_sparse_paths() {
        let mut s = run_spec();
        s.repository.sparse_paths = vec!["../etc".into()];
        assert!(matches!(s.validate(), Err(SpecError::BadSparsePath { .. })));
        s.repository.sparse_paths = vec!["/abs".into()];
        assert!(matches!(s.validate(), Err(SpecError::BadSparsePath { .. })));
        s.repository.sparse_paths = vec!["src/".into(), "tests".into()];
        s.validate().unwrap();
    }

    #[test]
    fn overrides_apply() {
        let s = RunSpec {
            timeouts: TimeoutOverrides { hard_seconds: Some(5), no_progress_seconds: None, grace_seconds: Some(1) },
            ..run_spec()
        };
        let t = s.effective_timeouts(&s.runner_classes[0]);
        assert_eq!(t.hard_seconds, 5);
        assert_eq!(t.grace_seconds, 1);
        assert_eq!(t.no_progress_seconds, 600);
    }

    #[test]
    fn credential_provider_requires_profiles() {
        let mut s = run_spec();
        s.runner_classes[0].credentials.provider = Some("claude".into());
        assert!(matches!(s.validate(), Err(SpecError::BadRunnerClass(..))));
    }

    #[test]
    fn egress_mode_defaults_validation_and_credential_policy() {
        let mut s = run_spec();
        assert_eq!(s.runner_classes[0].egress.effective_mode(), EgressMode::Direct);
        s.runner_classes[0].credentials = CredentialRequirement {
            provider: Some("claude".into()),
            profiles: vec!["max-1".into()],
            ..Default::default()
        };
        assert_eq!(s.credential_egress_violations(), vec!["claude-default".to_string()]);
        // proxy mode without a proxy is invalid
        s.runner_classes[0].egress.mode = Some(EgressMode::Proxy);
        assert!(matches!(s.validate(), Err(SpecError::BadRunnerClass(..))));
        s.runner_classes[0].egress.https_proxy = Some("http://acp-egress-proxy.acp-egress.svc:3128".into());
        s.validate().unwrap();
        assert!(s.credential_egress_violations().is_empty());
        // a proxy URL alone implies proxy mode
        let e = EgressPolicy { https_proxy: Some("http://p:3128".into()), ..Default::default() };
        assert_eq!(e.effective_mode(), EgressMode::Proxy);
        // ssh:// cannot go through a CONNECT proxy
        s.repository.url = "ssh://git@example.com/repo.git".into();
        assert!(matches!(s.validate(), Err(SpecError::BadRunnerClass(..))));
        // serde: lowercase (and PascalCase alias)
        let e: EgressPolicy = serde_json::from_str(r#"{"mode":"Proxy","httpsProxy":"http://p:1"}"#).unwrap();
        assert_eq!(e.mode, Some(EgressMode::Proxy));
        assert_eq!(serde_json::to_value(EgressMode::Direct).unwrap(), "direct");
    }

    #[test]
    fn full_sha_detection() {
        assert!(is_full_sha("0123456789abcdef0123456789abcdef01234567"));
        assert!(!is_full_sha("main"));
        assert!(is_safe_revision("refs/heads/main"));
        assert!(!is_safe_revision("a..b"));
    }
}
