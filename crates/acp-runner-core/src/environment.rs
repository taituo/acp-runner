//! Provider-neutral **agent execution environment** primitive.
//!
//! An `AgentEnvironment` is a durable, caller-facing handle to a disposable, bootstrapped
//! coding-agent runtime: a harness + credentials + configs/agents/skills + a workspace (a
//! repository at an exact revision, optionally with inherited work overlaid), exposing
//! authenticated **raw ACP** for one *or more* turns, with non-terminal `snapshot()`, `branch()`
//! from any snapshot/final artifact, and an explicit, authoritative `finish()`.
//!
//! ```yaml
//! externalRef: review-123
//! harness: {name: claude, version: 2.x, config: {permissionMode: acceptEdits}}
//! workspace:
//!   source: {type: git, url: https://…, revision: abc123}
//!   overlays: [{type: patchArtifact, artifactId: S1}]
//!   workdir: packages/backend
//! credentials: {profile: claude-max-1}
//! agents: [backend-reviewer]
//! skills: [rust, postgres]
//! configs: [company-claude-project]
//! bootstrap:
//!   files: [{bundle: reviewer-config, target: {root: workspace, path: CLAUDE.md}, artifactPolicy: exclude}]
//!   exec:  [{command: /opt/harness/bin/setup, args: [--profile, coding], cwd: app}]
//! lifetime: {idleSeconds: 600}
//! output: {artifact: patch}
//! egress: {mode: proxy}
//! ```
//!
//! Two filesystem inputs are deliberately different things: a **workspace overlay** is
//! inherited *work* (it belongs to the program state and to the artifact); a **bootstrap
//! file** / config bundle is *runtime configuration* (excluded from the artifact by default).
//!
//! The one-shot run/attempt model ([`crate::spec::RunSpec`]) is kept and can be expressed on
//! top of this primitive (the engine's compatibility wrapper). Nothing here mentions
//! Kubernetes.

use crate::bundle::{BundleKind, is_safe_bundle_name};
use crate::harness::PlacementRoot;
use crate::paths::validate_relative_path;
use crate::spec::{EgressPolicy, PermissionPolicy, RepositoryInput, SpecError, TimeoutOverrides, WorkspacePolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// What the caller asks the provider to create. Provider-neutral: no pod/secret/configmap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentSpec {
    /// Opaque external reference (task/session id) owned by the caller.
    pub external_ref: String,
    pub harness: HarnessSpec,
    /// Legacy alias of `workspace.source` (a git repository).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<RepositoryInput>,
    #[serde(default)]
    pub workspace: EnvironmentWorkspace,
    #[serde(default, skip_serializing_if = "BootstrapSpec::is_empty")]
    pub bootstrap: BootstrapSpec,
    #[serde(default)]
    pub credentials: CredentialSelection,
    /// Agent-definition bundle references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
    /// Skill bundle references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<String>,
    /// Configuration bundle references (placed in the workdir by the harness layout).
    #[serde(default, alias = "configBundles", skip_serializing_if = "Vec::is_empty")]
    pub configs: Vec<String>,
    #[serde(default, skip_serializing_if = "Lifetime::is_empty")]
    pub lifetime: Lifetime,
    /// Legacy alias of `lifetime.idleSeconds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub output: EnvironmentOutput,
    /// Kubernetes-style resource requirements as opaque JSON (backend detail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<serde_json::Value>,
    #[serde(default)]
    pub timeouts: TimeoutOverrides,
    #[serde(default)]
    pub permissions: PermissionPolicy,
    #[serde(default)]
    pub egress: EgressPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Preserve raw provider payloads in the journal (redacted, size-capped).
    #[serde(default = "default_true")]
    pub record_raw_payloads: bool,
}

/// Which harness (coding CLI + adapter) to run. The name selects a driver/adapter;
/// version/config are harness-specific. With a harness provider configured, `version` (and
/// optionally `digest`) select a pinned, digest-verified harness artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessSpec {
    /// Driver/harness name (`fake`, `codex`, `claude`, future ACP harnesses).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Expected `sha256:<hex>` of the harness artifact (pinning); verified when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Opaque driver configuration (mode, model, adapter command, …).
    #[serde(default)]
    pub config: serde_json::Value,
}

impl HarnessSpec {
    pub fn named(name: &str) -> HarnessSpec {
        HarnessSpec { name: name.into(), version: None, digest: None, config: serde_json::Value::Null }
    }
}

/// The workspace: where it comes from, what is overlaid on it, where the harness runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentWorkspace {
    /// Original repository/base. Omitted: an empty workspace (inference-only), or — with
    /// overlays — inherited from the overlay's origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<WorkspaceSource>,
    /// Inherited work applied on top of the checked-out base, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlays: Vec<WorkspaceOverlay>,
    /// Harness working directory relative to the workspace root (no `..`, no absolute
    /// paths, must not traverse symlinks). Default: the workspace root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(flatten)]
    pub policy: WorkspacePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum WorkspaceSource {
    Git(RepositoryInput),
}

impl WorkspaceSource {
    pub fn repository(&self) -> &RepositoryInput {
        match self {
            WorkspaceSource::Git(r) => r,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum WorkspaceOverlay {
    /// A patch artifact (snapshot / final) of any earlier environment or run. Artifacts are
    /// cumulative against the original base, so one overlay fully restores that state.
    PatchArtifact { artifact_id: Uuid },
}

impl WorkspaceOverlay {
    pub fn artifact_id(&self) -> Uuid {
        match self {
            WorkspaceOverlay::PatchArtifact { artifact_id } => *artifact_id,
        }
    }
}

/// Bootstrap as plain data: files placed by the trusted side, commands executed by the
/// untrusted side. No shell or Dockerfile language.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<BootstrapFile>,
    /// `execve(command, argv, env)` in the agent container (agentd), before the harness
    /// starts. Never run by runnerd.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<BootstrapExec>,
    /// Whether workspace changes made by `exec` belong to the artifact (default: exclude —
    /// setup output is runtime state, not work).
    #[serde(default)]
    pub exec_artifact_policy: ArtifactPolicy,
}

impl BootstrapSpec {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.exec.is_empty() && self.exec_artifact_policy == ArtifactPolicy::Exclude
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapFile {
    /// Bundle reference.
    pub bundle: String,
    /// Bundle namespace (default `config`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<BundleKind>,
    pub target: FileTarget,
    #[serde(default)]
    pub artifact_policy: ArtifactPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTarget {
    #[serde(default)]
    pub root: PlacementRoot,
    /// A single-file bundle lands exactly here; a multi-file bundle lands below this directory.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactPolicy {
    /// Not part of the workspace artifact (runtime configuration).
    #[default]
    Exclude,
    /// Part of the artifact like any other workspace change.
    Include,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapExec {
    /// Program: absolute path, a name resolved through PATH, or a path relative to `cwd`.
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Working directory relative to the workspace root (default: the workdir).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Extra non-secret environment (credential variables are never passed to bootstrap).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Lifetime {
    /// Destroy after this long idle (no turn, no caller).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_seconds: Option<u64>,
    /// Destroy after this long regardless of activity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_seconds: Option<u64>,
}

impl Lifetime {
    pub fn is_empty(&self) -> bool {
        self.idle_seconds.is_none() && self.max_seconds.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentOutput {
    #[serde(default)]
    pub artifact: OutputArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputArtifact {
    /// `finish()` produces the cumulative, BASE-relative patch artifact.
    #[default]
    Patch,
    /// No final artifact (e.g. a review whose result is the ACP conversation).
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSelection {
    /// Credential profile name resolved by the credential provider; never secret bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Override where a credential file lands, relative to the synthetic HOME.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub file_targets: BTreeMap<String, String>,
}

/// What `branch(artifact, overrides)` may change relative to the origin environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skills: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CredentialSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<Lifetime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<BootstrapSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<EnvironmentOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
}

/// Upper bounds for one environment.
pub const MAX_BUNDLE_REFS: usize = 64;
pub const MAX_BOOTSTRAP_FILES: usize = 64;
pub const MAX_BOOTSTRAP_EXEC: usize = 16;
pub const MAX_OVERLAYS: usize = 8;
pub const MAX_EXEC_TIMEOUT_SECONDS: u64 = 3600;
/// Kept for callers of the v2 API.
pub const MAX_SKILLS: usize = MAX_BUNDLE_REFS;

/// Normalize a workspace-relative working directory: `""`/`"."`/`"./"` → `""`,
/// `"./a/b/"` → `"a/b"`; `..`, absolute paths, `.git` and control characters are refused.
pub fn normalize_workdir(w: &str) -> Result<String, SpecError> {
    let t = w.trim();
    let t = t.strip_prefix("./").unwrap_or(t).trim_end_matches('/');
    if t.is_empty() || t == "." {
        return Ok(String::new());
    }
    validate_relative_path(t).map_err(|e| SpecError::Invalid("workspace.workdir", e.to_string()))?;
    Ok(t.split('/').filter(|c| !c.is_empty() && *c != ".").collect::<Vec<_>>().join("/"))
}

fn valid_env_name(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 128
        && !k.starts_with(|c: char| c.is_ascii_digit())
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl EnvironmentSpec {
    /// A spec for a git source with defaults everywhere else.
    pub fn new(external_ref: &str, harness: HarnessSpec, repository: Option<RepositoryInput>) -> EnvironmentSpec {
        EnvironmentSpec {
            external_ref: external_ref.into(),
            harness,
            repository: None,
            workspace: EnvironmentWorkspace { source: repository.map(WorkspaceSource::Git), ..Default::default() },
            bootstrap: Default::default(),
            credentials: Default::default(),
            agents: vec![],
            skills: vec![],
            configs: vec![],
            lifetime: Default::default(),
            idle_timeout_seconds: None,
            output: Default::default(),
            resources: None,
            timeouts: Default::default(),
            permissions: Default::default(),
            egress: Default::default(),
            runtime_class_name: None,
            env: BTreeMap::new(),
            record_raw_payloads: true,
        }
    }

    /// The original repository (`workspace.source`, or the legacy `repository`).
    pub fn source_repository(&self) -> Option<&RepositoryInput> {
        self.workspace.source.as_ref().map(WorkspaceSource::repository).or(self.repository.as_ref())
    }

    pub fn workdir(&self) -> Result<String, SpecError> {
        normalize_workdir(self.workspace.workdir.as_deref().unwrap_or(""))
    }

    pub fn idle_seconds(&self) -> Option<u64> {
        self.lifetime.idle_seconds.or(self.idle_timeout_seconds)
    }

    pub fn produces_artifact(&self) -> bool {
        self.output.artifact == OutputArtifact::Patch
    }

    pub fn validate(&self) -> Result<(), SpecError> {
        let inv = |what: &'static str, m: String| SpecError::Invalid(what, m);
        if self.external_ref.trim().is_empty() {
            return Err(SpecError::Empty("externalRef"));
        }
        if self.harness.name.trim().is_empty() {
            return Err(SpecError::Empty("harness.name"));
        }
        if let Some(d) = &self.harness.digest
            && !is_sha256_digest(d)
        {
            return Err(inv("harness.digest", format!("{d:?} is not sha256:<64 hex>")));
        }
        if let (Some(a), Some(WorkspaceSource::Git(b))) = (&self.repository, &self.workspace.source)
            && a != b
        {
            return Err(inv("repository", "conflicts with workspace.source (use one)".into()));
        }
        if let Some(r) = self.source_repository() {
            r.validate()?;
        }
        if self.workspace.overlays.len() > MAX_OVERLAYS {
            return Err(inv("workspace.overlays", format!("at most {MAX_OVERLAYS}")));
        }
        // At most one patch artifact (V8.5): artifacts are cumulative against
        // the original base, so stacking two would promise merge semantics
        // that are not defined. The field stays a list for future use.
        let patches =
            self.workspace.overlays.iter().filter(|o| matches!(o, WorkspaceOverlay::PatchArtifact { .. })).count();
        if patches > 1 {
            return Err(inv("workspace.overlays", "at most one patchArtifact overlay".into()));
        }
        self.workdir()?;
        for p in &self.workspace.policy.allowed_paths {
            validate_relative_path(p).map_err(|err| SpecError::BadAllowedPath { path: p.clone(), err })?;
        }
        let refs = self.agents.len() + self.skills.len() + self.configs.len();
        if refs > MAX_BUNDLE_REFS {
            return Err(inv("bundles", format!("at most {MAX_BUNDLE_REFS} agents+skills+configs")));
        }
        for (what, list) in [("agents", &self.agents), ("skills", &self.skills), ("configs", &self.configs)] {
            for s in list {
                if !is_safe_bundle_name(s) {
                    return Err(inv(what, format!("invalid bundle reference {s:?}")));
                }
            }
        }
        if self.bootstrap.files.len() > MAX_BOOTSTRAP_FILES {
            return Err(inv("bootstrap.files", format!("at most {MAX_BOOTSTRAP_FILES}")));
        }
        for f in &self.bootstrap.files {
            if !is_safe_bundle_name(&f.bundle) {
                return Err(inv("bootstrap.files", format!("invalid bundle reference {:?}", f.bundle)));
            }
            validate_relative_path(&f.target.path)
                .map_err(|e| inv("bootstrap.files", format!("target {:?}: {e}", f.target.path)))?;
        }
        if self.bootstrap.exec.len() > MAX_BOOTSTRAP_EXEC {
            return Err(inv("bootstrap.exec", format!("at most {MAX_BOOTSTRAP_EXEC} steps")));
        }
        for (i, x) in self.bootstrap.exec.iter().enumerate() {
            let bad = |m: &str| inv("bootstrap.exec", format!("step {i}: {m}"));
            if x.command.trim().is_empty() || x.command.contains('\0') || x.command.len() > 4096 {
                return Err(bad("command must be a non-empty path or program name"));
            }
            if x.args.len() > 256 || x.args.iter().any(|a| a.contains('\0') || a.len() > 64 * 1024) {
                return Err(bad("too many or too large arguments"));
            }
            if let Some(c) = &x.cwd {
                normalize_workdir(c).map_err(|e| bad(&format!("cwd: {e}")))?;
            }
            if x.env.keys().any(|k| !valid_env_name(k)) {
                return Err(bad("invalid environment variable name"));
            }
            if x.timeout_seconds.is_some_and(|t| t == 0 || t > MAX_EXEC_TIMEOUT_SECONDS) {
                return Err(bad(&format!("timeoutSeconds must be 1..={MAX_EXEC_TIMEOUT_SECONDS}")));
            }
        }
        for (k, target) in &self.credentials.file_targets {
            validate_relative_path(target).map_err(|e| inv("credentials.fileTargets", format!("{k}: {e}")))?;
        }
        if self.egress.effective_mode() == crate::spec::EgressMode::Proxy
            && let Some(r) = self.source_repository()
        {
            let url = r.url.trim();
            if !(url.starts_with("https://") || url.starts_with("file://")) {
                return Err(inv("egress", "mode proxy requires an https:// (or file://) repository URL".into()));
            }
        }
        Ok(())
    }

    pub fn uses_credentials(&self) -> bool {
        self.credentials.profile.is_some()
    }

    /// Apply branch overrides.
    pub fn with_overrides(mut self, o: &EnvironmentOverrides) -> EnvironmentSpec {
        if let Some(v) = &o.external_ref {
            self.external_ref = v.clone();
        }
        if let Some(v) = &o.harness {
            self.harness = v.clone();
        }
        if let Some(v) = &o.agents {
            self.agents = v.clone();
        }
        if let Some(v) = &o.skills {
            self.skills = v.clone();
        }
        if let Some(v) = &o.configs {
            self.configs = v.clone();
        }
        if let Some(v) = &o.credentials {
            self.credentials = v.clone();
        }
        if let Some(v) = &o.lifetime {
            self.lifetime = *v;
            self.idle_timeout_seconds = None;
        }
        if let Some(v) = &o.bootstrap {
            self.bootstrap = v.clone();
        }
        if let Some(v) = &o.output {
            self.output = *v;
        }
        if let Some(v) = &o.workdir {
            self.workspace.workdir = Some(v.clone());
        }
        if let Some(v) = &o.env {
            self.env = v.clone();
        }
        self
    }
}

/// `sha256:<64 lowercase hex>`.
pub fn is_sha256_digest(d: &str) -> bool {
    d.strip_prefix("sha256:").is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Skill/bundle names map to on-disk layout, so keep them to a safe slug.
pub fn is_safe_skill_name(s: &str) -> bool {
    is_safe_bundle_name(s)
}

/// Lifecycle of an environment. `end_turn` moves Busy → Idle, never to a terminal phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnvironmentPhase {
    /// Bootstrap in progress (harness, credentials, skills, repository, probes).
    Creating,
    /// Bootstrapped, session open, no turn running: ready to accept a prompt.
    Idle,
    /// A prompt turn is running.
    Busy,
    /// `finish()` requested: quiescing, collecting the final changeset.
    Finishing,
    /// Finished; the final artifact is available.
    Completed,
    /// Harness/process exit or bootstrap failure; a partial artifact may exist.
    Failed,
}

impl EnvironmentPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            EnvironmentPhase::Creating => "Creating",
            EnvironmentPhase::Idle => "Idle",
            EnvironmentPhase::Busy => "Busy",
            EnvironmentPhase::Finishing => "Finishing",
            EnvironmentPhase::Completed => "Completed",
            EnvironmentPhase::Failed => "Failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, EnvironmentPhase::Completed | EnvironmentPhase::Failed)
    }

    /// Ready to accept an ACP turn.
    pub fn accepts_prompt(self) -> bool {
        self == EnvironmentPhase::Idle
    }

    /// A consistent snapshot is only guaranteed at a turn boundary (Idle).
    pub fn accepts_snapshot(self) -> bool {
        self == EnvironmentPhase::Idle
    }

    pub fn can_transition_to(self, next: EnvironmentPhase) -> bool {
        use EnvironmentPhase::*;
        if self == next {
            return true;
        }
        match self {
            Creating => matches!(next, Idle | Failed),
            Idle => matches!(next, Busy | Finishing | Failed),
            Busy => matches!(next, Idle | Finishing | Failed),
            Finishing => matches!(next, Completed | Failed),
            Completed | Failed => false,
        }
    }
}

impl fmt::Display for EnvironmentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EnvironmentPhase {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Creating" => EnvironmentPhase::Creating,
            "Idle" => EnvironmentPhase::Idle,
            "Busy" => EnvironmentPhase::Busy,
            "Finishing" => EnvironmentPhase::Finishing,
            "Completed" => EnvironmentPhase::Completed,
            "Failed" => EnvironmentPhase::Failed,
            other => return Err(format!("unknown environment phase {other:?}")),
        })
    }
}

/// A caller-requested operation on an environment, resolved by the provider. Snapshot and
/// finish are provider-authoritative (delivered to runnerd as directives); prompt/cancel act
/// on the ACP session through the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum EnvironmentOp {
    Snapshot { label: Option<String> },
    Finish,
    Cancel { reason: String },
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> EnvironmentSpec {
        let mut s = EnvironmentSpec::new(
            "task-1",
            HarnessSpec {
                name: "claude".into(),
                version: Some("2.1.274".into()),
                digest: None,
                config: serde_json::json!({}),
            },
            Some(RepositoryInput {
                url: "https://example.com/repo.git".into(),
                revision: "0123456789abcdef0123456789abcdef01234567".into(),
                sparse_paths: vec![],
                depth: None,
            }),
        );
        s.skills = vec!["rust-backend".into(), "company/conventions".into()];
        s.lifetime.idle_seconds = Some(1800);
        s
    }

    #[test]
    fn valid_spec_passes_and_bad_skills_fail() {
        spec().validate().unwrap();
        let mut s = spec();
        s.skills = vec!["../escape".into()];
        assert!(s.validate().is_err());
        s.skills = vec!["ok".into()];
        s.validate().unwrap();
        s.external_ref = "  ".into();
        assert!(matches!(s.validate(), Err(SpecError::Empty("externalRef"))));
    }

    #[test]
    fn end_turn_never_finishes_the_environment() {
        use EnvironmentPhase::*;
        // Busy -> Idle (end_turn) is allowed; Busy -> Completed is not.
        assert!(Busy.can_transition_to(Idle));
        assert!(!Busy.can_transition_to(Completed));
        // finish() is the only path to Completed, via Finishing.
        assert!(Idle.can_transition_to(Finishing));
        assert!(Finishing.can_transition_to(Completed));
        assert!(!Idle.can_transition_to(Completed));
        // failure is reachable from every live phase.
        for p in [Creating, Idle, Busy, Finishing] {
            assert!(p.can_transition_to(Failed));
        }
        assert!(!Completed.can_transition_to(Failed));
        assert!(Idle.accepts_prompt() && Idle.accepts_snapshot());
        assert!(!Busy.accepts_snapshot());
    }

    #[test]
    fn phase_roundtrips() {
        for p in [
            EnvironmentPhase::Creating,
            EnvironmentPhase::Idle,
            EnvironmentPhase::Busy,
            EnvironmentPhase::Finishing,
            EnvironmentPhase::Completed,
            EnvironmentPhase::Failed,
        ] {
            assert_eq!(p.as_str().parse::<EnvironmentPhase>().unwrap(), p);
        }
    }

    #[test]
    fn proxy_egress_requires_https_or_file_repo() {
        let mut s = spec();
        s.egress.mode = Some(crate::spec::EgressMode::Proxy);
        s.egress.https_proxy = Some("http://p:3128".into());
        let set = |s: &mut EnvironmentSpec, u: &str| {
            if let Some(WorkspaceSource::Git(r)) = &mut s.workspace.source {
                r.url = u.into();
            }
        };
        set(&mut s, "ssh://git@example.com/r.git");
        assert!(s.validate().is_err());
        set(&mut s, "https://example.com/r.git");
        s.validate().unwrap();
    }

    #[test]
    fn at_most_one_patch_artifact_overlay() {
        // V8.5: two cumulative patches have no defined merge semantics.
        let mut s = spec();
        let a = WorkspaceOverlay::PatchArtifact { artifact_id: Uuid::now_v7() };
        let b = WorkspaceOverlay::PatchArtifact { artifact_id: Uuid::now_v7() };
        s.workspace.overlays = vec![a.clone()];
        s.validate().unwrap();
        s.workspace.overlays = vec![a, b];
        assert!(matches!(s.validate(), Err(SpecError::Invalid("workspace.overlays", _))));
    }

    #[test]
    fn v3_spec_shape_parses() {
        let y = serde_json::json!({
            "externalRef": "review-123",
            "harness": {"name": "claude", "version": "2.x", "config": {"permissionMode": "acceptEdits"}},
            "workspace": {
                "source": {"type": "git", "url": "https://example.com/r.git", "revision": "0123456789abcdef0123456789abcdef01234567"},
                "overlays": [{"type": "patchArtifact", "artifactId": "0192f5f0-0000-7000-8000-000000000001"}],
                "workdir": "packages/backend",
                "maxPatchBytes": 1000
            },
            "credentials": {"profile": "claude-max-1"},
            "agents": ["backend-reviewer"], "skills": ["rust", "postgres"], "configBundles": ["company-claude-project"],
            "bootstrap": {
                "files": [{"bundle": "reviewer-config", "target": {"root": "workspace", "path": "CLAUDE.md"}, "artifactPolicy": "exclude"}],
                "exec": [{"command": "/opt/harness/bin/setup", "args": ["--profile", "coding"], "cwd": "app"}]
            },
            "lifetime": {"idleSeconds": 600},
            "output": {"artifact": "none"},
            "egress": {"mode": "proxy"}
        });
        let s: EnvironmentSpec = serde_json::from_value(y).unwrap();
        s.validate().unwrap();
        assert_eq!(s.workdir().unwrap(), "packages/backend");
        assert_eq!(s.configs, vec!["company-claude-project".to_string()]);
        assert_eq!(s.workspace.overlays[0].artifact_id().to_string(), "0192f5f0-0000-7000-8000-000000000001");
        assert_eq!(s.workspace.policy.max_patch_bytes, 1000);
        assert_eq!(s.bootstrap.files[0].artifact_policy, ArtifactPolicy::Exclude);
        assert!(!s.produces_artifact());
        assert_eq!(s.idle_seconds(), Some(600));
        let back: EnvironmentSpec = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn workdir_and_bootstrap_validation() {
        assert_eq!(normalize_workdir("").unwrap(), "");
        assert_eq!(normalize_workdir("./").unwrap(), "");
        assert_eq!(normalize_workdir("./a/b/").unwrap(), "a/b");
        for bad in ["../x", "/abs", "a/../../b", ".git", "a/.git/b"] {
            assert!(normalize_workdir(bad).is_err(), "{bad}");
        }
        let mut s = spec();
        s.bootstrap.exec = vec![BootstrapExec {
            command: "npm".into(),
            args: vec!["ci".into()],
            cwd: Some("../escape".into()),
            env: Default::default(),
            timeout_seconds: None,
        }];
        assert!(s.validate().is_err());
        s.bootstrap.exec[0].cwd = Some("app".into());
        s.validate().unwrap();
        s.bootstrap.files = vec![BootstrapFile {
            bundle: "cfg".into(),
            kind: None,
            target: FileTarget { root: PlacementRoot::Workspace, path: "../CLAUDE.md".into() },
            artifact_policy: ArtifactPolicy::Exclude,
        }];
        assert!(s.validate().is_err());
        // no source at all: an inference-only environment
        let mut s = spec();
        s.workspace.source = None;
        s.validate().unwrap();
        assert!(s.source_repository().is_none());
    }

    #[test]
    fn overrides_replace_only_what_is_given() {
        let s = spec().with_overrides(&EnvironmentOverrides {
            harness: Some(HarnessSpec::named("codex")),
            skills: Some(vec!["review-rules".into()]),
            lifetime: Some(Lifetime { idle_seconds: None, max_seconds: Some(600) }),
            output: Some(EnvironmentOutput { artifact: OutputArtifact::None }),
            ..Default::default()
        });
        assert_eq!(s.harness.name, "codex");
        assert_eq!(s.skills, vec!["review-rules".to_string()]);
        assert_eq!(s.lifetime.max_seconds, Some(600));
        assert_eq!(s.external_ref, "task-1");
        assert!(!s.produces_artifact());
    }
}
