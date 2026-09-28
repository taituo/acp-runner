//! The **thin harness adapter** — data half.
//!
//! A harness adapter is responsible for: probe, auth layout, bundle placement, bootstrap
//! argv, launch argv, ACP transport and shutdown. The process half (probe, launch, ACP
//! transport, shutdown) lives in `acp-runner-drivers` and runs only under agentd. The data
//! half lives here because the *trusted* side needs it without linking driver code:
//!
//! * [`credential_provider`]: which credential whitelist ([`Provider`]) applies,
//! * [`bundle_placement`]: where config/agent/skill bundles go for this harness,
//! * [`HarnessArtifactRef`]: a pinned, digest-verified harness distribution to materialize
//!   under [`HARNESS_ROOT`] (one runtime image; harnesses arrive during bootstrap).
//!
//! Core does not understand any bundle *format*; it only maps a (harness, kind, name) to a
//! directory. Harnesses whose CLI needs more normalization than that get their own small ACP
//! wrapper (Claude Code: `agentd claude-acp-bridge`) so the provider only ever sees a normal
//! ACP agent.

use crate::bundle::BundleKind;
use crate::credentials::Provider;
use serde::{Deserialize, Serialize};

/// Where harness artifacts are materialized in the sandbox (agent view, read-only there).
pub const HARNESS_ROOT: &str = "/opt/harness";
/// Placeholder in harness `driverConfig` templates, replaced by the harness root.
pub const HARNESS_ROOT_PLACEHOLDER: &str = "{harness}";

/// Filesystem root a bundle or bootstrap file is placed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PlacementRoot {
    /// The repository working tree (`/workspace`).
    #[default]
    Workspace,
    /// The synthetic HOME (`/home/agent`).
    Home,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Placement {
    pub root: PlacementRoot,
    /// Directory relative to `root` (`""` = the root itself).
    pub dir: String,
}

/// Credential whitelist of a harness (none for harnesses without persistent login state).
pub fn credential_provider(harness: &str) -> Option<Provider> {
    harness.parse().ok()
}

/// Where a bundle of `kind` named `name` is placed for `harness`. `workdir` is the
/// normalized, workspace-relative harness working directory (`""` = workspace root).
///
/// | harness | agent                     | skill                        | config                 |
/// |---------|---------------------------|------------------------------|------------------------|
/// | claude  | `~/.claude/agents/`       | `~/.claude/skills/<name>/`   | `<workdir>/` (CLAUDE.md) |
/// | codex   | `~/.codex/agents/<name>/` | `~/.codex/skills/<name>/`    | `<workdir>/` (AGENTS.md) |
/// | other   | `~/.acp/agents/<name>/`   | `~/.acp/skills/<name>/`      | `<workdir>/`           |
pub fn bundle_placement(harness: &str, kind: BundleKind, name: &str, workdir: &str) -> Placement {
    let home = |dir: String| Placement { root: PlacementRoot::Home, dir };
    let last = name.rsplit('/').next().unwrap_or(name);
    match (harness, kind) {
        (_, BundleKind::Config) => Placement { root: PlacementRoot::Workspace, dir: workdir.to_string() },
        ("claude", BundleKind::Agent) => home(".claude/agents".into()),
        ("claude", BundleKind::Skill) => home(format!(".claude/skills/{last}")),
        ("codex", BundleKind::Agent) => home(format!(".codex/agents/{last}")),
        ("codex", BundleKind::Skill) => home(format!(".codex/skills/{last}")),
        (_, BundleKind::Agent) => home(format!(".acp/agents/{last}")),
        (_, BundleKind::Skill) => home(format!(".acp/skills/{last}")),
    }
}

/// A resolved, pinned harness distribution (see the engine's `HarnessProvider`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessArtifactRef {
    pub name: String,
    pub version: String,
    /// `sha256:<hex>` of the artifact archive; runnerd refuses anything else.
    pub digest: String,
    pub size_bytes: u64,
    /// Main executable, relative to the harness root.
    pub executable: String,
    /// Driver/adapter that launches it (`claude`, `codex`, `fake`, ...).
    pub adapter: String,
    /// Driver configuration merged over the environment's harness config; string values may
    /// contain [`HARNESS_ROOT_PLACEHOLDER`].
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub driver_config: serde_json::Value,
    /// Directories (relative to the harness root) prepended to the agent PATH.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<String>,
    /// Non-secret manifest as published (for status/debugging).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub manifest: serde_json::Value,
}

/// Replace [`HARNESS_ROOT_PLACEHOLDER`] in every string of `v`.
pub fn substitute_root(v: &serde_json::Value, root: &str) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => serde_json::Value::String(s.replace(HARNESS_ROOT_PLACEHOLDER, root)),
        serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(|x| substitute_root(x, root)).collect()),
        serde_json::Value::Object(o) => {
            serde_json::Value::Object(o.iter().map(|(k, x)| (k.clone(), substitute_root(x, root))).collect())
        }
        other => other.clone(),
    }
}

/// Shallow merge: keys of `overlay` replace keys of `base` (objects only).
pub fn merge_config(base: &serde_json::Value, overlay: &serde_json::Value) -> serde_json::Value {
    match (base, overlay) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            let mut m = b.clone();
            for (k, v) in o {
                m.insert(k.clone(), v.clone());
            }
            serde_json::Value::Object(m)
        }
        (b, serde_json::Value::Null) => b.clone(),
        (serde_json::Value::Null, o) => o.clone(),
        (b, _) => b.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn placement_is_per_harness_and_config_follows_the_workdir() {
        let p = bundle_placement("claude", BundleKind::Skill, "company/rust", "packages/backend");
        assert_eq!(p, Placement { root: PlacementRoot::Home, dir: ".claude/skills/rust".into() });
        let p = bundle_placement("claude", BundleKind::Config, "company-claude", "packages/backend");
        assert_eq!(p, Placement { root: PlacementRoot::Workspace, dir: "packages/backend".into() });
        assert_eq!(bundle_placement("claude", BundleKind::Agent, "reviewer", "").dir, ".claude/agents");
        assert_eq!(bundle_placement("kiro", BundleKind::Agent, "reviewer", "").dir, ".acp/agents/reviewer");
        assert_eq!(credential_provider("codex"), Some(Provider::Codex));
        assert_eq!(credential_provider("fake"), None);
    }

    #[test]
    fn templates_and_merge() {
        let t = json!({"command": "{harness}/bin/claude", "args": ["--x", "{harness}/y"], "n": 1});
        let s = substitute_root(&t, "/opt/harness");
        assert_eq!(s["command"], "/opt/harness/bin/claude");
        assert_eq!(s["args"][1], "/opt/harness/y");
        let m = merge_config(&json!({"model": "a", "command": "claude"}), &s);
        assert_eq!(m["model"], "a");
        assert_eq!(m["command"], "/opt/harness/bin/claude");
    }
}
