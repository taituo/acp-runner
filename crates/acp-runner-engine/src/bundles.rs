//! **Bundle providers**: resolve a reference (`configs: [company-claude]`, `agents:
//! [backend-reviewer]`, `skills: [rust]`) to a [`Bundle`] — files + metadata + digest.
//!
//! The provider API carries only references; the environment provider resolves them at
//! create time, stores the resolved bundles content-addressed in the journal, pins their
//! digests in the attempt spec, and runnerd fetches + verifies + places them. The core is
//! format-agnostic: where files go is the harness layout's decision
//! (`acp_runner_core::harness::bundle_placement`).
//!
//! Implementations: [`DirBundleProvider`] (a directory tree, e.g. a mounted ConfigMap or a
//! git checkout of a company config repo) and [`StaticBundleProvider`] (in memory). A
//! registry/OCI-backed provider only needs to implement [`BundleProvider`].

use acp_runner_core::bundle::{Bundle, BundleFile, BundleKind, is_safe_bundle_name};
use async_trait::async_trait;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum BundleResolveError {
    #[error("{kind} bundle {name:?} not found")]
    NotFound { kind: BundleKind, name: String },
    #[error("{kind} bundle {name:?}: {detail}")]
    Invalid { kind: BundleKind, name: String, detail: String },
}

#[async_trait]
pub trait BundleProvider: Send + Sync {
    async fn resolve(&self, kind: BundleKind, name: &str) -> Result<Bundle, BundleResolveError>;
}

/// `<root>/configs/<name>/…`, `<root>/agents/<name>/…`, `<root>/skills/<name>/…`. Every
/// regular file below the bundle directory is part of the bundle, except an optional
/// `bundle.json` (non-secret metadata). Symlinks and special files are refused.
pub struct DirBundleProvider {
    pub root: PathBuf,
}

fn dir_for(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Config => "configs",
        BundleKind::Agent => "agents",
        BundleKind::Skill => "skills",
    }
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<BundleFile>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let meta = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        let rel = e.path().strip_prefix(base).map_err(|e| e.to_string())?.to_string_lossy().to_string();
        if meta.file_type().is_symlink() {
            return Err(format!("{rel}: symlinks are not allowed in bundles"));
        }
        if meta.is_dir() {
            walk(base, &e.path(), out)?;
        } else if meta.is_file() {
            if rel == "bundle.json" {
                continue;
            }
            let content = std::fs::read(e.path()).map_err(|e| e.to_string())?;
            out.push(BundleFile { path: rel, mode: meta.permissions().mode() & 0o777, content });
        } else {
            return Err(format!("{rel}: not a regular file"));
        }
    }
    Ok(())
}

#[async_trait]
impl BundleProvider for DirBundleProvider {
    async fn resolve(&self, kind: BundleKind, name: &str) -> Result<Bundle, BundleResolveError> {
        let invalid = |detail: String| BundleResolveError::Invalid { kind, name: name.to_string(), detail };
        if !is_safe_bundle_name(name) {
            return Err(invalid("unsafe name".into()));
        }
        let dir = self.root.join(dir_for(kind)).join(name);
        let meta = match std::fs::symlink_metadata(&dir) {
            Ok(m) => m,
            Err(_) => return Err(BundleResolveError::NotFound { kind, name: name.to_string() }),
        };
        if !meta.is_dir() {
            return Err(invalid("not a directory".into()));
        }
        let mut files = vec![];
        walk(&dir, &dir, &mut files).map_err(invalid)?;
        let metadata = match std::fs::read(dir.join("bundle.json")) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| invalid(format!("bundle.json: {e}")))?,
            Err(_) => serde_json::json!({}),
        };
        Bundle::new(kind, name, files, metadata).map_err(|e| invalid(e.to_string()))
    }
}

/// In-memory provider (tests, embedding).
#[derive(Default)]
pub struct StaticBundleProvider {
    bundles: Mutex<HashMap<(BundleKind, String), Bundle>>,
}

impl StaticBundleProvider {
    pub fn insert(&self, b: Bundle) {
        self.bundles.lock().expect("lock").insert((b.kind, b.name.clone()), b);
    }
}

#[async_trait]
impl BundleProvider for StaticBundleProvider {
    async fn resolve(&self, kind: BundleKind, name: &str) -> Result<Bundle, BundleResolveError> {
        self.bundles
            .lock()
            .expect("lock")
            .get(&(kind, name.to_string()))
            .cloned()
            .ok_or_else(|| BundleResolveError::NotFound { kind, name: name.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn directory_bundles_resolve_and_refuse_links() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("skills/rust");
        std::fs::create_dir_all(d.join("scripts")).unwrap();
        std::fs::write(d.join("SKILL.md"), "# Rust").unwrap();
        std::fs::write(d.join("scripts/check.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(d.join("scripts/check.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(d.join("bundle.json"), r#"{"version":"1.2"}"#).unwrap();
        let p = DirBundleProvider { root: tmp.path().into() };
        let b = p.resolve(BundleKind::Skill, "rust").await.unwrap();
        assert_eq!(b.files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), vec!["SKILL.md", "scripts/check.sh"]);
        assert_eq!(b.files[1].mode, 0o755);
        assert_eq!(b.metadata["version"], "1.2");
        b.verify().unwrap();
        assert!(matches!(p.resolve(BundleKind::Skill, "missing").await, Err(BundleResolveError::NotFound { .. })));
        std::os::unix::fs::symlink("/etc/passwd", d.join("passwd")).unwrap();
        assert!(matches!(p.resolve(BundleKind::Skill, "rust").await, Err(BundleResolveError::Invalid { .. })));
    }
}
