//! Content-addressed **bundles**: configuration, agent definitions and skills materialized
//! into an environment during the trusted bootstrap.
//!
//! The provider API only carries *references* (`configs: [company-claude]`, `agents:
//! [backend-reviewer]`, `skills: [rust]`). A `BundleProvider` resolves a reference to a
//! [`Bundle`] — files + metadata + digest; the harness layout (see [`crate::harness`])
//! decides where the files go for a particular harness; runnerd fetches the bundle by
//! digest, verifies it and places it. Nothing here knows any harness file format.

use crate::paths::validate_relative_path;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Limits applied to every bundle.
pub const MAX_BUNDLE_FILES: usize = 512;
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleKind {
    /// Project/harness configuration (e.g. `CLAUDE.md`, `AGENTS.md`).
    Config,
    /// Agent / sub-agent definitions.
    Agent,
    /// Skills.
    Skill,
}

impl BundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BundleKind::Config => "config",
            BundleKind::Agent => "agent",
            BundleKind::Skill => "skill",
        }
    }
}

impl fmt::Display for BundleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleFile {
    /// Relative path inside the bundle.
    pub path: String,
    /// `0o644` or `0o755` (normalized).
    #[serde(default = "default_mode")]
    pub mode: u32,
    #[serde(with = "b64")]
    pub content: Vec<u8>,
}

fn default_mode() -> u32 {
    0o644
}

mod b64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    pub kind: BundleKind,
    pub name: String,
    /// Sorted by path.
    pub files: Vec<BundleFile>,
    /// Free-form, non-secret metadata (version, source, description).
    #[serde(default)]
    pub metadata: serde_json::Value,
    /// `sha256:<hex>` over kind, name and the canonical file list.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("invalid bundle name {0:?}")]
    Name(String),
    #[error("bundle has no files")]
    Empty,
    #[error("bundle has more than {MAX_BUNDLE_FILES} files")]
    TooManyFiles,
    #[error("bundle exceeds {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,
    #[error("invalid file path {0:?}: {1}")]
    Path(String, String),
    #[error("duplicate file path {0:?}")]
    Duplicate(String),
    #[error("bundle digest mismatch (declared {declared}, actual {actual})")]
    Digest { declared: String, actual: String },
}

/// Bundle names map to on-disk layout, so keep them to a safe slug (`a-z0-9._-/`).
pub fn is_safe_bundle_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with(['-', '.', '/'])
        && !s.ends_with('/')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !s.contains("..")
        && !s.contains("//")
}

fn normalize_mode(m: u32) -> u32 {
    if m & 0o111 != 0 { 0o755 } else { 0o644 }
}

impl Bundle {
    /// Build a validated bundle (files sorted, modes normalized, digest computed).
    pub fn new(
        kind: BundleKind,
        name: &str,
        mut files: Vec<BundleFile>,
        metadata: serde_json::Value,
    ) -> Result<Bundle, BundleError> {
        for f in &mut files {
            f.mode = normalize_mode(f.mode);
            f.path = f.path.trim_start_matches("./").to_string();
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let digest = Self::compute_digest(kind, name, &files);
        let b = Bundle { kind, name: name.to_string(), files, metadata, digest };
        b.check()?;
        Ok(b)
    }

    pub fn compute_digest(kind: BundleKind, name: &str, files: &[BundleFile]) -> String {
        let mut h = Sha256::new();
        h.update(b"acp-runner-bundle/v1\0");
        h.update(kind.as_str().as_bytes());
        h.update([0]);
        h.update(name.as_bytes());
        h.update([0]);
        for f in files {
            h.update(f.path.as_bytes());
            h.update([0]);
            h.update(f.mode.to_be_bytes());
            h.update((f.content.len() as u64).to_be_bytes());
            h.update(&f.content);
        }
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    fn check(&self) -> Result<(), BundleError> {
        if !is_safe_bundle_name(&self.name) {
            return Err(BundleError::Name(self.name.clone()));
        }
        if self.files.is_empty() {
            return Err(BundleError::Empty);
        }
        if self.files.len() > MAX_BUNDLE_FILES {
            return Err(BundleError::TooManyFiles);
        }
        if self.files.iter().map(|f| f.content.len()).sum::<usize>() > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        for (i, f) in self.files.iter().enumerate() {
            validate_relative_path(&f.path).map_err(|e| BundleError::Path(f.path.clone(), e.to_string()))?;
            if i > 0 && self.files[i - 1].path == f.path {
                return Err(BundleError::Duplicate(f.path.clone()));
            }
        }
        Ok(())
    }

    /// Re-validate and recompute the digest (runnerd does this before placing anything).
    pub fn verify(&self) -> Result<(), BundleError> {
        self.check()?;
        let sorted = self.files.windows(2).all(|w| w[0].path < w[1].path);
        let normalized = self.files.iter().all(|f| f.mode == normalize_mode(f.mode));
        let actual = Self::compute_digest(self.kind, &self.name, &self.files);
        if !sorted || !normalized || actual != self.digest {
            return Err(BundleError::Digest { declared: self.digest.clone(), actual });
        }
        Ok(())
    }

    pub fn size_bytes(&self) -> usize {
        self.files.iter().map(|f| f.content.len()).sum()
    }

    /// File list without content (for metadata listings).
    pub fn manifest(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.files
                .iter()
                .map(|f| {
                    serde_json::json!({"path": f.path, "mode": f.mode, "bytes": f.content.len(),
                    "sha256": hex::encode(Sha256::digest(&f.content))})
                })
                .collect(),
        )
    }
}

/// Convenience for tests and simple providers: a single text file.
pub fn text_file(path: &str, text: &str) -> BundleFile {
    BundleFile { path: path.to_string(), mode: 0o644, content: text.as_bytes().to_vec() }
}

/// Base64 helper exposed for transports that carry raw bundle bytes.
pub fn encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_canonical_and_verified() {
        let a = Bundle::new(
            BundleKind::Skill,
            "rust",
            vec![text_file("b.md", "B"), BundleFile { path: "./a.sh".into(), mode: 0o700, content: b"x".to_vec() }],
            serde_json::json!({"version": "1"}),
        )
        .unwrap();
        assert_eq!(a.files[0].path, "a.sh");
        assert_eq!(a.files[0].mode, 0o755);
        a.verify().unwrap();
        // same content in another order -> same digest
        let b = Bundle::new(
            BundleKind::Skill,
            "rust",
            vec![BundleFile { path: "a.sh".into(), mode: 0o755, content: b"x".to_vec() }, text_file("b.md", "B")],
            serde_json::Value::Null,
        )
        .unwrap();
        assert_eq!(a.digest, b.digest);
        // kind/name are part of the identity
        let c = Bundle::new(BundleKind::Agent, "rust", b.files.clone(), serde_json::Value::Null).unwrap();
        assert_ne!(c.digest, b.digest);
        // tampering is detected
        let mut t = a.clone();
        t.files[1].content = b"evil".to_vec();
        assert!(matches!(t.verify(), Err(BundleError::Digest { .. })));
        // JSON roundtrip keeps the digest valid
        let back: Bundle = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        back.verify().unwrap();
    }

    #[test]
    fn unsafe_bundles_are_refused() {
        let bad = |files: Vec<BundleFile>| Bundle::new(BundleKind::Config, "x", files, serde_json::Value::Null);
        assert!(matches!(bad(vec![]), Err(BundleError::Empty)));
        assert!(matches!(bad(vec![text_file("../x", "")]), Err(BundleError::Path(..))));
        assert!(matches!(bad(vec![text_file("/etc/x", "")]), Err(BundleError::Path(..))));
        assert!(matches!(bad(vec![text_file(".git/config", "")]), Err(BundleError::Path(..))));
        assert!(matches!(bad(vec![text_file("a", ""), text_file("a", "")]), Err(BundleError::Duplicate(_))));
        assert!(Bundle::new(BundleKind::Config, "../x", vec![text_file("a", "")], serde_json::Value::Null).is_err());
        assert!(is_safe_bundle_name("company/claude-review"));
        assert!(!is_safe_bundle_name("a//b"));
    }
}
