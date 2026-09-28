//! **Harness providers**: `resolve(name, version) → HarnessArtifact{digest, executable,
//! adapter, manifest}`. One runtime image (runnerd, agentd, git, generic runtime deps);
//! the selected harness is materialized under `/opt/harness` during the trusted bootstrap.
//! Artifacts are pinned by digest: the provider refuses an archive whose digest does not
//! match its manifest (or the environment's `harness.digest`), and runnerd verifies the
//! digest again after download.
//!
//! [`DirHarnessProvider`] layout:
//!
//! ```text
//! <root>/<name>/<version>/manifest.json
//! <root>/<name>/<version>/<archive>          (tar or tar.gz; default "harness.tar.gz")
//!
//! manifest.json = {
//!   "digest": "sha256:<hex of the archive>",       # required: the pin
//!   "archive": "harness.tar.gz",
//!   "executable": "bin/claude",                    # relative to the harness root
//!   "adapter": "claude",                           # driver that launches it
//!   "driverConfig": {"command": "{harness}/bin/claude"},
//!   "path": ["bin"]
//! }
//! ```
//!
//! An OCI-registry provider (pull by digest) implements the same trait.

use acp_runner_core::harness::HarnessArtifactRef;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;

#[async_trait]
pub trait HarnessProvider: Send + Sync {
    /// Resolve and verify a pinned harness artifact.
    async fn resolve(&self, name: &str, version: &str) -> anyhow::Result<HarnessArtifactRef>;
    /// Local path of the (verified) archive with `digest` (served to runnerd).
    async fn open(&self, digest: &str) -> anyhow::Result<PathBuf>;
}

pub struct DirHarnessProvider {
    pub root: PathBuf,
    known: Mutex<HashMap<String, PathBuf>>,
}

impl DirHarnessProvider {
    pub fn new(root: PathBuf) -> Self {
        DirHarnessProvider { root, known: Mutex::new(HashMap::new()) }
    }
}

fn file_digest(p: &std::path::Path) -> std::io::Result<(String, u64)> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        n += k as u64;
        h.update(&buf[..k]);
    }
    Ok((format!("sha256:{}", hex::encode(h.finalize())), n))
}

fn safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c))
}

#[async_trait]
impl HarnessProvider for DirHarnessProvider {
    async fn resolve(&self, name: &str, version: &str) -> anyhow::Result<HarnessArtifactRef> {
        anyhow::ensure!(safe_segment(name) && safe_segment(version), "invalid harness name/version");
        let dir = self.root.join(name).join(version);
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.join("manifest.json"))
                .map_err(|_| anyhow::anyhow!("harness {name} {version} is not available"))?,
        )?;
        let s = |k: &str| manifest.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let pinned = s("digest").ok_or_else(|| anyhow::anyhow!("harness manifest lacks the pinned digest"))?;
        anyhow::ensure!(acp_runner_core::environment::is_sha256_digest(&pinned), "manifest digest is malformed");
        let archive_name = s("archive").unwrap_or_else(|| "harness.tar.gz".into());
        anyhow::ensure!(safe_segment(&archive_name), "invalid archive name");
        let archive = dir.join(&archive_name);
        let a2 = archive.clone();
        let (actual, size) = tokio::task::spawn_blocking(move || file_digest(&a2)).await??;
        anyhow::ensure!(actual == pinned, "harness archive digest {actual} does not match the pinned {pinned}");
        let executable = s("executable").ok_or_else(|| anyhow::anyhow!("harness manifest lacks executable"))?;
        acp_runner_core::paths::validate_relative_path(&executable)?;
        self.known.lock().expect("lock").insert(pinned.clone(), archive);
        Ok(HarnessArtifactRef {
            name: name.into(),
            version: version.into(),
            digest: pinned,
            size_bytes: size,
            executable,
            adapter: s("adapter").unwrap_or_else(|| name.to_string()),
            driver_config: manifest.get("driverConfig").cloned().unwrap_or(serde_json::Value::Null),
            path: manifest
                .get("path")
                .and_then(|p| p.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default(),
            manifest,
        })
    }

    async fn open(&self, digest: &str) -> anyhow::Result<PathBuf> {
        if let Some(p) = self.known.lock().expect("lock").get(digest).cloned() {
            return Ok(p);
        }
        // After a provider restart: rescan manifests.
        for n in std::fs::read_dir(&self.root)?.flatten() {
            for v in std::fs::read_dir(n.path()).into_iter().flatten().flatten() {
                if let (Some(name), Some(ver)) = (n.file_name().to_str(), v.file_name().to_str())
                    && let Ok(r) = self.resolve(name, ver).await
                    && r.digest == digest
                {
                    return Ok(self.known.lock().expect("lock").get(digest).cloned().expect("inserted by resolve"));
                }
            }
        }
        anyhow::bail!("unknown harness artifact {digest}")
    }
}
