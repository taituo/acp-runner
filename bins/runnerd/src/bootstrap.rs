//! **Trusted bootstrap** steps of an environment (runnerd only).
//!
//! ```text
//! TRUSTED (runnerd)                         UNTRUSTED (agentd)
//!   harness artifact: fetch, digest check,    bootstrap.exec: execve(command, argv, env)
//!     safe extraction to /opt/harness           (npm/pip/harness init) in the workdir
//!   checkout BASE (or the empty base)         harness process
//!   overlays: fetch, sha256 + base check,
//!     git apply
//!   bundles: fetch, digest verification,
//!     placement without following links
//!   credentials (home.rs), workdir check
//! ```
//!
//! runnerd never executes anything supplied by the caller or a bundle: bundles are data,
//! `bootstrap.exec` goes to agentd.

use crate::sink::EventSink;
use acp_runner_core::attempt_spec::{BootstrapPlan, BundleMount};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::harness::{HarnessArtifactRef, PlacementRoot};
use acp_runner_core::paths::{replace_beneath, symlink_escapes, validate_relative_path};
use acp_runner_workspace::GitWorkspace;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Limits for harness archives.
pub const MAX_HARNESS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_HARNESS_ENTRIES: usize = 500_000;

fn failed(step: &str, detail: impl Into<String>) -> FailureReason {
    FailureReason::BootstrapFailed { step: step.to_string(), detail: detail.into() }
}

fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

/// Fetch, verify (digest) and extract the pinned harness artifact into `dest`.
pub async fn materialize_harness(
    sink: &mut dyn EventSink,
    h: &HarnessArtifactRef,
    dest: &Path,
    scratch: &Path,
) -> Result<usize, FailureReason> {
    std::fs::create_dir_all(scratch).map_err(|e| failed("harness", e.to_string()))?;
    let tmp = scratch.join("harness-artifact");
    let _ = std::fs::remove_file(&tmp);
    let size = sink.fetch_harness(&h.digest, &tmp).await.map_err(|e| failed("harness", format!("fetch: {e}")))?;
    if size > MAX_HARNESS_BYTES || (h.size_bytes > 0 && size != h.size_bytes) {
        return Err(failed("harness", format!("size {size} does not match the pinned {}", h.size_bytes)));
    }
    let actual = sha256_file(&tmp).map_err(|e| failed("harness", e.to_string()))?;
    if actual != h.digest {
        let _ = std::fs::remove_file(&tmp);
        return Err(failed("harness", format!("digest mismatch: pinned {}, got {actual}", h.digest)));
    }
    let (archive, dest_owned) = (tmp.clone(), dest.to_path_buf());
    let n = tokio::task::spawn_blocking(move || extract_archive(&archive, &dest_owned))
        .await
        .map_err(|e| failed("harness", e.to_string()))?
        .map_err(|e| failed("harness", format!("extract: {e}")))?;
    let _ = std::fs::remove_file(&tmp);
    validate_relative_path(&h.executable).map_err(|e| failed("harness", format!("executable: {e}")))?;
    let exe = std::fs::symlink_metadata(dest.join(&h.executable))
        .map_err(|e| failed("harness", format!("executable {}: {e}", h.executable)))?;
    if !exe.is_file() {
        return Err(failed("harness", format!("executable {} is not a regular file", h.executable)));
    }
    Ok(n)
}

/// Safe extraction of a (optionally gzip-compressed) tar archive into an empty `dest`:
/// regular files, directories and in-tree relative symlinks only; no absolute paths, no
/// `..`, no hard links/devices/FIFOs; setuid/setgid/sticky and group/world write bits are
/// dropped; nothing is written through a symlink.
pub fn extract_archive(archive: &Path, dest: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    if std::fs::read_dir(dest).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("{} is not empty", dest.display()));
    }
    let mut magic = [0u8; 2];
    let gz = std::fs::File::open(archive).and_then(|mut f| f.read_exact(&mut magic)).is_ok() && magic == [0x1f, 0x8b];
    let file = std::fs::File::open(archive).map_err(|e| e.to_string())?;
    let reader: Box<dyn Read> = if gz { Box::new(flate2::read::GzDecoder::new(file)) } else { Box::new(file) };
    let mut ar = tar::Archive::new(reader);
    let mut n = 0usize;
    let mut total: u64 = 0;
    for entry in ar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        n += 1;
        if n > MAX_HARNESS_ENTRIES {
            return Err("too many entries".into());
        }
        let raw = entry.path().map_err(|e| e.to_string())?.to_string_lossy().to_string();
        let rel = raw.trim_start_matches("./").trim_end_matches('/').to_string();
        if rel.is_empty() {
            continue;
        }
        validate_relative_path(&rel).map_err(|e| format!("{raw:?}: {e}"))?;
        let mode = entry.header().mode().unwrap_or(0o644) & 0o755;
        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                crate::home::ensure_dir_beneath(dest, &rel).map_err(|e| format!("{rel}: {e}"))?;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                total += entry.size();
                if total > MAX_HARNESS_BYTES {
                    return Err("archive expands beyond the size limit".into());
                }
                let mut bytes = Vec::with_capacity(entry.size() as usize);
                entry.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                replace_beneath(dest, &rel, &bytes, if mode & 0o111 != 0 { 0o755 } else { 0o644 })
                    .map_err(|e| format!("{rel}: {e}"))?;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("{rel}: symlink without target"))?
                    .to_string_lossy()
                    .to_string();
                if symlink_escapes(&rel, &target) {
                    return Err(format!("{rel}: symlink target {target:?} leaves the harness root"));
                }
                crate::home::symlink_beneath(dest, &rel, &target).map_err(|e| format!("{rel}: {e}"))?;
            }
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader | tar::EntryType::GNULongName => {}
            other => return Err(format!("{rel}: entry type {other:?} is not allowed")),
        }
    }
    Ok(n)
}

/// Fetch every overlay, verify it against the plan (sha256, base revision) and apply it to
/// the checked-out base. Returns (artifact id, changed files) per overlay.
pub async fn apply_overlays(
    sink: &mut dyn EventSink,
    plan: &BootstrapPlan,
    ws: &GitWorkspace,
) -> Result<Vec<(uuid::Uuid, usize)>, FailureReason> {
    let mut out = vec![];
    for o in &plan.overlays {
        let step = format!("overlay {}", o.artifact_id);
        if !o.base_revision.eq_ignore_ascii_case(&ws.base_sha) {
            return Err(failed(
                &step,
                format!("artifact base {} does not match the checked-out base {}", o.base_revision, ws.base_sha),
            ));
        }
        let bytes = sink.fetch_overlay(o.artifact_id).await.map_err(|e| failed(&step, format!("fetch: {e}")))?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != o.sha256 {
            return Err(failed(&step, format!("sha256 mismatch: expected {}, got {actual}", o.sha256)));
        }
        if !bytes.is_empty() {
            ws.apply_patch(&bytes).await.map_err(|e| failed(&step, format!("apply: {e}")))?;
        }
        let files = String::from_utf8_lossy(&bytes).matches("\ndiff --git ").count()
            + usize::from(bytes.starts_with(b"diff --git "));
        out.push((o.artifact_id, files));
    }
    Ok(out)
}

/// Fetch, verify and place every bundle. Returns the workspace-relative paths that must
/// stay out of the artifact.
pub async fn place_bundles(
    sink: &mut dyn EventSink,
    plan: &BootstrapPlan,
    workspace: &Path,
    home: &Path,
) -> Result<(Vec<String>, Vec<serde_json::Value>), FailureReason> {
    let mut excluded = vec![];
    let mut placed = vec![];
    for m in &plan.bundles {
        let step = format!("{} bundle {}", m.kind, m.name);
        let b = sink.fetch_bundle(&m.digest).await.map_err(|e| failed(&step, format!("fetch: {e}")))?;
        b.verify().map_err(|e| failed(&step, e.to_string()))?;
        if b.digest != m.digest || b.kind != m.kind || b.name != m.name {
            return Err(failed(
                &step,
                format!("served bundle {} {} {} is not the pinned one", b.kind, b.name, b.digest),
            ));
        }
        let targets = targets(m, &b).map_err(|e| failed(&step, e))?;
        let root = match m.root {
            PlacementRoot::Workspace => workspace,
            PlacementRoot::Home => home,
        };
        for (rel, file) in targets.iter().zip(&b.files) {
            replace_beneath(root, rel, &file.content, file.mode)
                .map_err(|e| failed(&step, format!("placing {rel}: {e}")))?;
            if m.root == PlacementRoot::Workspace && m.exclude_from_artifact {
                excluded.push(rel.clone());
            }
        }
        placed.push(serde_json::json!({"kind": m.kind, "name": m.name, "digest": m.digest,
            "root": m.root, "files": targets, "excludedFromArtifact": m.exclude_from_artifact && m.root == PlacementRoot::Workspace}));
    }
    Ok((excluded, placed))
}

/// Target path of each bundle file (same order as `b.files`).
fn targets(m: &BundleMount, b: &acp_runner_core::bundle::Bundle) -> Result<Vec<String>, String> {
    if let Some(file) = &m.file {
        if b.files.len() != 1 {
            return Err(format!("single-file target {file:?} but the bundle has {} files", b.files.len()));
        }
        validate_relative_path(file).map_err(|e| format!("target {file:?}: {e}"))?;
        return Ok(vec![file.clone()]);
    }
    let dir = m.dir.trim_matches('/');
    b.files
        .iter()
        .map(|f| {
            let rel = if dir.is_empty() { f.path.clone() } else { format!("{dir}/{}", f.path) };
            validate_relative_path(&rel).map(|_| rel.clone()).map_err(|e| format!("target {rel:?}: {e}"))
        })
        .collect()
}

/// Validate the workdir below the workspace root (real directory, no symlinks on the way)
/// and return it as the agent sees it.
pub fn validate_workdir(workspace: &Path, agent_workspace: &Path, rel: &str) -> Result<PathBuf, FailureReason> {
    crate::home::resolve_dir_beneath(workspace, rel)
        .map_err(|e| failed("workdir", format!("{rel:?} is not a directory inside the workspace: {e}")))?;
    Ok(if rel.is_empty() { agent_workspace.to_path_buf() } else { agent_workspace.join(rel) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_with(entries: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        entries(&mut b);
        b.into_inner().unwrap()
    }

    fn file(b: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, data: &[u8]) {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append_data(&mut h, path, data).unwrap();
    }

    fn link(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
        let mut h = tar::Header::new_gnu();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Symlink);
        b.append_link(&mut h, path, target).unwrap();
    }

    #[test]
    fn archives_extract_safely() {
        let tmp = tempfile::tempdir().unwrap();
        let good = tar_with(|b| {
            file(b, "bin/tool", 0o4755, b"#!/bin/sh\necho hi\n");
            file(b, "lib/data.txt", 0o666, b"d");
            link(b, "bin/alias", "tool");
        });
        let a = tmp.path().join("good.tar");
        std::fs::write(&a, &good).unwrap();
        let dest = tmp.path().join("h1");
        extract_archive(&a, &dest).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dest.join("bin/tool")).unwrap().permissions().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(dest.join("lib/data.txt")).unwrap().permissions().mode() & 0o7777, 0o644);
        assert_eq!(std::fs::read_link(dest.join("bin/alias")).unwrap(), PathBuf::from("tool"));
        for (name, bad) in [
            ("abs-link", tar_with(|b| link(b, "x", "/etc/passwd"))),
            ("escape-link", tar_with(|b| link(b, "x", "../../etc/passwd"))),
            (
                "write-through-link",
                tar_with(|b| {
                    link(b, "d", "e");
                    file(b, "d/f", 0o644, b"x");
                }),
            ),
        ] {
            let p = tmp.path().join(format!("{name}.tar"));
            std::fs::write(&p, &bad).unwrap();
            assert!(extract_archive(&p, &tmp.path().join(name)).is_err(), "{name} extracted");
        }
        // gzip is detected by magic
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &good).unwrap();
        let p = tmp.path().join("good.tar.gz");
        std::fs::write(&p, gz.finish().unwrap()).unwrap();
        extract_archive(&p, &tmp.path().join("h2")).unwrap();
    }
}
