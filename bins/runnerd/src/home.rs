//! Synthetic per-attempt HOME and credential placement.
//!
//! Separation (Kubernetes pod, v2):
//!
//! ```text
//! runnerd container only:
//!   /var/run/acp-runner/attempt/   read-only Secret: `token`, `cred.<key>` (never written, never shared)
//!   /var/lib/acp-runner/           runnerd-private state (authoritative git dir, scratch)
//! shared with the agent container:
//!   /home/agent                    synthetic HOME (memory-backed, writable by the agent)
//!     .codex/auth.json               ephemeral COPY of the leased credential (CLI may refresh it)
//!     .acp-credentials/<key>         credentials the CLI receives via environment variable;
//!                                    agentd reads + deletes them and sets the variable for the
//!                                    CLI process only (e.g. CLAUDE_CODE_OAUTH_TOKEN)
//!     .claude/ .cache/ .config/ ...  ephemeral CLI state
//!   /workspace                     git working tree (disposable)
//!   /run/acp-runner                agentd socket
//! ```
//!
//! A credential the CLI must use is unavoidably inside the agent's trust domain; what the
//! agent never gets is the Kubernetes Secret, the attempt token or the controller's
//! identity. Persistent credential state is never writable by the run: the CLI works on a
//! copy, and a refreshed copy only reaches the store through the controller's validated
//! write-back.
//!
//! The HOME is shared with an untrusted process, so every path below it is resolved with
//! `openat(2)` + `O_NOFOLLOW` component by component ([`write_beneath`], [`read_beneath`]):
//! a symlink planted by the agent can neither redirect where runnerd writes a credential nor
//! make runnerd read (and hand to the controller) a file outside the HOME.

use acp_runner_core::attempt_spec::{CredentialLayout, secret_file_name};
use acp_runner_core::failure::FailureReason;
use acp_runner_core::paths::validate_relative_path;
use acp_runner_core::redact::Redactor;
use acp_runner_ipc::STAGED_CREDENTIALS_DIR;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Upper bound for a credential file read back from the shared HOME.
pub const MAX_WRITEBACK_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone)]
pub struct WritebackFile {
    pub key: String,
    /// Path relative to the HOME.
    pub rel: String,
    pub original_sha256: String,
}

/// A credential staged for environment delivery (relative to the HOME).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEnv {
    pub env_name: String,
    pub rel: String,
}

#[derive(Debug, Clone, Default)]
pub struct PreparedHome {
    pub staged_env: Vec<StagedEnv>,
    pub writeback: Vec<WritebackFile>,
    pub placed_files: Vec<PathBuf>,
}

fn open_dir(root: &Path) -> std::io::Result<OwnedFd> {
    nix::fcntl::open(root, OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(std::io::Error::from)
}

fn components(rel: &str) -> std::io::Result<Vec<&str>> {
    validate_relative_path(rel).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(rel.split('/').filter(|c| !c.is_empty() && *c != ".").collect())
}

/// Walk to the parent directory of `rel` below `root` without following symlinks,
/// optionally creating missing directories (mode 0700).
fn walk_parent(root: &Path, comps: &[&str], create: bool) -> std::io::Result<OwnedFd> {
    let mut dir = open_dir(root)?;
    for c in &comps[..comps.len().saturating_sub(1)] {
        if create {
            match mkdirat(&dir, *c, Mode::from_bits_truncate(0o700)) {
                Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        dir = openat(
            &dir,
            *c,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
    }
    Ok(dir)
}

/// Create a file that must not exist yet below `root`, never following symlinks.
pub fn write_beneath(root: &Path, rel: &str, bytes: &[u8], mode: u32) -> std::io::Result<PathBuf> {
    let comps = components(rel)?;
    let name = *comps.last().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let dir = walk_parent(root, &comps, true)?;
    let fd = openat(
        &dir,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode),
    )
    .map_err(std::io::Error::from)?;
    let mut f = std::fs::File::from(fd);
    f.write_all(bytes)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    Ok(root.join(comps.join("/")))
}

/// Walk (creating, 0755) every directory of `rel` below `root` without following symlinks.
fn walk_create(root: &Path, comps: &[&str]) -> std::io::Result<OwnedFd> {
    let mut dir = open_dir(root)?;
    for c in comps {
        match mkdirat(&dir, *c, Mode::from_bits_truncate(0o755)) {
            Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
            Err(e) => return Err(e.into()),
        }
        dir = openat(
            &dir,
            *c,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
    }
    Ok(dir)
}

/// Create the directory `rel` (and parents) below `root` without following symlinks.
pub fn ensure_dir_beneath(root: &Path, rel: &str) -> std::io::Result<()> {
    let comps = components(rel)?;
    walk_create(root, &comps).map(|_| ())
}

/// Create a symlink `rel -> target` below `root` (parents created without following links).
/// The caller validates `target`.
pub fn symlink_beneath(root: &Path, rel: &str, target: &str) -> std::io::Result<()> {
    let comps = components(rel)?;
    let name = *comps.last().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let dir = walk_create(root, &comps[..comps.len() - 1])?;
    nix::unistd::symlinkat(target, &dir, name).map_err(std::io::Error::from)
}

/// Check that `rel` (`""` = `root`) is a real directory below `root`, reached without
/// traversing any symlink.
pub fn resolve_dir_beneath(root: &Path, rel: &str) -> std::io::Result<PathBuf> {
    let mut dir = open_dir(root)?;
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }
    let comps = components(rel)?;
    for c in &comps {
        dir = openat(
            &dir,
            *c,
            OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{c}: {e}")))?;
    }
    drop(dir);
    Ok(root.join(comps.join("/")))
}

/// Read a regular file below `root` without following symlinks (FIFOs/devices refused,
/// size-capped).
pub fn read_beneath(root: &Path, rel: &str, max: u64) -> std::io::Result<Vec<u8>> {
    let comps = components(rel)?;
    let name = *comps.last().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let dir = walk_parent(root, &comps, false)?;
    let fd =
        openat(&dir, name, OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC, Mode::empty())
            .map_err(std::io::Error::from)?;
    let f = std::fs::File::from(fd);
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a regular file"));
    }
    if meta.len() > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too large"));
    }
    Ok(buf)
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && !key.starts_with('.')
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Create the synthetic HOME skeleton (directories only, no secrets). Always
/// safe to run before the untrusted bootstrap: it carries no credentials.
pub fn prepare_home_base(home: &Path) -> Result<(), FailureReason> {
    let io = |e: std::io::Error| FailureReason::Internal { detail: format!("preparing HOME: {e}") };
    std::fs::create_dir_all(home).map_err(io)?;
    std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
    for d in [".config", ".cache", ".local/share", ".local/state"] {
        std::fs::create_dir_all(home.join(d)).map_err(io)?;
    }
    Ok(())
}

/// Staged env files derived from a credential layout (relative to the HOME).
/// Used both when placing and when advertising the paths to agentd before the
/// files exist (deferred placement).
pub fn staged_env_rels(layout: &CredentialLayout) -> Vec<StagedEnv> {
    layout
        .env
        .iter()
        .map(|e| StagedEnv { env_name: e.env_name.clone(), rel: format!("{STAGED_CREDENTIALS_DIR}/{}", e.key) })
        .collect()
}

/// Place credential copies and staged env files into a prepared HOME. Must run
/// only after the untrusted bootstrap finished (or when there is no bootstrap):
/// anything the bootstrap planted at a credential target fails here with
/// [`FailureReason::WorkspacePolicyViolation`] (`O_EXCL`, links never followed)
/// instead of being overwritten or redirected.
pub fn place_credentials(
    home: &Path,
    layout: Option<&CredentialLayout>,
    secret_dir: Option<&Path>,
    redactor: &mut Redactor,
) -> Result<PreparedHome, FailureReason> {
    let mut out = PreparedHome::default();
    let Some(layout) = layout else { return Ok(out) };
    let secret_dir = secret_dir.ok_or_else(|| FailureReason::CredentialUnavailable {
        detail: "credential layout present but no secret mount".into(),
    })?;
    let read_secret = |key: &str| -> Result<Vec<u8>, FailureReason> {
        let p = secret_dir.join(secret_file_name(key));
        std::fs::read(&p).map_err(|e| FailureReason::CredentialUnavailable {
            detail: format!("credential key {key:?} of profile {:?} not mounted: {e}", layout.profile),
        })
    };
    let policy = |what: String, e: std::io::Error| FailureReason::WorkspacePolicyViolation {
        detail: format!("cannot place {what} (refusing to follow links/overwrite): {e}"),
    };
    for f in &layout.files {
        let bytes = read_secret(&f.key)?;
        if let Ok(s) = std::str::from_utf8(&bytes) {
            redactor.add_secret(s);
        }
        let target = write_beneath(home, &f.target, &bytes, f.mode)
            .map_err(|e| policy(format!("credential at {:?}", f.target), e))?;
        out.placed_files.push(target);
        if f.writeback {
            out.writeback.push(WritebackFile {
                key: f.key.clone(),
                rel: f.target.clone(),
                original_sha256: hex::encode(Sha256::digest(&bytes)),
            });
        }
    }
    for e in &layout.env {
        if !valid_key(&e.key) {
            return Err(FailureReason::Unsupported { detail: format!("invalid credential key {:?}", e.key) });
        }
        let bytes = read_secret(&e.key)?;
        let value = String::from_utf8(bytes)
            .map_err(|_| FailureReason::CredentialUnavailable {
                detail: format!("credential {:?} is not UTF-8", e.key),
            })?
            .trim()
            .to_string();
        redactor.add_secret(&value);
        let rel = format!("{STAGED_CREDENTIALS_DIR}/{}", e.key);
        let path = write_beneath(home, &rel, value.as_bytes(), 0o600)
            .map_err(|err| policy(format!("staged credential {:?}", e.key), err))?;
        out.placed_files.push(path);
        out.staged_env.push(StagedEnv { env_name: e.env_name.clone(), rel });
    }
    Ok(out)
}

pub fn prepare_home(
    home: &Path,
    layout: Option<&CredentialLayout>,
    secret_dir: Option<&Path>,
    redactor: &mut Redactor,
) -> Result<PreparedHome, FailureReason> {
    prepare_home_base(home)?;
    place_credentials(home, layout, secret_dir, redactor)
}

/// Refreshed credential files that differ from what was placed. Read without following
/// symlinks; anything that is not a regular file of sane size is ignored.
pub fn changed_writeback_files(home: &Path, prepared: &PreparedHome) -> Vec<(String, Vec<u8>)> {
    prepared
        .writeback
        .iter()
        .filter_map(|w| {
            let bytes = read_beneath(home, &w.rel, MAX_WRITEBACK_BYTES).ok()?;
            (hex::encode(Sha256::digest(&bytes)) != w.original_sha256).then(|| (w.key.clone(), bytes))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_runner_core::attempt_spec::{CredentialEnvLayout, CredentialFileLayout};
    use acp_runner_core::paths::replace_beneath;

    fn layout(target: &str) -> CredentialLayout {
        CredentialLayout {
            provider: "codex".into(),
            profile: "p1".into(),
            files: vec![CredentialFileLayout {
                key: "auth.json".into(),
                target: target.into(),
                mode: 0o600,
                writeback: true,
            }],
            env: vec![CredentialEnvLayout { key: "oauth-token".into(), env_name: "CLAUDE_CODE_OAUTH_TOKEN".into() }],
        }
    }

    fn secrets(dir: &Path) {
        std::fs::write(dir.join("cred.auth.json"), br#"{"tokens":{"access_token":"access-token-value-123456789"}}"#)
            .unwrap();
        std::fs::write(dir.join("cred.oauth-token"), b"sk-ant-oat01-secretvalue0000000\n").unwrap();
    }

    #[test]
    fn credentials_become_ephemeral_copies_and_staged_env_files() {
        let t = tempfile::tempdir().unwrap();
        let (home, sec) = (t.path().join("home"), t.path().join("sec"));
        std::fs::create_dir_all(&sec).unwrap();
        secrets(&sec);
        let mut r = Redactor::new();
        let p = prepare_home(&home, Some(&layout(".codex/auth.json")), Some(&sec), &mut r).unwrap();
        let copy = home.join(".codex/auth.json");
        assert!(copy.exists());
        assert_eq!(std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            p.staged_env,
            vec![StagedEnv { env_name: "CLAUDE_CODE_OAUTH_TOKEN".into(), rel: ".acp-credentials/oauth-token".into() }]
        );
        let staged = home.join(".acp-credentials/oauth-token");
        assert_eq!(std::fs::read_to_string(&staged).unwrap(), "sk-ant-oat01-secretvalue0000000");
        assert_eq!(std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(r.redact_string("x access-token-value-123456789 y").contains("[REDACTED]"));
        assert!(changed_writeback_files(&home, &p).is_empty());
        std::fs::write(&copy, b"{\"refreshed\":true}").unwrap();
        assert_eq!(changed_writeback_files(&home, &p).len(), 1);
        // the mounted original is untouched
        assert!(std::fs::read_to_string(sec.join("cred.auth.json")).unwrap().contains("access-token-value"));
    }

    #[test]
    fn base_then_place_defers_credentials_past_bootstrap() {
        // V4: the HOME skeleton carries no secrets; credentials land only in
        // `place_credentials`, after the untrusted bootstrap finished.
        let t = tempfile::tempdir().unwrap();
        let (home, sec) = (t.path().join("home"), t.path().join("sec"));
        std::fs::create_dir_all(&sec).unwrap();
        secrets(&sec);
        let mut r = Redactor::new();
        prepare_home_base(&home).unwrap();
        assert!(home.join(".config").is_dir());
        assert!(!home.join(".codex/auth.json").exists());
        assert!(!home.join(".acp-credentials/oauth-token").exists());
        let p = place_credentials(&home, Some(&layout(".codex/auth.json")), Some(&sec), &mut r).unwrap();
        assert!(home.join(".codex/auth.json").exists());
        assert_eq!(p.staged_env, staged_env_rels(&layout(".codex/auth.json")));
        // what the bootstrap planted at a credential target is refused, not
        // overwritten: the file the step created survives untouched.
        let home2 = t.path().join("home2");
        prepare_home_base(&home2).unwrap();
        std::fs::create_dir_all(home2.join(".codex")).unwrap();
        std::fs::write(home2.join(".codex/auth.json"), b"planted by bootstrap").unwrap();
        assert!(matches!(
            place_credentials(&home2, Some(&layout(".codex/auth.json")), Some(&sec), &mut r),
            Err(FailureReason::WorkspacePolicyViolation { .. })
        ));
        assert_eq!(std::fs::read_to_string(home2.join(".codex/auth.json")).unwrap(), "planted by bootstrap");
    }

    #[test]
    fn traversal_and_symlink_targets_are_refused() {
        let t = tempfile::tempdir().unwrap();
        let (home, sec) = (t.path().join("home"), t.path().join("sec"));
        std::fs::create_dir_all(&sec).unwrap();
        secrets(&sec);
        let mut r = Redactor::new();
        assert!(matches!(
            prepare_home(&home, Some(&layout("../escape.json")), Some(&sec), &mut r),
            Err(FailureReason::WorkspacePolicyViolation { .. })
        ));
        // pre-planted symlink at the target location
        let home2 = t.path().join("home2");
        std::fs::create_dir_all(home2.join(".codex")).unwrap();
        std::os::unix::fs::symlink(t.path().join("stolen.json"), home2.join(".codex/auth.json")).unwrap();
        assert!(matches!(
            prepare_home(&home2, Some(&layout(".codex/auth.json")), Some(&sec), &mut r),
            Err(FailureReason::WorkspacePolicyViolation { .. })
        ));
        assert!(!t.path().join("stolen.json").exists());
        // pre-planted symlinked *directory* (redirect the whole .codex dir)
        let home3 = t.path().join("home3");
        let elsewhere = t.path().join("elsewhere");
        std::fs::create_dir_all(&home3).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home3.join(".codex")).unwrap();
        assert!(matches!(
            prepare_home(&home3, Some(&layout(".codex/auth.json")), Some(&sec), &mut r),
            Err(FailureReason::WorkspacePolicyViolation { .. })
        ));
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn replace_and_resolve_never_follow_links() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("CLAUDE.md"), "victim").unwrap();
        // target is a symlink to a file outside: it is replaced, the victim untouched
        std::os::unix::fs::symlink(outside.join("CLAUDE.md"), root.join("app/CLAUDE.md")).unwrap();
        replace_beneath(&root, "app/CLAUDE.md", b"placed", 0o644).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("app/CLAUDE.md")).unwrap(), "placed");
        assert_eq!(std::fs::read_to_string(outside.join("CLAUDE.md")).unwrap(), "victim");
        assert!(!std::fs::symlink_metadata(root.join("app/CLAUDE.md")).unwrap().file_type().is_symlink());
        // a symlinked directory on the way is refused
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(replace_beneath(&root, "link/x.md", b"x", 0o644).is_err());
        assert!(!outside.join("x.md").exists());
        // workdir resolution
        resolve_dir_beneath(&root, "app").unwrap();
        resolve_dir_beneath(&root, "").unwrap();
        assert!(resolve_dir_beneath(&root, "link").is_err());
        assert!(resolve_dir_beneath(&root, "missing").is_err());
        assert!(resolve_dir_beneath(&root, "app/CLAUDE.md").is_err());
        assert!(resolve_dir_beneath(&root, "../outside").is_err());
    }

    #[test]
    fn missing_secret_is_credential_unavailable() {
        let t = tempfile::tempdir().unwrap();
        let mut r = Redactor::new();
        let res = prepare_home(&t.path().join("h"), Some(&layout(".codex/auth.json")), Some(t.path()), &mut r);
        assert!(matches!(res, Err(FailureReason::CredentialUnavailable { .. })));
    }

    #[test]
    fn writeback_never_follows_links_or_reads_special_files() {
        let t = tempfile::tempdir().unwrap();
        let (home, sec) = (t.path().join("home"), t.path().join("sec"));
        std::fs::create_dir_all(&sec).unwrap();
        secrets(&sec);
        let mut r = Redactor::new();
        let p = prepare_home(&home, Some(&layout(".codex/auth.json")), Some(&sec), &mut r).unwrap();
        let copy = home.join(".codex/auth.json");
        // (a) file replaced by a symlink to a runner-private file
        std::fs::remove_file(&copy).unwrap();
        std::fs::write(t.path().join("private-token"), b"attempt-token-must-not-leak").unwrap();
        std::os::unix::fs::symlink(t.path().join("private-token"), &copy).unwrap();
        assert!(changed_writeback_files(&home, &p).is_empty());
        // (b) parent directory replaced by a symlink
        std::fs::remove_file(&copy).unwrap();
        std::fs::remove_dir(home.join(".codex")).unwrap();
        let other = t.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("auth.json"), b"{\"planted\":true}").unwrap();
        std::os::unix::fs::symlink(&other, home.join(".codex")).unwrap();
        assert!(changed_writeback_files(&home, &p).is_empty());
        // (c) a FIFO does not block the reader
        std::fs::remove_file(home.join(".codex")).unwrap();
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        nix::unistd::mkfifo(&copy, Mode::from_bits_truncate(0o600)).unwrap();
        assert!(changed_writeback_files(&home, &p).is_empty());
    }
}
