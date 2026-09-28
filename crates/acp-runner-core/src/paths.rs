//! Path safety helpers: lexical validation plus symlink-safe filesystem placement.
//!
//! Used for sparse-checkout paths, allowed-path prefixes, credential file targets inside
//! the synthetic HOME, launch files (V9), and symlink escape detection when collecting
//! a patch.

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, mkdirat};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path must be relative")]
    Absolute,
    #[error("path must not contain '..'")]
    ParentTraversal,
    #[error("path must not contain NUL or control characters")]
    ControlChar,
    #[error("path must not address the .git directory")]
    GitDir,
    #[error("path is too long")]
    TooLong,
}

/// Validate a repository- or HOME-relative path supplied by configuration.
pub fn validate_relative_path(p: &str) -> Result<(), PathError> {
    if p.is_empty() || p.trim().is_empty() {
        return Err(PathError::Empty);
    }
    if p.len() > 1024 {
        return Err(PathError::TooLong);
    }
    if p.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(PathError::ControlChar);
    }
    if p.starts_with('/') || p.starts_with('\\') || Path::new(p).is_absolute() {
        return Err(PathError::Absolute);
    }
    for comp in Path::new(p).components() {
        match comp {
            Component::ParentDir => return Err(PathError::ParentTraversal),
            Component::RootDir | Component::Prefix(_) => return Err(PathError::Absolute),
            Component::Normal(s) if s == ".git" => return Err(PathError::GitDir),
            _ => {}
        }
    }
    Ok(())
}

/// Join `rel` under `root` after validating it; the result is guaranteed (lexically) to
/// stay inside `root`. Callers that write files must additionally refuse to follow
/// symlinks (see runnerd's `write_new_file`).
pub fn join_within(root: &Path, rel: &str) -> Result<PathBuf, PathError> {
    validate_relative_path(rel)?;
    let mut out = root.to_path_buf();
    for comp in Path::new(rel).components() {
        if let Component::Normal(s) = comp {
            out.push(s);
        }
    }
    Ok(out)
}

/// Lexically normalize a path (resolve `.` and `..` without touching the filesystem).
/// Returns `None` if `..` would climb above the start of a relative path.
pub fn normalize_lexically(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    let mut depth: usize = 0;
    let absolute = p.is_absolute();
    for comp in p.components() {
        match comp {
            Component::RootDir => {
                out.push("/");
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    if absolute {
                        continue; // "/.." == "/"
                    }
                    return None;
                }
                out.pop();
                depth -= 1;
            }
            Component::Normal(s) => {
                out.push(s);
                depth += 1;
            }
            Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Does a symlink at repository-relative `link_path` with target `target` point outside
/// the repository root? Absolute targets always escape.
pub fn symlink_escapes(link_path: &str, target: &str) -> bool {
    let target_path = Path::new(target);
    if target_path.is_absolute() || target.starts_with('~') {
        return true;
    }
    let parent = Path::new(link_path).parent().unwrap_or_else(|| Path::new(""));
    let joined = parent.join(target_path);
    match normalize_lexically(&joined) {
        None => true,
        Some(p) => p.components().any(|c| matches!(c, Component::Normal(s) if s == ".git")),
    }
}

/// Does repository-relative `path` fall under one of `prefixes`? Empty prefix list allows all.
pub fn path_allowed(path: &str, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|pre| {
        let pre = pre.trim_end_matches('/');
        path == pre || path.starts_with(&format!("{pre}/"))
    })
}

fn open_dir(root: &Path) -> std::io::Result<OwnedFd> {
    nix::fcntl::open(root, OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(std::io::Error::from)
}

/// Create or replace a file below `root`, never following symlinks: a symlink (or file) at
/// the target is unlinked — not followed — before the new file is created exclusively.
/// Directories on the way are created (0755) and must not be symlinks.
/// `rel` is validated like any other configuration-supplied relative path.
pub fn replace_beneath(root: &Path, rel: &str, bytes: &[u8], mode: u32) -> std::io::Result<PathBuf> {
    validate_relative_path(rel)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    let name = *comps.last().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let mut dir = open_dir(root)?;
    for c in &comps[..comps.len() - 1] {
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
    match nix::unistd::unlinkat(&dir, name, nix::unistd::UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(nix::errno::Errno::ENOENT) => {}
        Err(e) => return Err(e.into()),
    }
    let fd = openat(
        &dir,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode),
    )
    .map_err(std::io::Error::from)?;
    let mut f = std::fs::File::from(fd);
    use std::io::Write as _;
    f.write_all(bytes)?;
    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(root.join(comps.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_rejected() {
        assert_eq!(validate_relative_path("../x"), Err(PathError::ParentTraversal));
        assert_eq!(validate_relative_path("a/../../x"), Err(PathError::ParentTraversal));
        assert_eq!(validate_relative_path("/etc/passwd"), Err(PathError::Absolute));
        assert_eq!(validate_relative_path(".git/config"), Err(PathError::GitDir));
        assert_eq!(validate_relative_path("a\0b"), Err(PathError::ControlChar));
        assert_eq!(validate_relative_path(""), Err(PathError::Empty));
        assert!(validate_relative_path("src/lib.rs").is_ok());
        assert!(validate_relative_path("./src").is_ok());
    }

    #[test]
    fn join_within_stays_inside() {
        let root = Path::new("/home/agent");
        assert_eq!(join_within(root, ".codex/auth.json").unwrap(), PathBuf::from("/home/agent/.codex/auth.json"));
        assert!(join_within(root, "../../etc/shadow").is_err());
        assert!(join_within(root, "/etc/shadow").is_err());
    }

    #[test]
    fn symlink_escape_detection() {
        assert!(symlink_escapes("evil", "/etc/passwd"));
        assert!(symlink_escapes("evil", "../outside"));
        assert!(symlink_escapes("a/b/evil", "../../../x"));
        assert!(symlink_escapes("a/evil", "../.git/config"));
        assert!(!symlink_escapes("a/b/ok", "../c"));
        assert!(!symlink_escapes("ok", "src/lib.rs"));
        assert!(symlink_escapes("home", "~/x"));
    }

    #[test]
    fn allowed_prefixes() {
        let p = vec!["src/".to_string(), "README.md".to_string()];
        assert!(path_allowed("src/a.rs", &p));
        assert!(path_allowed("README.md", &p));
        assert!(!path_allowed("srcx/a.rs", &p));
        assert!(!path_allowed("Makefile", &p));
        assert!(path_allowed("anything", &[]));
    }
}
