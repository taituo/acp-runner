//! Disposable git workspace + patch artifact collection.
//!
//! Invariant implemented here:
//!
//! ```text
//! authoritative input revision  +  disposable filesystem mutations  ->  patch artifact
//! ```
//!
//! * [`prepare`] creates a real git working tree at an exact revision (shallow fetch,
//!   optional sparse checkout). Nothing is ever pushed.
//! * [`collect_patch`] diffs the *working tree* (tracked + untracked, respecting
//!   `.gitignore`) against the base commit into a binary-capable git patch
//!   (`git diff --binary --full-index`), with size cap, symlink-escape and allowed-path
//!   checks.
//!
//! Trust split (v2): the working tree is shared with the untrusted agent, but the
//! **authoritative repository is not**. After checkout, the repository's git directory is
//! snapshotted into a runner-private directory ([`GitWorkspace::git_dir`], e.g.
//! `/var/lib/acp-runner/git`, never mounted into the agent container). Every post-agent git
//! command runs with `--git-dir=<private> --work-tree=<workspace>` and a private index, so
//! whatever the agent does to `<workspace>/.git` (config with `core.fsmonitor`/filters,
//! hooks, alternates, a gitfile pointing elsewhere, a deleted index, rewritten refs) has no
//! effect on patch collection. The agent keeps its own copy in `<workspace>/.git` so the CLI
//! can use `git status`/`git diff`/commits normally; agent commits are still captured
//! because the patch is computed from working-tree *content* against the base commit.
//! (Cost: the object store exists twice; both copies live in memory-backed volumes.)
//!
//! Hardening: every git invocation runs with system/global config disabled, hooks
//! disabled, fsmonitor disabled, no global excludes/attributes files, no external
//! diff/textconv, no terminal prompts.

use acp_runner_core::events::ChangedPath;
use acp_runner_core::paths::{path_allowed, symlink_escapes};
use acp_runner_core::spec::{RepositoryInput, is_full_sha};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("git {args}: {detail}")]
    Git { args: String, detail: String },
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("patch is {size_bytes} bytes, limit is {limit_bytes}")]
    TooLarge { size_bytes: u64, limit_bytes: u64 },
    #[error("workspace policy violation: {0}")]
    Policy(String),
    #[error("base revision mismatch: requested {requested}, got {got}")]
    RevisionMismatch { requested: String, got: String },
}

#[derive(Debug, Clone)]
pub struct GitWorkspace {
    /// The repository working tree (shared with the agent).
    pub dir: PathBuf,
    /// Runner-private snapshot of the git directory taken right after checkout.
    pub git_dir: PathBuf,
    /// Resolved base commit (authoritative input revision).
    pub base_sha: String,
    pub sparse: bool,
    /// Private scratch directory for temporary index files.
    pub scratch: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PatchArtifact {
    pub base_sha: String,
    pub patch: Vec<u8>,
    pub sha256: String,
    pub changed_paths: Vec<ChangedPath>,
}

impl PatchArtifact {
    pub fn is_empty(&self) -> bool {
        self.changed_paths.is_empty()
    }
    pub fn size_bytes(&self) -> u64 {
        self.patch.len() as u64
    }
}

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub max_bytes: u64,
    pub allowed_paths: Vec<String>,
    /// Treat symlinks pointing outside the repository as a policy violation.
    pub reject_symlink_escape: bool,
    /// Exact repository-relative paths that are never part of the artifact (runtime
    /// configuration placed by the bootstrap, setup output). They keep their base content in
    /// the artifact's view whatever happens to them in the working tree.
    pub exclude_paths: Vec<String>,
    /// Opt in to `.gitmodules` changes in the patch (V6, default false).
    /// Gitlinks (mode 160000) are always a policy violation, with or without this.
    pub allow_submodules: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        CollectOptions {
            max_bytes: 8 * 1024 * 1024,
            allowed_paths: vec![],
            reject_symlink_escape: true,
            exclude_paths: vec![],
            allow_submodules: false,
        }
    }
}

/// A `.gitmodules` path: the root file or a nested one (git only honors the
/// root, but nested copies confuse consumers the same way).
fn is_gitmodules(path: &str) -> bool {
    path == ".gitmodules" || path.ends_with("/.gitmodules")
}

/// A path segment that must never appear in the patch (V6): `.git`
/// case-insensitively (the patch must stay safe for macOS and Windows
/// consumers too) and `..`.
fn is_forbidden_segment(seg: &str) -> bool {
    seg.eq_ignore_ascii_case(".git") || seg == ".."
}

fn path_has_forbidden_segment(path: &str) -> bool {
    path.split('/').any(is_forbidden_segment)
}

/// Deterministic base commit of an environment without a repository (inference-only): an
/// empty tree committed with fixed identity and time, so artifacts of such environments can
/// be branched like any other.
pub const EMPTY_BASE_MESSAGE: &str = "acp-runner empty workspace";

/// Build a hardened git command.
pub fn git(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("SSH_ASKPASS", "/bin/false")
        .env("LC_ALL", "C")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "advice.detachedHead=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "safe.directory=*",
        ])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    c
}

async fn run(mut cmd: Command, what: &str) -> Result<Vec<u8>, WorkspaceError> {
    let out = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output().await?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(WorkspaceError::Git {
            args: what.to_string(),
            detail: stderr.lines().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | "),
        });
    }
    Ok(out.stdout)
}

async fn git_ok(dir: &Path, args: &[&str]) -> Result<Vec<u8>, WorkspaceError> {
    let mut c = git(dir);
    c.args(args);
    run(c, &args.join(" ")).await
}

/// Prepare a disposable working tree for `repo` under `dir` (created if missing; must be
/// empty). `scratch` is a runner-private directory (never shared with the agent): it
/// receives the authoritative git directory snapshot (`scratch/git`) and temporary files.
pub async fn prepare(dir: &Path, scratch: &Path, repo: &RepositoryInput) -> Result<GitWorkspace, WorkspaceError> {
    prepare_with_env(dir, scratch, repo, &[]).await
}

/// Like [`prepare`], with extra environment for the network-facing git commands (e.g.
/// `HTTPS_PROXY` when egress goes through a policy proxy).
pub async fn prepare_with_env(
    dir: &Path,
    scratch: &Path,
    repo: &RepositoryInput,
    net_env: &[(String, String)],
) -> Result<GitWorkspace, WorkspaceError> {
    repo.validate().map_err(|e| WorkspaceError::Policy(e.to_string()))?;
    let (dir, scratch) = (&std::path::absolute(dir)?, &std::path::absolute(scratch)?);
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::create_dir_all(scratch).await?;
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(WorkspaceError::Policy(format!("workspace directory {} is not empty", dir.display())));
    }
    git_ok(dir, &["init", "-q", "--initial-branch=acp-runner-base"]).await?;
    git_ok(dir, &["remote", "add", "origin", &repo.url]).await?;
    let sparse = !repo.sparse_paths.is_empty();
    if sparse {
        let mut args = vec!["sparse-checkout", "set", "--no-cone", "--"];
        let patterns: Vec<String> =
            repo.sparse_paths.iter().map(|p| format!("/{}", p.trim_start_matches("./"))).collect();
        args.extend(patterns.iter().map(String::as_str));
        git_ok(dir, &args).await?;
    }
    let depth = format!("--depth={}", repo.depth.unwrap_or(1).max(1));
    let mut fetch: Vec<&str> = vec!["fetch", "-q", "--no-tags", "--no-recurse-submodules", &depth];
    if sparse {
        fetch.push("--filter=blob:none");
    }
    fetch.extend(["origin", "--", repo.revision.as_str()]);
    let net = |args: &[&str]| {
        let mut c = git(dir);
        c.envs(net_env.iter().map(|(k, v)| (k.as_str(), v.as_str()))).args(args);
        c
    };
    if let Err(first) = run(net(&fetch), "fetch").await {
        // Partial clone filters are not supported by every server; retry without.
        if sparse {
            let without: Vec<&str> = fetch.iter().copied().filter(|a| *a != "--filter=blob:none").collect();
            run(net(&without), "fetch").await.map_err(|_| first)?;
        } else {
            return Err(first);
        }
    }
    // Checkout may lazily fetch blobs (partial clone) -> network env as well.
    run(net(&["checkout", "-q", "--detach", "FETCH_HEAD"]), "checkout").await?;
    let base = String::from_utf8_lossy(&git_ok(dir, &["rev-parse", "HEAD"]).await?).trim().to_string();
    if is_full_sha(&repo.revision) && !base.eq_ignore_ascii_case(&repo.revision) {
        return Err(WorkspaceError::RevisionMismatch { requested: repo.revision.clone(), got: base });
    }
    // Identity for agents that commit inside the disposable workspace.
    git_ok(dir, &["config", "user.name", "acp-runner agent"]).await?;
    git_ok(dir, &["config", "user.email", "agent@acp-runner.invalid"]).await?;
    // Authoritative snapshot: runner-private, taken before any agent code runs.
    let git_dir = scratch.join("git");
    if tokio::fs::symlink_metadata(&git_dir).await.is_ok() {
        tokio::fs::remove_dir_all(&git_dir).await?;
    }
    let (src, dst) = (dir.join(".git"), git_dir.clone());
    tokio::task::spawn_blocking(move || copy_tree(&src, &dst))
        .await
        .map_err(|e| WorkspaceError::Io(std::io::Error::other(e.to_string())))??;
    Ok(GitWorkspace { dir: dir.to_path_buf(), git_dir, base_sha: base, sparse, scratch: scratch.to_path_buf() })
}

/// Prepare an empty workspace whose base is the deterministic empty commit
/// ([`EMPTY_BASE_MESSAGE`]). Same private-git-dir split as [`prepare`].
pub async fn prepare_empty(dir: &Path, scratch: &Path) -> Result<GitWorkspace, WorkspaceError> {
    let (dir, scratch) = (&std::path::absolute(dir)?, &std::path::absolute(scratch)?);
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::create_dir_all(scratch).await?;
    if std::fs::read_dir(dir)?.next().is_some() {
        return Err(WorkspaceError::Policy(format!("workspace directory {} is not empty", dir.display())));
    }
    git_ok(dir, &["init", "-q", "--initial-branch=acp-runner-base"]).await?;
    let mut c = git(dir);
    c.env("GIT_AUTHOR_NAME", "acp-runner")
        .env("GIT_AUTHOR_EMAIL", "base@acp-runner.invalid")
        .env("GIT_AUTHOR_DATE", "1970-01-01T00:00:00Z")
        .env("GIT_COMMITTER_NAME", "acp-runner")
        .env("GIT_COMMITTER_EMAIL", "base@acp-runner.invalid")
        .env("GIT_COMMITTER_DATE", "1970-01-01T00:00:00Z")
        .args(["commit", "-q", "--allow-empty", "--no-gpg-sign", "-m", EMPTY_BASE_MESSAGE]);
    run(c, "commit --allow-empty").await?;
    let base = String::from_utf8_lossy(&git_ok(dir, &["rev-parse", "HEAD"]).await?).trim().to_string();
    git_ok(dir, &["config", "user.name", "acp-runner agent"]).await?;
    git_ok(dir, &["config", "user.email", "agent@acp-runner.invalid"]).await?;
    let git_dir = scratch.join("git");
    if tokio::fs::symlink_metadata(&git_dir).await.is_ok() {
        tokio::fs::remove_dir_all(&git_dir).await?;
    }
    let (src, dst) = (dir.join(".git"), git_dir.clone());
    tokio::task::spawn_blocking(move || copy_tree(&src, &dst))
        .await
        .map_err(|e| WorkspaceError::Io(std::io::Error::other(e.to_string())))??;
    Ok(GitWorkspace { dir: dir.to_path_buf(), git_dir, base_sha: base, sparse: false, scratch: scratch.to_path_buf() })
}

/// Recursive copy of a directory tree (regular files, directories, symlinks as links).
fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&entry.path(), &to)?;
        } else if ty.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(entry.path())?, &to)?;
        } else if ty.is_file() {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

impl GitWorkspace {
    /// A hardened git command bound to the private git directory and the shared work tree.
    pub fn authoritative_git(&self) -> Command {
        let mut c = git(&self.dir);
        c.arg(format!("--git-dir={}", self.git_dir.display())).arg(format!("--work-tree={}", self.dir.display()));
        c
    }

    /// Apply a (binary) patch produced by a previous attempt to the working tree (before the
    /// agent starts; the agent sees it as uncommitted changes).
    pub async fn apply_patch(&self, patch: &[u8]) -> Result<(), WorkspaceError> {
        let file = self.scratch.join("previous.patch");
        tokio::fs::write(&file, patch).await?;
        let mut c = self.authoritative_git();
        c.args(["apply", "--binary", "--whitespace=nowarn", file.to_string_lossy().as_ref()]);
        run(c, "apply").await?;
        Ok(())
    }
}

/// Collect the patch of the working tree relative to the base commit.
pub async fn collect_patch(ws: &GitWorkspace, opts: &CollectOptions) -> Result<PatchArtifact, WorkspaceError> {
    let meta = tokio::fs::symlink_metadata(&ws.dir).await?;
    if !meta.is_dir() {
        return Err(WorkspaceError::Policy("the workspace is no longer a directory".into()));
    }
    // Per-call name (V6): parallel collections in one process must not share
    // an index file.
    let index = ws.scratch.join(format!("collect-{}.index", uuid::Uuid::new_v4().simple()));
    let _ = tokio::fs::remove_file(&index).await;
    // Start from the private checkout index so sparse-checkout skip-worktree bits are
    // respected (the agent's `.git/index` is never read).
    let real_index = ws.git_dir.join("index");
    match tokio::fs::symlink_metadata(&real_index).await {
        Ok(m) if m.is_file() => {
            tokio::fs::copy(&real_index, &index).await?;
            // "Racy git": entries whose stat data (seconds granularity) still matches the
            // file are trusted without hashing. An agent edit within the same second as the
            // checkout that keeps the size (e.g. `-` -> `+`) would be invisible, and copying
            // the index gives it a fresh mtime that defeats git's own racy-entry check.
            // Back-dating the copy to t=1s makes every entry racy => contents are verified.
            let f = std::fs::OpenOptions::new().write(true).open(&index)?;
            f.set_times(
                std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)),
            )?;
        }
        _ if !ws.sparse => {
            let mut c = ws.authoritative_git();
            c.env("GIT_INDEX_FILE", &index).args(["read-tree", &ws.base_sha]);
            run(c, "read-tree").await?;
        }
        _ => return Err(WorkspaceError::Policy("git index missing in sparse workspace".into())),
    }
    let with_index = |args: &[&str]| {
        let mut c = ws.authoritative_git();
        c.env("GIT_INDEX_FILE", &index).args(args);
        c
    };
    let excludes: Vec<String> = opts.exclude_paths.iter().map(|p| format!(":(exclude,literal){p}")).collect();
    let mut add: Vec<&str> = vec!["add", "-A", "--", "."];
    add.extend(excludes.iter().map(String::as_str));
    run(with_index(&add), "add -A").await?;

    let name_status = run(
        with_index(&["diff", "--cached", "--no-renames", "--name-status", "-z", &ws.base_sha]),
        "diff --name-status",
    )
    .await?;
    let numstat =
        run(with_index(&["diff", "--cached", "--no-renames", "--numstat", "-z", &ws.base_sha]), "diff --numstat")
            .await?;
    let binary_paths = parse_numstat_binary(&numstat);
    let staged = run(with_index(&["ls-files", "-s", "-z"]), "ls-files -s").await?;
    let modes = parse_modes(&staged);

    let mut changed = vec![];
    let fields: Vec<&[u8]> = name_status.split(|b| *b == 0).filter(|f| !f.is_empty()).collect();
    let mut i = 0;
    while i + 1 < fields.len() {
        let status = String::from_utf8_lossy(fields[i]).to_string();
        let path = String::from_utf8_lossy(fields[i + 1]).to_string();
        i += 2;
        let (mode, blob) = modes
            .iter()
            .find(|(p, _, _)| p == &path)
            .map(|(_, m, b)| (m.clone(), b.clone()))
            .unwrap_or_default();
        // Gitlinks (mode 160000, e.g. a nested `git init`) are always a policy
        // violation (V6): a patch must never smuggle submodule pointers.
        if mode == "160000" {
            let _ = tokio::fs::remove_file(&index).await;
            return Err(WorkspaceError::Policy(format!("gitlink {path:?} is not allowed in the patch")));
        }
        let symlink_blob = (mode == "120000").then(|| blob.clone());
        changed.push(ChangedPath {
            is_binary: binary_paths.contains(&path),
            is_symlink: symlink_blob.is_some() && status != "D",
            path,
            status,
            mode,
        });
        if let Some(blob) = symlink_blob
            && opts.reject_symlink_escape
            && changed.last().map(|c| c.status != "D").unwrap_or(false)
        {
            let target = run(with_index(&["cat-file", "blob", &blob]), "cat-file").await?;
            let target = String::from_utf8_lossy(&target).to_string();
            let p = &changed.last().expect("pushed").path;
            if symlink_escapes(p, &target) {
                let _ = tokio::fs::remove_file(&index).await;
                return Err(WorkspaceError::Policy(format!(
                    "symlink {p:?} points outside the repository ({target:?})"
                )));
            }
        }
    }
    for c in &changed {
        // Case-insensitive `.git` (V6): the patch must stay safe for macOS and
        // Windows consumers too.
        if path_has_forbidden_segment(&c.path) {
            let _ = tokio::fs::remove_file(&index).await;
            return Err(WorkspaceError::Policy(format!("path {:?} is not allowed", c.path)));
        }
        if is_gitmodules(&c.path) && !opts.allow_submodules {
            let _ = tokio::fs::remove_file(&index).await;
            return Err(WorkspaceError::Policy(format!(
                "path {:?} is a submodule configuration (set allowSubmodules to opt in)",
                c.path
            )));
        }
        if !path_allowed(&c.path, &opts.allowed_paths) {
            let _ = tokio::fs::remove_file(&index).await;
            return Err(WorkspaceError::Policy(format!("path {:?} is outside the allowed paths", c.path)));
        }
    }

    let mut cmd = with_index(&[
        "diff",
        "--cached",
        "--binary",
        "--full-index",
        "--no-renames",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        &ws.base_sha,
    ]);
    let (patch, total) = capture_capped(&mut cmd, opts.max_bytes).await?;
    let _ = tokio::fs::remove_file(&index).await;
    if total > opts.max_bytes {
        return Err(WorkspaceError::TooLarge { size_bytes: total, limit_bytes: opts.max_bytes });
    }
    let sha256 = hex::encode(Sha256::digest(&patch));
    Ok(PatchArtifact { base_sha: ws.base_sha.clone(), patch, sha256, changed_paths: changed })
}

/// Content fingerprint of the working tree (as the artifact would see it): path →
/// `mode blob-sha`, computed with a private temporary index. Used to attribute workspace
/// changes to a bootstrap phase.
pub async fn fingerprint(
    ws: &GitWorkspace,
    exclude_paths: &[String],
) -> Result<std::collections::BTreeMap<String, String>, WorkspaceError> {
    // Per-call name (V6): see collect_patch.
    let index = ws.scratch.join(format!("fingerprint-{}.index", uuid::Uuid::new_v4().simple()));
    let _ = tokio::fs::remove_file(&index).await;
    let with_index = |args: &[&str]| {
        let mut c = ws.authoritative_git();
        c.env("GIT_INDEX_FILE", &index).args(args);
        c
    };
    run(with_index(&["read-tree", &ws.base_sha]), "read-tree").await?;
    let excludes: Vec<String> = exclude_paths.iter().map(|p| format!(":(exclude,literal){p}")).collect();
    let mut add: Vec<&str> = vec!["add", "-A", "--", "."];
    add.extend(excludes.iter().map(String::as_str));
    run(with_index(&add), "add -A").await?;
    let staged = run(with_index(&["ls-files", "-s", "-z"]), "ls-files -s").await?;
    let _ = tokio::fs::remove_file(&index).await;
    Ok(staged
        .split(|b| *b == 0)
        .filter_map(|rec| {
            let s = String::from_utf8_lossy(rec);
            let (meta, path) = s.split_once('\t')?;
            let mut m = meta.split_whitespace();
            Some((path.to_string(), format!("{} {}", m.next()?, m.next()?)))
        })
        .collect())
}

/// Paths whose content/mode/presence differs between two fingerprints.
pub fn changed_between(
    before: &std::collections::BTreeMap<String, String>,
    after: &std::collections::BTreeMap<String, String>,
) -> Vec<String> {
    let mut out: Vec<String> =
        after.iter().filter(|(p, v)| before.get(*p) != Some(v)).map(|(p, _)| p.clone()).collect();
    out.extend(before.keys().filter(|p| !after.contains_key(*p)).cloned());
    out.sort();
    out.dedup();
    out
}

/// Run `cmd`, keep at most `cap` bytes of stdout but count all of it.
async fn capture_capped(cmd: &mut Command, cap: u64) -> Result<(Vec<u8>, u64), WorkspaceError> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut stdout = child.stdout.take().expect("piped");
    let mut buf = Vec::new();
    let mut total: u64 = 0;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = stdout.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if (buf.len() as u64) < cap + 1 {
            let room = (cap + 1 - buf.len() as u64) as usize;
            buf.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        return Err(WorkspaceError::Git {
            args: "diff --binary".into(),
            detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok((buf, total))
}

fn parse_numstat_binary(numstat: &[u8]) -> Vec<String> {
    // -z format: "added\tdeleted\tpath\0"
    numstat
        .split(|b| *b == 0)
        .filter_map(|rec| {
            let s = String::from_utf8_lossy(rec);
            let mut parts = s.splitn(3, '\t');
            let (a, d, p) = (parts.next()?, parts.next()?, parts.next()?);
            (a == "-" && d == "-").then(|| p.to_string())
        })
        .collect()
}

/// All staged entries as `(path, mode, blob sha)` (V6: generalizes the old
/// symlink-only parse so gitlinks and exec-bit changes are visible too).
fn parse_modes(ls_files: &[u8]) -> Vec<(String, String, String)> {
    // -z format: "mode sha stage\tpath\0"
    ls_files
        .split(|b| *b == 0)
        .filter_map(|rec| {
            let s = String::from_utf8_lossy(rec);
            let (meta, path) = s.split_once('\t')?;
            let mut m = meta.split_whitespace();
            let (mode, sha) = (m.next()?, m.next()?);
            Some((path.to_string(), mode.to_string(), sha.to_string()))
        })
        .collect()
}

/// Check that `patch` applies cleanly to `base` of `url` (fresh clone into `dir`).
/// Used by tests and the compatibility suite; never touches an authoritative repository.
pub async fn check_patch_applies(url: &str, base: &str, patch: &[u8], dir: &Path) -> Result<(), WorkspaceError> {
    let repo =
        RepositoryInput { url: url.to_string(), revision: base.to_string(), sparse_paths: vec![], depth: Some(1) };
    let scratch = dir.join(".scratch");
    let ws = prepare(&dir.join("repo"), &scratch, &repo).await?;
    let file = scratch.join("check.patch");
    tokio::fs::write(&file, patch).await?;
    git_ok(&ws.dir, &["apply", "--check", "--binary", file.to_string_lossy().as_ref()]).await?;
    Ok(())
}

pub mod fixture {
    //! Tiny fixture repository with a known bug (used by tests, the fake agent and the live
    //! smoke test). The same content ships in `tests/fixtures/buggy-repo`.
    use super::*;

    pub const ADD_SH_BUGGY: &str =
        "#!/bin/sh\n# add A B -> prints A+B\nadd() {\n  echo $(( $1 - $2 ))\n}\nadd \"$1\" \"$2\"\n";
    pub const ADD_SH_FIXED: &str =
        "#!/bin/sh\n# add A B -> prints A+B\nadd() {\n  echo $(( $1 + $2 ))\n}\nadd \"$1\" \"$2\"\n";
    pub const TEST_SH: &str = "#!/bin/sh\n# Exit 0 when add.sh is correct.\nset -e\nout=$(sh \"$(dirname \"$0\")/add.sh\" 2 3)\nif [ \"$out\" = \"5\" ]; then echo PASS; exit 0; fi\necho \"FAIL: expected 5, got $out\"; exit 1\n";
    pub const README: &str = "# buggy-repo\n\n`add.sh` should print the sum of its two arguments. Run `sh test.sh`.\n";

    /// Create the fixture as a git repository at `dir`; returns the commit SHA.
    pub async fn create(dir: &Path) -> Result<String, WorkspaceError> {
        tokio::fs::create_dir_all(dir.join("docs")).await?;
        tokio::fs::write(dir.join("add.sh"), ADD_SH_BUGGY).await?;
        tokio::fs::write(dir.join("test.sh"), TEST_SH).await?;
        tokio::fs::write(dir.join("README.md"), README).await?;
        tokio::fs::write(dir.join("docs/notes.md"), "notes\n").await?;
        git_ok(dir, &["init", "-q", "--initial-branch=main"]).await?;
        git_ok(dir, &["add", "-A"]).await?;
        let mut c = git(dir);
        c.args([
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "buggy add",
        ]);
        run(c, "commit").await?;
        let sha = git_ok(dir, &["rev-parse", "HEAD"]).await?;
        Ok(String::from_utf8_lossy(&sha).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> (tempfile::TempDir, String, String) {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let sha = fixture::create(&src).await.unwrap();
        let url = format!("file://{}", src.display());
        (tmp, url, sha)
    }

    fn opts() -> CollectOptions {
        CollectOptions { max_bytes: 1 << 20, ..Default::default() }
    }

    #[tokio::test]
    async fn excluded_paths_keep_their_base_content_in_the_artifact() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        // provider-injected config (new file) and an overwritten tracked file
        std::fs::write(ws.dir.join("CLAUDE.md"), "injected").unwrap();
        std::fs::write(ws.dir.join("README.md"), "overwritten by bootstrap").unwrap();
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        let o = CollectOptions { exclude_paths: vec!["CLAUDE.md".into(), "README.md".into()], ..opts() };
        let p = collect_patch(&ws, &o).await.unwrap();
        let paths: Vec<_> = p.changed_paths.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["add.sh"]);
        // fingerprints attribute changes
        let before = fingerprint(&ws, &[]).await.unwrap();
        std::fs::write(ws.dir.join("setup.out"), "x").unwrap();
        std::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_BUGGY).unwrap();
        let after = fingerprint(&ws, &[]).await.unwrap();
        assert_eq!(changed_between(&before, &after), vec!["add.sh".to_string(), "setup.out".to_string()]);
    }

    #[tokio::test]
    async fn empty_base_is_deterministic_and_collectable() {
        let tmp = tempfile::tempdir().unwrap();
        let a = prepare_empty(&tmp.path().join("a"), &tmp.path().join("sa")).await.unwrap();
        let b = prepare_empty(&tmp.path().join("b"), &tmp.path().join("sb")).await.unwrap();
        assert_eq!(a.base_sha, b.base_sha);
        std::fs::write(a.dir.join("notes.txt"), "hello\n").unwrap();
        let p = collect_patch(&a, &opts()).await.unwrap();
        assert_eq!(p.changed_paths.len(), 1);
        b.apply_patch(&p.patch).await.unwrap();
        assert_eq!(std::fs::read_to_string(b.dir.join("notes.txt")).unwrap(), "hello\n");
    }

    #[tokio::test]
    async fn prepare_modify_collect_and_apply() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url: url.clone(), revision: sha.clone(), sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        assert_eq!(ws.base_sha, sha);
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        tokio::fs::write(ws.dir.join("new.bin"), [0u8, 159, 146, 150, 0, 1, 2]).await.unwrap();
        tokio::fs::remove_file(ws.dir.join("docs/notes.md")).await.unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        let mut paths: Vec<_> =
            p.changed_paths.iter().map(|c| (c.path.as_str(), c.status.as_str(), c.is_binary)).collect();
        paths.sort();
        assert_eq!(paths, vec![("add.sh", "M", false), ("docs/notes.md", "D", false), ("new.bin", "A", true)]);
        // V6: consumers see the staged modes (empty for deletions).
        let mut modes: Vec<_> = p.changed_paths.iter().map(|c| (c.path.as_str(), c.mode.as_str())).collect();
        modes.sort();
        assert_eq!(modes, vec![("add.sh", "100644"), ("docs/notes.md", ""), ("new.bin", "100644")]);
        let text = String::from_utf8_lossy(&p.patch);
        assert!(text.contains("GIT binary patch"), "{text}");
        assert_eq!(p.sha256.len(), 64);
        check_patch_applies(&url, &sha, &p.patch, &tmp.path().join("check")).await.unwrap();
    }

    #[tokio::test]
    async fn same_second_same_size_edit_is_detected() {
        for _ in 0..5 {
            let (tmp, url, sha) = setup().await;
            let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
            let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
            // immediately rewrite with identical size
            std::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).unwrap();
            let p = collect_patch(&ws, &opts()).await.unwrap();
            assert_eq!(p.changed_paths.len(), 1, "racy edit missed");
        }
    }

    #[tokio::test]
    async fn committed_changes_are_included_and_unchanged_is_empty() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        assert!(p.is_empty());
        assert!(p.patch.is_empty());
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        git_ok(&ws.dir, &["commit", "-qam", "agent commit"]).await.unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        assert_eq!(p.changed_paths.len(), 1);
    }

    #[tokio::test]
    async fn nested_git_init_is_rejected_as_gitlink() {
        // V6: whatever the agent `git init`s inside the worktree stages as a
        // gitlink (mode 160000) — the patch must never carry submodule pointers.
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        let nested = ws.dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        git_ok(&nested, &["init", "-q"]).await.unwrap();
        std::fs::write(nested.join("inner.txt"), "x\n").unwrap();
        git_ok(&nested, &["add", "-A"]).await.unwrap();
        let mut c = git(&nested);
        c.args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "inner"]);
        run(c, "commit").await.unwrap();
        let err = collect_patch(&ws, &opts()).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::Policy(ref m) if m.contains("gitlink")), "{err}");
    }

    #[test]
    fn forbidden_segments_are_case_insensitive_with_boundaries() {
        // V6: direct unit test of the policy helper — `git add` itself refuses
        // `.GIT` variants before `collect_patch` runs, so the helper is tested
        // in isolation (plus the end-to-end collection test below).
        for seg in [".git", ".GIT", ".Git", ".gIt", ".."] {
            assert!(is_forbidden_segment(seg), "{seg}");
        }
        for seg in ["", "git", "x.git", ".github", ".gitmodules", ".gitignore", "…git"] {
            assert!(!is_forbidden_segment(seg), "{seg}");
        }
        for path in [".git/x", "a/.GIT/b", "a/.Git", ".git", "..", "a/../b"] {
            assert!(path_has_forbidden_segment(path), "{path}");
        }
        for path in ["add.sh", "docs/notes.md", ".gitmodules", "a/.gitmodules", "x.git/y", ".github/z"] {
            assert!(!path_has_forbidden_segment(path), "{path}");
        }
    }

    #[tokio::test]
    async fn git_segment_check_is_case_insensitive() {
        // V6: `.GIT`/`.Git` must never reach the patch (macOS/Windows
        // consumers). Our own check is case-insensitive belt-and-suspenders;
        // this git build already refuses the variants at `add` time — either
        // way collection must fail, never produce an artifact containing them.
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        for variant in [".GIT", ".Git"] {
            std::fs::create_dir_all(ws.dir.join(variant)).unwrap();
            std::fs::write(ws.dir.join(variant).join("evil.txt"), "x\n").unwrap();
            let err = collect_patch(&ws, &opts()).await.unwrap_err();
            assert!(
                matches!(err, WorkspaceError::Policy(ref m) if m.contains("not allowed"))
                    || matches!(err, WorkspaceError::Git { .. }),
                "{variant}: {err}"
            );
            std::fs::remove_dir_all(ws.dir.join(variant)).unwrap();
        }
    }

    #[tokio::test]
    async fn gitmodules_change_is_rejected_unless_allowed() {
        // V6: `.gitmodules` is denied by default, opt-in via allowSubmodules.
        // Gitlinks stay denied even with the opt-in.
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        std::fs::write(ws.dir.join(".gitmodules"), "[submodule \"x\"]\n\tpath = x\n").unwrap();
        let err = collect_patch(&ws, &opts()).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::Policy(ref m) if m.contains("submodule")), "{err}");
        let o = CollectOptions { allow_submodules: true, ..opts() };
        let p = collect_patch(&ws, &o).await.unwrap();
        assert!(p.changed_paths.iter().any(|c| c.path == ".gitmodules"));
        // ...but a gitlink is still rejected with the opt-in on.
        let nested = ws.dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        git_ok(&nested, &["init", "-q"]).await.unwrap();
        std::fs::write(nested.join("inner.txt"), "x\n").unwrap();
        git_ok(&nested, &["add", "-A"]).await.unwrap();
        let mut c = git(&nested);
        c.args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "inner"]);
        run(c, "commit").await.unwrap();
        let err = collect_patch(&ws, &o).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::Policy(ref m) if m.contains("gitlink")), "{err}");
    }

    #[tokio::test]
    async fn parallel_collects_are_identical() {
        // V6: per-call index names — two concurrent collections in one process
        // (same pid!) must not share an index file, and must agree byte for byte.
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        let o = opts();
        let (p1, p2) = tokio::join!(collect_patch(&ws, &o), collect_patch(&ws, &o));
        let (p1, p2) = (p1.unwrap(), p2.unwrap());
        assert_eq!(p1.patch, p2.patch);
        assert_eq!(p1.sha256, p2.sha256);
        let mut c1: Vec<_> =
            p1.changed_paths.iter().map(|c| (c.path.clone(), c.status.clone(), c.mode.clone())).collect();
        let mut c2: Vec<_> =
            p2.changed_paths.iter().map(|c| (c.path.clone(), c.status.clone(), c.mode.clone())).collect();
        c1.sort();
        c2.sort();
        assert_eq!(c1, c2);
        assert_eq!(c1, vec![("add.sh".to_string(), "M".to_string(), "100644".to_string())]);
    }

    #[tokio::test]
    async fn symlink_escape_is_rejected() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        std::os::unix::fs::symlink("/etc/passwd", ws.dir.join("evil")).unwrap();
        let err = collect_patch(&ws, &opts()).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::Policy(ref m) if m.contains("symlink")), "{err}");
        // inside-repo symlinks are fine
        std::fs::remove_file(ws.dir.join("evil")).unwrap();
        std::os::unix::fs::symlink("docs/notes.md", ws.dir.join("ok-link")).unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        assert!(p.changed_paths.iter().any(|c| c.path == "ok-link" && c.is_symlink));
    }

    #[tokio::test]
    async fn size_limit_enforced() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        tokio::fs::write(ws.dir.join("big.txt"), "x\n".repeat(50_000)).await.unwrap();
        let o = CollectOptions { max_bytes: 10_000, ..opts() };
        let err = collect_patch(&ws, &o).await.unwrap_err();
        assert!(matches!(err, WorkspaceError::TooLarge { size_bytes, limit_bytes: 10_000 } if size_bytes > 10_000));
    }

    #[tokio::test]
    async fn allowed_paths_enforced() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        let o = CollectOptions { allowed_paths: vec!["docs/".into()], ..opts() };
        assert!(matches!(collect_patch(&ws, &o).await, Err(WorkspaceError::Policy(_))));
        let o = CollectOptions { allowed_paths: vec!["add.sh".into()], ..opts() };
        collect_patch(&ws, &o).await.unwrap();
    }

    #[tokio::test]
    async fn sparse_checkout_does_not_report_missing_files_as_deleted() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec!["docs/".into()], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        assert!(!ws.dir.join("add.sh").exists());
        assert!(ws.dir.join("docs/notes.md").exists());
        tokio::fs::write(ws.dir.join("docs/notes.md"), "changed\n").await.unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        let paths: Vec<_> = p.changed_paths.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["docs/notes.md"]);
    }

    #[tokio::test]
    async fn tampered_git_config_is_neutralized() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        let marker = tmp.path().join("pwned");
        let cfg = format!(
            "[core]\n\tfsmonitor = \"touch {}\"\n[filter \"x\"]\n\tclean = touch {}\n",
            marker.display(),
            marker.display()
        );
        tokio::fs::write(ws.dir.join(".git/config"), cfg).await.unwrap();
        tokio::fs::write(ws.dir.join(".gitattributes"), "* filter=x\n").await.unwrap();
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        collect_patch(&ws, &opts()).await.unwrap();
        assert!(!marker.exists(), "git executed agent-controlled config");
    }

    #[tokio::test]
    async fn agent_rewriting_its_git_dir_does_not_affect_collection() {
        let (tmp, url, sha) = setup().await;
        let repo = RepositoryInput { url, revision: sha, sparse_paths: vec![], depth: None };
        let ws = prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.unwrap();
        assert!(ws.git_dir.starts_with(tmp.path().join("scratch")));
        tokio::fs::write(ws.dir.join("add.sh"), fixture::ADD_SH_FIXED).await.unwrap();
        // The agent replaces its .git with a gitfile pointing at a directory it controls,
        // e.g. to make runnerd read/write somewhere else.
        std::fs::remove_dir_all(ws.dir.join(".git")).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(ws.dir.join(".git"), format!("gitdir: {}\n", elsewhere.display())).unwrap();
        let p = collect_patch(&ws, &opts()).await.unwrap();
        let paths: Vec<_> = p.changed_paths.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["add.sh"]);
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none(), "runnerd touched the agent-chosen gitdir");
    }

    #[tokio::test]
    async fn revision_mismatch_detected_for_unknown_sha() {
        let (tmp, url, _sha) = setup().await;
        let repo = RepositoryInput {
            url,
            revision: "1111111111111111111111111111111111111111".into(),
            sparse_paths: vec![],
            depth: None,
        };
        assert!(prepare(&tmp.path().join("ws"), &tmp.path().join("scratch"), &repo).await.is_err());
    }
}
