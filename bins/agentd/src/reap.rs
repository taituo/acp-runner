//! Child-subreaper cleanup for bootstrap steps.
//!
//! agentd becomes a child subreaper, so a bootstrap step that backgrounds work
//! (`sh -c 'sleep 600 &'`) cannot disown it past init: the orphan reparents to
//! agentd, the per-step sweep finds it (anything with our pid as ppid that is
//! not us), SIGKILLs and reaps it, and the step fails with `BootstrapFailed`.
//! Already-exited (zombie) children are reaped silently — only processes that
//! outlive the step are a violation, since they would still be alive when the
//! credentials land in the HOME afterwards.

use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::time::Duration;

/// Become a child subreaper (fail-closed: without this, orphaned bootstrap
/// grandchildren would reparent to init and the sweep could not see them).
pub fn ensure_subreaper() -> anyhow::Result<()> {
    nix::sys::prctl::set_child_subreaper(true)
        .map_err(|e| anyhow::anyhow!("PR_SET_CHILD_SUBREAPER: {e}"))?;
    Ok(())
}

/// Is `pid` our live (non-zombie) child process?
fn is_live_child(me: i32, pid: i32) -> bool {
    if pid == me {
        return false;
    }
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Some(end) = stat.rfind(')') else { return false };
    let mut fields = stat[end + 1..].split_whitespace();
    // state, then ppid
    if fields.next() == Some("Z") {
        return false;
    }
    fields.next().and_then(|p| p.parse::<i32>().ok()) == Some(me)
}

fn live_children() -> Vec<i32> {
    let me = std::process::id() as i32;
    let mut out = vec![];
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Ok(pid): Result<i32, _> = e.file_name().to_string_lossy().parse() else { continue };
        if is_live_child(me, pid) {
            out.push(pid);
        }
    }
    out
}

/// Reap all exited children (ours or reparented orphans). Returns true if at
/// least one child was reaped.
fn reap_all() -> bool {
    let mut reaped = false;
    for _ in 0..128 {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => break,
            Ok(_) => reaped = true,
            Err(_) => break,
        }
    }
    reaped
}

/// SIGKILL and reap every live process reparented to (or still parented by)
/// us; reap exited zombies silently. Returns the pids that were still alive —
/// each is a background process that outlived its bootstrap step.
pub fn kill_and_reap_descendants() -> Vec<u32> {
    let mut removed = vec![];
    // Reap first every round: a child may exit (→ zombie, invisible to
    // `live_children`) at any moment, including right after we killed it —
    // stopping on "no live children" alone would leave zombies behind.
    for _ in 0..100 {
        let reaped = reap_all();
        let kids = live_children();
        if kids.is_empty() && !reaped {
            break;
        }
        for pid in kids {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            removed.push(pid as u32);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    removed.sort_unstable();
    removed.dedup();
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    // The sweep uses process-wide `waitpid(-1)`: serialize these tests so one
    // test cannot reap another's children.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn gone(pid: u32) -> bool {
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    fn null_stdio(c: &mut std::process::Command) {
        use std::process::Stdio;
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    }

    #[test]
    fn live_background_child_is_killed_and_reaped() {
        let _g = LOCK.lock().unwrap();
        let mut cmd = std::process::Command::new("sleep");
        null_stdio(cmd.arg("300"));
        let kid = cmd.spawn().unwrap();
        let pid = kid.id();
        // a direct child needs no subreaper for the sweep to see it
        assert!(live_children().contains(&(pid as i32)));
        let removed = kill_and_reap_descendants();
        assert!(removed.contains(&pid), "{removed:?}");
        // the sweep reaped it; do not wait() (ECHILD) — just check it is gone
        for _ in 0..100 {
            if gone(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(gone(pid));
        std::mem::forget(kid);
    }

    #[test]
    fn exited_zombie_is_reaped_silently() {
        let _g = LOCK.lock().unwrap();
        let mut cmd = std::process::Command::new("sh");
        null_stdio(cmd.args(["-c", "exit 0"]));
        let kid = cmd.spawn().unwrap();
        let pid = kid.id();
        // wait until it is a zombie (exited but not yet reaped)
        let mut zombie = false;
        for _ in 0..200 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat.rfind(')').is_some_and(|end| stat[end + 1..].split_whitespace().next() == Some("Z")) {
                zombie = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(zombie, "child never became a zombie");
        assert!(kill_and_reap_descendants().is_empty());
        assert!(gone(pid));
        std::mem::forget(kid);
    }
}
