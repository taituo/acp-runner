//! A minimal local "container" for the agent side of [`LocalProcessBackend`]
//! (development and tests on Linux, requires root).
//!
//! It reproduces the parts of the Kubernetes agent container that the trust tests depend on:
//!
//! * new mount + PID namespaces: a tmpfs root with read-only binds of `/usr` and `/etc`, the
//!   declared volume mounts only (so the runnerd-only secret directory simply does not exist
//!   in the agent's view), a private `/proc` (runnerd is invisible);
//! * optional new network namespace whose only route out is a relay to the egress proxy's
//!   Unix socket — the local stand-in for the `egress=proxy` NetworkPolicy;
//! * `chroot` + `setpriv` to an unprivileged uid with no capabilities, empty bounding set and
//!   `no_new_privs`.
//!
//! This is test infrastructure, NOT a production sandbox: the Kubernetes pod (plus optional
//! gVisor) is the isolation boundary. Nothing here is used by the Kubernetes backends.
//!
//! [`LocalProcessBackend`]: crate::backend::LocalProcessBackend

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Mount {
    pub host: PathBuf,
    pub container: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone)]
pub enum Net {
    /// Share the host network namespace.
    Host,
    /// New network namespace; `relay` (acp-egress-proxy) listens on `listen` inside it and
    /// forwards to the proxy's Unix socket on the host.
    ProxyOnly { listen: String, proxy_socket: PathBuf, relay: PathBuf },
}

#[derive(Debug, Clone)]
pub struct LocalContainer {
    /// Empty host directory used as the mount point of the container root (tmpfs).
    pub root: PathBuf,
    pub mounts: Vec<Mount>,
    pub uid: u32,
    pub gid: u32,
    pub env: Vec<(String, String)>,
    /// Working directory (container path).
    pub cwd: PathBuf,
    /// Program (container path) and arguments.
    pub program: PathBuf,
    pub args: Vec<String>,
    pub net: Net,
}

/// Single-quote a string for `/bin/sh`.
pub fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn qp(p: &Path) -> String {
    q(&p.to_string_lossy())
}

/// Namespaces, mounts and privilege drop are usable here (root + util-linux).
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        nix::unistd::geteuid().is_root()
            && ["/usr/bin/unshare", "/usr/bin/setpriv", "/usr/sbin/chroot"].iter().all(|p| Path::new(p).exists())
            && Command::new("unshare")
                .args(["--mount", "--pid", "--net", "--fork", "--propagation", "private", "--", "/bin/sh", "-c"])
                .arg("mount -t tmpfs t /mnt && setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- true")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
    })
}

/// `setpriv` prefix dropping to `uid:gid` with no capabilities (used for runnerd, which
/// keeps the host mount namespace like its own container would).
pub fn setpriv_args(uid: u32, gid: u32) -> Vec<String> {
    vec![
        format!("--reuid={uid}"),
        format!("--regid={gid}"),
        "--clear-groups".into(),
        "--inh-caps=-all".into(),
        "--bounding-set=-all".into(),
        "--no-new-privs".into(),
        "--".into(),
    ]
}

impl LocalContainer {
    pub fn script(&self) -> String {
        let r = qp(&self.root);
        let mut s = String::from("set -eu\n");
        s.push_str(&format!("R={r}\nmkdir -p \"$R\"\nmount -t tmpfs -o mode=0755,size=64m acp-root \"$R\"\n"));
        // base system: symlinks stay symlinks, directories are read-only binds
        s.push_str(
            "for d in bin sbin lib lib32 lib64 libx32 usr etc; do\n  if [ -L \"/$d\" ]; then ln -s \"$(readlink \"/$d\")\" \"$R/$d\";\n  elif [ -d \"/$d\" ]; then mkdir -p \"$R/$d\"; mount --rbind \"/$d\" \"$R/$d\"; mount -o remount,bind,ro \"$R/$d\" 2>/dev/null || true; fi\ndone\n",
        );
        s.push_str("mkdir -p \"$R/proc\" \"$R/dev\" \"$R/tmp\"\nmount -t proc proc \"$R/proc\"\n");
        s.push_str("for n in null zero full random urandom; do touch \"$R/dev/$n\"; mount --bind \"/dev/$n\" \"$R/dev/$n\"; done\n");
        s.push_str("mount -t tmpfs -o mode=1777,size=64m tmp \"$R/tmp\"\n");
        let mut mounts = self.mounts.clone();
        mounts.sort_by_key(|m| m.container.components().count());
        for m in &mounts {
            let target = format!("\"$R\"{}", qp(&m.container));
            s.push_str(&format!("mkdir -p {target}\nmount --bind {} {target}\n", qp(&m.host)));
            if m.read_only {
                s.push_str(&format!("mount -o remount,bind,ro {target}\n"));
            }
        }
        if let Net::ProxyOnly { listen, proxy_socket, relay } = &self.net {
            s.push_str(&format!(
                "{} relay --lo-up --listen {} --unix {} >/dev/null 2>&1 &\nsleep 0.3\n",
                qp(relay),
                q(listen),
                qp(proxy_socket)
            ));
        }
        let mut cmd = vec!["/usr/bin/setpriv".to_string()];
        cmd.extend(setpriv_args(self.uid, self.gid));
        cmd.push("/usr/bin/env".into());
        cmd.push("-i".into());
        for (k, v) in &self.env {
            cmd.push(format!("{k}={v}"));
        }
        cmd.extend(["/bin/sh".into(), "-c".into(), "cd \"$0\" && exec \"$@\"".into()]);
        cmd.push(self.cwd.to_string_lossy().to_string());
        cmd.push(self.program.to_string_lossy().to_string());
        cmd.extend(self.args.iter().cloned());
        s.push_str("exec chroot \"$R\"");
        for a in cmd {
            s.push(' ');
            s.push_str(&q(&a));
        }
        s.push('\n');
        s
    }

    pub fn command(&self) -> Command {
        let mut c = Command::new("/usr/bin/unshare");
        c.args(["--mount", "--pid", "--fork", "--kill-child", "--propagation", "private"]);
        if matches!(self.net, Net::ProxyOnly { .. }) {
            c.arg("--net");
        }
        c.args(["--", "/bin/sh", "-c"]).arg(self.script());
        c.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(q("a'b"), r"'a'\''b'");
    }

    #[test]
    fn isolated_view_hides_undeclared_paths() {
        if !available() {
            eprintln!("SKIPPED: namespaces unavailable (needs root + util-linux)");
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let shared = t.path().join("shared");
        let secret = t.path().join("secret");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("token"), "attempt-token").unwrap();
        nix::unistd::chown(&shared, Some(nix::unistd::Uid::from_raw(10001)), Some(nix::unistd::Gid::from_raw(10001)))
            .unwrap();
        let probe = format!(
            "id -u > /work/uid; test -e {} && echo visible > /work/secret || echo hidden > /work/secret; \
             ls /proc | grep -c '^[0-9]' > /work/procs",
            secret.join("token").display()
        );
        let c = LocalContainer {
            root: t.path().join("root"),
            mounts: vec![Mount { host: shared.clone(), container: "/work".into(), read_only: false }],
            uid: 10001,
            gid: 10001,
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            cwd: "/work".into(),
            program: "/bin/sh".into(),
            args: vec!["-c".into(), probe],
            net: Net::Host,
        };
        let st = c.command().status().unwrap();
        assert!(st.success());
        assert_eq!(std::fs::read_to_string(shared.join("uid")).unwrap().trim(), "10001");
        assert_eq!(std::fs::read_to_string(shared.join("secret")).unwrap().trim(), "hidden");
        // only the processes of this namespace are visible
        let procs: u32 = std::fs::read_to_string(shared.join("procs")).unwrap().trim().parse().unwrap();
        assert!(procs <= 4, "{procs}");
    }
}
