//! Sandbox posture self-check, journaled at the start of every attempt.
//!
//! This is evidence, not enforcement: enforcement is the pod spec (non-root, no SA token,
//! read-only root filesystem, dropped capabilities, no privilege escalation, seccomp
//! RuntimeDefault, optional gVisor) plus NetworkPolicy. With `strict` (set by the Kubernetes
//! backends) a violated invariant fails the attempt before any credential is placed.

use serde::Serialize;
use std::path::Path;

pub const SA_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    pub uid: u32,
    pub gid: u32,
    pub service_account_token_present: bool,
    pub docker_socket_present: bool,
    pub root_fs_writable: bool,
    pub effective_capabilities: Option<String>,
    pub no_new_privs: Option<bool>,
    pub seccomp_mode: Option<u32>,
    pub workspace_fs: Option<String>,
    pub home_fs: Option<String>,
    pub kernel: Option<String>,
}

impl Posture {
    pub fn violations(&self) -> Vec<String> {
        let mut v = vec![];
        if self.uid == 0 {
            v.push("running as root".to_string());
        }
        if self.service_account_token_present {
            v.push("Kubernetes service-account token is mounted".to_string());
        }
        if self.docker_socket_present {
            v.push("container runtime socket is mounted".to_string());
        }
        if self.root_fs_writable {
            v.push("root filesystem is writable".to_string());
        }
        if let Some(c) = &self.effective_capabilities
            && u64::from_str_radix(c, 16).map(|x| x != 0).unwrap_or(false)
        {
            v.push(format!("effective capabilities not empty ({c})"));
        }
        if self.no_new_privs == Some(false) {
            v.push("no_new_privs not set (allowPrivilegeEscalation must be false)".to_string());
        }
        v
    }
}

fn status_field(status: &str, name: &str) -> Option<String> {
    status.lines().find_map(|l| l.strip_prefix(&format!("{name}:")).map(|v| v.trim().to_string()))
}

fn fs_type(p: &Path) -> Option<String> {
    let st = nix::sys::statfs::statfs(p).ok()?;
    let magic = st.filesystem_type();
    Some(if magic == nix::sys::statfs::TMPFS_MAGIC {
        "tmpfs".to_string()
    } else if magic == nix::sys::statfs::OVERLAYFS_SUPER_MAGIC {
        "overlayfs".to_string()
    } else {
        format!("{:#x}", magic.0)
    })
}

pub fn check(workspace: &Path, home: &Path) -> Posture {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let probe = Path::new("/usr/.acp-runner-rootfs-probe");
    let root_fs_writable = std::fs::write(probe, b"x").is_ok();
    if root_fs_writable {
        let _ = std::fs::remove_file(probe);
    }
    Posture {
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
        service_account_token_present: Path::new(SA_TOKEN_PATH).exists(),
        docker_socket_present: ["/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/crio/crio.sock"]
            .iter()
            .any(|p| Path::new(p).exists()),
        root_fs_writable,
        effective_capabilities: status_field(&status, "CapEff"),
        no_new_privs: status_field(&status, "NoNewPrivs").map(|v| v == "1"),
        seccomp_mode: status_field(&status, "Seccomp").and_then(|v| v.parse().ok()),
        workspace_fs: fs_type(workspace),
        home_fs: fs_type(home),
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn violations_are_reported() {
        let p = Posture {
            uid: 0,
            gid: 0,
            service_account_token_present: true,
            docker_socket_present: true,
            root_fs_writable: true,
            effective_capabilities: Some("00000000a80425fb".into()),
            no_new_privs: Some(false),
            seccomp_mode: Some(0),
            workspace_fs: None,
            home_fs: None,
            kernel: None,
        };
        let v = p.violations();
        assert_eq!(v.len(), 6, "{v:?}");
        let ok = Posture {
            uid: 10001,
            gid: 10001,
            service_account_token_present: false,
            docker_socket_present: false,
            root_fs_writable: false,
            effective_capabilities: Some("0000000000000000".into()),
            no_new_privs: Some(true),
            seccomp_mode: Some(2),
            workspace_fs: Some("tmpfs".into()),
            home_fs: Some("tmpfs".into()),
            kernel: None,
        };
        assert!(ok.violations().is_empty());
    }

    #[test]
    fn check_runs_locally() {
        let p = check(Path::new("/tmp"), Path::new("/tmp"));
        assert!(p.effective_capabilities.is_some());
    }
}
