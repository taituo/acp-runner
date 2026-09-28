//! Environment policy for agent processes.
//!
//! The agent process never inherits runnerd's environment. Its environment is composed from
//! a fixed base, the runner class' non-secret `env`, driver-specific variables and — last —
//! the leased credential variables. Variables that would switch a CLI to API-key billing or
//! a different inference provider are refused.

use crate::{DriverContext, DriverError};

/// Variables that must never reach an agent process. Their presence would silently move
/// the CLI to API-key billing or another provider, or leak unrelated credentials.
pub const FORBIDDEN_ENV: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_PROFILE",
    "ANTHROPIC_FEDERATION_RULE_ID",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_OPENAI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "DATABASE_URL",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
];

pub fn is_forbidden(name: &str) -> bool {
    FORBIDDEN_ENV.iter().any(|f| f.eq_ignore_ascii_case(name)) || name.starts_with("ACP_RUNNER_")
}

pub const DEFAULT_PATH: &str = "/opt/acp-runner/node_modules/.bin:/usr/local/bin:/usr/bin:/bin";

/// runnerd-owned variables (V9.4): always (re-)applied last so class, driver
/// or run overrides can never redirect HOME, XDG state, or proxy routing.
fn protected_vars(ctx: &DriverContext, home: &str) -> Vec<(String, String)> {
    let mut out = vec![
        ("HOME".into(), home.to_string()),
        ("XDG_CONFIG_HOME".into(), format!("{home}/.config")),
        ("XDG_CACHE_HOME".into(), format!("{home}/.cache")),
        ("XDG_DATA_HOME".into(), format!("{home}/.local/share")),
        ("XDG_STATE_HOME".into(), format!("{home}/.local/state")),
    ];
    if let Some(p) = &ctx.egress.https_proxy {
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            out.push((k.into(), p.clone()));
        }
        let no_proxy = ctx.egress.no_proxy.clone().unwrap_or_else(|| "localhost,127.0.0.1".into());
        out.push(("NO_PROXY".into(), no_proxy.clone()));
        out.push(("no_proxy".into(), no_proxy));
    }
    out
}

/// Build the complete environment for an agent process.
///
/// * `driver_env`: non-secret, driver-specific variables (validated against the forbidden list)
/// * `ctx.credential_env`: leased secret variables explicitly whitelisted by the provider
///   credential spec (e.g. `CLAUDE_CODE_OAUTH_TOKEN`) — the only allowed secrets.
/// * runnerd-owned variables (`HOME`, `XDG_*`, proxy) are set last and cannot
///   be overridden (V9.4).
pub fn compose(ctx: &DriverContext, driver_env: &[(String, String)]) -> Result<Vec<(String, String)>, DriverError> {
    let home = ctx.home.to_string_lossy().to_string();
    let path = ctx.path_env.clone().unwrap_or_else(|| DEFAULT_PATH.to_string());
    let mut env: Vec<(String, String)> = vec![
        ("PATH".into(), path),
        ("HOME".into(), home.clone()),
        ("USER".into(), "agent".into()),
        ("LOGNAME".into(), "agent".into()),
        (
            "SHELL".into(),
            if std::path::Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() },
        ),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("TERM".into(), "dumb".into()),
        ("NO_COLOR".into(), "1".into()),
        ("TMPDIR".into(), ctx.tmp.to_string_lossy().to_string()),
        ("XDG_CONFIG_HOME".into(), format!("{home}/.config")),
        ("XDG_CACHE_HOME".into(), format!("{home}/.cache")),
        ("XDG_DATA_HOME".into(), format!("{home}/.local/share")),
        ("XDG_STATE_HOME".into(), format!("{home}/.local/state")),
        ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
        ("GIT_TERMINAL_PROMPT".into(), "0".into()),
        ("npm_config_update_notifier".into(), "false".into()),
    ];
    if let Some(p) = &ctx.egress.https_proxy {
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.push((k.into(), p.clone()));
        }
        let no_proxy = ctx.egress.no_proxy.clone().unwrap_or_else(|| "localhost,127.0.0.1".into());
        env.push(("NO_PROXY".into(), no_proxy.clone()));
        env.push(("no_proxy".into(), no_proxy));
    }
    if let Some(ca) = &ctx.extra_ca_file {
        env.push(("NODE_EXTRA_CA_CERTS".into(), ca.clone()));
        env.push(("SSL_CERT_FILE".into(), ca.clone()));
    }
    for (k, v) in ctx.class_env.iter().map(|(k, v)| (k.clone(), v.clone())).chain(driver_env.iter().cloned()) {
        if is_forbidden(&k) {
            return Err(DriverError::Config(format!(
                "environment variable {k} is forbidden for agent processes (API-key billing / credential leak guard)"
            )));
        }
        set(&mut env, k, v);
    }
    for (k, v) in &ctx.credential_env {
        set(&mut env, k.clone(), v.clone());
    }
    // V9.4: runnerd wins over any class/driver/run override. `set` replaces
    // in place, so the base order (credentials last) is preserved.
    for (k, v) in protected_vars(ctx, &home) {
        set(&mut env, k, v);
    }
    Ok(env)
}

fn set(env: &mut Vec<(String, String)>, k: String, v: String) {
    if let Some(slot) = env.iter_mut().find(|(ek, _)| *ek == k) {
        slot.1 = v;
    } else {
        env.push((k, v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ctx;

    #[test]
    fn forbidden_variables_are_rejected() {
        let mut c = ctx();
        c.class_env.insert("ANTHROPIC_API_KEY".into(), "sk-ant-api03-x".into());
        assert!(matches!(compose(&c, &[]), Err(DriverError::Config(_))));
        let c = ctx();
        assert!(compose(&c, &[("OPENAI_API_KEY".into(), "x".into())]).is_err());
        assert!(compose(&c, &[("ACP_RUNNER_TOKEN".into(), "x".into())]).is_err());
    }

    #[test]
    fn runnerd_owned_variables_win_over_overrides() {
        // V9.4 (A23): HOME/XDG/proxy come from runnerd even when the class or
        // run (driver env) tries to set them. Other keys still pass through.
        let mut c = ctx();
        c.egress.https_proxy = Some("http://proxy:3128".into());
        c.class_env.insert("HOME".into(), "/evil".into());
        c.class_env.insert("XDG_CONFIG_HOME".into(), "/evil".into());
        let env = compose(&c, &[("HTTPS_PROXY".into(), "http://evil:9".into()), ("FOO".into(), "bar".into())])
            .unwrap();
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone());
        assert_eq!(get("HOME").unwrap(), c.home.to_string_lossy());
        assert_eq!(get("XDG_CONFIG_HOME").unwrap(), format!("{}/.config", c.home.to_string_lossy()));
        assert_eq!(get("HTTPS_PROXY").as_deref(), Some("http://proxy:3128"));
        assert_eq!(get("https_proxy").as_deref(), Some("http://proxy:3128"));
        assert_eq!(get("NO_PROXY").as_deref(), Some("localhost,127.0.0.1"));
        assert_eq!(get("FOO").as_deref(), Some("bar"));
    }

    #[test]
    fn credentials_are_added_last_and_home_is_synthetic() {
        let mut c = ctx();
        c.credential_env = vec![("CLAUDE_CODE_OAUTH_TOKEN".into(), "sk-ant-oat01-zzzzzzzzzzzz".into())];
        let env = compose(&c, &[("FOO".into(), "bar".into())]).unwrap();
        let get = |k: &str| env.iter().find(|(ek, _)| ek == k).map(|(_, v)| v.clone());
        assert_eq!(get("HOME").unwrap(), c.home.to_string_lossy());
        assert_eq!(get("FOO").as_deref(), Some("bar"));
        assert_eq!(env.last().unwrap().0, "CLAUDE_CODE_OAUTH_TOKEN");
        assert!(get("ANTHROPIC_API_KEY").is_none());
    }
}
