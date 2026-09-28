//! acp-runnerctl credential enrollment tests with scripted stand-ins for the provider CLIs
//! (file credential store, local runtime). No real provider accounts are used.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_acp-runnerctl"))
}

fn b64(s: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let b = s.as_bytes();
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &x)| acc | ((x as u32) << (16 - 8 * i)));
        for i in 0..(chunk.len() + 1) {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

const REFRESH: &str = "rt_cli_test_refresh_token_value_0000000000";
const ACCESS_CLAIMS: &str = r#"{"exp":1900000000}"#;

fn codex_auth_json() -> String {
    let jwt = |c: &str| format!("{}.{}.{}", b64(r#"{"alg":"none"}"#), b64(c), b64("sig-sig-sig"));
    format!(
        r#"{{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{{"id_token":"{}","access_token":"{}","refresh_token":"{REFRESH}","account_id":"acct-cli"}},"last_refresh":"2026-09-01T00:00:00Z"}}"#,
        jwt(r#"{"email":"bob@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"pro"}}"#),
        jwt(ACCESS_CLAIMS)
    )
}

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn ctl(args: &[&str], store: &Path, stdin: Option<&str>) -> (bool, String, String) {
    let mut c = Command::new(bin());
    c.args(args)
        .args(["--store", "file", "--credential-dir", store.to_str().unwrap()])
        .env_remove("DATABASE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    if let Some(s) = stdin {
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn codex_import_list_and_inspect_never_print_secrets() {
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let f = t.path().join("auth.json");
    std::fs::write(&f, codex_auth_json()).unwrap();
    let (ok, out, err) =
        ctl(&["auth", "enroll", "codex", "personal-1", "--from-file", f.to_str().unwrap()], &store, None);
    assert!(ok, "{out}{err}");
    let (ok, out, _) = ctl(&["auth", "list"], &store, None);
    assert!(ok);
    assert!(out.contains("personal-1") && out.contains("chatgpt") && out.contains("pro"), "{out}");
    let (ok, out, err) = ctl(&["auth", "inspect", "personal-1"], &store, None);
    assert!(ok, "{err}");
    let all = format!("{out}{err}");
    assert!(!all.contains(REFRESH));
    assert!(!all.contains("acct-cli"));
    assert!(!all.contains(&b64(ACCESS_CLAIMS)));
    assert!(all.contains("b***@example.com"));
    // a second enrollment without --force is refused
    let (ok, _, err) =
        ctl(&["auth", "enroll", "codex", "personal-1", "--from-file", f.to_str().unwrap()], &store, None);
    assert!(!ok && err.contains("already exists"));
}

#[test]
fn api_keys_are_refused_for_both_providers() {
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let f = t.path().join("auth.json");
    std::fs::write(&f, r#"{"auth_mode":"apikey","OPENAI_API_KEY":"sk-proj-abcdefghijklmnopqrstuvwxyz"}"#).unwrap();
    let (ok, _, err) = ctl(&["auth", "enroll", "codex", "k", "--from-file", f.to_str().unwrap()], &store, None);
    assert!(!ok);
    assert!(err.contains("API-key"), "{err}");
    let (ok, _, err) = ctl(
        &["auth", "enroll", "claude", "k2", "--token-stdin", "--no-verify"],
        &store,
        Some("sk-ant-api03-abcdefghijklmnopqrst\n"),
    );
    assert!(!ok);
    assert!(err.contains("API"), "{err}");
    assert!(!store.join("k").exists() && !store.join("k2").exists());
}

#[test]
fn codex_device_login_captures_only_auth_json() {
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let auth = codex_auth_json();
    // stand-in for `codex`: writes login state plus unrelated files that must not be captured
    let fake = script(
        t.path(),
        "codex",
        &format!(
            r#"case "$*" in
  *--device-auth*) mkdir -p "$CODEX_HOME/sessions"; printf '%s' '{auth}' > "$CODEX_HOME/auth.json";
                   echo history > "$CODEX_HOME/history.jsonl"; echo secret-session > "$CODEX_HOME/sessions/s1";
                   echo 'export X=1' > "$HOME/.bashrc"; echo "Visit https://auth.openai.com/codex/device and enter ABCD-1234" ;;
  *"login status"*) if [ -f "$CODEX_HOME/auth.json" ]; then echo "Logged in using ChatGPT" >&2; exit 0; else echo "Not logged in" >&2; exit 1; fi ;;
  *) exit 2 ;;
esac"#
        ),
    );
    let (ok, out, err) =
        ctl(&["auth", "enroll", "codex", "device-1", "--codex-command", fake.to_str().unwrap()], &store, None);
    assert!(ok, "{out}{err}");
    let mut files: Vec<String> = std::fs::read_dir(store.join("device-1"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files.sort();
    assert_eq!(files, vec!["auth.json".to_string(), "profile.json".to_string()]);
}

#[test]
fn claude_setup_token_is_verified_and_stored_without_echo() {
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let token = "sk-ant-oat01-CLItestTOKENvalue0123456789abcdef";
    // stand-in for `claude auth status --json`
    let fake = script(
        t.path(),
        "claude",
        r#"if [ "$1 $2" = "auth status" ]; then
  if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ]; then echo '{"loggedIn":true,"authMethod":"oauth_token","apiProvider":"firstParty"}';
  else echo '{"loggedIn":false}'; fi; exit 0; fi
exit 3"#,
    );
    let (ok, out, err) = ctl(
        &[
            "auth",
            "enroll",
            "claude",
            "max-1",
            "--token-stdin",
            "--claude-command",
            fake.to_str().unwrap(),
            "--max-concurrent-leases",
            "2",
        ],
        &store,
        Some(&format!("{token}\n")),
    );
    assert!(ok, "{out}{err}");
    assert!(!format!("{out}{err}").contains(token));
    assert_eq!(std::fs::read_to_string(store.join("max-1/oauth-token")).unwrap(), token);
    let (_, out, _) = ctl(&["auth", "inspect", "max-1"], &store, None);
    assert!(out.contains("claude-oauth-token") && !out.contains(token));
    assert!(out.contains("maxConcurrentLeases: 2"));
    // a token the CLI rejects is not stored
    let bad = script(t.path(), "claude-bad", r#"echo '{"loggedIn":false}'"#);
    let (ok, _, _) = ctl(
        &["auth", "enroll", "claude", "max-2", "--token-stdin", "--claude-command", bad.to_str().unwrap()],
        &store,
        Some(&format!("{token}\n")),
    );
    assert!(!ok);
    assert!(!store.join("max-2").exists());
}

#[test]
fn enroll_grants_and_allow_update_usage_policy() {
    // V2: enrollment without grants denies by default; --allow-* grants at
    // enroll time and `auth allow` replaces the policy afterwards.
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let f = t.path().join("auth.json");
    std::fs::write(&f, codex_auth_json()).unwrap();
    let (ok, out, err) = ctl(
        &["auth", "enroll", "codex", "g-1", "--from-file", f.to_str().unwrap()],
        &store,
        None,
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("denies all leases"), "{out}");
    let pf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join("g-1/profile.json")).unwrap()).unwrap();
    assert_eq!(pf["allowedNamespaces"], serde_json::json!([]), "{pf}");
    let (ok, out, err) = ctl(
        &[
            "auth", "allow", "g-1", "--allow-namespace", "team-a", "--allow-class", "codex-prod",
        ],
        &store,
        None,
    );
    assert!(ok, "{out}{err}");
    let pf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join("g-1/profile.json")).unwrap()).unwrap();
    assert_eq!(pf["allowedNamespaces"], serde_json::json!(["team-a"]), "{pf}");
    assert_eq!(pf["allowedClasses"], serde_json::json!(["codex-prod"]), "{pf}");
}

#[test]
fn files_enroll_stores_from_file_with_select() {
    // V9: generic named files; --select keeps only the chosen top-level keys.
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let f = t.path().join("auth.json");
    std::fs::write(
        &f,
        r#"{"openai":{"type":"api","key":"sk-test-000000000000000000000000"},"other":{"type":"api","key":"sk-other-111111111111111111111111"}}"#,
    )
    .unwrap();
    let (ok, out, err) = ctl(
        &["auth", "enroll", "files", "o-1", "--from-file", f.to_str().unwrap(), "--select", "openai"],
        &store,
        None,
    );
    assert!(ok, "{out}{err}");
    let stored = std::fs::read_to_string(store.join("o-1/auth.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stored).unwrap();
    assert!(v.get("openai").is_some(), "{stored}");
    assert!(v.get("other").is_none(), "{stored}");
    let (_, out, _) = ctl(&["auth", "inspect", "o-1"], &store, None);
    assert!(out.contains("files"), "{out}");
    assert!(!out.contains("sk-test-000000000000000000000000"), "{out}");
    // missing --select key is refused and stores nothing
    let (ok, _, _) = ctl(
        &["auth", "enroll", "files", "o-2", "--from-file", f.to_str().unwrap(), "--select", "nope"],
        &store,
        None,
    );
    assert!(!ok);
    assert!(!store.join("o-2").exists());
    // files enrollment needs --from-file
    let (ok, _, _) = ctl(&["auth", "enroll", "files", "o-3"], &store, None);
    assert!(!ok);
}
