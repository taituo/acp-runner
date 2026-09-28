//! Secret redaction for logs, journal payloads and diagnostics.
//!
//! Two layers:
//! 1. *Literal* secrets known to the process (credential file contents, OAuth tokens,
//!    ingest token) are replaced wherever they appear.
//! 2. *Pattern* redaction catches well-known credential shapes (Anthropic/OpenAI keys,
//!    JWTs, bearer headers, GitHub tokens) and JSON fields with sensitive names.
//!
//! Redaction is applied before anything leaves runnerd and again in the controller's ingest
//! path (defence in depth).

use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;
use std::sync::OnceLock;

pub const REDACTED: &str = "[REDACTED]";
const MIN_LITERAL_LEN: usize = 8;

fn patterns() -> &'static [Regex] {
    static P: OnceLock<Vec<Regex>> = OnceLock::new();
    P.get_or_init(|| {
        [
            // Anthropic keys and OAuth tokens (sk-ant-api03-..., sk-ant-oat01-...)
            r"sk-ant-[A-Za-z0-9_\-]{8,}",
            // OpenAI style keys (sk-..., sk-proj-...)
            r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
            // JWTs (OpenAI/ChatGPT access and id tokens are JWTs)
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
            // Authorization headers
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{16,}=*",
            // GitHub tokens
            r"\bgh[pousr]_[A-Za-z0-9]{20,}",
            r"\bgithub_pat_[A-Za-z0-9_]{20,}",
            // ChatGPT/OpenAI refresh tokens are opaque but typically prefixed
            r"\brt_[A-Za-z0-9_\-]{20,}",
            // Generic "token=..."/"api_key: ..." assignments in free text
            r#"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|oauth[_-]?token|secret|password)(\s*[:=]\s*)"?[A-Za-z0-9._~+/\-]{12,}"?"#,
        ]
        .iter()
        .map(|p| Regex::new(p).expect("valid redaction regex"))
        .collect()
    })
}

/// JSON object keys whose values are always redacted.
pub fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase().replace(['-', '_'], "");
    const EXACT: &[&str] = &["authorization", "cookie", "setcookie", "password", "secret", "token"];
    const CONTAINS: &[&str] = &[
        "apikey",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "oauthtoken",
        "clientsecret",
        "privatekey",
        "sessiontoken",
        "bearertoken",
        "personalaccesstoken",
    ];
    EXACT.contains(&k.as_str()) || CONTAINS.iter().any(|c| k.contains(c))
}

/// Environment variable names whose values must never be logged.
pub fn is_sensitive_env(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("TOKEN")
        || n.contains("SECRET")
        || n.contains("PASSWORD")
        || n.contains("API_KEY")
        || n.contains("APIKEY")
        || n.ends_with("_KEY")
        || n == "DATABASE_URL"
        || n.contains("CREDENTIAL")
}

#[derive(Debug, Clone, Default)]
pub struct Redactor {
    literals: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Redactor::default()
    }

    /// Register a literal secret. Very short values are ignored (they would destroy
    /// unrelated text) — callers must not rely on redaction for such values.
    pub fn add_secret(&mut self, secret: &str) {
        let s = secret.trim();
        if s.len() < MIN_LITERAL_LEN {
            return;
        }
        // A JSON credential file contributes each string leaf (>= 8 chars) as a
        // literal *instead of* the whole file (V8.1): the whole file never
        // appears verbatim, while individual field leaks are caught — including
        // refresh tokens without any recognizable prefix.
        if (s.starts_with('{') || s.starts_with('['))
            && let Ok(v) = serde_json::from_str::<Value>(s)
        {
            let mut leaves = vec![];
            collect_string_leaves(&v, &mut leaves);
            for leaf in leaves {
                self.add_literal(&leaf);
            }
            return;
        }
        self.add_literal(s);
    }

    fn add_literal(&mut self, s: &str) {
        let s = s.trim();
        if s.len() < MIN_LITERAL_LEN || self.literals.iter().any(|l| l == s) {
            return;
        }
        self.literals.push(s.to_string());
        // longest first so overlapping secrets are fully removed
        self.literals.sort_by_key(|l| std::cmp::Reverse(l.len()));
    }

    pub fn literal_count(&self) -> usize {
        self.literals.len()
    }

    pub fn redact_str<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut out: Cow<'a, str> = Cow::Borrowed(input);
        for lit in &self.literals {
            if out.contains(lit.as_str()) {
                out = Cow::Owned(out.replace(lit.as_str(), REDACTED));
            }
        }
        for re in patterns() {
            if re.is_match(&out) {
                let replaced = re.replace_all(&out, REDACTED).into_owned();
                out = Cow::Owned(replaced);
            }
        }
        out
    }

    pub fn redact_string(&self, input: &str) -> String {
        self.redact_str(input).into_owned()
    }

    /// Recursively redact a JSON value in place.
    pub fn redact_json(&self, v: &mut Value) {
        match v {
            Value::String(s) => {
                if let Cow::Owned(r) = self.redact_str(s) {
                    *s = r;
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.redact_json(i)),
            Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    if is_sensitive_key(k) && !matches!(val, Value::Null | Value::Bool(_)) {
                        *val = Value::String(REDACTED.to_string());
                    } else {
                        self.redact_json(val);
                    }
                }
            }
            _ => {}
        }
    }

    /// Render environment variables for logging with sensitive values replaced.
    pub fn redact_env<'a, I>(&self, vars: I) -> Vec<(String, String)>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        vars.into_iter()
            .map(|(k, v)| {
                let shown = if is_sensitive_env(k) { REDACTED.to_string() } else { self.redact_string(v) };
                (k.to_string(), shown)
            })
            .collect()
    }
}

fn collect_string_leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_string_leaves(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_string_leaves(x, out)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn literal_secrets_are_removed() {
        let mut r = Redactor::new();
        r.add_secret("super-secret-value-123");
        let s = r.redact_string("prefix super-secret-value-123 suffix");
        assert_eq!(s, format!("prefix {REDACTED} suffix"));
    }

    #[test]
    fn short_literals_ignored() {
        let mut r = Redactor::new();
        r.add_secret("abc");
        assert_eq!(r.literal_count(), 0);
        assert_eq!(r.redact_string("abc"), "abc");
    }

    #[test]
    fn known_shapes_are_removed() {
        let r = Redactor::new();
        for secret in [
            "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "sk-proj-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX19fX19fXw",
            "ghp_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        ] {
            let out = r.redact_string(&format!("x {secret} y"));
            assert!(!out.contains(secret), "{out}");
            assert!(out.contains(REDACTED));
        }
        let out = r.redact_string("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz0123"));
        let out = r.redact_string("export CODEX_ACCESS_TOKEN=abcdefghijklmnop1234");
        assert!(!out.contains("abcdefghijklmnop1234"), "{out}");
    }

    #[test]
    fn json_sensitive_keys_and_nested_values() {
        let mut r = Redactor::new();
        r.add_secret(r#"{"tokens":{"access_token":"tok_live_value_000000000000","account_id":"acct_123"}}"#);
        let mut v = json!({
            "headers": {"Authorization": "whatever"},
            "nested": [{"refresh_token": "zzz"}, "leaked tok_live_value_000000000000 here"],
            "ok": "fine",
            "id_token": null
        });
        r.redact_json(&mut v);
        assert_eq!(v["headers"]["Authorization"], REDACTED);
        assert_eq!(v["nested"][0]["refresh_token"], REDACTED);
        assert!(!v.to_string().contains("tok_live_value_000000000000"));
        assert_eq!(v["ok"], "fine");
        assert!(v["id_token"].is_null());
    }

    #[test]
    fn refresh_token_without_prefix_is_redacted() {
        // V8.1: no recognizable shape — only the JSON-leaf literal catches it.
        let mut r = Redactor::new();
        r.add_secret(r#"{"tokens":{"refresh_token":"abcdefghijklmnopqrstuvwxyz012345"}}"#);
        let out = r.redact_string("token=abcdefghijklmnopqrstuvwxyz012345&x=1");
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz012345"), "{out}");
        assert!(out.contains(REDACTED));
    }

    #[test]
    fn json_files_contribute_leaves_not_the_whole_file() {
        // V8.1: every string leaf >= 8 chars is a literal instead of the file.
        let mut r = Redactor::new();
        r.add_secret(r#"{"a":"12345678","b":"short","c":{"d":"87654321"}}"#);
        assert_eq!(r.literal_count(), 2);
        assert!(!r.redact_string("x 12345678 y").contains("12345678"));
        assert!(!r.redact_string("x 87654321 y").contains("87654321"));
        assert_eq!(r.redact_string("x short y"), "x short y");
    }

    #[test]
    fn env_redaction() {
        let r = Redactor::new();
        let env = r.redact_env([
            ("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-xxxxxxxxxxxxxxxxxxxx"),
            ("OPENAI_API_KEY", "sk-whatever"),
            ("DATABASE_URL", "postgres://u:p@h/db"),
            ("HOME", "/home/agent"),
        ]);
        assert_eq!(env[0].1, REDACTED);
        assert_eq!(env[1].1, REDACTED);
        assert_eq!(env[2].1, REDACTED);
        assert_eq!(env[3].1, "/home/agent");
    }
}
