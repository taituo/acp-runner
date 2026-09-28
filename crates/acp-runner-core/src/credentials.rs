//! Provider credential whitelists and bundle validation.
//!
//! A *credential profile* is the persisted, provider-supported login state produced by a
//! human enrollment. A *bundle* is the set of whitelisted files (key -> bytes) of one
//! profile. Only the keys listed in the provider spec are ever stored or mounted; an entire
//! `$HOME` is never captured.
//!
//! Verified provider behaviour (see README "Authentication findings"):
//!
//! * **Codex** (`codex login` / `codex login --device-auth`): with
//!   `cli_auth_credentials_store = "file"` the login state is `$CODEX_HOME/auth.json`.
//!   OpenAI documents copying this file to headless machines and, for CI, restoring it,
//!   running Codex and persisting the *refreshed* file back ("one auth.json per runner or
//!   serialized workflow stream"). Hence: exclusive lease + validated write-back.
//! * **Claude Code** (`claude setup-token`): prints a one-year OAuth token for use as
//!   `CLAUDE_CODE_OAUTH_TOKEN` "for CI pipelines and scripts". It does not rotate, so no
//!   write-back. We never copy `~/.claude/.credentials.json` (not documented as portable).
//!
//! Anything that is an API key is rejected: this system does not use API-key billing.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Codex,
    Claude,
    /// Generic named files (V9): the bundle keys are filenames, targets come
    /// from the runner class `fileTargets`. No refresh, no write-back.
    Files,
}

impl Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::Codex => "codex",
            Provider::Claude => "claude",
            Provider::Files => "files",
        }
    }

    pub fn spec(self) -> &'static ProviderCredentialSpec {
        match self {
            Provider::Codex => &CODEX_SPEC,
            Provider::Claude => &CLAUDE_SPEC,
            Provider::Files => &FILES_SPEC,
        }
    }

    /// Whether bundle keys are dynamic (per-profile filenames) rather than the
    /// static spec list. Stores enumerate stored keys for such providers.
    pub fn dynamic_keys(self) -> bool {
        matches!(self, Provider::Files)
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Provider {
    type Err = CredentialError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "codex" => Ok(Provider::Codex),
            "claude" => Ok(Provider::Claude),
            "files" => Ok(Provider::Files),
            other => Err(CredentialError::UnknownProvider(other.to_string())),
        }
    }
}

/// A whitelisted credential file.
#[derive(Debug, Clone, Copy)]
pub struct CredentialFileSpec {
    /// Key in the credential store (Secret data key).
    pub key: &'static str,
    /// Default location relative to the synthetic HOME (overridable per runner class).
    pub default_target: &'static str,
    /// File mode of the ephemeral copy.
    pub mode: u32,
    /// The CLI rewrites this file (token refresh); runnerd hands the refreshed copy back
    /// for validated write-back.
    pub writeback: bool,
}

/// A whitelisted credential that is passed via environment variable to the CLI process
/// only (never to runnerd's own environment).
#[derive(Debug, Clone, Copy)]
pub struct CredentialEnvSpec {
    pub env_name: &'static str,
    pub key: &'static str,
}

#[derive(Debug)]
pub struct ProviderCredentialSpec {
    pub provider: Provider,
    pub files: &'static [CredentialFileSpec],
    pub env: &'static [CredentialEnvSpec],
    /// Only one attempt may hold a lease on a profile at a time.
    pub exclusive_lease: bool,
}

impl ProviderCredentialSpec {
    pub fn keys(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.files.iter().map(|f| f.key).chain(self.env.iter().map(|e| e.key))
    }
}

pub static CODEX_SPEC: ProviderCredentialSpec = ProviderCredentialSpec {
    provider: Provider::Codex,
    files: &[CredentialFileSpec { key: "auth.json", default_target: ".codex/auth.json", mode: 0o600, writeback: true }],
    env: &[],
    exclusive_lease: true,
};

pub static CLAUDE_SPEC: ProviderCredentialSpec = ProviderCredentialSpec {
    provider: Provider::Claude,
    files: &[],
    env: &[CredentialEnvSpec { env_name: "CLAUDE_CODE_OAUTH_TOKEN", key: "oauth-token" }],
    exclusive_lease: false,
};

pub static FILES_SPEC: ProviderCredentialSpec = ProviderCredentialSpec {
    provider: Provider::Files,
    files: &[],
    env: &[],
    exclusive_lease: false,
};

/// Bundle keys for the generic files provider are filenames: flat, relative,
/// no leading dots (V9).
pub fn valid_bundle_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && !key.starts_with('.')
        && !key.contains('/')
        && !key.contains('\\')
        && !key.contains('\0')
        && key != ".."
        && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

/// Validate a generic files bundle (V9): non-empty, safe filename keys,
/// non-empty values. Contents are opaque on purpose — this is the one
/// provider that may hold plain API keys (see the API-key policy decision).
pub fn validate_files_bundle(bundle: &CredentialBundle) -> Result<CredentialMetadata, CredentialError> {
    if bundle.is_empty() {
        return Err(CredentialError::Malformed("files credential bundle is empty".into()));
    }
    for (k, v) in bundle {
        if !valid_bundle_key(k) {
            return Err(CredentialError::Malformed(format!("files credential key {k:?} is not a safe filename")));
        }
        if v.is_empty() {
            return Err(CredentialError::Malformed(format!("files credential {k:?} is empty")));
        }
    }
    let mut fp = Sha256::new();
    for (k, v) in bundle.iter() {
        fp.update(k.as_bytes());
        fp.update([0]);
        fp.update(v);
        fp.update([0]);
    }
    Ok(CredentialMetadata {
        provider: "files".into(),
        auth_kind: "files".into(),
        material_fingerprint: hex::encode(&fp.finalize()[..8]),
        ..Default::default()
    })
}

/// key -> raw bytes
pub type CredentialBundle = BTreeMap<String, Vec<u8>>;

/// Non-secret facts about a credential bundle. Safe to print, store in annotations,
/// and journal. Never contains token material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub provider: String,
    /// e.g. `chatgpt`, `personalAccessToken`, `agentIdentity`, `claude-oauth-token`.
    pub auth_kind: String,
    /// sha256 prefix of the provider account id (codex) — used to validate write-back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<String>,
    /// sha256 prefix of the whole secret material (changes on refresh).
    pub material_fingerprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    #[error("unknown provider {0:?} (supported: codex, claude, files)")]
    UnknownProvider(String),
    #[error("credential bundle is missing required key {0:?}")]
    MissingKey(String),
    #[error("credential bundle contains non-whitelisted key {0:?}")]
    UnexpectedKey(String),
    #[error("credential material is malformed: {0}")]
    Malformed(String),
    #[error("API-key authentication is forbidden in acp-runner: {0}")]
    ApiKeyForbidden(String),
    #[error("unsupported auth mode {0:?}")]
    UnsupportedAuthMode(String),
    #[error("write-back rejected: account does not match the enrolled profile")]
    AccountMismatch,
}

pub fn fingerprint(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    hex::encode(&d[..8])
}

pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((user, domain)) if !user.is_empty() => {
            let first: String = user.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        _ => "***".to_string(),
    }
}

/// Decode (without verifying) the claims segment of a JWT. Used only to extract
/// non-secret metadata (plan, expiry, email) for `auth inspect`.
pub fn decode_jwt_claims(jwt: &str) -> Option<serde_json::Value> {
    let mut parts = jwt.split('.');
    let (_h, p, _s) = (parts.next()?, parts.next()?, parts.next()?);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Validate a bundle against the provider whitelist and policy, returning safe metadata.
pub fn validate_bundle(provider: Provider, bundle: &CredentialBundle) -> Result<CredentialMetadata, CredentialError> {
    // Dynamic-key providers (files) validate their own key set; static
    // providers require exactly the spec keys.
    if !provider.dynamic_keys() {
        let spec = provider.spec();
        let allowed: Vec<&str> = spec.keys().collect();
        for k in bundle.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(CredentialError::UnexpectedKey(k.clone()));
            }
        }
        for k in &allowed {
            if !bundle.contains_key(*k) {
                return Err(CredentialError::MissingKey((*k).to_string()));
            }
        }
    }
    match provider {
        Provider::Codex => validate_codex_auth_json(&bundle["auth.json"]),
        Provider::Claude => validate_claude_token(&bundle["oauth-token"]),
        Provider::Files => validate_files_bundle(bundle),
    }
}

/// Codex auth modes that represent a human/workspace ChatGPT login (not API billing).
/// Values from codex-rs `AuthMode` (serde lowercase / explicit renames), v0.157.
const CODEX_ALLOWED_MODES: &[&str] = &["chatgpt", "personalAccessToken", "agentIdentity"];
const CODEX_FORBIDDEN_MODES: &[&str] =
    &["apikey", "bedrockApiKey", "bedrockAccessKeys", "headers", "chatgptAuthTokens"];

pub fn validate_codex_auth_json(bytes: &[u8]) -> Result<CredentialMetadata, CredentialError> {
    let v: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| CredentialError::Malformed(format!("auth.json is not JSON: {e}")))?;
    let obj = v.as_object().ok_or_else(|| CredentialError::Malformed("auth.json is not an object".into()))?;

    if let Some(k) = obj.get("OPENAI_API_KEY")
        && !k.is_null()
        && k.as_str().map(|s| !s.is_empty()).unwrap_or(true)
    {
        return Err(CredentialError::ApiKeyForbidden("auth.json contains OPENAI_API_KEY".into()));
    }
    for forbidden in ["bedrock_api_key", "bedrock_access_keys"] {
        if obj.get(forbidden).is_some_and(|v| !v.is_null()) {
            return Err(CredentialError::ApiKeyForbidden(format!("auth.json contains {forbidden}")));
        }
    }
    let tokens = obj.get("tokens").filter(|t| !t.is_null());
    let pat = obj.get("personal_access_token").filter(|t| !t.is_null());
    let agent_identity = obj.get("agent_identity").filter(|t| !t.is_null());

    let mode = match obj.get("auth_mode").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        // Older files have no auth_mode; infer from contents.
        None if tokens.is_some() => "chatgpt".to_string(),
        None if pat.is_some() => "personalAccessToken".to_string(),
        None if agent_identity.is_some() => "agentIdentity".to_string(),
        None => return Err(CredentialError::Malformed("auth.json has no login state".into())),
    };
    if CODEX_FORBIDDEN_MODES.contains(&mode.as_str()) {
        return Err(if mode.to_ascii_lowercase().contains("key") {
            CredentialError::ApiKeyForbidden(format!("auth_mode={mode}"))
        } else {
            CredentialError::UnsupportedAuthMode(mode)
        });
    }
    if !CODEX_ALLOWED_MODES.contains(&mode.as_str()) {
        return Err(CredentialError::UnsupportedAuthMode(mode));
    }

    let mut md = CredentialMetadata {
        provider: "codex".into(),
        auth_kind: mode.clone(),
        material_fingerprint: fingerprint(bytes),
        ..Default::default()
    };
    if let Some(lr) = obj.get("last_refresh").and_then(|x| x.as_str()) {
        md.last_refresh = Some(lr.to_string());
    }
    if mode == "chatgpt" {
        let t = tokens
            .and_then(|t| t.as_object())
            .ok_or_else(|| CredentialError::Malformed("chatgpt auth without tokens".into()))?;
        for req in ["access_token", "refresh_token", "id_token"] {
            let present = t.get(req).map(|x| !x.is_null()).unwrap_or(false);
            if !present {
                return Err(CredentialError::Malformed(format!("tokens.{req} missing")));
            }
        }
        if let Some(acct) = t.get("account_id").and_then(|a| a.as_str()) {
            md.account_fingerprint = Some(fingerprint(acct.as_bytes()));
        }
        // id_token may be stored as a raw JWT string (current codex serializes it that way).
        if let Some(claims) = t.get("id_token").and_then(|x| x.as_str()).and_then(decode_jwt_claims) {
            if let Some(email) = claims.get("email").and_then(|e| e.as_str()) {
                md.email_hint = Some(mask_email(email));
            }
            if let Some(auth) = claims.get("https://api.openai.com/auth") {
                if let Some(plan) = auth.get("chatgpt_plan_type").and_then(|p| p.as_str()) {
                    md.plan = Some(plan.to_string());
                }
                if md.account_fingerprint.is_none()
                    && let Some(acct) = auth.get("chatgpt_account_id").and_then(|a| a.as_str())
                {
                    md.account_fingerprint = Some(fingerprint(acct.as_bytes()));
                }
            }
        }
        if let Some(exp) = t
            .get("access_token")
            .and_then(|x| x.as_str())
            .and_then(decode_jwt_claims)
            .and_then(|c| c.get("exp").and_then(|e| e.as_i64()))
            && let Some(dt) = chrono::DateTime::from_timestamp(exp, 0)
        {
            md.access_token_expires_at = Some(dt.to_rfc3339());
        }
        md.notes.push(
            "Codex refreshes ChatGPT tokens during use; runs hold an exclusive lease and hand the refreshed auth.json back (validated write-back).".into(),
        );
        md.notes.push(
            "OpenAI treats a session as stale after ~8 days without refresh; run at least weekly or re-enroll.".into(),
        );
    }
    Ok(md)
}

pub fn validate_claude_token(bytes: &[u8]) -> Result<CredentialMetadata, CredentialError> {
    let s = std::str::from_utf8(bytes).map_err(|_| CredentialError::Malformed("token is not UTF-8".into()))?.trim();
    if s.is_empty() {
        return Err(CredentialError::Malformed("token is empty".into()));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CredentialError::Malformed("token contains whitespace/control characters".into()));
    }
    if s.starts_with("sk-ant-api") {
        return Err(CredentialError::ApiKeyForbidden(
            "this is an Anthropic API key (sk-ant-api...), not a `claude setup-token` OAuth token".into(),
        ));
    }
    let mut md = CredentialMetadata {
        provider: "claude".into(),
        auth_kind: "claude-oauth-token".into(),
        material_fingerprint: fingerprint(s.as_bytes()),
        ..Default::default()
    };
    if !s.starts_with("sk-ant-oat") {
        md.notes
            .push("token prefix not recognized as a setup-token OAuth token; verify with `claude auth status`".into());
    }
    md.notes.push("Generated by `claude setup-token` (one-year OAuth token, model requests only). Not refreshed by the CLI; no write-back.".into());
    Ok(md)
}

/// Validate a refreshed credential file handed back by an attempt.
pub fn validate_writeback(
    provider: Provider,
    enrolled: &CredentialMetadata,
    key: &str,
    new_bytes: &[u8],
) -> Result<CredentialMetadata, CredentialError> {
    let spec = provider.spec();
    if !spec.files.iter().any(|f| f.key == key && f.writeback) {
        return Err(CredentialError::UnexpectedKey(key.to_string()));
    }
    let mut bundle = CredentialBundle::new();
    bundle.insert(key.to_string(), new_bytes.to_vec());
    let md = validate_bundle(provider, &bundle)?;
    if md.auth_kind != enrolled.auth_kind {
        return Err(CredentialError::AccountMismatch);
    }
    match (&enrolled.account_fingerprint, &md.account_fingerprint) {
        (Some(a), Some(b)) if a == b => Ok(md),
        (None, None) => Ok(md),
        _ => Err(CredentialError::AccountMismatch),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    #[test]
    fn files_bundles_take_any_safe_filenames() {
        // V9: dynamic keys, opaque contents (may be plain API keys).
        let mut b = CredentialBundle::new();
        assert!(matches!(validate_bundle(Provider::Files, &b), Err(CredentialError::Malformed(_))));
        b.insert("auth.json".into(), br#"{"openai":{"type":"api","key":"sk-test-00000000"}}"#.to_vec());
        b.insert("opencode.json".into(), br#"{"model":"openai/gpt-x"}"#.to_vec());
        let md = validate_bundle(Provider::Files, &b).unwrap();
        assert_eq!(md.provider, "files");
        assert_eq!(md.auth_kind, "files");
        assert!(!md.material_fingerprint.is_empty());
        for bad in ["", "../x", "a/b", ".hidden", "x y", "x\0y"] {
            let mut bb = CredentialBundle::new();
            bb.insert(bad.into(), b"v".to_vec());
            assert!(validate_bundle(Provider::Files, &bb).is_err(), "{bad:?}");
        }
        let mut bb = CredentialBundle::new();
        bb.insert("empty".into(), vec![]);
        assert!(validate_bundle(Provider::Files, &bb).is_err());
        // no write-back for static files, ever.
        assert!(validate_writeback(Provider::Files, &md, "auth.json", b"x").is_err());
    }

    pub fn fake_jwt(claims: serde_json::Value) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
            URL_SAFE_NO_PAD.encode(b"signature-bytes-000")
        )
    }

    pub fn codex_auth(account: &str) -> Vec<u8> {
        json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": fake_jwt(json!({"email":"alice@example.com","https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_id":account}})),
                "access_token": fake_jwt(json!({"exp": 1900000000})),
                "refresh_token": "rt_refresh_token_value_abcdefghijkl",
                "account_id": account
            },
            "last_refresh": "2026-09-20T10:00:00Z"
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn codex_chatgpt_accepted_with_safe_metadata() {
        let mut b = CredentialBundle::new();
        b.insert("auth.json".into(), codex_auth("acct-1"));
        let md = validate_bundle(Provider::Codex, &b).unwrap();
        assert_eq!(md.auth_kind, "chatgpt");
        assert_eq!(md.plan.as_deref(), Some("pro"));
        assert_eq!(md.email_hint.as_deref(), Some("a***@example.com"));
        assert!(md.access_token_expires_at.is_some());
        let printed = serde_json::to_string(&md).unwrap();
        assert!(!printed.contains("rt_refresh_token_value"));
        assert!(!printed.contains("acct-1"));
    }

    #[test]
    fn codex_api_key_rejected() {
        let mut b = CredentialBundle::new();
        b.insert("auth.json".into(), br#"{"OPENAI_API_KEY":"sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx"}"#.to_vec());
        assert!(matches!(validate_bundle(Provider::Codex, &b), Err(CredentialError::ApiKeyForbidden(_))));
        let mut b = CredentialBundle::new();
        b.insert("auth.json".into(), br#"{"auth_mode":"apikey","OPENAI_API_KEY":null}"#.to_vec());
        assert!(matches!(validate_bundle(Provider::Codex, &b), Err(CredentialError::ApiKeyForbidden(_))));
    }

    #[test]
    fn whitelist_enforced() {
        let mut b = CredentialBundle::new();
        b.insert("auth.json".into(), codex_auth("a"));
        b.insert("config.toml".into(), b"x".to_vec());
        assert!(matches!(validate_bundle(Provider::Codex, &b), Err(CredentialError::UnexpectedKey(_))));
        let b = CredentialBundle::new();
        assert!(matches!(validate_bundle(Provider::Claude, &b), Err(CredentialError::MissingKey(_))));
    }

    #[test]
    fn claude_token_rules() {
        let mut b = CredentialBundle::new();
        b.insert("oauth-token".into(), b"sk-ant-oat01-abcdefghijklmnopqrstuvwxyz\n".to_vec());
        let md = validate_bundle(Provider::Claude, &b).unwrap();
        assert_eq!(md.auth_kind, "claude-oauth-token");
        b.insert("oauth-token".into(), b"sk-ant-api03-abcdefghijklmnop".to_vec());
        assert!(matches!(validate_bundle(Provider::Claude, &b), Err(CredentialError::ApiKeyForbidden(_))));
    }

    #[test]
    fn writeback_requires_same_account() {
        let mut b = CredentialBundle::new();
        b.insert("auth.json".into(), codex_auth("acct-1"));
        let enrolled = validate_bundle(Provider::Codex, &b).unwrap();
        assert!(validate_writeback(Provider::Codex, &enrolled, "auth.json", &codex_auth("acct-1")).is_ok());
        assert_eq!(
            validate_writeback(Provider::Codex, &enrolled, "auth.json", &codex_auth("acct-2")),
            Err(CredentialError::AccountMismatch)
        );
        assert!(validate_writeback(Provider::Claude, &enrolled, "oauth-token", b"sk-ant-oat01-xxxxxxxxxxxx").is_err());
    }
}
