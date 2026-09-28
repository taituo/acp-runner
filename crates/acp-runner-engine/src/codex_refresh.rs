//! Controller-side Codex OAuth refresh (V1a, verifying write-back).
//!
//! Values verified against the pinned `@openai/codex` 0.156.1 source
//! (upstream tag `rust-v0.156.1`, `codex-rs/`):
//!
//! * token endpoint `https://auth.openai.com/oauth/token`
//!   (`login/src/auth/manager.rs:212`), override env
//!   `CODEX_REFRESH_TOKEN_URL_OVERRIDE` (`manager.rs:214`, resolved at `:1707-1709`);
//! * client id `app_EMoamEEZ73f0CkXaXp7hrann` (`manager.rs:1698`), override env
//!   `CODEX_APP_SERVER_LOGIN_CLIENT_ID` (`manager.rs:216`, resolved at `:1700-1705`);
//! * JSON refresh body `{grant_type: "refresh_token", client_id, refresh_token}`
//!   (`login/src/oauth/client.rs:76-108`; `resource` omitted, mirroring
//!   `refresh(RefreshTokenGrant { refresh_token, resource: None })` at
//!   `manager.rs:1610-1635`);
//! * id_token account claim path `https://api.openai.com/auth` →
//!   `chatgpt_account_id` (`login/src/token_data.rs`, `AuthClaims`);
//! * **no JWKS / signature verification anywhere in `codex-rs`**
//!   (`rg jwks` finds nothing; `decode_jwt_payload` in `token_data.rs:117-140`
//!   ignores the signature and parses claims only).
//!
//! Trust design (approved 1a): the account binding is established by performing
//! the refresh itself over TLS against the provider — a forged refresh token
//! cannot produce a provider response. The account id is read from the
//! *response* id_token claims (same paths the CLI parses), whose `exp` must be
//! present and in the future.
//!
//! Terminology is deliberate: these are **provider-response claims**, not
//! "verified" claims. Neither this module nor the pinned CLI verifies the JWT
//! signature (`decode_jwt_payload` in `token_data.rs:117-140` ignores it; no
//! JWKS usage exists in `codex-rs`). Authentication of the response rests
//! solely on the TLS connection to the trusted token endpoint — which is why
//! [`CodexRefreshConfig`] pins the endpoint scheme and host. A man-in-the-middle
//! with a trusted-CA position is outside this threat model.
//!
//! We deliberately do not invent a JWKS URL: none exists in the pinned source.

use std::time::Duration;

/// Verified default; prefer [`CodexRefreshConfig::from_env_or_default`] so the
/// same overrides as the CLI keep working.
pub const DEFAULT_TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";
/// Verified default; see module docs.
pub const DEFAULT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// Same override env var as the CLI (`manager.rs:214`).
pub const TOKEN_ENDPOINT_OVERRIDE_ENV_VAR: &str = "CODEX_REFRESH_TOKEN_URL_OVERRIDE";
/// Same override env var as the CLI (`manager.rs:216`).
pub const CLIENT_ID_OVERRIDE_ENV_VAR: &str = "CODEX_APP_SERVER_LOGIN_CLIENT_ID";
/// Proxy for the refresh call (CONNECT allowlist proxy). The controller routes
/// its token refresh through the same allowlisted proxy as agent traffic so no
/// component needs general public egress; the proxy allowlist already permits
/// the trusted auth host.
pub const REFRESH_PROXY_ENV_VAR: &str = "ACP_RUNNER_CODEX_REFRESH_PROXY";

/// Claim namespace the CLI parses (`token_data.rs`, `AuthClaims`).
pub const AUTH_CLAIM_NAMESPACE: &str = "https://api.openai.com/auth";

/// Only this host is ever trusted as a token endpoint in production.
pub const TRUSTED_TOKEN_HOST: &str = "auth.openai.com";
/// Only this path is ever trusted in production: the refresh token must not
/// be posted to an arbitrary route, even on the trusted host.
pub const TRUSTED_TOKEN_PATH: &str = "/oauth/token";

#[derive(Debug, Clone)]
pub struct CodexRefreshConfig {
    pub token_endpoint: String,
    pub client_id: String,
    pub timeout: Duration,
    /// HTTP CONNECT proxy URL for the refresh call (e.g. the allowlisting
    /// egress proxy). The proxy — not this client — enforces the destination
    /// allowlist; the endpoint policy below still applies end to end.
    pub proxy_url: Option<String>,
    /// Test-only escape hatch for the local fake Axum endpoint. Private on
    /// purpose: the only constructor that sets it is `#[cfg(test)]`, so no
    /// production build can enable it. [`refresh_tokens`] always validates
    /// the endpoint unless this hatch is set.
    test_only_allow_insecure_endpoint: bool,
}

impl Default for CodexRefreshConfig {
    fn default() -> Self {
        Self {
            token_endpoint: DEFAULT_TOKEN_ENDPOINT.to_string(),
            client_id: DEFAULT_CLIENT_ID.to_string(),
            timeout: Duration::from_secs(30),
            proxy_url: None,
            test_only_allow_insecure_endpoint: false,
        }
    }
}

impl CodexRefreshConfig {
    /// Test-only constructor pointing at the local fake endpoint. The only
    /// way to enable the insecure-endpoint hatch; absent from non-test builds.
    #[cfg(test)]
    pub(crate) fn test_with_endpoint(url: String) -> Self {
        Self {
            token_endpoint: url,
            client_id: "test-client".into(),
            timeout: Duration::from_secs(10),
            proxy_url: None,
            test_only_allow_insecure_endpoint: true,
        }
    }



    /// Production validation: the endpoint must be exactly the trusted token
    /// URL (default port, no query/fragment), and the test hatch must be off.
    /// Returns the offending detail for the operator to fix.
    pub fn validated_production_endpoint(&self) -> Result<(), String> {
        if self.test_only_allow_insecure_endpoint {
            return Err("test_only_allow_insecure_endpoint must not be set in production".into());
        }
        check_trusted_endpoint(&self.token_endpoint)
    }
}

/// Shared endpoint policy: exactly `https://auth.openai.com/oauth/token`
/// (default port, no credentials, no query, no fragment). Anything else is
/// refused before any token material touches the network.
fn check_trusted_endpoint(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("unparseable token endpoint {url:?}: {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!("token endpoint must use https, got {url:?}"));
    }
    if parsed.host_str() != Some(TRUSTED_TOKEN_HOST) {
        return Err(format!("token endpoint host must be {TRUSTED_TOKEN_HOST}, got {url:?}"));
    }
    if parsed.port().is_some() {
        return Err(format!("token endpoint must use the default https port, got {url:?}"));
    }
    if parsed.path() != TRUSTED_TOKEN_PATH {
        return Err(format!("token endpoint path must be {TRUSTED_TOKEN_PATH}, got {url:?}"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!("token endpoint must not carry query or fragment: {url:?}"));
    }
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(format!("token endpoint must not embed credentials: {url:?}"));
    }
    Ok(())
}

impl CodexRefreshConfig {
    pub fn from_env_or_default() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var(TOKEN_ENDPOINT_OVERRIDE_ENV_VAR)
            && !v.trim().is_empty()
        {
            cfg.token_endpoint = v;
        }
        if let Ok(v) = std::env::var(CLIENT_ID_OVERRIDE_ENV_VAR)
            && !v.trim().is_empty()
        {
            cfg.client_id = v;
        }
        if let Ok(v) = std::env::var(REFRESH_PROXY_ENV_VAR)
            && !v.trim().is_empty()
        {
            cfg.proxy_url = Some(v);
        }
        cfg
    }
}

/// Tokens the provider returned for the submitted refresh token. `account_id`
/// is the `chatgpt_account_id` from the TLS-authenticated provider response
/// (parsed, not signature-verified — see module docs). Callers must still
/// match it against the enrolled profile; it is evidence, not authorization.
#[derive(Debug, Clone)]
pub struct RefreshedTokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshError {
    /// The refresh token is dead (revoked/expired/reused) or the request is
    /// malformed: retrying with the same token is pointless.
    Permanent { reason: String },
    /// Transport, timeout, 5xx or unparseable response: may succeed on retry.
    Transient { reason: String },
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::Permanent { reason } => write!(f, "permanent refresh failure: {reason}"),
            RefreshError::Transient { reason } => write!(f, "transient refresh failure: {reason}"),
        }
    }
}

impl std::error::Error for RefreshError {}

#[derive(serde::Deserialize)]
struct RefreshResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    // NOTE: `error_description` is intentionally not parsed — provider error
    // bodies can echo request material and must never reach logs.
}

/// Perform the refresh. Only the submitted `refresh_token` leaves this host;
/// nothing agent-written is trusted before this call succeeds.
pub async fn refresh_tokens(
    client: &reqwest::Client,
    cfg: &CodexRefreshConfig,
    refresh_token: &str,
) -> Result<RefreshedTokens, RefreshError> {
    if !cfg.test_only_allow_insecure_endpoint
        && let Err(detail) = check_trusted_endpoint(&cfg.token_endpoint)
    {
        // Config error, never a network attempt: no token material may leave
        // the host towards an untrusted endpoint.
        return Err(RefreshError::Permanent { reason: detail });
    }
    use std::collections::BTreeMap;
    let body: BTreeMap<&str, &str> = [
        ("grant_type", "refresh_token"),
        ("client_id", cfg.client_id.as_str()),
        ("refresh_token", refresh_token),
    ]
    .into_iter()
    .collect();
    let resp = client
        .post(cfg.token_endpoint.as_str())
        .header("Content-Type", "application/json")
        .timeout(cfg.timeout)
        .json(&body)
        .send()
        .await
        .map_err(|e| RefreshError::Transient { reason: format!("token endpoint unreachable: {e}") })?;
    let status = resp.status();
    let parsed: RefreshResponse = resp.json().await.map_err(|_| RefreshError::Transient {
        reason: "token endpoint returned an unparseable body".into(),
    })?;
    if !status.is_success() {
        // Mirror the CLI's classification (manager.rs:1660-1690): revoked /
        // expired / reused grants and 401s are permanent; anything else is
        // transient. The provider `error` string is NEVER propagated: it is
        // provider-controlled text that can echo request token material.
        // Only an allowlisted classification plus the status leaves this fn.
        let code = normalized_error_code(parsed.error.as_deref().unwrap_or(""));
        let permanent = status.as_u16() == 401 || matches!(code, "invalid_grant" | "expired" | "revoked" | "reused" | "invalidated");
        let reason = format!("http {status}: {code}");
        return Err(if permanent {
            RefreshError::Permanent { reason }
        } else {
            RefreshError::Transient { reason }
        });
    }
    let (Some(access_token), Some(id_token)) = (parsed.access_token, parsed.id_token) else {
        return Err(RefreshError::Transient { reason: "token endpoint omitted access_token or id_token".into() });
    };
    let account_id = response_chatgpt_account_id(&id_token)?;
    Ok(RefreshedTokens { access_token, id_token, refresh_token: parsed.refresh_token, account_id })
}

/// Injectable refresh behavior so tests can script provider responses without
/// HTTP. Production uses [`HttpCodexRefresher`]; integration tests inject a
/// fake. The account-binding check in `post_credential` applies to every
/// implementation: a refresher is evidence, never authorization.
#[async_trait::async_trait]
pub trait CodexRefresher: Send + Sync {
    async fn refresh(&self, refresh_token: &str) -> Result<RefreshedTokens, RefreshError>;
}

/// Production refresher: TLS against the pinned token endpoint. Construct via
/// [`HttpCodexRefresher::new`], which enforces the endpoint policy before any
/// token material can flow.
pub struct HttpCodexRefresher {
    client: reqwest::Client,
    cfg: CodexRefreshConfig,
}

impl HttpCodexRefresher {
    /// Build the production refresher: validates the endpoint, then builds a
    /// client that routes via `proxy_url` when set (otherwise direct TLS).
    /// A malformed proxy URL fails here, before any token material flows.
    pub fn new(cfg: CodexRefreshConfig) -> Result<Self, String> {
        cfg.validated_production_endpoint()?;
        let mut builder = reqwest::Client::builder();
        if let Some(proxy) = cfg.proxy_url.as_deref() {
            let parsed = reqwest::Url::parse(proxy)
                .map_err(|e| format!("unparseable refresh proxy {proxy:?}: {e}"))?;
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!("refresh proxy must be http(s), got {proxy:?}"));
            }
            builder = builder.proxy(
                reqwest::Proxy::https(parsed.as_str())
                    .map_err(|e| format!("invalid refresh proxy {proxy:?}: {e}"))?,
            );
        }
        let client =
            builder.build().map_err(|e| format!("failed to build refresh HTTP client: {e}"))?;
        Ok(Self { client, cfg })
    }
}

#[async_trait::async_trait]
impl CodexRefresher for HttpCodexRefresher {
    async fn refresh(&self, refresh_token: &str) -> Result<RefreshedTokens, RefreshError> {
        refresh_tokens(&self.client, &self.cfg, refresh_token).await
    }
}

/// Normalize a provider-supplied error code to a small allowlist so arbitrary
/// response text (which may echo the submitted refresh token) can never reach
/// API errors, metrics, or logs. Matching is case-insensitive substring, as
/// providers vary the exact code spelling.
fn normalized_error_code(raw: &str) -> &'static str {
    let lower = raw.to_ascii_lowercase();
    for known in [
        "invalid_grant",
        "unauthorized",
        "expired",
        "revoked",
        "reused",
        "invalidated",
        "temporarily_unavailable",
        "server_error",
        "unsupported_grant_type",
        "invalid_request",
        "invalid_client",
        "access_denied",
    ] {
        if lower.contains(known) {
            return known;
        }
    }
    "rejected"
}

/// Extract `chatgpt_account_id` from a provider-response id_token using the same
/// claim paths the CLI parses, and require a future `exp`. Call only with
/// tokens that arrived over TLS from the trusted token endpoint — this parses,
/// it does not authenticate (exactly like the CLI's `decode_jwt_payload`).
fn response_chatgpt_account_id(id_token: &str) -> Result<String, RefreshError> {
    let claims = acp_runner_core::credentials::decode_jwt_claims(id_token).ok_or(RefreshError::Transient {
        reason: "response id_token is not a parseable JWT".into(),
    })?;
    let account = claims
        .get(AUTH_CLAIM_NAMESPACE)
        .and_then(|a| a.get("chatgpt_account_id"))
        .and_then(|a| a.as_str())
        .filter(|a| !a.is_empty())
        .ok_or(RefreshError::Transient { reason: "response id_token has no chatgpt_account_id".into() })?;
    let exp = claims.get("exp").and_then(|e| e.as_i64()).ok_or(RefreshError::Transient {
        reason: "response id_token has no exp".into(),
    })?;
    let now = chrono::Utc::now().timestamp();
    if exp <= now {
        return Err(RefreshError::Transient { reason: "response id_token is expired".into() });
    }
    Ok(account.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use base64::Engine as _;

    pub fn unsigned_jwt(claims: serde_json::Value) -> String {
        let b64 = |v: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
        format!("{}.{}.{}", b64(serde_json::json!({"alg": "none"})), b64(claims), b64(serde_json::json!({})))
    }

    pub fn account_id_token(account: &str, exp_offset_secs: i64) -> String {
        unsigned_jwt(serde_json::json!({
            "email": "t@example.com",
            AUTH_CLAIM_NAMESPACE: {"chatgpt_account_id": account},
            "exp": chrono::Utc::now().timestamp() + exp_offset_secs,
        }))
    }

    /// Fake provider: `good-rt-<account>` succeeds, `echo-rt-*` fails with an
    /// error body echoing the submitted token (leak probe), everything else
    /// 400 invalid_grant.
    async fn fake_token_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/oauth/token",
            post(|axum::Json(body): axum::Json<serde_json::Value>| async move {
                let ok_grant = body.get("grant_type").and_then(|v| v.as_str()) == Some("refresh_token");
                let rt = body.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(secret) = rt.strip_prefix("echo-rt-") {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": format!("invalid_grant for token {secret}")})),
                    );
                }
                let Some(account) = rt.strip_prefix("good-rt-") else {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "invalid_grant"})),
                    );
                };
                if !ok_grant {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "unsupported_grant_type"})),
                    );
                }
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "access_token": format!("access-for-{account}"),
                        "id_token": account_id_token(account, 3600),
                        "refresh_token": format!("good-rt-{account}-rotated"),
                    })),
                )
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/oauth/token", l.local_addr().unwrap());
        let h = tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, h)
    }

    fn test_client() -> reqwest::Client {
        // Exactly one provider; this graph has no kube-supplied ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder().build().unwrap()
    }

    fn test_cfg(url: String) -> CodexRefreshConfig {
        CodexRefreshConfig::test_with_endpoint(url)
    }

    #[tokio::test]
    async fn production_config_rejects_untrusted_endpoints() {
        let client = test_client();
        // Plain HTTP, wrong host, wrong path, explicit port, query/fragment,
        // credentials in URL: all refused before any I/O takes the token.
        for url in [
            "http://127.0.0.1:9/oauth/token",
            "https://evil.example.com/oauth/token",
            "https://auth.openai.com.evil.example.com/oauth/token",
            "https://user:pass@auth.openai.com/oauth/token",
            "https://auth.openai.com/other/route",
            "https://auth.openai.com:8443/oauth/token",
            "https://auth.openai.com/oauth/token?next=evil",
            "https://auth.openai.com/oauth/token#frag",
            "not a url",
        ] {
            let cfg = CodexRefreshConfig {
                token_endpoint: url.into(),
                ..CodexRefreshConfig::default()
            };
            let err = refresh_tokens(&client, &cfg, "rt").await.unwrap_err();
            assert!(matches!(err, RefreshError::Permanent { .. }), "{url}: {err}");
        }
        assert!(CodexRefreshConfig::default().validated_production_endpoint().is_ok());
        let hatch = CodexRefreshConfig::test_with_endpoint("http://127.0.0.1:9/oauth/token".into());
        assert!(hatch.validated_production_endpoint().is_err());
    }

    #[tokio::test]
    async fn refresh_accepts_a_good_token_and_binds_the_account() {
        let (url, _srv) = fake_token_server().await;
        let out = refresh_tokens(&test_client(), &test_cfg(url), "good-rt-acct-1").await.unwrap();
        assert_eq!(out.account_id, "acct-1");
        assert_eq!(out.access_token, "access-for-acct-1");
        assert_eq!(out.refresh_token.as_deref(), Some("good-rt-acct-1-rotated"));
    }

    #[tokio::test]
    async fn refresh_rejects_a_bad_token_as_permanent() {
        let (url, _srv) = fake_token_server().await;
        let err = refresh_tokens(&test_client(), &test_cfg(url), "forged-rt").await.unwrap_err();
        assert!(matches!(err, RefreshError::Permanent { .. }), "{err}");
    }

    #[tokio::test]
    async fn provider_error_echo_never_leaks_the_submitted_token() {
        let (url, _srv) = fake_token_server().await;
        // The fake provider echoes the submitted refresh token inside its
        // error string; the allowlist must strip it before it can reach API
        // errors, metrics, or logs.
        let secret = "echo-rt-secret-value-123";
        let err = refresh_tokens(&test_client(), &test_cfg(url), secret).await.unwrap_err();
        assert!(matches!(err, RefreshError::Permanent { .. }), "{err}");
        let rendered = err.to_string();
        assert!(!rendered.contains(secret), "token material leaked: {rendered}");
        assert!(!rendered.contains("secret-value"), "token material leaked: {rendered}");
        assert!(rendered.contains("invalid_grant"), "classification lost: {rendered}");
    }

    #[tokio::test]
    async fn response_without_account_or_exp_is_rejected() {
        assert!(response_chatgpt_account_id(&account_id_token("", 3600)).is_err());
        assert!(response_chatgpt_account_id(&unsigned_jwt(serde_json::json!({"exp": 9999999999i64})) ).is_err());
        assert!(response_chatgpt_account_id(&unsigned_jwt(serde_json::json!({
            AUTH_CLAIM_NAMESPACE: {"chatgpt_account_id": "a"}, "exp": 1000,
        }))).is_err());
        assert!(response_chatgpt_account_id(&account_id_token("a", 3600)).unwrap() == "a");
    }
}
