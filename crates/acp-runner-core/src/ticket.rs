//! Signed, short-lived **connection tickets** for the environment ACP gateway.
//!
//! ```text
//! ticket = "act1." base64url(claims-json) "." base64url(HMAC-SHA256(K_env, "act1." base64url(claims-json)))
//! claims = { env, aud, exp, nonce }
//! K_env  = HMAC-SHA256(provider_master_key, "acp-runner/gateway-key/v1/" || env-uuid-bytes)
//! ```
//!
//! * The provider holds one long-lived master key (a Kubernetes Secret / file). It never
//!   stores tickets: after a provider restart it re-derives `K_env` and issues new tickets
//!   for environments that are still alive.
//! * runnerd of environment X receives only `K_env(X)` (in its per-attempt Secret). It can
//!   verify tickets for X — and could mint them, which grants nothing it does not already
//!   control — but it cannot verify or mint tickets for any other environment: a ticket for
//!   environment A is MAC'd with `K_env(A)` and fails verification on B's gateway even
//!   before the `env` claim is compared.
//! * Tickets are bearer credentials scoped to one environment, one audience and a short
//!   lifetime; the gateway additionally rejects a nonce it has already accepted (single
//!   use). Tickets are distinct from the ingest token and from provider (Claude/Codex)
//!   credentials, and never appear in CRD status, events or the journal.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Ticket format prefix / version.
pub const TICKET_PREFIX: &str = "act1";
/// Audience of gateway connection tickets.
pub const GATEWAY_AUDIENCE: &str = "acp-runner/gateway";
/// Default lifetime of a connection ticket (only needed to open the connection).
pub const DEFAULT_TICKET_TTL_SECONDS: i64 = 300;
/// Upper bound accepted by the gateway regardless of what a ticket claims.
pub const MAX_TICKET_TTL_SECONDS: i64 = 3600;
/// Minimum master key length.
pub const MIN_MASTER_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketClaims {
    /// Environment id the ticket authorizes.
    pub env: Uuid,
    /// Audience (`acp-runner/gateway`).
    pub aud: String,
    /// Expiry, unix seconds.
    pub exp: i64,
    /// Random nonce (single-use at the gateway).
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("malformed ticket")]
    Malformed,
    #[error("ticket signature is invalid")]
    BadSignature,
    #[error("ticket is not valid for this environment")]
    WrongEnvironment,
    #[error("ticket audience mismatch")]
    WrongAudience,
    #[error("ticket expired")]
    Expired,
    #[error("ticket lifetime exceeds the allowed maximum")]
    TooLong,
    #[error("master key must be at least {MIN_MASTER_KEY_BYTES} bytes")]
    WeakKey,
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Per-environment gateway key derived from the provider master key.
pub fn derive_env_key(master: &[u8], environment_id: Uuid) -> Result<[u8; 32], TicketError> {
    if master.len() < MIN_MASTER_KEY_BYTES {
        return Err(TicketError::WeakKey);
    }
    let mut msg = b"acp-runner/gateway-key/v1/".to_vec();
    msg.extend_from_slice(environment_id.as_bytes());
    Ok(hmac_sha256(master, &msg))
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Issue a ticket for `claims` with the environment key.
pub fn issue(env_key: &[u8; 32], claims: &TicketClaims) -> String {
    let body = serde_json::to_vec(claims).expect("claims serialize");
    let signed = format!("{TICKET_PREFIX}.{}", b64().encode(body));
    let mac = hmac_sha256(env_key, signed.as_bytes());
    format!("{signed}.{}", b64().encode(mac))
}

/// Verify signature, environment, audience and expiry. Nonce replay is the caller's job.
pub fn verify(
    env_key: &[u8; 32],
    ticket: &str,
    environment_id: Uuid,
    audience: &str,
    now_unix: i64,
) -> Result<TicketClaims, TicketError> {
    if ticket.len() > 4096 {
        return Err(TicketError::Malformed);
    }
    let (signed, mac_b64) = ticket.rsplit_once('.').ok_or(TicketError::Malformed)?;
    let (prefix, body_b64) = signed.split_once('.').ok_or(TicketError::Malformed)?;
    if prefix != TICKET_PREFIX {
        return Err(TicketError::Malformed);
    }
    let mac = b64().decode(mac_b64).map_err(|_| TicketError::Malformed)?;
    if !ct_eq(&mac, &hmac_sha256(env_key, signed.as_bytes())) {
        return Err(TicketError::BadSignature);
    }
    let body = b64().decode(body_b64).map_err(|_| TicketError::Malformed)?;
    let claims: TicketClaims = serde_json::from_slice(&body).map_err(|_| TicketError::Malformed)?;
    if claims.env != environment_id {
        return Err(TicketError::WrongEnvironment);
    }
    if claims.aud != audience {
        return Err(TicketError::WrongAudience);
    }
    if claims.exp <= now_unix {
        return Err(TicketError::Expired);
    }
    if claims.exp - now_unix > MAX_TICKET_TTL_SECONDS {
        return Err(TicketError::TooLong);
    }
    if claims.nonce.len() < 16 || claims.nonce.len() > 128 {
        return Err(TicketError::Malformed);
    }
    Ok(claims)
}

/// Build fresh claims for `environment_id` valid for `ttl_seconds` from `now_unix`.
pub fn claims_for(environment_id: Uuid, now_unix: i64, ttl_seconds: i64) -> TicketClaims {
    let nonce = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    TicketClaims {
        env: environment_id,
        aud: GATEWAY_AUDIENCE.to_string(),
        exp: now_unix + ttl_seconds.clamp(1, MAX_TICKET_TTL_SECONDS),
        nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef-master";

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn issue_verify_roundtrip_and_rejections() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let ka = derive_env_key(MASTER, a).unwrap();
        let kb = derive_env_key(MASTER, b).unwrap();
        assert_ne!(ka, kb);
        let now = 1_800_000_000;
        let t = issue(&ka, &claims_for(a, now, 300));
        let c = verify(&ka, &t, a, GATEWAY_AUDIENCE, now).unwrap();
        assert_eq!(c.env, a);
        // a ticket for A does not verify on B's gateway (different key), even if B's gateway
        // was misconfigured to expect A's id.
        assert_eq!(verify(&kb, &t, b, GATEWAY_AUDIENCE, now), Err(TicketError::BadSignature));
        assert_eq!(verify(&kb, &t, a, GATEWAY_AUDIENCE, now), Err(TicketError::BadSignature));
        // A's key with the wrong expected env
        assert_eq!(verify(&ka, &t, b, GATEWAY_AUDIENCE, now), Err(TicketError::WrongEnvironment));
        assert_eq!(verify(&ka, &t, a, "other", now), Err(TicketError::WrongAudience));
        assert_eq!(verify(&ka, &t, a, GATEWAY_AUDIENCE, now + 301), Err(TicketError::Expired));
        // tampering with the claims breaks the MAC
        let (signed, mac) = t.rsplit_once('.').unwrap();
        let forged_claims = TicketClaims { exp: now + 100_000, ..c.clone() };
        let forged = format!("{TICKET_PREFIX}.{}.{mac}", b64().encode(serde_json::to_vec(&forged_claims).unwrap()));
        assert_ne!(forged.rsplit_once('.').unwrap().0, signed);
        assert_eq!(verify(&ka, &forged, a, GATEWAY_AUDIENCE, now), Err(TicketError::BadSignature));
        // over-long lifetimes are refused even when correctly signed
        let long = issue(&ka, &TicketClaims { exp: now + MAX_TICKET_TTL_SECONDS + 10, ..c });
        assert_eq!(verify(&ka, &long, a, GATEWAY_AUDIENCE, now), Err(TicketError::TooLong));
        assert_eq!(verify(&ka, "garbage", a, GATEWAY_AUDIENCE, now), Err(TicketError::Malformed));
        // restart safety: a re-derived key verifies tickets of the previous instance
        let ka2 = derive_env_key(MASTER, a).unwrap();
        verify(&ka2, &t, a, GATEWAY_AUDIENCE, now).unwrap();
        assert_eq!(derive_env_key(b"short", a), Err(TicketError::WeakKey));
    }
}
