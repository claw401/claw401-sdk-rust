use serde::{Deserialize, Serialize};

use crate::error::{Claw401Error, Result};
use crate::utils::{derive_session_id, now_ms, DEFAULT_SESSION_TTL_MS};

/// An authenticated session issued after successful challenge verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub session_id: String,
    pub public_key: String,
    pub scopes: Vec<String>,
    pub domain: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

pub struct CreateSessionOptions {
    pub public_key: String,
    pub domain: String,
    pub nonce: String,
    pub scopes: Vec<String>,
    pub ttl_ms: Option<u64>,
}

/// Create an authenticated session.
pub fn create_session(options: CreateSessionOptions) -> Session {
    let created_at = now_ms();
    let ttl_ms = options.ttl_ms.unwrap_or(DEFAULT_SESSION_TTL_MS);
    let expires_at = created_at + ttl_ms;
    let session_id = derive_session_id(&options.nonce, &options.public_key, &options.domain, created_at);

    Session {
        session_id,
        public_key: options.public_key,
        scopes: options.scopes,
        domain: options.domain,
        created_at,
        expires_at,
        nonce: options.nonce,
    }
}

pub struct VerifySessionOptions<'a> {
    pub session: &'a Session,
    pub expected_domain: &'a str,
    pub required_scopes: &'a [String],
    pub clock_skew_ms: Option<u64>,
}

/// Verify a session against the expected domain and required scopes.
///
/// # Errors
/// Returns a typed [`crate::error::Claw401Error`] on any failed check.
pub fn verify_session(options: VerifySessionOptions<'_>) -> Result<()> {
    let clock_skew = options.clock_skew_ms.unwrap_or(30_000);
    let session = options.session;
    let now = now_ms();

    if now > session.expires_at.saturating_add(clock_skew) {
        return Err(Claw401Error::SessionExpired);
    }

    let expected = options.expected_domain.trim().to_lowercase();
    if session.domain != expected {
        return Err(Claw401Error::SessionDomainMismatch);
    }

    for required in options.required_scopes {
        if !session.scopes.contains(required) {
            return Err(Claw401Error::MissingScope(required.clone()));
        }
    }

    Ok(())
}
