use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Claw401Error, Result};
use crate::utils::{
    base58_to_pubkey, base64_to_bytes, bytes_to_base64, canonicalize, generate_nonce, now_ms,
    DEFAULT_CHALLENGE_TTL_MS, PROTOCOL_VERSION,
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A server-generated, domain-scoped authentication challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub nonce: String,
    pub domain: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub version: String,
}

/// A signed challenge submitted for server verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedChallenge {
    pub challenge: Challenge,
    /// Base64-encoded Ed25519 signature (64 bytes).
    pub signature: String,
    /// Base58-encoded Ed25519 public key (32 bytes).
    pub public_key: String,
}

/// Options for challenge generation.
pub struct GenerateChallengeOptions {
    pub domain: String,
    pub ttl_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Nonce cache trait
// ---------------------------------------------------------------------------

/// Nonce replay cache interface.
///
/// Implementations must be thread-safe if used across async tasks or threads.
pub trait NonceCache: Send + Sync {
    fn has(&self, nonce: &str) -> bool;
    fn set(&self, nonce: &str);
}

// ---------------------------------------------------------------------------
// Challenge generation
// ---------------------------------------------------------------------------

/// Generate a domain-scoped authentication challenge.
///
/// # Errors
/// Returns [`Claw401Error::EmptyDomain`] if the domain is empty.
pub fn generate_challenge(options: GenerateChallengeOptions) -> Result<Challenge> {
    let domain = options.domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err(Claw401Error::EmptyDomain);
    }

    let ttl_ms = options.ttl_ms.unwrap_or(DEFAULT_CHALLENGE_TTL_MS);
    let issued_at = now_ms();
    let expires_at = issued_at + ttl_ms;

    Ok(Challenge {
        nonce: generate_nonce(),
        domain,
        issued_at,
        expires_at,
        version: PROTOCOL_VERSION.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Signing payload
// ---------------------------------------------------------------------------

/// Returns the canonical bytes that a client should sign for the given challenge.
pub fn challenge_signing_bytes(challenge: &Challenge) -> Result<Vec<u8>> {
    canonicalize(challenge)
}

/// Base64-encode a raw signature for use in [`SignedChallenge`].
pub fn encode_signature(bytes: &[u8]) -> String {
    bytes_to_base64(bytes)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

pub struct VerifySignatureOptions<'a, C: NonceCache> {
    pub signed_challenge: &'a SignedChallenge,
    pub expected_domain: &'a str,
    pub nonce_cache: &'a C,
    /// Clock skew tolerance in milliseconds. Default: 30 000.
    pub clock_skew_ms: Option<u64>,
}

pub struct VerifySignatureResult {
    pub public_key: String,
}

/// Verify a signed challenge.
///
/// Checks:
///   1. Challenge has not expired
///   2. Domain matches expected domain
///   3. Nonce has not been replayed
///   4. Signature is a valid Ed25519 signature over the canonical payload
///   5. Mark nonce as consumed
///
/// # Errors
/// Returns a typed [`Claw401Error`] describing the first failing check.
pub fn verify_signature<C: NonceCache>(
    options: VerifySignatureOptions<'_, C>,
) -> Result<VerifySignatureResult> {
    let clock_skew = options.clock_skew_ms.unwrap_or(30_000);
    let challenge = &options.signed_challenge.challenge;
    let now = now_ms();

    // 1. Expiry
    if now > challenge.expires_at.saturating_add(clock_skew) {
        return Err(Claw401Error::ChallengeExpired);
    }
    if challenge.issued_at > now.saturating_add(clock_skew) {
        return Err(Claw401Error::ChallengeNotYetValid);
    }

    // 2. Domain binding
    let expected = options.expected_domain.trim().to_lowercase();
    if challenge.domain != expected {
        return Err(Claw401Error::InvalidDomain {
            expected,
            got: challenge.domain.clone(),
        });
    }

    // 3. Replay protection
    if options.nonce_cache.has(&challenge.nonce) {
        return Err(Claw401Error::NonceReplayed);
    }

    // 4. Decode public key and signature
    let pubkey_bytes = base58_to_pubkey(&options.signed_challenge.public_key)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| Claw401Error::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = base64_to_bytes(&options.signed_challenge.signature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Claw401Error::EncodingError("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    let payload = challenge_signing_bytes(challenge)?;

    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| Claw401Error::InvalidSignature)?;

    // 5. Consume nonce — only after all checks pass
    options.nonce_cache.set(&challenge.nonce);

    Ok(VerifySignatureResult {
        public_key: options.signed_challenge.public_key.clone(),
    })
}
