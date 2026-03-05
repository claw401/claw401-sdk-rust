use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Claw401Error, Result};
use crate::utils::{
    base58_to_pubkey, base64_to_bytes, bytes_to_base64, canonicalize, generate_nonce, now_ms,
    PROTOCOL_VERSION,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Capability,
    Identity,
    Delegation,
}

/// A signed capability or identity proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: ProofType,
    pub issuer: String,
    pub subject: String,
    pub claims: Value,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub nonce: String,
    pub signature: String,
    pub version: String,
}

pub struct SignProofOptions<'a> {
    pub proof_type: ProofType,
    pub issuer_public_key: String,
    pub subject: String,
    pub claims: Value,
    /// Ed25519 signing key (32-byte seed).
    pub issuer_signing_key: &'a SigningKey,
    pub ttl_ms: Option<u64>,
}

/// Sign a capability or identity proof.
pub fn sign_proof(options: SignProofOptions<'_>) -> Result<Proof> {
    let now = now_ms();
    let expires_at = options.ttl_ms.map(|ttl| now + ttl);
    let nonce = generate_nonce();

    // Build payload (everything except signature)
    let payload_struct = ProofPayload {
        proof_type: &options.proof_type,
        issuer: &options.issuer_public_key,
        subject: &options.subject,
        claims: &options.claims,
        issued_at: now,
        expires_at,
        nonce: &nonce,
        version: PROTOCOL_VERSION,
    };

    let payload_bytes = canonicalize(&payload_struct)?;
    let signature = options.issuer_signing_key.sign(&payload_bytes);

    Ok(Proof {
        proof_type: options.proof_type,
        issuer: options.issuer_public_key,
        subject: options.subject,
        claims: options.claims,
        issued_at: now,
        expires_at,
        nonce,
        signature: bytes_to_base64(&signature.to_bytes()),
        version: PROTOCOL_VERSION.to_string(),
    })
}

pub struct VerifyProofOptions<'a> {
    pub proof: &'a Proof,
    pub clock_skew_ms: Option<u64>,
}

/// Verify a signed proof.
pub fn verify_proof(options: VerifyProofOptions<'_>) -> Result<()> {
    let clock_skew = options.clock_skew_ms.unwrap_or(30_000);
    let proof = options.proof;
    let now = now_ms();

    if let Some(exp) = proof.expires_at {
        if now > exp.saturating_add(clock_skew) {
            return Err(Claw401Error::ProofExpired);
        }
    }

    let pubkey_bytes = base58_to_pubkey(&proof.issuer)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| Claw401Error::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = base64_to_bytes(&proof.signature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Claw401Error::EncodingError("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    let payload_struct = ProofPayload {
        proof_type: &proof.proof_type,
        issuer: &proof.issuer,
        subject: &proof.subject,
        claims: &proof.claims,
        issued_at: proof.issued_at,
        expires_at: proof.expires_at,
        nonce: &proof.nonce,
        version: &proof.version,
    };
    let payload_bytes = canonicalize(&payload_struct)?;

    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|_| Claw401Error::InvalidSignature)
}

// Internal signing payload struct (without signature field)
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofPayload<'a> {
    #[serde(rename = "type")]
    proof_type: &'a ProofType,
    issuer: &'a str,
    subject: &'a str,
    claims: &'a Value,
    issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    nonce: &'a str,
    version: &'a str,
}
