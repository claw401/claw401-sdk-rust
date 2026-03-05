use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Claw401Error, Result};

/// Protocol version string included in all signed payloads.
pub const PROTOCOL_VERSION: &str = "x401/1.0";

/// Default challenge TTL: 5 minutes in milliseconds.
pub const DEFAULT_CHALLENGE_TTL_MS: u64 = 5 * 60 * 1000;

/// Default session TTL: 24 hours in milliseconds.
pub const DEFAULT_SESSION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Returns the current Unix timestamp in milliseconds.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/// Generates a cryptographically random 32-byte nonce as a lowercase hex string.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Encode bytes as a base64 string.
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    BASE64.encode(bytes)
}

/// Decode a base64 string to bytes.
pub fn base64_to_bytes(b64: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(b64)
        .map_err(|e| Claw401Error::EncodingError(format!("base64 decode: {e}")))
}

/// Decode a base58 public key to 32 raw bytes.
pub fn base58_to_pubkey(b58: &str) -> Result<[u8; 32]> {
    let decoded = bs58::decode(b58)
        .into_vec()
        .map_err(|e| Claw401Error::InvalidPublicKey(format!("base58 decode: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| Claw401Error::InvalidPublicKey("expected 32 bytes".into()))
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// SHA-256 hex digest of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Deterministic session ID: sha256(nonce:publicKey:domain:createdAt)
pub fn derive_session_id(nonce: &str, public_key: &str, domain: &str, created_at: u64) -> String {
    let raw = format!("{nonce}:{public_key}:{domain}:{created_at}");
    sha256_hex(raw.as_bytes())
}

/// Deterministic attestation ID: sha256(agentKey:operatorKey:issuedAt:nonce)
pub fn derive_attestation_id(
    agent_key: &str,
    operator_key: &str,
    issued_at: u64,
    nonce: &str,
) -> String {
    let raw = format!("{agent_key}:{operator_key}:{issued_at}:{nonce}");
    sha256_hex(raw.as_bytes())
}

// ---------------------------------------------------------------------------
// Canonical serialization
// ---------------------------------------------------------------------------

/// Produce the canonical signing bytes for any serializable payload.
///
/// Serializes to JSON with serde and then sorts all object keys.
/// The sort is applied post-hoc via serde_json::Value manipulation.
/// This ensures cross-implementation compatibility with the TypeScript and Python SDKs.
pub fn canonicalize<T: Serialize>(payload: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(payload)
        .map_err(|e| Claw401Error::SerializationError(e.to_string()))?;
    let sorted = sort_json_keys(value);
    serde_json::to_vec(&sorted)
        .map_err(|e| Claw401Error::SerializationError(e.to_string()))
}

fn sort_json_keys(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut sorted: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            for key in keys {
                let v = map.into_iter().find(|(k, _)| k == &key).map(|(_, v)| v).unwrap();
                sorted.insert(key, sort_json_keys(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json_keys).collect()),
        other => other,
    }
}
