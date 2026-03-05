use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Claw401Error, Result};
use crate::utils::{
    base58_to_pubkey, base64_to_bytes, bytes_to_base64, canonicalize, derive_attestation_id,
    generate_nonce, now_ms, PROTOCOL_VERSION,
};

/// Declared capabilities of an autonomous agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    pub actions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default, rename = "mcpTools")]
    pub mcp_tools: Vec<String>,
}

/// An operator-signed agent attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAttestation {
    pub attestation_id: String,
    pub agent_key: String,
    pub operator_key: String,
    pub capabilities: AgentCapabilities,
    pub agent_id: String,
    pub issued_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub nonce: String,
    pub signature: String,
    pub version: String,
}

pub struct CreateAgentAttestationOptions<'a> {
    pub agent_key: String,
    pub operator_key: String,
    pub operator_signing_key: &'a SigningKey,
    pub agent_id: String,
    pub capabilities: AgentCapabilities,
    pub ttl_ms: Option<u64>,
}

/// Create and sign an agent attestation.
pub fn create_agent_attestation(options: CreateAgentAttestationOptions<'_>) -> Result<AgentAttestation> {
    let now = now_ms();
    let nonce = generate_nonce();
    let expires_at = options.ttl_ms.map(|ttl| now + ttl);
    let attestation_id =
        derive_attestation_id(&options.agent_key, &options.operator_key, now, &nonce);

    let payload = AttestationPayload {
        attestation_id: &attestation_id,
        agent_key: &options.agent_key,
        operator_key: &options.operator_key,
        capabilities: &options.capabilities,
        agent_id: &options.agent_id,
        issued_at: now,
        expires_at,
        nonce: &nonce,
        version: PROTOCOL_VERSION,
    };

    let payload_bytes = canonicalize(&payload)?;
    let signature = options.operator_signing_key.sign(&payload_bytes);

    Ok(AgentAttestation {
        attestation_id,
        agent_key: options.agent_key,
        operator_key: options.operator_key,
        capabilities: options.capabilities,
        agent_id: options.agent_id,
        issued_at: now,
        expires_at,
        nonce,
        signature: bytes_to_base64(&signature.to_bytes()),
        version: PROTOCOL_VERSION.to_string(),
    })
}

pub struct VerifyAgentAttestationOptions<'a> {
    pub attestation: &'a AgentAttestation,
    pub expected_operator_key: Option<&'a str>,
    pub clock_skew_ms: Option<u64>,
}

/// Verify an agent attestation.
pub fn verify_agent_attestation(options: VerifyAgentAttestationOptions<'_>) -> Result<()> {
    let clock_skew = options.clock_skew_ms.unwrap_or(30_000);
    let att = options.attestation;
    let now = now_ms();

    if let Some(exp) = att.expires_at {
        if now > exp.saturating_add(clock_skew) {
            return Err(Claw401Error::AttestationExpired);
        }
    }

    if let Some(expected_op) = options.expected_operator_key {
        if att.operator_key != expected_op {
            return Err(Claw401Error::OperatorKeyMismatch);
        }
    }

    let pubkey_bytes = base58_to_pubkey(&att.operator_key)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| Claw401Error::InvalidPublicKey(e.to_string()))?;

    let sig_bytes = base64_to_bytes(&att.signature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Claw401Error::EncodingError("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    let payload = AttestationPayload {
        attestation_id: &att.attestation_id,
        agent_key: &att.agent_key,
        operator_key: &att.operator_key,
        capabilities: &att.capabilities,
        agent_id: &att.agent_id,
        issued_at: att.issued_at,
        expires_at: att.expires_at,
        nonce: &att.nonce,
        version: &att.version,
    };
    let payload_bytes = canonicalize(&payload)?;

    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|_| Claw401Error::InvalidSignature)
}

// Internal payload struct (without signature)
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationPayload<'a> {
    attestation_id: &'a str,
    agent_key: &'a str,
    agent_id: &'a str,
    capabilities: &'a AgentCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    issued_at: u64,
    nonce: &'a str,
    operator_key: &'a str,
    version: &'a str,
}
