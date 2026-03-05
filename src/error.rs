use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum Claw401Error {
    #[error("Challenge has expired")]
    ChallengeExpired,

    #[error("Challenge issuedAt is in the future")]
    ChallengeNotYetValid,

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Domain mismatch: expected {expected}, got {got}")]
    InvalidDomain { expected: String, got: String },

    #[error("Nonce has already been used")]
    NonceReplayed,

    #[error("Session has expired")]
    SessionExpired,

    #[error("Session domain mismatch")]
    SessionDomainMismatch,

    #[error("Missing required scope: {0}")]
    MissingScope(String),

    #[error("Proof has expired")]
    ProofExpired,

    #[error("Attestation has expired")]
    AttestationExpired,

    #[error("Operator key mismatch")]
    OperatorKeyMismatch,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Domain must not be empty")]
    EmptyDomain,
}

pub type Result<T> = std::result::Result<T, Claw401Error>;
