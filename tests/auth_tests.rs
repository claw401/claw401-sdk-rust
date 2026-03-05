use claw401_core::{
    auth::{
        challenge_signing_bytes, encode_signature, generate_challenge, verify_signature,
        GenerateChallengeOptions, SignedChallenge, VerifySignatureOptions,
    },
    cache::InMemoryNonceCache,
    utils::bytes_to_base64,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn make_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn pubkey_to_base58(signing_key: &SigningKey) -> String {
    bs58::encode(signing_key.verifying_key().to_bytes()).into_string()
}

fn sign_challenge(
    challenge: &claw401_core::auth::Challenge,
    signing_key: &SigningKey,
) -> SignedChallenge {
    let payload = challenge_signing_bytes(challenge).unwrap();
    let signature = signing_key.sign(&payload);
    SignedChallenge {
        challenge: challenge.clone(),
        signature: encode_signature(&signature.to_bytes()),
        public_key: pubkey_to_base58(signing_key),
    }
}

#[test]
fn test_generate_challenge_structure() {
    let ch = generate_challenge(GenerateChallengeOptions {
        domain: "app.test".into(),
        ttl_ms: None,
    })
    .unwrap();
    assert_eq!(ch.nonce.len(), 64);
    assert_eq!(ch.domain, "app.test");
    assert_eq!(ch.version, "x401/1.0");
    assert!(ch.expires_at > ch.issued_at);
}

#[test]
fn test_generate_challenge_normalizes_domain() {
    let ch = generate_challenge(GenerateChallengeOptions {
        domain: "App.Example.COM".into(),
        ttl_ms: None,
    })
    .unwrap();
    assert_eq!(ch.domain, "app.example.com");
}

#[test]
fn test_empty_domain_returns_error() {
    let result = generate_challenge(GenerateChallengeOptions {
        domain: "".into(),
        ttl_ms: None,
    });
    assert!(result.is_err());
}

#[test]
fn test_verify_valid_signature() {
    let signing_key = make_keypair();
    let cache = InMemoryNonceCache::new(None);

    let challenge = generate_challenge(GenerateChallengeOptions {
        domain: "app.test".into(),
        ttl_ms: None,
    })
    .unwrap();
    let signed = sign_challenge(&challenge, &signing_key);

    let result = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "app.test",
        nonce_cache: &cache,
        clock_skew_ms: None,
    });
    assert!(result.is_ok());
    assert_eq!(result.unwrap().public_key, pubkey_to_base58(&signing_key));
}

#[test]
fn test_reject_expired_challenge() {
    let signing_key = make_keypair();
    let cache = InMemoryNonceCache::new(None);

    let mut challenge = generate_challenge(GenerateChallengeOptions {
        domain: "app.test".into(),
        ttl_ms: None,
    })
    .unwrap();

    // Manually expire the challenge
    challenge.expires_at = challenge.issued_at;

    let signed = sign_challenge(&challenge, &signing_key);

    let result = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "app.test",
        nonce_cache: &cache,
        clock_skew_ms: Some(0),
    });

    assert!(matches!(result, Err(claw401_core::Claw401Error::ChallengeExpired)));
}

#[test]
fn test_reject_domain_mismatch() {
    let signing_key = make_keypair();
    let cache = InMemoryNonceCache::new(None);

    let challenge = generate_challenge(GenerateChallengeOptions {
        domain: "correct.com".into(),
        ttl_ms: None,
    })
    .unwrap();
    let signed = sign_challenge(&challenge, &signing_key);

    let result = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "wrong.com",
        nonce_cache: &cache,
        clock_skew_ms: None,
    });

    assert!(matches!(result, Err(claw401_core::Claw401Error::InvalidDomain { .. })));
}

#[test]
fn test_reject_replayed_nonce() {
    let signing_key = make_keypair();
    let cache = InMemoryNonceCache::new(None);

    let challenge = generate_challenge(GenerateChallengeOptions {
        domain: "app.test".into(),
        ttl_ms: None,
    })
    .unwrap();
    let signed = sign_challenge(&challenge, &signing_key);

    let first = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "app.test",
        nonce_cache: &cache,
        clock_skew_ms: None,
    });
    assert!(first.is_ok());

    let second = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "app.test",
        nonce_cache: &cache,
        clock_skew_ms: None,
    });
    assert!(matches!(second, Err(claw401_core::Claw401Error::NonceReplayed)));
}

#[test]
fn test_reject_invalid_signature() {
    let signing_key = make_keypair();
    let other_key = make_keypair();
    let cache = InMemoryNonceCache::new(None);

    let challenge = generate_challenge(GenerateChallengeOptions {
        domain: "app.test".into(),
        ttl_ms: None,
    })
    .unwrap();

    // Sign with other_key but claim signing_key's public key
    let payload = challenge_signing_bytes(&challenge).unwrap();
    let wrong_sig = other_key.sign(&payload);
    let signed = SignedChallenge {
        challenge,
        signature: encode_signature(&wrong_sig.to_bytes()),
        public_key: pubkey_to_base58(&signing_key),
    };

    let result = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: "app.test",
        nonce_cache: &cache,
        clock_skew_ms: None,
    });

    assert!(matches!(result, Err(claw401_core::Claw401Error::InvalidSignature)));
}
