/*!
# claw401-core

Core verification engine for the Claw401 X401 wallet authentication protocol.

## Modules

- [`auth`]: Challenge generation, signature verification
- [`session`]: Session creation and verification
- [`proof`]: Signed capability and identity proofs
- [`agent`]: Agent attestation (create and verify)
- [`cache`]: In-memory nonce cache
- [`utils`]: Encoding, hashing, nonce generation
- [`error`]: Error types

## Quick Start

```rust,no_run
use claw401_core::{
    auth::{generate_challenge, verify_signature, GenerateChallengeOptions, VerifySignatureOptions},
    session::{create_session, CreateSessionOptions},
    cache::InMemoryNonceCache,
};

let cache = InMemoryNonceCache::new(None);

let challenge = generate_challenge(GenerateChallengeOptions {
    domain: "app.example.com".into(),
    ttl_ms: None,
}).unwrap();

// After receiving signed challenge from client...
// let result = verify_signature(VerifySignatureOptions {
//     signed_challenge: &signed,
//     expected_domain: "app.example.com",
//     nonce_cache: &cache,
//     clock_skew_ms: None,
// }).unwrap();
```
*/

pub mod agent;
pub mod auth;
pub mod cache;
pub mod error;
pub mod proof;
pub mod session;
pub mod utils;

pub use error::{Claw401Error, Result};
