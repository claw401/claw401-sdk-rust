# claw401-core

Core verification engine for the Claw401 X401 wallet authentication protocol.

## Add to your project

```toml
[dependencies]
claw401-core = "0.1"
```

## Usage

```rust
use claw401_core::{
    auth::{generate_challenge, verify_signature, GenerateChallengeOptions, VerifySignatureOptions},
    session::{create_session, CreateSessionOptions},
    cache::InMemoryNonceCache,
};

let cache = InMemoryNonceCache::new(None);

let challenge = generate_challenge(GenerateChallengeOptions {
    domain: "app.example.com".into(),
    ttl_ms: None,
})?;

// After client sends back signed challenge...
let result = verify_signature(VerifySignatureOptions {
    signed_challenge: &signed_challenge,
    expected_domain: "app.example.com",
    nonce_cache: &cache,
    clock_skew_ms: None,
})?;

let session = create_session(CreateSessionOptions {
    public_key: result.public_key,
    domain: "app.example.com".into(),
    nonce: challenge.nonce,
    scopes: vec!["read".into(), "write".into()],
    ttl_ms: None,
});
```

## Features

- `wasm` — enables WASM bindings via `wasm-bindgen`

## License

Apache-2.0
