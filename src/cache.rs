use std::collections::HashMap;
use std::sync::Mutex;

use crate::auth::NonceCache;
use crate::utils::now_ms;

/// In-memory nonce cache with TTL eviction.
///
/// Thread-safe via a Mutex. Not appropriate for distributed deployments.
/// For production use, implement [`NonceCache`] with a shared store.
pub struct InMemoryNonceCache {
    inner: Mutex<NonceCacheInner>,
}

struct NonceCacheInner {
    map: HashMap<String, u64>, // nonce -> consumed_at_ms
    ttl_ms: u64,
}

impl InMemoryNonceCache {
    /// Creates a new cache with the given TTL.
    ///
    /// Nonces older than `ttl_ms` are eligible for eviction.
    /// Default: 10 minutes.
    pub fn new(ttl_ms: Option<u64>) -> Self {
        Self {
            inner: Mutex::new(NonceCacheInner {
                map: HashMap::new(),
                ttl_ms: ttl_ms.unwrap_or(10 * 60 * 1000),
            }),
        }
    }
}

impl NonceCache for InMemoryNonceCache {
    fn has(&self, nonce: &str) -> bool {
        self.inner.lock().expect("nonce cache lock poisoned").map.contains_key(nonce)
    }

    fn set(&self, nonce: &str) {
        let mut inner = self.inner.lock().expect("nonce cache lock poisoned");
        let cutoff = now_ms().saturating_sub(inner.ttl_ms);
        inner.map.retain(|_, ts| *ts > cutoff);
        inner.map.insert(nonce.to_string(), now_ms());
    }
}
