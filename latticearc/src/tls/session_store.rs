#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Session management for TLS session resumption
//!
//! This module provides session storage configuration for faster TLS reconnections.
//!
//! ## Performance Benefits
//!
//! TLS session resumption significantly reduces handshake latency:
//! - Full handshake: ~2 round trips + cryptographic operations
//! - Resumed session: ~1 round trip, minimal crypto
//!
//! For hybrid PQ-TLS, the savings are even more significant due to
//! the larger key sizes involved in ML-KEM key exchange.
//!
//! ## Session Storage Options
//!
//! - **In-memory cache**: Fast, volatile (lost on restart)
//! - **Persistent storage**: Reserved for future use when rustls supports serialization
//!
//! ## Security Considerations
//!
//! - Session tickets are encrypted by the server
//! - Sessions automatically expire based on server policy
//! - In-memory storage is cleared on process exit

use rustls::client::ClientSessionStore;
use std::sync::Arc;

/// Enhanced session store with configurable capacity
///
/// Wraps rustls's in-memory session cache with additional configuration options.
#[derive(Debug)]
pub struct ConfigurableSessionStore {
    /// Maximum number of sessions to cache
    max_sessions: usize,
    /// The underlying session store
    inner: Arc<dyn ClientSessionStore>,
}

impl ConfigurableSessionStore {
    /// Create a new configurable session store
    ///
    /// # Arguments
    /// * `max_sessions` - Maximum number of sessions to cache
    ///
    /// # Returns
    /// A session store with the specified capacity
    ///
    /// # Example
    /// ```
    /// use latticearc::tls::session_store::ConfigurableSessionStore;
    ///
    /// let store = ConfigurableSessionStore::new(100);
    /// ```
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            inner: Arc::new(rustls::client::ClientSessionMemoryCache::new(max_sessions)),
        }
    }

    /// Get the maximum number of sessions this store can hold
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_sessions
    }

    /// Get the underlying session store for use with rustls
    #[must_use]
    pub fn as_store(&self) -> Arc<dyn ClientSessionStore> {
        self.inner.clone()
    }
}

/// Persistent session store (placeholder for future rustls serialization support)
///
/// Currently uses in-memory storage. File persistence will be enabled when
/// rustls provides public serialization APIs for session values.
#[derive(Debug)]
pub struct PersistentSessionStore {
    /// Path for future file-based persistence
    path: std::path::PathBuf,
    /// Maximum number of sessions
    max_sessions: usize,
    /// The underlying in-memory store
    inner: Arc<dyn ClientSessionStore>,
}

impl PersistentSessionStore {
    /// Create a new persistent session store
    ///
    /// Note: Currently uses in-memory storage. The path parameter is reserved
    /// for future file-based persistence when rustls supports serialization.
    ///
    /// # Arguments
    /// * `path` - Path for future file-based storage (currently unused)
    /// * `max_sessions` - Maximum number of sessions to cache
    ///
    /// # Returns
    /// A session store with the specified capacity
    ///
    /// # Example
    /// ```
    /// use latticearc::tls::session_store::PersistentSessionStore;
    ///
    /// let store = PersistentSessionStore::new("/var/cache/tls_sessions.bin", 1000);
    /// ```
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>, max_sessions: usize) -> Self {
        Self {
            path: path.into(),
            max_sessions,
            inner: Arc::new(rustls::client::ClientSessionMemoryCache::new(max_sessions)),
        }
    }

    /// Get the maximum number of sessions this store can hold
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_sessions
    }

    /// Get the configured persistence path
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Get the underlying session store for use with rustls
    #[must_use]
    pub fn as_store(&self) -> Arc<dyn ClientSessionStore> {
        self.inner.clone()
    }

    /// Check if persistence is currently supported
    ///
    /// Returns false until rustls provides public serialization APIs.
    #[must_use]
    pub const fn is_persistence_enabled(&self) -> bool {
        // Rustls does not expose session serialization APIs
        false
    }
}

/// Create a session store based on configuration
///
/// Returns either a persistent store (when supported) or an in-memory store.
///
/// # Arguments
/// * `persistence` - Optional persistence configuration
///
/// # Returns
/// An Arc-wrapped session store suitable for use with rustls
///
/// # Example
/// ```
/// use latticearc::tls::session_store::create_session_store;
/// use latticearc::tls::SessionPersistenceConfig;
///
/// // In-memory store (default)
/// let store = create_session_store(None);
///
/// // Configured store (in-memory for now, path reserved for future use)
/// let config = SessionPersistenceConfig::new(std::env::temp_dir().join("sessions.bin"), 500);
/// let store = create_session_store(Some(&config));
/// ```
#[must_use]
pub fn create_session_store(
    persistence: Option<&crate::tls::SessionPersistenceConfig>,
) -> Arc<dyn ClientSessionStore> {
    if let Some(config) = persistence {
        Arc::new(rustls::client::ClientSessionMemoryCache::new(config.max_sessions))
    } else {
        // Default: 32 sessions in memory
        Arc::new(rustls::client::ClientSessionMemoryCache::new(32))
    }
}

/// Create a session resumption configuration for rustls client
///
/// # Arguments
/// * `persistence` - Optional persistence configuration
///
/// # Returns
/// A rustls Resumption configuration
#[must_use]
pub fn create_resumption_config(
    persistence: Option<&crate::tls::SessionPersistenceConfig>,
) -> rustls::client::Resumption {
    let store = create_session_store(persistence);
    rustls::client::Resumption::store(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configurable_store_creation() {
        let store = ConfigurableSessionStore::new(100);
        assert_eq!(store.capacity(), 100);
    }

    #[test]
    fn test_persistent_store_creation() {
        let store = PersistentSessionStore::new(std::env::temp_dir().join("test.bin"), 50);
        assert_eq!(store.capacity(), 50);
        assert!(!store.is_persistence_enabled());
    }

    #[test]
    fn test_create_session_store_none() {
        let store = create_session_store(None);
        assert_eq!(Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_create_session_store_with_config() {
        let config =
            crate::tls::SessionPersistenceConfig::new(std::env::temp_dir().join("test.bin"), 200);
        let store = create_session_store(Some(&config));
        assert_eq!(Arc::strong_count(&store), 1);
    }

    #[test]
    fn test_create_resumption_config() {
        let resumption = create_resumption_config(None);
        // Just verify it creates without error
        let _ = resumption;
    }
}
