//! # LatticeArc Logging Utilities
//!
//! Security-conscious logging utilities for LatticeArc Core.
//! Provides structured logging with tracing while ensuring no sensitive
//! cryptographic material is logged.
//!
//! ## Security Features
//!
//! - **No Sensitive Data**: Automatic sanitization of cryptographic keys and secrets
//! - **Structured Logging**: Consistent log format across all components
//! - **Performance Conscious**: Minimal overhead in cryptographic operations
//! - **Configurable**: Environment-based log levels and output formats
//!
//! ## Usage
//!
//! ```rust
//! use arc_core::logging::{init_tracing, sanitize_data};
//!
//! // Initialize logging
//! init_tracing().expect("Failed to init tracing");
//!
//! // Log with automatic sanitization
//! let key_data = b"sensitive_key_material";
//! tracing::info!("Key operation completed: {}", sanitize_data(key_data));
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

// ============================================================================
// Key Lifecycle Event Types for Audit Logging
// ============================================================================

/// Key type classification for lifecycle events.
///
/// Distinguishes between different key categories for proper audit logging
/// and compliance reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Symmetric keys (e.g., AES-256)
    Symmetric,
    /// Asymmetric public keys (can be shared)
    AsymmetricPublic,
    /// Asymmetric private keys (must be protected)
    AsymmetricPrivate,
    /// Complete keypair (public + private)
    KeyPair,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Symmetric => write!(f, "Symmetric"),
            KeyType::AsymmetricPublic => write!(f, "AsymmetricPublic"),
            KeyType::AsymmetricPrivate => write!(f, "AsymmetricPrivate"),
            KeyType::KeyPair => write!(f, "KeyPair"),
        }
    }
}

/// Key purpose classification per NIST SP 800-57.
///
/// Defines the intended use of a cryptographic key for audit and
/// compliance tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Key used for encryption operations
    Encryption,
    /// Key used for digital signature creation
    Signing,
    /// Key used for key exchange protocols (e.g., KEM, DH)
    KeyExchange,
    /// Key used for authentication operations
    Authentication,
    /// Key used for wrapping other keys
    KeyWrapping,
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyPurpose::Encryption => write!(f, "Encryption"),
            KeyPurpose::Signing => write!(f, "Signing"),
            KeyPurpose::KeyExchange => write!(f, "KeyExchange"),
            KeyPurpose::Authentication => write!(f, "Authentication"),
            KeyPurpose::KeyWrapping => write!(f, "KeyWrapping"),
        }
    }
}

/// Reason for key rotation.
///
/// Tracks why a key was rotated for compliance and audit purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Scheduled rotation per policy
    Scheduled,
    /// Key was potentially compromised
    Compromised,
    /// Policy or compliance requirements changed
    PolicyChange,
    /// Key reached its cryptoperiod end
    Expiration,
    /// Manual rotation by administrator
    Manual,
}

impl fmt::Display for RotationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RotationReason::Scheduled => write!(f, "Scheduled"),
            RotationReason::Compromised => write!(f, "Compromised"),
            RotationReason::PolicyChange => write!(f, "PolicyChange"),
            RotationReason::Expiration => write!(f, "Expiration"),
            RotationReason::Manual => write!(f, "Manual"),
        }
    }
}

/// Method used for key destruction.
///
/// Documents how key material was destroyed for compliance verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructionMethod {
    /// Memory zeroization (software)
    Zeroization,
    /// Cryptographic erasure (key deletion from encrypted storage)
    CryptoErase,
    /// Manual destruction by administrator
    Manual,
}

impl fmt::Display for DestructionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DestructionMethod::Zeroization => write!(f, "Zeroization"),
            DestructionMethod::CryptoErase => write!(f, "CryptoErase"),
            DestructionMethod::Manual => write!(f, "Manual"),
        }
    }
}

/// Key lifecycle events for comprehensive audit logging.
///
/// These events track all significant operations on cryptographic keys
/// throughout their lifecycle, from generation to destruction.
///
/// # Audit Trail Compliance
///
/// This enum supports compliance with:
/// - NIST SP 800-57 (Key Management)
/// - FIPS 140-3 (Cryptographic Module Security)
/// - SOC 2 Type II (Security Controls)
/// - PCI DSS (Payment Card Industry)
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{KeyLifecycleEvent, KeyType, KeyPurpose};
///
/// let event = KeyLifecycleEvent::Generated {
///     key_id: "key-001".to_string(),
///     algorithm: "ML-KEM-768".to_string(),
///     key_type: KeyType::KeyPair,
///     purpose: KeyPurpose::KeyExchange,
/// };
///
/// // Log the event using the provided macros
/// // log_key_generated!("key-001", "ML-KEM-768", KeyType::KeyPair, KeyPurpose::KeyExchange);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyLifecycleEvent {
    /// Key was generated.
    ///
    /// Logged when new cryptographic key material is created.
    Generated {
        /// Unique identifier for the key
        key_id: String,
        /// Algorithm used (e.g., "ML-KEM-768", "AES-256-GCM")
        algorithm: String,
        /// Type of key generated
        key_type: KeyType,
        /// Intended purpose of the key
        purpose: KeyPurpose,
    },

    /// Key was rotated (old key deprecated, new key active).
    ///
    /// Logged when a key is replaced with a new key while
    /// maintaining service continuity.
    Rotated {
        /// ID of the key being replaced
        old_key_id: String,
        /// ID of the replacement key
        new_key_id: String,
        /// Algorithm (should match for proper rotation)
        algorithm: String,
        /// Reason for the rotation
        reason: RotationReason,
    },

    /// Key was marked as deprecated.
    ///
    /// Logged when a key is scheduled for retirement but
    /// may still be used for decryption of existing data.
    Deprecated {
        /// ID of the deprecated key
        key_id: String,
        /// When the deprecation takes effect
        deprecation_date: DateTime<Utc>,
        /// Human-readable reason for deprecation
        reason: String,
    },

    /// Key was suspended (temporarily disabled).
    ///
    /// Logged when a key is temporarily disabled, typically
    /// due to a suspected security incident.
    Suspended {
        /// ID of the suspended key
        key_id: String,
        /// Reason for suspension
        reason: String,
    },

    /// Key was destroyed/zeroized.
    ///
    /// Logged when key material is permanently destroyed.
    /// This is a critical audit event.
    Destroyed {
        /// ID of the destroyed key
        key_id: String,
        /// Method used for destruction
        method: DestructionMethod,
    },

    /// Key was accessed for an operation.
    ///
    /// Logged when a key is used for a cryptographic operation.
    /// This may be logged at DEBUG level to avoid log volume issues.
    Accessed {
        /// ID of the accessed key
        key_id: String,
        /// Type of operation (e.g., "encrypt", "sign", "decrypt")
        operation: String,
        /// Optional accessor identity (user, service, etc.)
        accessor: Option<String>,
    },

    /// Key was exported (if allowed by policy).
    ///
    /// Logged when a key is exported from the system.
    /// This is a security-sensitive event.
    Exported {
        /// ID of the exported key
        key_id: String,
        /// Export format (e.g., "PEM", "PKCS#12", "raw")
        format: String,
        /// Destination identifier
        destination: String,
    },

    /// Key was imported into the system.
    ///
    /// Logged when external key material is imported.
    Imported {
        /// ID assigned to the imported key
        key_id: String,
        /// Algorithm of the imported key
        algorithm: String,
        /// Source of the key material
        source: String,
    },
}

impl KeyLifecycleEvent {
    /// Get the key ID associated with this event.
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            KeyLifecycleEvent::Generated { key_id, .. }
            | KeyLifecycleEvent::Deprecated { key_id, .. }
            | KeyLifecycleEvent::Suspended { key_id, .. }
            | KeyLifecycleEvent::Destroyed { key_id, .. }
            | KeyLifecycleEvent::Accessed { key_id, .. }
            | KeyLifecycleEvent::Exported { key_id, .. }
            | KeyLifecycleEvent::Imported { key_id, .. } => key_id,
            KeyLifecycleEvent::Rotated { new_key_id, .. } => new_key_id,
        }
    }

    /// Get the event type as a string for logging.
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        match self {
            KeyLifecycleEvent::Generated { .. } => "generated",
            KeyLifecycleEvent::Rotated { .. } => "rotated",
            KeyLifecycleEvent::Deprecated { .. } => "deprecated",
            KeyLifecycleEvent::Suspended { .. } => "suspended",
            KeyLifecycleEvent::Destroyed { .. } => "destroyed",
            KeyLifecycleEvent::Accessed { .. } => "accessed",
            KeyLifecycleEvent::Exported { .. } => "exported",
            KeyLifecycleEvent::Imported { .. } => "imported",
        }
    }

    /// Create a new Generated event.
    #[must_use]
    pub fn generated(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        key_type: KeyType,
        purpose: KeyPurpose,
    ) -> Self {
        Self::Generated { key_id: key_id.into(), algorithm: algorithm.into(), key_type, purpose }
    }

    /// Create a new Rotated event.
    #[must_use]
    pub fn rotated(
        old_key_id: impl Into<String>,
        new_key_id: impl Into<String>,
        algorithm: impl Into<String>,
        reason: RotationReason,
    ) -> Self {
        Self::Rotated {
            old_key_id: old_key_id.into(),
            new_key_id: new_key_id.into(),
            algorithm: algorithm.into(),
            reason,
        }
    }

    /// Create a new Destroyed event.
    #[must_use]
    pub fn destroyed(key_id: impl Into<String>, method: DestructionMethod) -> Self {
        Self::Destroyed { key_id: key_id.into(), method }
    }

    /// Create a new Accessed event.
    #[must_use]
    pub fn accessed(
        key_id: impl Into<String>,
        operation: impl Into<String>,
        accessor: Option<String>,
    ) -> Self {
        Self::Accessed { key_id: key_id.into(), operation: operation.into(), accessor }
    }

    /// Create a new Imported event.
    #[must_use]
    pub fn imported(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self::Imported { key_id: key_id.into(), algorithm: algorithm.into(), source: source.into() }
    }

    /// Create a new Exported event.
    #[must_use]
    pub fn exported(
        key_id: impl Into<String>,
        format: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        Self::Exported {
            key_id: key_id.into(),
            format: format.into(),
            destination: destination.into(),
        }
    }

    /// Create a new Deprecated event.
    #[must_use]
    pub fn deprecated(
        key_id: impl Into<String>,
        deprecation_date: DateTime<Utc>,
        reason: impl Into<String>,
    ) -> Self {
        Self::Deprecated { key_id: key_id.into(), deprecation_date, reason: reason.into() }
    }

    /// Create a new Suspended event.
    #[must_use]
    pub fn suspended(key_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Suspended { key_id: key_id.into(), reason: reason.into() }
    }
}

// ============================================================================
// Correlation ID Infrastructure
// ============================================================================
//
// Thread-local correlation ID storage for async context propagation.
// The correlation ID is stored per-thread and can be propagated across async
// task boundaries using the `CorrelationGuard` RAII guard or the
// `with_correlation_id` function.
// ============================================================================

thread_local! {
    static CORRELATION_ID: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Global counter for generating lightweight correlation IDs.
///
/// This counter is used by [`generate_lightweight_correlation_id`] when
/// UUID generation overhead is not acceptable.
static CORRELATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a new correlation ID using UUID v4.
///
/// This function generates a cryptographically random UUID v4 string
/// suitable for distributed tracing and audit logging.
///
/// # Returns
///
/// A UUID v4 string in the format `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::generate_correlation_id;
///
/// let id = generate_correlation_id();
/// assert_eq!(id.len(), 36); // UUID format with hyphens
/// ```
#[must_use]
pub fn generate_correlation_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generate a lightweight correlation ID using an atomic counter.
///
/// This function generates a correlation ID based on an atomic counter,
/// which is faster than UUID generation but provides less uniqueness
/// across distributed systems.
///
/// # Returns
///
/// A string in the format `corr-{counter:016x}`.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::generate_lightweight_correlation_id;
///
/// let id1 = generate_lightweight_correlation_id();
/// let id2 = generate_lightweight_correlation_id();
/// assert_ne!(id1, id2);
/// assert!(id1.starts_with("corr-"));
/// ```
#[must_use]
pub fn generate_lightweight_correlation_id() -> String {
    let counter = CORRELATION_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("corr-{counter:016x}")
}

/// Set the correlation ID for the current thread/task.
///
/// This function stores a correlation ID in thread-local storage,
/// making it available to all logging calls on the current thread.
///
/// # Arguments
///
/// * `id` - The correlation ID to set.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{set_correlation_id, current_correlation_id};
///
/// set_correlation_id("request-12345".to_string());
/// assert_eq!(current_correlation_id(), Some("request-12345".to_string()));
/// ```
pub fn set_correlation_id(id: String) {
    CORRELATION_ID.with(|cell| {
        *cell.borrow_mut() = Some(id);
    });
}

/// Get the current correlation ID, if set.
///
/// This function retrieves the correlation ID from thread-local storage.
///
/// # Returns
///
/// `Some(id)` if a correlation ID is set, `None` otherwise.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{set_correlation_id, current_correlation_id, clear_correlation_id};
///
/// assert_eq!(current_correlation_id(), None);
/// set_correlation_id("test-id".to_string());
/// assert_eq!(current_correlation_id(), Some("test-id".to_string()));
/// clear_correlation_id();
/// assert_eq!(current_correlation_id(), None);
/// ```
#[must_use]
pub fn current_correlation_id() -> Option<String> {
    CORRELATION_ID.with(|cell| cell.borrow().clone())
}

/// Clear the correlation ID for the current thread.
///
/// This function removes the correlation ID from thread-local storage.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{set_correlation_id, current_correlation_id, clear_correlation_id};
///
/// set_correlation_id("test-id".to_string());
/// clear_correlation_id();
/// assert_eq!(current_correlation_id(), None);
/// ```
pub fn clear_correlation_id() {
    CORRELATION_ID.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

/// Execute a closure with a specific correlation ID.
///
/// This function sets the correlation ID for the duration of the closure
/// execution, then restores the previous correlation ID (if any) afterward.
///
/// # Arguments
///
/// * `id` - The correlation ID to use during the closure execution.
/// * `f` - The closure to execute.
///
/// # Returns
///
/// The return value of the closure.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{with_correlation_id, current_correlation_id};
///
/// let result = with_correlation_id("request-123".to_string(), || {
///     assert_eq!(current_correlation_id(), Some("request-123".to_string()));
///     42
/// });
/// assert_eq!(result, 42);
/// assert_eq!(current_correlation_id(), None);
/// ```
pub fn with_correlation_id<F, R>(id: String, f: F) -> R
where
    F: FnOnce() -> R,
{
    let old = current_correlation_id();
    set_correlation_id(id);
    let result = f();
    match old {
        Some(prev_id) => set_correlation_id(prev_id),
        None => clear_correlation_id(),
    }
    result
}

/// RAII guard for correlation ID scope management.
///
/// This guard automatically sets a correlation ID when created and restores
/// the previous correlation ID (if any) when dropped. This is useful for
/// propagating correlation IDs across async task boundaries.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::{CorrelationGuard, current_correlation_id};
///
/// {
///     let guard = CorrelationGuard::new();
///     let id = guard.id();
///     assert!(id.is_some());
///     // Correlation ID is automatically set
/// }
/// // Correlation ID is restored to previous value (None in this case)
/// ```
pub struct CorrelationGuard {
    previous: Option<String>,
}

impl CorrelationGuard {
    /// Create a new correlation scope with an automatically generated UUID v4.
    ///
    /// # Returns
    ///
    /// A new `CorrelationGuard` that sets and manages the correlation ID.
    #[must_use]
    pub fn new() -> Self {
        let previous = current_correlation_id();
        set_correlation_id(generate_correlation_id());
        Self { previous }
    }

    /// Create a new correlation scope with a specific ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The correlation ID to use.
    ///
    /// # Returns
    ///
    /// A new `CorrelationGuard` that sets and manages the correlation ID.
    #[must_use]
    pub fn with_id(id: String) -> Self {
        let previous = current_correlation_id();
        set_correlation_id(id);
        Self { previous }
    }

    /// Create a new correlation scope with a lightweight counter-based ID.
    ///
    /// # Returns
    ///
    /// A new `CorrelationGuard` with a lightweight correlation ID.
    #[must_use]
    pub fn lightweight() -> Self {
        let previous = current_correlation_id();
        set_correlation_id(generate_lightweight_correlation_id());
        Self { previous }
    }

    /// Get the current correlation ID.
    ///
    /// # Returns
    ///
    /// The current correlation ID, if set.
    #[must_use]
    pub fn id(&self) -> Option<String> {
        current_correlation_id()
    }

    /// Get the previous correlation ID that will be restored on drop.
    ///
    /// # Returns
    ///
    /// The previous correlation ID, if any.
    #[must_use]
    pub fn previous_id(&self) -> Option<&String> {
        self.previous.as_ref()
    }
}

impl Drop for CorrelationGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(id) => set_correlation_id(id.clone()),
            None => clear_correlation_id(),
        }
    }
}

impl Default for CorrelationGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Metadata Sanitization Constants and Functions
// ============================================================================

/// Keys that indicate potentially sensitive data.
///
/// Any metadata key containing these patterns (case-insensitive) will be redacted
/// to prevent sensitive data leakage in audit logs.
pub const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "key",
    "secret",
    "password",
    "token",
    "credential",
    "private",
    "auth",
    "session",
    "bearer",
    "api_key",
    "apikey",
    "passphrase",
];

/// Maximum length for metadata values before truncation.
///
/// Values longer than this will be truncated with a length indicator.
pub const MAX_METADATA_VALUE_LENGTH: usize = 1000;

/// Check if a metadata key might contain sensitive data.
///
/// Performs a case-insensitive check against known sensitive key patterns.
///
/// # Arguments
///
/// * `key` - The metadata key to check
///
/// # Returns
///
/// `true` if the key matches any sensitive pattern, `false` otherwise.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::is_potentially_sensitive;
///
/// assert!(is_potentially_sensitive("api_key"));
/// assert!(is_potentially_sensitive("user_password"));
/// assert!(is_potentially_sensitive("AuthToken"));
/// assert!(!is_potentially_sensitive("username"));
/// assert!(!is_potentially_sensitive("operation_id"));
/// ```
#[must_use]
pub fn is_potentially_sensitive(key: &str) -> bool {
    let lower = key.to_lowercase();
    SENSITIVE_KEY_PATTERNS.iter().any(|pattern| lower.contains(pattern))
}

/// Sanitize a single metadata value based on its key.
///
/// This function applies the following rules:
/// 1. If the key is potentially sensitive, the value is replaced with `[REDACTED]`
/// 2. If the value exceeds `MAX_METADATA_VALUE_LENGTH`, it is truncated
/// 3. Otherwise, the value is returned as-is
///
/// # Arguments
///
/// * `key` - The metadata key (used to determine if the value is sensitive)
/// * `value` - The metadata value to sanitize
///
/// # Returns
///
/// A sanitized string safe for logging.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::sanitize_value;
///
/// // Sensitive keys are redacted
/// assert_eq!(sanitize_value("api_key", "sk-12345"), "[REDACTED]");
///
/// // Normal keys pass through
/// assert_eq!(sanitize_value("operation", "encrypt"), "encrypt");
///
/// // Long values are truncated
/// let long_value = "x".repeat(2000);
/// assert!(sanitize_value("data", &long_value).contains("chars truncated"));
/// ```
#[must_use]
pub fn sanitize_value(key: &str, value: &str) -> String {
    if is_potentially_sensitive(key) {
        "[REDACTED]".to_string()
    } else if value.len() > MAX_METADATA_VALUE_LENGTH {
        format!("[{} chars truncated]", value.len())
    } else {
        value.to_string()
    }
}

/// Compute the first 16 hex characters of a SHA-256 hash.
///
/// This provides a fingerprint for data correlation without revealing content.
/// Uses the first 8 bytes of the SHA-256 hash, producing 16 hex characters.
fn sha256_first_16_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    // SHA-256 always produces 32 bytes, so .get(..8) will always succeed.
    // Using .get() for safe array access per project lint rules.
    result.get(..8).map_or_else(|| hex::encode(result), hex::encode)
}

/// Sanitize byte data for logging.
///
/// This function ensures raw bytes (which could be cryptographic keys or other
/// sensitive material) are never logged directly. Instead, it produces a safe
/// representation showing:
/// - For data <= 32 bytes: just the length
/// - For data > 32 bytes: length plus a fingerprint hash for correlation
///
/// # Arguments
///
/// * `data` - The byte data to sanitize
///
/// # Returns
///
/// A safe string representation of the data.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::sanitize_bytes;
///
/// // Small data shows only length
/// assert_eq!(sanitize_bytes(&[1, 2, 3]), "[3 bytes]");
///
/// // Larger data shows length and fingerprint
/// let large = vec![0u8; 100];
/// let result = sanitize_bytes(&large);
/// assert!(result.contains("100 bytes"));
/// assert!(result.contains("fingerprint:"));
/// ```
#[must_use]
pub fn sanitize_bytes(data: &[u8]) -> String {
    if data.len() <= 32 {
        format!("[{} bytes]", data.len())
    } else {
        // Show length and truncated hash for correlation
        let fingerprint = sha256_first_16_hex(data);
        format!("[{} bytes, fingerprint: {}]", data.len(), fingerprint)
    }
}

/// Sanitize an entire metadata map.
///
/// Applies `sanitize_value` to each key-value pair in the metadata map,
/// ensuring all sensitive values are redacted and long values are truncated.
///
/// # Arguments
///
/// * `metadata` - The metadata map to sanitize
///
/// # Returns
///
/// A new map with all values sanitized.
///
/// # Example
///
/// ```rust
/// use std::collections::HashMap;
/// use arc_core::logging::sanitize_metadata;
///
/// let mut metadata = HashMap::new();
/// metadata.insert("operation".to_string(), "encrypt".to_string());
/// metadata.insert("api_key".to_string(), "secret-123".to_string());
///
/// let sanitized = sanitize_metadata(&metadata);
/// assert_eq!(sanitized.get("operation"), Some(&"encrypt".to_string()));
/// assert_eq!(sanitized.get("api_key"), Some(&"[REDACTED]".to_string()));
/// ```
#[must_use]
pub fn sanitize_metadata(metadata: &HashMap<String, String>) -> HashMap<String, String> {
    metadata.iter().map(|(k, v)| (k.clone(), sanitize_value(k, v))).collect()
}

/// Initialize tracing with security-conscious defaults.
///
/// Sets up structured logging with:
/// - Environment-based filtering (RUST_LOG)
/// - JSON output for production
/// - Sensitive data sanitization
/// - Performance-optimized formatting
///
/// # Errors
///
/// Returns an error if the tracing subscriber cannot be initialized,
/// typically due to a subscriber already being set.
pub fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("latticearc=info"));

    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .compact(),
    );

    subscriber.init();

    info!("LatticeArc logging initialized");
    Ok(())
}

/// Sanitize data to prevent logging of sensitive information
///
/// This function replaces potentially sensitive byte sequences with
/// safe placeholder text. Used automatically in logging macros.
#[must_use]
pub fn sanitize_data(data: &[u8]) -> SanitizedData<'_> {
    SanitizedData(data)
}

/// Wrapper type for sanitized data display
pub struct SanitizedData<'a>(&'a [u8]);

impl<'a> fmt::Display for SanitizedData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For small data, show length only
        if self.0.len() <= 32 {
            write!(f, "[{} bytes]", self.0.len())
        } else {
            // For larger data, show truncated hash-like representation
            let hash = blake2_hash(self.0);
            write!(f, "[{} bytes, hash: {}]", self.0.len(), &hash[..16])
        }
    }
}

/// Compute a simple hash for data identification without revealing content
fn blake2_hash(data: &[u8]) -> String {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Security-conscious logging macros
///
/// These macros automatically sanitize sensitive data and provide
/// consistent logging across the LatticeArc codebase.
/// Log cryptographic operation start
#[macro_export]
macro_rules! log_crypto_start {
    ($operation:expr) => {
        trace!("Starting crypto operation: {}", $operation);
    };
    ($operation:expr, $($field:tt)*) => {
        trace!("Starting crypto operation: {} {}", $operation, format_args!($($field)*));
    };
}

/// Log cryptographic operation completion
#[macro_export]
macro_rules! log_crypto_complete {
    ($operation:expr) => {
        trace!("Completed crypto operation: {}", $operation);
    };
    ($operation:expr, $($field:tt)*) => {
        trace!("Completed crypto operation: {} {}", $operation, format_args!($($field)*));
    };
}

/// Log cryptographic operation error
#[macro_export]
macro_rules! log_crypto_error {
    ($operation:expr, $error:expr) => {
        error!("Crypto operation failed: {} - {}", $operation, $error);
    };
}

/// Log key generation
#[macro_export]
macro_rules! log_key_generation {
    ($algorithm:expr, $key_type:expr) => {
        info!("Generated {} key using {}", $key_type, $algorithm);
    };
}

/// Log encryption operation
#[macro_export]
macro_rules! log_encryption {
    ($algorithm:expr, $data_len:expr) => {
        debug!("Encrypted {} bytes using {}", $data_len, $algorithm);
    };
}

/// Log decryption operation
#[macro_export]
macro_rules! log_decryption {
    ($algorithm:expr, $data_len:expr) => {
        debug!("Decrypted {} bytes using {}", $data_len, $algorithm);
    };
}

/// Log signature operation
#[macro_export]
macro_rules! log_signature {
    ($algorithm:expr) => {
        debug!("Created signature using {}", $algorithm);
    };
}

/// Log verification operation
#[macro_export]
macro_rules! log_verification {
    ($algorithm:expr, $result:expr) => {
        debug!(
            "Verification {} using {}",
            if $result { "succeeded" } else { "failed" },
            $algorithm
        );
    };
}

/// Log security event (always logged, never filtered)
#[macro_export]
macro_rules! log_security_event {
    ($event:expr) => {
        tracing::event!(Level::ERROR, security_event = true, "{}", $event);
    };
    ($event:expr, $($field:tt)*) => {
        tracing::event!(Level::ERROR, security_event = true, "{} {}", $event, format_args!($($field)*));
    };
}

/// Log performance metrics
#[macro_export]
macro_rules! log_performance {
    ($operation:expr, $duration:expr) => {
        debug!("Performance: {} took {:?}", $operation, $duration);
    };
}

// ============================================================================
// Key Lifecycle Audit Logging Macros
// ============================================================================

/// Log a key generation event.
///
/// Logs at INFO level when new cryptographic key material is created.
/// This is an auditable event for compliance tracking.
///
/// # Arguments
///
/// * `$key_id` - Unique identifier for the key
/// * `$algorithm` - Algorithm used (e.g., "ML-KEM-768")
/// * `$key_type` - Type of key (use `KeyType` enum)
/// * `$purpose` - Purpose of key (use `KeyPurpose` enum)
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{log_key_generated, logging::{KeyType, KeyPurpose}};
///
/// log_key_generated!("key-001", "ML-KEM-768", KeyType::KeyPair, KeyPurpose::KeyExchange);
/// ```
#[macro_export]
macro_rules! log_key_generated {
    ($key_id:expr, $algorithm:expr, $key_type:expr, $purpose:expr) => {
        tracing::info!(
            target: "key_lifecycle::generated",
            key_id = %$key_id,
            algorithm = %$algorithm,
            key_type = ?$key_type,
            purpose = ?$purpose,
            "Key generated"
        );
    };
}

/// Log a key rotation event.
///
/// Logs at WARN level (notable event requiring attention) when a key
/// is replaced with a new key. This is a critical audit event.
///
/// # Arguments
///
/// * `$old_key_id` - ID of the key being replaced
/// * `$new_key_id` - ID of the replacement key
/// * `$algorithm` - Algorithm (should match)
/// * `$reason` - Reason for rotation (use `RotationReason` enum)
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{log_key_rotated, logging::RotationReason};
///
/// log_key_rotated!("key-001", "key-002", "ML-KEM-768", RotationReason::Scheduled);
/// ```
#[macro_export]
macro_rules! log_key_rotated {
    ($old_key_id:expr, $new_key_id:expr, $algorithm:expr, $reason:expr) => {
        tracing::warn!(
            target: "key_lifecycle::rotated",
            old_key_id = %$old_key_id,
            new_key_id = %$new_key_id,
            algorithm = %$algorithm,
            reason = ?$reason,
            "Key rotated"
        );
    };
}

/// Log a key destruction event.
///
/// Logs at WARN level (critical audit event) when key material is
/// permanently destroyed. This is required for compliance verification.
///
/// # Arguments
///
/// * `$key_id` - ID of the destroyed key
/// * `$method` - Method used (use `DestructionMethod` enum)
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{log_key_destroyed, logging::DestructionMethod};
///
/// log_key_destroyed!("key-001", DestructionMethod::Zeroization);
/// ```
#[macro_export]
macro_rules! log_key_destroyed {
    ($key_id:expr, $method:expr) => {
        tracing::warn!(
            target: "key_lifecycle::destroyed",
            key_id = %$key_id,
            method = ?$method,
            "Key destroyed"
        );
    };
}

/// Log a key access event.
///
/// Logs at DEBUG level (high volume, may be rate-limited) when a key
/// is used for a cryptographic operation. Useful for access auditing.
///
/// # Arguments
///
/// * `$key_id` - ID of the accessed key
/// * `$operation` - Type of operation (e.g., "encrypt", "sign")
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::log_key_accessed;
///
/// log_key_accessed!("key-001", "encrypt");
/// ```
#[macro_export]
macro_rules! log_key_accessed {
    ($key_id:expr, $operation:expr) => {
        tracing::debug!(
            target: "key_lifecycle::accessed",
            key_id = %$key_id,
            operation = %$operation,
            "Key accessed"
        );
    };
    ($key_id:expr, $operation:expr, $accessor:expr) => {
        tracing::debug!(
            target: "key_lifecycle::accessed",
            key_id = %$key_id,
            operation = %$operation,
            accessor = %$accessor,
            "Key accessed"
        );
    };
}

/// Log a key deprecation event.
///
/// Logs at INFO level when a key is scheduled for retirement.
/// The key may still be used for decryption of existing data.
///
/// # Arguments
///
/// * `$key_id` - ID of the deprecated key
/// * `$reason` - Human-readable reason for deprecation
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::log_key_deprecated;
///
/// log_key_deprecated!("key-001", "Scheduled retirement per policy");
/// ```
#[macro_export]
macro_rules! log_key_deprecated {
    ($key_id:expr, $reason:expr) => {
        tracing::info!(
            target: "key_lifecycle::deprecated",
            key_id = %$key_id,
            reason = %$reason,
            "Key deprecated"
        );
    };
}

/// Log a key suspension event.
///
/// Logs at WARN level when a key is temporarily disabled,
/// typically due to a suspected security incident.
///
/// # Arguments
///
/// * `$key_id` - ID of the suspended key
/// * `$reason` - Reason for suspension
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::log_key_suspended;
///
/// log_key_suspended!("key-001", "Suspected compromise");
/// ```
#[macro_export]
macro_rules! log_key_suspended {
    ($key_id:expr, $reason:expr) => {
        tracing::warn!(
            target: "key_lifecycle::suspended",
            key_id = %$key_id,
            reason = %$reason,
            "Key suspended"
        );
    };
}

/// Log a key export event.
///
/// Logs at WARN level (security-sensitive) when a key is exported.
/// This is a critical audit event requiring special attention.
///
/// # Arguments
///
/// * `$key_id` - ID of the exported key
/// * `$format` - Export format (e.g., "PEM", "PKCS#12")
/// * `$destination` - Destination identifier
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::log_key_exported;
///
/// log_key_exported!("key-001", "PEM", "backup-hsm-01");
/// ```
#[macro_export]
macro_rules! log_key_exported {
    ($key_id:expr, $format:expr, $destination:expr) => {
        tracing::warn!(
            target: "key_lifecycle::exported",
            key_id = %$key_id,
            format = %$format,
            destination = %$destination,
            "Key exported"
        );
    };
}

/// Log a key import event.
///
/// Logs at INFO level when external key material is imported.
/// Important for tracking key provenance.
///
/// # Arguments
///
/// * `$key_id` - ID assigned to the imported key
/// * `$algorithm` - Algorithm of the imported key
/// * `$source` - Source of the key material
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::log_key_imported;
///
/// log_key_imported!("key-001", "ML-KEM-768", "external-hsm-02");
/// ```
#[macro_export]
macro_rules! log_key_imported {
    ($key_id:expr, $algorithm:expr, $source:expr) => {
        tracing::info!(
            target: "key_lifecycle::imported",
            key_id = %$key_id,
            algorithm = %$algorithm,
            source = %$source,
            "Key imported"
        );
    };
}

// ============================================================================
// Correlation-Aware Crypto Logging Macros
// ============================================================================

/// Log a cryptographic operation with automatic correlation ID inclusion.
///
/// This macro automatically includes the current correlation ID (if set)
/// in log events, enabling distributed tracing across async boundaries.
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{log_crypto_operation, logging::{set_correlation_id, CorrelationGuard}};
///
/// // Set a correlation ID
/// let _guard = CorrelationGuard::new();
///
/// // Log includes correlation_id automatically
/// log_crypto_operation!("encrypt", algorithm = "AES-256-GCM", data_size = 1024);
/// ```
#[macro_export]
macro_rules! log_crypto_operation {
    ($op:expr, $($field:tt)*) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::debug!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                $($field)*
            );
        } else {
            tracing::debug!(
                target: "crypto::operation",
                operation = $op,
                $($field)*
            );
        }
    };
    ($op:expr) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::debug!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
            );
        } else {
            tracing::debug!(
                target: "crypto::operation",
                operation = $op,
            );
        }
    };
}

/// Log a cryptographic operation start with correlation ID.
///
/// Similar to [`log_crypto_operation`] but at TRACE level for detailed tracing.
#[macro_export]
macro_rules! log_crypto_operation_start {
    ($op:expr, $($field:tt)*) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::trace!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                phase = "start",
                $($field)*
            );
        } else {
            tracing::trace!(
                target: "crypto::operation",
                operation = $op,
                phase = "start",
                $($field)*
            );
        }
    };
    ($op:expr) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::trace!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                phase = "start",
            );
        } else {
            tracing::trace!(
                target: "crypto::operation",
                operation = $op,
                phase = "start",
            );
        }
    };
}

/// Log a cryptographic operation completion with correlation ID.
///
/// Similar to [`log_crypto_operation`] but at TRACE level for detailed tracing.
#[macro_export]
macro_rules! log_crypto_operation_complete {
    ($op:expr, $($field:tt)*) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::trace!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                phase = "complete",
                $($field)*
            );
        } else {
            tracing::trace!(
                target: "crypto::operation",
                operation = $op,
                phase = "complete",
                $($field)*
            );
        }
    };
    ($op:expr) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::trace!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                phase = "complete",
            );
        } else {
            tracing::trace!(
                target: "crypto::operation",
                operation = $op,
                phase = "complete",
            );
        }
    };
}

/// Log a cryptographic operation error with correlation ID.
///
/// Logs at ERROR level and includes the correlation ID for tracing.
#[macro_export]
macro_rules! log_crypto_operation_error {
    ($op:expr, $error:expr, $($field:tt)*) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::error!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                error = %$error,
                phase = "error",
                $($field)*
            );
        } else {
            tracing::error!(
                target: "crypto::operation",
                operation = $op,
                error = %$error,
                phase = "error",
                $($field)*
            );
        }
    };
    ($op:expr, $error:expr) => {
        if let Some(corr_id) = $crate::logging::current_correlation_id() {
            tracing::error!(
                target: "crypto::operation",
                correlation_id = %corr_id,
                operation = $op,
                error = %$error,
                phase = "error",
            );
        } else {
            tracing::error!(
                target: "crypto::operation",
                operation = $op,
                error = %$error,
                phase = "error",
            );
        }
    };
}

// ============================================================================
// Zero Trust Audit Logging Macros
// ============================================================================

/// Log Zero Trust authentication attempt.
///
/// Logs the initiation of a Zero Trust authentication attempt with session ID.
/// Session ID is logged as hex string for audit traceability.
#[macro_export]
macro_rules! log_zero_trust_auth_attempt {
    ($session_id_hex:expr) => {
        tracing::info!(
            target: "zero_trust::auth",
            session_id = %$session_id_hex,
            "Zero Trust authentication attempt initiated"
        );
    };
}

/// Log Zero Trust authentication success.
///
/// Logs successful authentication with session ID and achieved trust level.
#[macro_export]
macro_rules! log_zero_trust_auth_success {
    ($session_id_hex:expr, $trust_level:expr) => {
        tracing::info!(
            target: "zero_trust::auth",
            session_id = %$session_id_hex,
            trust_level = ?$trust_level,
            "Zero Trust authentication succeeded"
        );
    };
}

/// Log Zero Trust authentication failure.
///
/// Logs failed authentication attempts with session ID and reason.
/// Reason should never contain sensitive data.
#[macro_export]
macro_rules! log_zero_trust_auth_failure {
    ($session_id_hex:expr, $reason:expr) => {
        tracing::error!(
            target: "zero_trust::auth",
            session_id = %$session_id_hex,
            reason = %$reason,
            "Zero Trust authentication failed"
        );
    };
}

/// Log Zero Trust session creation.
///
/// Logs the creation of a new verified session with trust level and expiration.
#[macro_export]
macro_rules! log_zero_trust_session_created {
    ($session_id_hex:expr, $trust_level:expr, $expires_at:expr) => {
        tracing::info!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            trust_level = ?$trust_level,
            expires_at = %$expires_at,
            "Zero Trust session created"
        );
    };
}

/// Log Zero Trust session verification success.
///
/// Logs successful session verification for ongoing trust validation.
#[macro_export]
macro_rules! log_zero_trust_session_verified {
    ($session_id_hex:expr) => {
        tracing::info!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            "Zero Trust session verified"
        );
    };
}

/// Log Zero Trust session verification failure.
///
/// Logs failed session verification with session ID and reason.
#[macro_export]
macro_rules! log_zero_trust_session_verification_failed {
    ($session_id_hex:expr, $reason:expr) => {
        tracing::error!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            reason = %$reason,
            "Zero Trust session verification failed"
        );
    };
}

/// Log Zero Trust session expiration.
///
/// Logs when a session has expired during a validation check.
#[macro_export]
macro_rules! log_zero_trust_session_expired {
    ($session_id_hex:expr) => {
        tracing::warn!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            "Zero Trust session expired"
        );
    };
}

/// Log Zero Trust trust level transition.
///
/// Logs trust level changes (upgrades or downgrades) for audit trail.
#[macro_export]
macro_rules! log_zero_trust_trust_level_changed {
    ($session_id_hex:expr, $from_level:expr, $to_level:expr) => {
        tracing::info!(
            target: "zero_trust::trust",
            session_id = %$session_id_hex,
            from_level = ?$from_level,
            to_level = ?$to_level,
            "Zero Trust trust level changed"
        );
    };
}

/// Log SecurityMode::Unverified usage (warning).
///
/// Logs when an operation is performed in Unverified mode.
/// This is a security-relevant event that should trigger audit review.
#[macro_export]
macro_rules! log_zero_trust_unverified_mode {
    ($operation:expr) => {
        tracing::warn!(
            target: "zero_trust::security",
            operation = %$operation,
            "Operation performed in SecurityMode::Unverified - no session verification"
        );
    };
}

/// Log Zero Trust challenge generation.
///
/// Logs challenge generation for authentication flows.
#[macro_export]
macro_rules! log_zero_trust_challenge_generated {
    ($complexity:expr) => {
        tracing::debug!(
            target: "zero_trust::auth",
            complexity = ?$complexity,
            "Zero Trust challenge generated"
        );
    };
}

/// Log Zero Trust proof verification result.
///
/// Logs the outcome of proof verification attempts.
#[macro_export]
macro_rules! log_zero_trust_proof_verified {
    ($result:expr) => {
        if $result {
            tracing::debug!(
                target: "zero_trust::auth",
                "Zero Trust proof verification succeeded"
            );
        } else {
            tracing::warn!(
                target: "zero_trust::auth",
                "Zero Trust proof verification failed"
            );
        }
    };
}

/// Log Zero Trust access control decision.
///
/// Logs access control decisions for audit trail compliance.
#[macro_export]
macro_rules! log_zero_trust_access_decision {
    ($session_id_hex:expr, $allowed:expr, $reason:expr) => {
        if $allowed {
            tracing::info!(
                target: "zero_trust::access",
                session_id = %$session_id_hex,
                allowed = $allowed,
                reason = %$reason,
                "Zero Trust access granted"
            );
        } else {
            tracing::warn!(
                target: "zero_trust::access",
                session_id = %$session_id_hex,
                allowed = $allowed,
                reason = %$reason,
                "Zero Trust access denied"
            );
        }
    };
}

/// Log Zero Trust session revocation.
///
/// Logs when a session is explicitly revoked.
#[macro_export]
macro_rules! log_zero_trust_session_revoked {
    ($session_id_hex:expr) => {
        tracing::info!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            "Zero Trust session revoked"
        );
    };
}

/// Log Zero Trust continuous verification status.
///
/// Logs periodic verification status updates.
#[macro_export]
macro_rules! log_zero_trust_continuous_verification {
    ($session_id_hex:expr, $status:expr) => {
        tracing::debug!(
            target: "zero_trust::session",
            session_id = %$session_id_hex,
            status = ?$status,
            "Zero Trust continuous verification status"
        );
    };
}

// ============================================================================
// Zero Trust Logging Utility Functions
// ============================================================================

/// Convert a session ID (byte array) to a hex string for safe logging.
///
/// This function converts raw session ID bytes to a hexadecimal string,
/// which is safe to log and useful for audit trail correlation.
///
/// # Arguments
///
/// * `session_id` - The raw session ID bytes
///
/// # Returns
///
/// A hexadecimal string representation of the session ID.
///
/// # Example
///
/// ```rust
/// use arc_core::logging::session_id_to_hex;
///
/// let session_id = [0x12, 0x34, 0xAB, 0xCD];
/// assert_eq!(session_id_to_hex(&session_id), "1234abcd");
/// ```
#[must_use]
pub fn session_id_to_hex(session_id: &[u8]) -> String {
    hex::encode(session_id)
}

/// Initialize tracing with file output for persistent logging.
///
/// # Errors
///
/// Returns an error if:
/// - The tracing subscriber cannot be initialized
/// - The log file cannot be created or written to
pub fn init_tracing_with_file(log_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", log_file);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("latticearc=info"));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false).with_writer(file_appender));

    subscriber.init();

    info!("LatticeArc logging to file initialized: {}", log_file);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::unnecessary_map_or)]
#[allow(clippy::option_as_ref_deref)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_data_small() {
        let data = b"short";
        let sanitized = sanitize_data(data);
        assert_eq!(format!("{}", sanitized), "[5 bytes]");
    }

    #[test]
    fn test_sanitize_data_large() {
        let data = vec![0u8; 100];
        let sanitized = sanitize_data(&data);
        let output = format!("{}", sanitized);
        assert!(output.contains("[100 bytes"));
        assert!(output.contains("hash:"));
    }

    #[test]
    fn test_blake2_hash() {
        let data = b"test data";
        let hash = blake2_hash(data);
        assert_eq!(hash.len(), 64); // Blake2s256 produces 32 bytes, hex encoded = 64 chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ========================================================================
    // Metadata Sanitization Tests
    // ========================================================================

    #[test]
    fn test_is_potentially_sensitive_matches_sensitive_keys() {
        // Direct matches
        assert!(is_potentially_sensitive("key"));
        assert!(is_potentially_sensitive("secret"));
        assert!(is_potentially_sensitive("password"));
        assert!(is_potentially_sensitive("token"));
        assert!(is_potentially_sensitive("credential"));
        assert!(is_potentially_sensitive("private"));
        assert!(is_potentially_sensitive("auth"));
        assert!(is_potentially_sensitive("session"));
        assert!(is_potentially_sensitive("bearer"));
        assert!(is_potentially_sensitive("api_key"));
        assert!(is_potentially_sensitive("apikey"));
        assert!(is_potentially_sensitive("passphrase"));
    }

    #[test]
    fn test_is_potentially_sensitive_matches_compound_keys() {
        // Compound keys containing sensitive patterns
        assert!(is_potentially_sensitive("user_password"));
        assert!(is_potentially_sensitive("api_key_header"));
        assert!(is_potentially_sensitive("auth_token"));
        assert!(is_potentially_sensitive("private_key_pem"));
        assert!(is_potentially_sensitive("session_id"));
        assert!(is_potentially_sensitive("bearer_token"));
        assert!(is_potentially_sensitive("encryption_key"));
        assert!(is_potentially_sensitive("secret_value"));
        assert!(is_potentially_sensitive("credential_store"));
    }

    #[test]
    fn test_is_potentially_sensitive_case_insensitive() {
        // Case insensitive matching
        assert!(is_potentially_sensitive("API_KEY"));
        assert!(is_potentially_sensitive("Password"));
        assert!(is_potentially_sensitive("SECRET"));
        assert!(is_potentially_sensitive("AuthToken"));
        assert!(is_potentially_sensitive("BEARER_TOKEN"));
        assert!(is_potentially_sensitive("PrivateKey"));
    }

    #[test]
    fn test_is_potentially_sensitive_non_sensitive_keys() {
        // Keys that should NOT be flagged
        assert!(!is_potentially_sensitive("username"));
        assert!(!is_potentially_sensitive("operation"));
        assert!(!is_potentially_sensitive("timestamp"));
        assert!(!is_potentially_sensitive("request_id"));
        assert!(!is_potentially_sensitive("user_id"));
        assert!(!is_potentially_sensitive("algorithm"));
        assert!(!is_potentially_sensitive("data_size"));
        assert!(!is_potentially_sensitive("operation_type"));
        assert!(!is_potentially_sensitive("status"));
        assert!(!is_potentially_sensitive("result"));
    }

    #[test]
    fn test_sanitize_value_redacts_sensitive_keys() {
        assert_eq!(sanitize_value("api_key", "sk-12345abcdef"), "[REDACTED]");
        assert_eq!(sanitize_value("password", "super_secret_123"), "[REDACTED]");
        assert_eq!(sanitize_value("auth_token", "Bearer xyz"), "[REDACTED]");
        assert_eq!(sanitize_value("private_key", "-----BEGIN PRIVATE KEY-----"), "[REDACTED]");
    }

    #[test]
    fn test_sanitize_value_passes_normal_values() {
        assert_eq!(sanitize_value("operation", "encrypt"), "encrypt");
        assert_eq!(sanitize_value("algorithm", "ML-KEM-768"), "ML-KEM-768");
        assert_eq!(sanitize_value("user_id", "user123"), "user123");
        assert_eq!(sanitize_value("status", "success"), "success");
    }

    #[test]
    fn test_sanitize_value_truncates_long_values() {
        let long_value = "x".repeat(2000);
        let result = sanitize_value("data", &long_value);
        assert_eq!(result, "[2000 chars truncated]");

        // Exactly at limit should pass through
        let exact_value = "x".repeat(MAX_METADATA_VALUE_LENGTH);
        let result = sanitize_value("data", &exact_value);
        assert_eq!(result, exact_value);

        // One over limit should truncate
        let over_value = "x".repeat(MAX_METADATA_VALUE_LENGTH + 1);
        let result = sanitize_value("data", &over_value);
        assert!(result.contains("chars truncated"));
    }

    #[test]
    fn test_sanitize_value_sensitive_key_takes_precedence() {
        // Even long sensitive values are just redacted, not truncated
        let long_secret = "x".repeat(5000);
        let result = sanitize_value("api_key", &long_secret);
        assert_eq!(result, "[REDACTED]");
    }

    #[test]
    fn test_sanitize_bytes_small_data() {
        assert_eq!(sanitize_bytes(&[]), "[0 bytes]");
        assert_eq!(sanitize_bytes(&[1]), "[1 bytes]");
        assert_eq!(sanitize_bytes(&[1, 2, 3]), "[3 bytes]");
        assert_eq!(sanitize_bytes(&[0u8; 32]), "[32 bytes]");
    }

    #[test]
    fn test_sanitize_bytes_large_data_has_fingerprint() {
        let data = vec![0u8; 33];
        let result = sanitize_bytes(&data);
        assert!(result.contains("33 bytes"));
        assert!(result.contains("fingerprint:"));

        let data = vec![0u8; 100];
        let result = sanitize_bytes(&data);
        assert!(result.contains("100 bytes"));
        assert!(result.contains("fingerprint:"));
    }

    #[test]
    fn test_sanitize_bytes_fingerprint_is_consistent() {
        // Same data should produce same fingerprint
        let data = b"test data for fingerprint consistency check";
        let result1 = sanitize_bytes(data);
        let result2 = sanitize_bytes(data);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_sanitize_bytes_fingerprint_differs_for_different_data() {
        let data1 = vec![0u8; 100];
        let data2 = vec![1u8; 100];
        let result1 = sanitize_bytes(&data1);
        let result2 = sanitize_bytes(&data2);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_sha256_first_16_hex() {
        // Known test vector - SHA-256 of empty string
        let empty_hash = sha256_first_16_hex(&[]);
        assert_eq!(empty_hash.len(), 16);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // First 8 bytes = e3b0c44298fc1c14
        assert_eq!(empty_hash, "e3b0c44298fc1c14");

        // Verify it's valid hex
        assert!(empty_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sanitize_metadata_full_map() {
        let mut metadata = HashMap::new();
        metadata.insert("operation".to_string(), "encrypt".to_string());
        metadata.insert("api_key".to_string(), "sk-secret-123".to_string());
        metadata.insert("user_id".to_string(), "user_456".to_string());
        metadata.insert("password_hash".to_string(), "hashed_value".to_string());
        metadata.insert("algorithm".to_string(), "ML-KEM-768".to_string());

        let sanitized = sanitize_metadata(&metadata);

        // Non-sensitive keys pass through
        assert_eq!(sanitized.get("operation"), Some(&"encrypt".to_string()));
        assert_eq!(sanitized.get("user_id"), Some(&"user_456".to_string()));
        assert_eq!(sanitized.get("algorithm"), Some(&"ML-KEM-768".to_string()));

        // Sensitive keys are redacted
        assert_eq!(sanitized.get("api_key"), Some(&"[REDACTED]".to_string()));
        assert_eq!(sanitized.get("password_hash"), Some(&"[REDACTED]".to_string()));
    }

    #[test]
    fn test_sanitize_metadata_empty_map() {
        let metadata = HashMap::new();
        let sanitized = sanitize_metadata(&metadata);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn test_sanitize_metadata_preserves_all_keys() {
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());
        metadata.insert("secret".to_string(), "hidden".to_string());

        let sanitized = sanitize_metadata(&metadata);

        // All keys should still be present
        assert_eq!(sanitized.len(), 3);
        assert!(sanitized.contains_key("key1"));
        assert!(sanitized.contains_key("key2"));
        assert!(sanitized.contains_key("secret"));
    }

    #[test]
    fn test_sanitize_metadata_with_long_values() {
        let mut metadata = HashMap::new();
        let long_value = "x".repeat(2000);
        metadata.insert("description".to_string(), long_value);
        metadata.insert("short".to_string(), "brief".to_string());

        let sanitized = sanitize_metadata(&metadata);

        assert!(sanitized.get("description").map_or(false, |v| v.contains("chars truncated")));
        assert_eq!(sanitized.get("short"), Some(&"brief".to_string()));
    }

    #[test]
    fn test_session_id_to_hex() {
        let session_id = [0x12, 0x34, 0xAB, 0xCD];
        assert_eq!(session_id_to_hex(&session_id), "1234abcd");

        let empty: [u8; 0] = [];
        assert_eq!(session_id_to_hex(&empty), "");

        let all_zeros = [0u8; 16];
        assert_eq!(session_id_to_hex(&all_zeros), "00000000000000000000000000000000");
    }

    // ========================================================================
    // Correlation ID Tests
    // ========================================================================

    #[test]
    fn test_generate_correlation_id_is_valid_uuid() {
        let id = generate_correlation_id();
        // UUID v4 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars with hyphens)
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
        // Verify it parses as a valid UUID
        assert!(Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_generate_correlation_id_is_unique() {
        let id1 = generate_correlation_id();
        let id2 = generate_correlation_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_generate_lightweight_correlation_id_format() {
        let id = generate_lightweight_correlation_id();
        assert!(id.starts_with("corr-"));
        // corr- (5 chars) + 16 hex chars = 21 chars total
        assert_eq!(id.len(), 21);
        // Verify the hex part is valid
        let hex_part = &id[5..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_lightweight_correlation_id_increments() {
        let id1 = generate_lightweight_correlation_id();
        let id2 = generate_lightweight_correlation_id();
        assert_ne!(id1, id2);
        // Extract counter values and verify they're sequential
        let counter1 = u64::from_str_radix(&id1[5..], 16);
        let counter2 = u64::from_str_radix(&id2[5..], 16);
        assert!(counter1.is_ok());
        assert!(counter2.is_ok());
    }

    #[test]
    fn test_set_and_get_correlation_id() {
        // Clear any existing correlation ID
        clear_correlation_id();
        assert_eq!(current_correlation_id(), None);

        // Set a correlation ID
        set_correlation_id("test-correlation-123".to_string());
        assert_eq!(current_correlation_id(), Some("test-correlation-123".to_string()));

        // Clean up
        clear_correlation_id();
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_clear_correlation_id() {
        set_correlation_id("to-be-cleared".to_string());
        assert!(current_correlation_id().is_some());

        clear_correlation_id();
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_with_correlation_id_executes_closure() {
        clear_correlation_id();

        let result = with_correlation_id("request-456".to_string(), || {
            assert_eq!(current_correlation_id(), Some("request-456".to_string()));
            42
        });

        assert_eq!(result, 42);
        // After closure, correlation ID should be cleared (was None before)
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_with_correlation_id_restores_previous() {
        clear_correlation_id();
        set_correlation_id("outer-id".to_string());

        with_correlation_id("inner-id".to_string(), || {
            assert_eq!(current_correlation_id(), Some("inner-id".to_string()));
        });

        // Should restore the outer ID
        assert_eq!(current_correlation_id(), Some("outer-id".to_string()));

        // Clean up
        clear_correlation_id();
    }

    #[test]
    fn test_correlation_guard_new_sets_uuid() {
        clear_correlation_id();

        {
            let guard = CorrelationGuard::new();
            let id = guard.id();
            assert!(id.is_some());
            let id_str = id.as_ref().map(String::as_str);
            // Should be a valid UUID
            assert!(id_str.map_or(false, |s| Uuid::parse_str(s).is_ok()));
        }

        // After guard drops, should be cleared
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_correlation_guard_with_id() {
        clear_correlation_id();

        {
            let guard = CorrelationGuard::with_id("custom-id-789".to_string());
            assert_eq!(guard.id(), Some("custom-id-789".to_string()));
            assert_eq!(current_correlation_id(), Some("custom-id-789".to_string()));
        }

        // After guard drops, should be cleared
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_correlation_guard_lightweight() {
        clear_correlation_id();

        {
            let guard = CorrelationGuard::lightweight();
            let id = guard.id();
            assert!(id.is_some());
            assert!(id.as_ref().map_or(false, |s| s.starts_with("corr-")));
        }

        // After guard drops, should be cleared
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_correlation_guard_restores_previous_on_drop() {
        clear_correlation_id();
        set_correlation_id("original-id".to_string());

        {
            let guard = CorrelationGuard::with_id("temporary-id".to_string());
            assert_eq!(guard.previous_id(), Some(&"original-id".to_string()));
            assert_eq!(current_correlation_id(), Some("temporary-id".to_string()));
        }

        // Should restore original ID after guard drops
        assert_eq!(current_correlation_id(), Some("original-id".to_string()));

        // Clean up
        clear_correlation_id();
    }

    #[test]
    fn test_correlation_guard_nested() {
        clear_correlation_id();

        {
            let guard1 = CorrelationGuard::with_id("level-1".to_string());
            assert_eq!(current_correlation_id(), Some("level-1".to_string()));

            {
                let guard2 = CorrelationGuard::with_id("level-2".to_string());
                assert_eq!(current_correlation_id(), Some("level-2".to_string()));
                assert_eq!(guard2.previous_id(), Some(&"level-1".to_string()));
            }

            // After inner guard drops, should restore level-1
            assert_eq!(current_correlation_id(), Some("level-1".to_string()));
            assert_eq!(guard1.previous_id(), None);
        }

        // After outer guard drops, should be cleared
        assert_eq!(current_correlation_id(), None);
    }

    #[test]
    fn test_correlation_guard_default() {
        clear_correlation_id();

        {
            let guard = CorrelationGuard::default();
            let id = guard.id();
            assert!(id.is_some());
            // Default should create a UUID
            assert!(id.as_ref().map_or(false, |s| Uuid::parse_str(s).is_ok()));
        }

        assert_eq!(current_correlation_id(), None);
    }

    // ========================================================================
    // Key Lifecycle Event Tests
    // ========================================================================

    #[test]
    fn test_key_type_display() {
        assert_eq!(KeyType::Symmetric.to_string(), "Symmetric");
        assert_eq!(KeyType::AsymmetricPublic.to_string(), "AsymmetricPublic");
        assert_eq!(KeyType::AsymmetricPrivate.to_string(), "AsymmetricPrivate");
        assert_eq!(KeyType::KeyPair.to_string(), "KeyPair");
    }

    #[test]
    fn test_key_purpose_display() {
        assert_eq!(KeyPurpose::Encryption.to_string(), "Encryption");
        assert_eq!(KeyPurpose::Signing.to_string(), "Signing");
        assert_eq!(KeyPurpose::KeyExchange.to_string(), "KeyExchange");
        assert_eq!(KeyPurpose::Authentication.to_string(), "Authentication");
        assert_eq!(KeyPurpose::KeyWrapping.to_string(), "KeyWrapping");
    }

    #[test]
    fn test_rotation_reason_display() {
        assert_eq!(RotationReason::Scheduled.to_string(), "Scheduled");
        assert_eq!(RotationReason::Compromised.to_string(), "Compromised");
        assert_eq!(RotationReason::PolicyChange.to_string(), "PolicyChange");
        assert_eq!(RotationReason::Expiration.to_string(), "Expiration");
        assert_eq!(RotationReason::Manual.to_string(), "Manual");
    }

    #[test]
    fn test_destruction_method_display() {
        assert_eq!(DestructionMethod::Zeroization.to_string(), "Zeroization");
        assert_eq!(DestructionMethod::CryptoErase.to_string(), "CryptoErase");
        assert_eq!(DestructionMethod::Manual.to_string(), "Manual");
    }

    #[test]
    fn test_key_lifecycle_event_generated() {
        let event = KeyLifecycleEvent::generated(
            "key-001",
            "ML-KEM-768",
            KeyType::KeyPair,
            KeyPurpose::KeyExchange,
        );

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "generated");

        // Verify internal structure
        match event {
            KeyLifecycleEvent::Generated { key_id, algorithm, key_type, purpose } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(algorithm, "ML-KEM-768");
                assert_eq!(key_type, KeyType::KeyPair);
                assert_eq!(purpose, KeyPurpose::KeyExchange);
            }
            _ => panic!("Expected Generated event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_rotated() {
        let event = KeyLifecycleEvent::rotated(
            "old-key-001",
            "new-key-002",
            "ML-KEM-768",
            RotationReason::Scheduled,
        );

        assert_eq!(event.key_id(), "new-key-002");
        assert_eq!(event.event_type(), "rotated");

        match event {
            KeyLifecycleEvent::Rotated { old_key_id, new_key_id, algorithm, reason } => {
                assert_eq!(old_key_id, "old-key-001");
                assert_eq!(new_key_id, "new-key-002");
                assert_eq!(algorithm, "ML-KEM-768");
                assert_eq!(reason, RotationReason::Scheduled);
            }
            _ => panic!("Expected Rotated event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_destroyed() {
        let event = KeyLifecycleEvent::destroyed("key-001", DestructionMethod::Zeroization);

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "destroyed");

        match event {
            KeyLifecycleEvent::Destroyed { key_id, method } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(method, DestructionMethod::Zeroization);
            }
            _ => panic!("Expected Destroyed event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_accessed() {
        // Without accessor
        let event = KeyLifecycleEvent::accessed("key-001", "encrypt", None);
        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "accessed");

        // With accessor
        let event_with_accessor =
            KeyLifecycleEvent::accessed("key-002", "sign", Some("user-123".to_string()));
        match event_with_accessor {
            KeyLifecycleEvent::Accessed { key_id, operation, accessor } => {
                assert_eq!(key_id, "key-002");
                assert_eq!(operation, "sign");
                assert_eq!(accessor, Some("user-123".to_string()));
            }
            _ => panic!("Expected Accessed event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_imported() {
        let event = KeyLifecycleEvent::imported("key-001", "ML-KEM-768", "external-hsm");

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "imported");

        match event {
            KeyLifecycleEvent::Imported { key_id, algorithm, source } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(algorithm, "ML-KEM-768");
                assert_eq!(source, "external-hsm");
            }
            _ => panic!("Expected Imported event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_exported() {
        let event = KeyLifecycleEvent::exported("key-001", "PEM", "backup-server");

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "exported");

        match event {
            KeyLifecycleEvent::Exported { key_id, format, destination } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(format, "PEM");
                assert_eq!(destination, "backup-server");
            }
            _ => panic!("Expected Exported event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_deprecated() {
        let deprecation_date = Utc::now();
        let event = KeyLifecycleEvent::deprecated("key-001", deprecation_date, "End of life");

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "deprecated");

        match event {
            KeyLifecycleEvent::Deprecated { key_id, deprecation_date: date, reason } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(date, deprecation_date);
                assert_eq!(reason, "End of life");
            }
            _ => panic!("Expected Deprecated event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_suspended() {
        let event = KeyLifecycleEvent::suspended("key-001", "Suspected compromise");

        assert_eq!(event.key_id(), "key-001");
        assert_eq!(event.event_type(), "suspended");

        match event {
            KeyLifecycleEvent::Suspended { key_id, reason } => {
                assert_eq!(key_id, "key-001");
                assert_eq!(reason, "Suspected compromise");
            }
            _ => panic!("Expected Suspended event"),
        }
    }

    #[test]
    fn test_key_lifecycle_event_serialization() {
        let event = KeyLifecycleEvent::generated(
            "key-001",
            "ML-KEM-768",
            KeyType::KeyPair,
            KeyPurpose::KeyExchange,
        );

        // Test JSON serialization
        let json = serde_json::to_string(&event);
        assert!(json.is_ok());

        let json_str = json.as_ref().map(String::as_str);
        assert!(json_str.map_or(false, |s| s.contains("key-001")));
        assert!(json_str.map_or(false, |s| s.contains("ML-KEM-768")));
        assert!(json_str.map_or(false, |s| s.contains("KeyPair")));
        assert!(json_str.map_or(false, |s| s.contains("KeyExchange")));

        // Test deserialization
        let deserialized: Result<KeyLifecycleEvent, _> =
            serde_json::from_str(json.as_ref().map_or("", String::as_str));
        assert!(deserialized.is_ok());

        if let Ok(KeyLifecycleEvent::Generated { key_id, algorithm, key_type, purpose }) =
            deserialized
        {
            assert_eq!(key_id, "key-001");
            assert_eq!(algorithm, "ML-KEM-768");
            assert_eq!(key_type, KeyType::KeyPair);
            assert_eq!(purpose, KeyPurpose::KeyExchange);
        } else {
            panic!("Failed to deserialize Generated event");
        }
    }

    #[test]
    fn test_key_type_serialization() {
        for key_type in [
            KeyType::Symmetric,
            KeyType::AsymmetricPublic,
            KeyType::AsymmetricPrivate,
            KeyType::KeyPair,
        ] {
            let json = serde_json::to_string(&key_type);
            assert!(json.is_ok());
            let deserialized: Result<KeyType, _> =
                serde_json::from_str(json.as_ref().map_or("", String::as_str));
            assert!(deserialized.is_ok());
            assert_eq!(
                deserialized.unwrap_or_else(|_| panic!("Failed to deserialize {:?}", key_type)),
                key_type
            );
        }
    }

    #[test]
    fn test_key_purpose_serialization() {
        for purpose in [
            KeyPurpose::Encryption,
            KeyPurpose::Signing,
            KeyPurpose::KeyExchange,
            KeyPurpose::Authentication,
            KeyPurpose::KeyWrapping,
        ] {
            let json = serde_json::to_string(&purpose);
            assert!(json.is_ok());
            let deserialized: Result<KeyPurpose, _> =
                serde_json::from_str(json.as_ref().map_or("", String::as_str));
            assert!(deserialized.is_ok());
            assert_eq!(
                deserialized.unwrap_or_else(|_| panic!("Failed to deserialize {:?}", purpose)),
                purpose
            );
        }
    }

    #[test]
    fn test_rotation_reason_serialization() {
        for reason in [
            RotationReason::Scheduled,
            RotationReason::Compromised,
            RotationReason::PolicyChange,
            RotationReason::Expiration,
            RotationReason::Manual,
        ] {
            let json = serde_json::to_string(&reason);
            assert!(json.is_ok());
            let deserialized: Result<RotationReason, _> =
                serde_json::from_str(json.as_ref().map_or("", String::as_str));
            assert!(deserialized.is_ok());
            assert_eq!(
                deserialized.unwrap_or_else(|_| panic!("Failed to deserialize {:?}", reason)),
                reason
            );
        }
    }

    #[test]
    fn test_destruction_method_serialization() {
        for method in [
            DestructionMethod::Zeroization,
            DestructionMethod::CryptoErase,
            DestructionMethod::Manual,
        ] {
            let json = serde_json::to_string(&method);
            assert!(json.is_ok());
            let deserialized: Result<DestructionMethod, _> =
                serde_json::from_str(json.as_ref().map_or("", String::as_str));
            assert!(deserialized.is_ok());
            assert_eq!(
                deserialized.unwrap_or_else(|_| panic!("Failed to deserialize {:?}", method)),
                method
            );
        }
    }
}
