//! Fundamental cryptographic types for LatticeArc Core.
//!
//! Provides core data structures for keys, encrypted data, signed data,
//! and cryptographic context.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use chrono::{DateTime, Utc};
use zeroize::Zeroize;

/// A secure byte container that zeroizes its contents on drop.
///
/// # Security Note
/// Clone is intentionally NOT implemented to prevent creating
/// copies of sensitive data that might not be properly zeroized.
/// If you need to share the data, use `as_slice()` to get a reference.
#[derive(Debug)]
pub struct ZeroizedBytes {
    data: Vec<u8>,
}

impl ZeroizedBytes {
    /// Creates a new `ZeroizedBytes` from raw byte data.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Returns the data as a byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the data in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the data is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for ZeroizedBytes {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl AsRef<[u8]> for ZeroizedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// A public key represented as a byte vector.
pub type PublicKey = Vec<u8>;
/// A private key with automatic zeroization on drop.
pub type PrivateKey = ZeroizedBytes;
/// A symmetric key with automatic zeroization on drop.
pub type SymmetricKey = ZeroizedBytes;
/// A 256-bit hash output.
pub type HashOutput = [u8; 32];

/// Metadata associated with encrypted data.
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedMetadata {
    /// The nonce/IV used for encryption.
    pub nonce: Vec<u8>,
    /// The authentication tag (for AEAD schemes).
    pub tag: Option<Vec<u8>>,
    /// Optional key identifier for key management.
    pub key_id: Option<String>,
}

/// Metadata associated with signed data.
#[derive(Debug, Clone)]
pub struct SignedMetadata {
    /// The signature bytes.
    pub signature: Vec<u8>,
    /// The algorithm used to create the signature.
    pub signature_algorithm: String,
    /// The public key that can verify the signature.
    pub public_key: Vec<u8>,
    /// Optional key identifier for key management.
    pub key_id: Option<String>,
}

/// A generic cryptographic payload with metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoPayload<T> {
    /// The encrypted or signed data.
    pub data: Vec<u8>,
    /// Scheme-specific metadata.
    pub metadata: T,
    /// The cryptographic scheme used.
    pub scheme: String,
    /// Unix timestamp when the operation was performed.
    pub timestamp: u64,
}

/// Encrypted data with associated metadata.
pub type EncryptedData = CryptoPayload<EncryptedMetadata>;
/// Signed data with associated metadata.
pub type SignedData = CryptoPayload<SignedMetadata>;

/// A cryptographic key pair containing public and private keys.
///
/// # Security Note
/// Clone is intentionally NOT implemented because this struct contains
/// sensitive private key material that should not be copied.
#[derive(Debug)]
pub struct KeyPair {
    /// The public key component of the key pair.
    pub public_key: PublicKey,
    /// The private key component of the key pair (sensitive material).
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Create a new key pair from public and private key components.
    #[must_use]
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self { public_key, private_key }
    }

    /// Get a reference to the public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get a reference to the private key.
    #[must_use]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

/// Security level for cryptographic operations.
///
/// Higher levels provide stronger protection but may impact performance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    /// 128-bit equivalent security. Suitable for low-sensitivity data.
    Low,
    /// 128-bit security with additional safeguards.
    Medium,
    /// 192-bit equivalent security. Recommended for most applications.
    #[default]
    High,
    /// 256-bit equivalent security. For high-value assets.
    Maximum,
}

/// Performance optimization preference.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PerformancePreference {
    /// Prioritize throughput over memory usage.
    Speed,
    /// Prioritize memory efficiency over speed.
    Memory,
    /// Balance between speed and memory usage.
    #[default]
    Balanced,
}

/// Predefined use cases for automatic scheme selection.
#[derive(Debug, Clone, PartialEq)]
pub enum UseCase {
    /// Real-time messaging with low latency requirements.
    SecureMessaging,
    /// Database column or row encryption.
    DatabaseEncryption,
    /// Large file encryption at rest.
    FileStorage,
    /// High-integrity financial transaction signing.
    FinancialTransactions,
    /// Encrypted search over ciphertext.
    SearchableEncryption,
    /// Computation on encrypted data.
    HomomorphicComputation,
    /// User or service authentication.
    Authentication,
    /// Secure key exchange protocols.
    KeyExchange,
}

/// Category of cryptographic scheme.
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoScheme {
    /// Hybrid PQC + classical for defense in depth.
    Hybrid,
    /// Symmetric encryption (e.g., AES-GCM).
    Symmetric,
    /// Classical asymmetric (e.g., Ed25519).
    Asymmetric,
    /// Homomorphic encryption schemes.
    Homomorphic,
    /// Pure post-quantum without classical fallback.
    PostQuantum,
}

/// Context for cryptographic operations.
///
/// Carries configuration and metadata that influences scheme selection
/// and operation behavior.
#[derive(Debug, Clone)]
pub struct CryptoContext {
    /// Security level for operations.
    pub security_level: SecurityLevel,
    /// Performance optimization preference.
    pub performance_preference: PerformancePreference,
    /// Optional use case for automatic scheme selection.
    pub use_case: Option<UseCase>,
    /// Whether hardware acceleration is enabled.
    pub hardware_acceleration: bool,
    /// Timestamp when the context was created.
    pub timestamp: DateTime<Utc>,
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            performance_preference: PerformancePreference::default(),
            use_case: None,
            hardware_acceleration: true,
            timestamp: Utc::now(),
        }
    }
}
