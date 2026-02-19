//! Fundamental cryptographic types for LatticeArc.
//!
//! Provides core data structures for keys, encrypted data, signed data,
//! and cryptographic context. All types are pure Rust with zero FFI dependencies.

use std::fmt;

use chrono::{DateTime, Utc};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// A secure byte container that zeroizes its contents on drop.
///
/// # Security Note
/// Clone is intentionally NOT implemented to prevent creating
/// copies of sensitive data that might not be properly zeroized.
/// If you need to share the data, use `as_slice()` to get a reference.
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

impl fmt::Debug for ZeroizedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroizedBytes").field("data", &"[REDACTED]").finish()
    }
}

impl AsRef<[u8]> for ZeroizedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl ConstantTimeEq for ZeroizedBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.data.ct_eq(&other.data)
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
/// All levels use hybrid encryption (PQ + classical) by default for defense-in-depth
/// during the post-quantum transition period, except `Quantum` which is PQ-only.
///
/// Higher levels provide stronger protection but may impact performance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum SecurityLevel {
    /// NIST Level 1 (128-bit equivalent). Hybrid mode.
    /// Uses ML-KEM-512 + X25519, ML-DSA-44 + Ed25519.
    /// Suitable for resource-constrained devices and general use.
    Standard,
    /// NIST Level 3 (192-bit equivalent). Hybrid mode. (default)
    /// Uses ML-KEM-768 + X25519, ML-DSA-65 + Ed25519.
    /// Recommended for most enterprise applications.
    #[default]
    High,
    /// NIST Level 5 (256-bit equivalent). Hybrid mode.
    /// Uses ML-KEM-1024 + X25519, ML-DSA-87 + Ed25519.
    /// For high-value assets and long-term security.
    Maximum,
    /// NIST Level 5 (256-bit equivalent). PQ-only mode.
    /// Uses ML-KEM-1024, ML-DSA-87 (no classical algorithms).
    /// For CNSA 2.0 compliance and government use cases.
    /// Must be explicitly selected - no UseCase defaults to this.
    Quantum,
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
///
/// The library selects optimal algorithms based on the use case requirements:
/// security level, performance characteristics, and compliance needs.
#[derive(Debug, Clone, PartialEq)]
pub enum UseCase {
    // ========================================================================
    // Communication
    // ========================================================================
    /// Real-time messaging with low latency requirements.
    /// Uses ML-KEM-768 for balanced security and performance.
    SecureMessaging,
    /// Email encryption for at-rest and in-transit protection.
    /// Uses ML-KEM-1024 for long-term confidentiality.
    EmailEncryption,
    /// VPN tunnel encryption requiring high throughput.
    /// Uses ML-KEM-768 with performance optimizations.
    VpnTunnel,
    /// API request/response encryption.
    /// Uses ML-KEM-768 for low-latency operations.
    ApiSecurity,

    // ========================================================================
    // Storage
    // ========================================================================
    /// Large file encryption at rest.
    /// Uses ML-KEM-1024 for long-term storage security.
    FileStorage,
    /// Database column or row encryption.
    /// Uses ML-KEM-768 for frequent access patterns.
    DatabaseEncryption,
    /// Cloud storage encryption.
    /// Uses ML-KEM-1024 for data potentially stored for years.
    CloudStorage,
    /// Backup and archive encryption.
    /// Uses ML-KEM-1024 for maximum long-term security.
    BackupArchive,
    /// Configuration and secrets encryption.
    /// Uses ML-KEM-768 for application secrets.
    ConfigSecrets,

    // ========================================================================
    // Authentication & Identity
    // ========================================================================
    /// User or service authentication.
    /// Uses ML-DSA-87 for maximum signature security.
    Authentication,
    /// Session token generation and validation.
    /// Uses ML-KEM-768 with short expiration.
    SessionToken,
    /// Digital certificate signing.
    /// Uses ML-DSA-87 for certificate authorities.
    DigitalCertificate,
    /// Secure key exchange protocols.
    /// Uses ML-KEM-1024 for key agreement.
    KeyExchange,

    // ========================================================================
    // Financial & Legal
    // ========================================================================
    /// High-integrity financial transaction signing.
    /// Uses ML-DSA-87 + Ed25519 hybrid for compliance.
    FinancialTransactions,
    /// Legal document signing with non-repudiation.
    /// Uses ML-DSA-87 for legally binding signatures.
    LegalDocuments,
    /// Blockchain and distributed ledger transactions.
    /// Uses ML-DSA-65 for on-chain efficiency.
    BlockchainTransaction,

    // ========================================================================
    // Regulated Industries
    // ========================================================================
    /// Healthcare records (HIPAA compliance).
    /// Uses ML-KEM-1024 with audit logging.
    HealthcareRecords,
    /// Government classified information.
    /// Uses ML-KEM-1024 + ML-DSA-87 (highest security).
    GovernmentClassified,
    /// Payment card industry (PCI-DSS).
    /// Uses ML-KEM-1024 for cardholder data.
    PaymentCard,

    // ========================================================================
    // IoT & Embedded
    // ========================================================================
    /// IoT device communication (constrained resources).
    /// Uses ML-KEM-512 for resource-limited devices.
    IoTDevice,
    /// Firmware signing and verification.
    /// Uses ML-DSA-65 for update integrity.
    FirmwareSigning,

    // ========================================================================
    // Advanced
    // ========================================================================
    /// Encrypted search over ciphertext.
    /// Uses specialized searchable encryption schemes.
    SearchableEncryption,
    /// Computation on encrypted data.
    /// Uses homomorphic-compatible encryption.
    HomomorphicComputation,
    /// Audit log encryption (append-only).
    /// Uses ML-KEM-768 with integrity verification.
    AuditLog,
}

/// Category of cryptographic scheme.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
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

/// Selection mode for cryptographic algorithm selection.
///
/// Either a `UseCase` (recommended) or a `SecurityLevel` (manual control).
/// These are mutually exclusive - set one or the other, not both.
#[derive(Debug, Clone, PartialEq)]
pub enum AlgorithmSelection {
    /// Select algorithm based on use case (recommended).
    /// The library will choose the optimal algorithm for this use case.
    UseCase(UseCase),
    /// Select algorithm based on security level (manual control).
    /// Use this when your use case doesn't fit predefined options.
    SecurityLevel(SecurityLevel),
}

impl Default for AlgorithmSelection {
    fn default() -> Self {
        Self::SecurityLevel(SecurityLevel::High)
    }
}

// Formal verification with Kani
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves that the default SecurityLevel is High (NIST Level 3).
    /// Security property: if a developer doesn't explicitly choose a level,
    /// they get strong (192-bit) security, not the weakest option.
    #[kani::proof]
    fn security_level_default_is_high() {
        let default = SecurityLevel::default();
        kani::assert(
            default == SecurityLevel::High,
            "Default SecurityLevel must be High (NIST Level 3)",
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // --- ZeroizedBytes tests ---

    #[test]
    fn test_zeroized_bytes_new() {
        let data = vec![1u8, 2, 3, 4, 5];
        let zb = ZeroizedBytes::new(data.clone());
        assert_eq!(zb.as_slice(), &data);
    }

    #[test]
    fn test_zeroized_bytes_len() {
        let zb = ZeroizedBytes::new(vec![0u8; 32]);
        assert_eq!(zb.len(), 32);
        assert!(!zb.is_empty());
    }

    #[test]
    fn test_zeroized_bytes_empty() {
        let zb = ZeroizedBytes::new(vec![]);
        assert_eq!(zb.len(), 0);
        assert!(zb.is_empty());
    }

    #[test]
    fn test_zeroized_bytes_as_ref() {
        let data = vec![10u8, 20, 30];
        let zb = ZeroizedBytes::new(data.clone());
        let slice: &[u8] = zb.as_ref();
        assert_eq!(slice, &data);
    }

    #[test]
    fn test_zeroized_bytes_debug() {
        let zb = ZeroizedBytes::new(vec![1, 2, 3]);
        let debug = format!("{:?}", zb);
        assert!(debug.contains("ZeroizedBytes"));
    }

    // --- EncryptedMetadata tests ---

    #[test]
    fn test_encrypted_metadata_with_tag() {
        let meta = EncryptedMetadata {
            nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            tag: Some(vec![0xAA; 16]),
            key_id: Some("key-001".to_string()),
        };
        assert_eq!(meta.nonce.len(), 12);
        assert!(meta.tag.is_some());
        assert_eq!(meta.key_id.as_deref(), Some("key-001"));
    }

    #[test]
    fn test_encrypted_metadata_without_tag() {
        let meta = EncryptedMetadata { nonce: vec![0u8; 12], tag: None, key_id: None };
        assert!(meta.tag.is_none());
        assert!(meta.key_id.is_none());
    }

    #[test]
    fn test_encrypted_metadata_eq() {
        let meta1 = EncryptedMetadata { nonce: vec![1, 2, 3], tag: None, key_id: None };
        let meta2 = meta1.clone();
        assert_eq!(meta1, meta2);
    }

    // --- SignedMetadata tests ---

    #[test]
    fn test_signed_metadata_clone_debug() {
        let meta = SignedMetadata {
            signature: vec![0xBB; 64],
            signature_algorithm: "ML-DSA-65".to_string(),
            public_key: vec![0xCC; 32],
            key_id: Some("sig-key-001".to_string()),
        };
        let cloned = meta.clone();
        assert_eq!(cloned.signature_algorithm, "ML-DSA-65");
        assert_eq!(cloned.public_key.len(), 32);

        let debug = format!("{:?}", meta);
        assert!(debug.contains("SignedMetadata"));
    }

    // --- CryptoPayload tests ---

    #[test]
    fn test_crypto_payload_clone_eq() {
        let payload: CryptoPayload<EncryptedMetadata> = CryptoPayload {
            data: vec![1, 2, 3],
            metadata: EncryptedMetadata { nonce: vec![0u8; 12], tag: None, key_id: None },
            scheme: "AES-256-GCM".to_string(),
            timestamp: 1234567890,
        };
        let cloned = payload.clone();
        assert_eq!(payload, cloned);
        assert_eq!(payload.scheme, "AES-256-GCM");
        assert_eq!(payload.timestamp, 1234567890);
    }

    // --- KeyPair tests ---

    #[test]
    fn test_keypair_new() {
        let pk = vec![1u8; 32];
        let sk = ZeroizedBytes::new(vec![2u8; 64]);
        let kp = KeyPair::new(pk.clone(), sk);
        assert_eq!(kp.public_key(), &pk);
        assert_eq!(kp.private_key().len(), 64);
    }

    #[test]
    fn test_keypair_debug() {
        let kp = KeyPair::new(vec![1u8; 32], ZeroizedBytes::new(vec![2u8; 32]));
        let debug = format!("{:?}", kp);
        assert!(debug.contains("KeyPair"));
    }

    // --- SecurityLevel tests ---

    #[test]
    fn test_security_level_default() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::High);
    }

    #[test]
    fn test_security_level_variants() {
        let variants = vec![
            SecurityLevel::Standard,
            SecurityLevel::High,
            SecurityLevel::Maximum,
            SecurityLevel::Quantum,
        ];
        for v in &variants {
            assert_eq!(*v, v.clone());
        }
        assert_ne!(SecurityLevel::Standard, SecurityLevel::Maximum);
    }

    #[test]
    fn test_security_level_debug() {
        let debug = format!("{:?}", SecurityLevel::Quantum);
        assert!(debug.contains("Quantum"));
    }

    // --- PerformancePreference tests ---

    #[test]
    fn test_performance_preference_default() {
        assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);
    }

    #[test]
    fn test_performance_preference_variants() {
        assert_ne!(PerformancePreference::Speed, PerformancePreference::Memory);
        assert_eq!(PerformancePreference::Speed, PerformancePreference::Speed.clone());
    }

    // --- UseCase tests ---

    #[test]
    fn test_use_case_variants() {
        let cases = vec![
            UseCase::SecureMessaging,
            UseCase::EmailEncryption,
            UseCase::VpnTunnel,
            UseCase::ApiSecurity,
            UseCase::FileStorage,
            UseCase::DatabaseEncryption,
            UseCase::CloudStorage,
            UseCase::BackupArchive,
            UseCase::ConfigSecrets,
            UseCase::Authentication,
            UseCase::SessionToken,
            UseCase::DigitalCertificate,
            UseCase::KeyExchange,
            UseCase::FinancialTransactions,
            UseCase::LegalDocuments,
            UseCase::BlockchainTransaction,
            UseCase::HealthcareRecords,
            UseCase::GovernmentClassified,
            UseCase::PaymentCard,
            UseCase::IoTDevice,
            UseCase::FirmwareSigning,
            UseCase::SearchableEncryption,
            UseCase::HomomorphicComputation,
            UseCase::AuditLog,
        ];
        for c in &cases {
            assert_eq!(*c, c.clone());
        }
        assert_ne!(UseCase::SecureMessaging, UseCase::FileStorage);
    }

    // --- CryptoScheme tests ---

    #[test]
    fn test_crypto_scheme_variants() {
        let schemes = vec![
            CryptoScheme::Hybrid,
            CryptoScheme::Symmetric,
            CryptoScheme::Asymmetric,
            CryptoScheme::Homomorphic,
            CryptoScheme::PostQuantum,
        ];
        for s in &schemes {
            assert_eq!(*s, s.clone());
        }
        assert_ne!(CryptoScheme::Hybrid, CryptoScheme::Symmetric);
    }

    // --- CryptoContext tests ---

    #[test]
    fn test_crypto_context_default() {
        let ctx = CryptoContext::default();
        assert_eq!(ctx.security_level, SecurityLevel::High);
        assert_eq!(ctx.performance_preference, PerformancePreference::Balanced);
        assert!(ctx.use_case.is_none());
        assert!(ctx.hardware_acceleration);
    }

    #[test]
    fn test_crypto_context_clone_debug() {
        let ctx = CryptoContext::default();
        let cloned = ctx.clone();
        assert_eq!(cloned.security_level, ctx.security_level);
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("CryptoContext"));
    }

    // --- AlgorithmSelection tests ---

    #[test]
    fn test_algorithm_selection_default() {
        let sel = AlgorithmSelection::default();
        assert_eq!(sel, AlgorithmSelection::SecurityLevel(SecurityLevel::High));
    }

    #[test]
    fn test_algorithm_selection_use_case() {
        let sel = AlgorithmSelection::UseCase(UseCase::FileStorage);
        assert_eq!(sel, AlgorithmSelection::UseCase(UseCase::FileStorage));
        assert_ne!(sel, AlgorithmSelection::default());
    }
}
