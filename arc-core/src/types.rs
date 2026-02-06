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

use crate::zero_trust::VerifiedSession;

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
/// All levels use hybrid encryption (PQ + classical) by default for defense-in-depth
/// during the post-quantum transition period, except `Quantum` which is PQ-only.
///
/// Higher levels provide stronger protection but may impact performance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

// ============================================================================
// Unified Crypto Configuration
// ============================================================================

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

/// Unified configuration for cryptographic operations.
///
/// Provides a single, consistent way to configure encrypt, decrypt, sign, and verify
/// operations. Uses a builder pattern for ergonomic configuration.
///
/// # Examples
///
/// ```rust,ignore
/// use arc_core::{encrypt, CryptoConfig, UseCase, SecurityLevel, VerifiedSession};
///
/// // Simple - all defaults (High security, no session)
/// encrypt(data, key, CryptoConfig::new())?;
///
/// // With Zero Trust session
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// encrypt(data, key, CryptoConfig::new().session(&session))?;
///
/// // With use case (recommended - library picks optimal algorithm)
/// encrypt(data, key, CryptoConfig::new()
///     .session(&session)
///     .use_case(UseCase::FileStorage))?;
///
/// // With security level (manual control)
/// encrypt(data, key, CryptoConfig::new()
///     .session(&session)
///     .security_level(SecurityLevel::Maximum))?;
/// ```
#[derive(Debug, Clone)]
pub struct CryptoConfig<'a> {
    /// Optional Zero Trust verified session.
    /// If None, operates in unverified mode.
    session: Option<&'a VerifiedSession>,
    /// Algorithm selection mode (use case or security level).
    selection: AlgorithmSelection,
}

impl<'a> Default for CryptoConfig<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CryptoConfig<'a> {
    /// Creates new configuration with defaults (High security, no session).
    #[must_use]
    pub fn new() -> Self {
        Self { session: None, selection: AlgorithmSelection::default() }
    }

    /// Sets the Zero Trust verified session.
    ///
    /// When set, the session is validated before each operation.
    /// Operations will fail if the session has expired.
    #[must_use]
    pub fn session(mut self, session: &'a VerifiedSession) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the use case for automatic algorithm selection (recommended).
    ///
    /// The library will choose the optimal algorithm for this use case.
    /// This overrides any previously set security level.
    #[must_use]
    pub fn use_case(mut self, use_case: UseCase) -> Self {
        self.selection = AlgorithmSelection::UseCase(use_case);
        self
    }

    /// Sets the security level for manual algorithm selection.
    ///
    /// Use this when your use case doesn't fit predefined options.
    /// This overrides any previously set use case.
    #[must_use]
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.selection = AlgorithmSelection::SecurityLevel(level);
        self
    }

    /// Returns the session if set.
    #[must_use]
    pub fn get_session(&self) -> Option<&'a VerifiedSession> {
        self.session
    }

    /// Returns the algorithm selection mode.
    #[must_use]
    pub fn get_selection(&self) -> &AlgorithmSelection {
        &self.selection
    }

    /// Returns true if a session is set (verified mode).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.session.is_some()
    }

    /// Validates the session if present.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the session has expired.
    pub fn validate(&self) -> crate::error::Result<()> {
        if let Some(session) = self.session { session.verify_valid() } else { Ok(()) }
    }
}
