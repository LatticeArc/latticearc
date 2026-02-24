//! # LatticeArc Types
//!
//! Pure-Rust domain types, traits, configuration, and policy engine for the
//! LatticeArc post-quantum cryptography platform.
//!
//! This module contains all types that have **zero FFI dependencies**, enabling:
//! - Formal verification with Kani (which cannot compile C FFI)
//! - Lightweight dependency for crates that only need types (no aws-lc-sys)
//! - Clean separation of type definitions from cryptographic implementations
//!
//! ## What's Here
//!
//! - **types**: `ZeroizedBytes`, `SecurityLevel`, `UseCase`, `CryptoScheme`, etc.
//! - **traits**: `Encryptable`, `Decryptable`, `Signable`, `Verifiable`, `SchemeSelector`, etc.
//! - **config**: `CoreConfig`, `EncryptionConfig`, `SignatureConfig`, etc.
//! - **key_lifecycle**: `KeyStateMachine`, `KeyLifecycleRecord` (with Kani proofs)
//! - **selector**: `CryptoPolicyEngine` and scheme constants
//! - **zero_trust**: `TrustLevel` enum
//! - **error**: `TypeError` for pure-Rust error conditions
//!
//! ## What's NOT Here (lives in `unified_api`)
//!
//! - `CryptoConfig<'a>` (references `VerifiedSession` which uses Ed25519 FFI)
//! - `CoreError` (has `#[from]` variants for FFI error types)
//! - Zero-trust sessions, challenges, proofs (Ed25519 FFI)
//! - Actual cryptographic operations (encrypt, decrypt, sign, verify)

/// Configuration types for cryptographic operations.
pub mod config;
/// Type-safe encryption types for the unified API.
pub mod crypto_types;
/// Domain separation constants for HKDF key derivation.
pub mod domains;
/// Error types for pure-Rust operations.
pub mod error;
/// Key lifecycle management per NIST SP 800-57.
pub mod key_lifecycle;
/// Resource limits for cryptographic operations (DoS prevention).
pub mod resource_limits;
/// Cryptographic policy engine for intelligent scheme selection.
pub mod selector;
/// Core traits for cryptographic operations.
pub mod traits;
/// Fundamental cryptographic types.
#[allow(clippy::module_inception)]
pub mod types;
/// Pure-Rust zero-trust types.
pub mod zero_trust;

// Re-export commonly used items at crate root
pub use config::{
    CoreConfig, EncryptionConfig, HardwareConfig, ProofComplexity, SignatureConfig, UseCaseConfig,
    ZeroTrustConfig,
};
pub use crypto_types::{
    DecryptKey, EncryptKey, EncryptedOutput, EncryptionScheme, HybridComponents,
};
pub use error::{Result, TypeError};
pub use key_lifecycle::{
    CustodianRole, KeyCustodian, KeyLifecycleRecord, KeyLifecycleState, KeyStateMachine,
    StateTransition,
};
pub use selector::{
    CHACHA20_POLY1305, CLASSICAL_AES_GCM, CLASSICAL_ED25519, CLASSICAL_FALLBACK_SIZE_THRESHOLD,
    CryptoPolicyEngine, DEFAULT_ENCRYPTION_SCHEME, DEFAULT_PQ_ENCRYPTION_SCHEME,
    DEFAULT_PQ_SIGNATURE_SCHEME, DEFAULT_SIGNATURE_SCHEME, HYBRID_ENCRYPTION_512,
    HYBRID_ENCRYPTION_768, HYBRID_ENCRYPTION_1024, HYBRID_SIGNATURE_44, HYBRID_SIGNATURE_65,
    HYBRID_SIGNATURE_87, PQ_ENCRYPTION_512, PQ_ENCRYPTION_768, PQ_ENCRYPTION_1024, PQ_SIGNATURE_44,
    PQ_SIGNATURE_65, PQ_SIGNATURE_87, PerformanceMetrics,
};
pub use traits::{
    AsyncDecryptable, AsyncEncryptable, AsyncSignable, AsyncVerifiable, ContinuousVerifiable,
    DataCharacteristics, Decryptable, Encryptable, HardwareAccelerator, HardwareAware,
    HardwareCapabilities, HardwareInfo, HardwareType, KeyDerivable, PatternType, ProofOfPossession,
    SchemeSelector, Signable, Verifiable, VerificationStatus, ZeroTrustAuthenticable,
};
pub use types::{
    AlgorithmSelection, ComplianceMode, CryptoContext, CryptoPayload, CryptoScheme, EncryptedData,
    EncryptedMetadata, HashOutput, KeyPair, PerformancePreference, PrivateKey, PublicKey,
    SecurityLevel, SignedData, SignedMetadata, SymmetricKey, UseCase, ZeroizedBytes,
    fips_available,
};
pub use zero_trust::TrustLevel;
