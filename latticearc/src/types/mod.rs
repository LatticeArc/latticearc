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
//! - **traits**: `ZeroTrustAuthenticable`, `ProofOfPossession`, `ContinuousVerifiable`,
//!   `SchemeSelector`, `VerificationStatus`, `DataCharacteristics`, `PatternType`.
//! - **config**: `CoreConfig`, `EncryptionConfig`, `SignatureConfig`, etc.
//! - **key_lifecycle**: `KeyStateMachine`, `KeyLifecycleRecord` (with Kani proofs)
//! - **zero_trust**: `TrustLevel` enum
//! - **error**: `TypeError` for pure-Rust error conditions
//!
//! ## What's NOT Here (lives in `unified_api`)
//!
//! - `CryptoConfig<'a>` (references `VerifiedSession` which uses Ed25519 FFI)
//! - `CoreError` (has `#[from]` variants for FFI error types)
//! - Zero-trust sessions, challenges, proofs (Ed25519 FFI)
//! - Actual cryptographic operations (encrypt, decrypt, sign, verify)
//! - `CryptoPolicyEngine` and `EncryptionScheme` (depend on hybrid/primitives)

/// Configuration types for cryptographic operations.
pub mod config;
/// Domain separation constants for HKDF key derivation.
pub mod domains;
/// Error types for pure-Rust operations.
pub mod error;
/// Key lifecycle management per NIST SP 800-57.
pub mod key_lifecycle;
/// Core traits for cryptographic operations.
pub mod traits;
/// Fundamental cryptographic types.
#[allow(clippy::module_inception)]
pub mod types;
/// Pure-Rust zero-trust types.
pub mod zero_trust;

// Re-export commonly used items at crate root
#[allow(deprecated)]
pub use config::{
    CoreConfig, EncryptionConfig, HardwareConfig, ProofComplexity, SignatureConfig, UseCaseConfig,
    ZeroTrustConfig,
};
pub use error::{Result, TypeError};
pub use key_lifecycle::{
    CustodianRole, KeyCustodian, KeyLifecycleRecord, KeyLifecycleState, KeyStateMachine,
    StateTransition,
};
pub use traits::{
    ContinuousVerifiable, DataCharacteristics, HardwareCapabilities, HardwareInfo, HardwareType,
    PatternType, ProofOfPossession, SchemeSelector, VerificationStatus, ZeroTrustAuthenticable,
};
pub use types::{
    AlgorithmSelection, ComplianceMode, CryptoContext, CryptoPayload, CryptoScheme, EncryptedData,
    EncryptedMetadata, HashOutput, KeyPair, PerformancePreference, PrivateKey, PublicKey,
    SecurityLevel, SignedData, SignedMetadata, SymmetricKey, UseCase, ZeroizedBytes,
    fips_available,
};
pub use zero_trust::TrustLevel;
