//! # LatticeArc Unified API
//!
//! Unified cryptographic API for the LatticeArc post-quantum cryptography platform.
//! Provides unified APIs for encryption, decryption, signing, verification, and
//! use case-based scheme selection.
//!
//! ## Key Features
//!
//! - **Post-Quantum Cryptography**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
//! - **Hybrid Schemes**: Combined PQC + classical for defense in depth
//! - **Hardware Traits**: Type definitions for hardware-aware operations
//! - **Zero-Trust Authentication**: Challenge-response with continuous verification
//! - **FIPS 140-3 Compliance**: Power-up self-tests and validated implementations
//! - **Unified API**: Single API with `SecurityMode` parameter for verified/unverified operations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use latticearc::unified_api::{
//!     encrypt, decrypt, CryptoConfig, VerifiedSession, generate_keypair,
//!     EncryptKey, DecryptKey,
//! };
//!
//! # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
//! // Generate a keypair for session establishment
//! let (public_key, private_key) = generate_keypair()?;
//!
//! // Establish a Zero Trust verified session (recommended)
//! let session = VerifiedSession::establish(public_key.as_slice(), private_key.as_ref())?;
//!
//! // Symmetric encryption with session verification
//! let key = [0u8; 32];
//! let encrypted = encrypt(b"secret", EncryptKey::Symmetric(&key),
//!     CryptoConfig::new().session(&session)
//!         .force_scheme(latticearc::CryptoScheme::Symmetric))?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key),
//!     CryptoConfig::new().session(&session))?;
//!
//! // Hybrid encryption (ML-KEM-768 + X25519 + HKDF + AES-256-GCM)
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new().session(&session))?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk),
//!     CryptoConfig::new().session(&session))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## SecurityMode API
//!
//! The `SecurityMode` enum is the core abstraction for Zero Trust cryptographic operations.
//! All cryptographic functions accept a `SecurityMode` parameter that controls verification
//! behavior.
//!
//! ### SecurityMode::Verified(&session)
//!
//! Use `Verified` mode with a reference to a [`VerifiedSession`] for production use:
//!
//! ```rust,no_run
//! use latticearc::unified_api::{encrypt_aes_gcm, SecurityMode, VerifiedSession, generate_keypair};
//!
//! # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
//! // Step 1: Generate credentials (done once, typically at provisioning)
//! let (public_key, private_key) = generate_keypair()?;
//!
//! // Step 2: Establish a verified session (performs challenge-response)
//! let session = VerifiedSession::establish(public_key.as_slice(), private_key.as_ref())?;
//!
//! // Step 3: Use the session for cryptographic operations
//! let key = [0u8; 32];
//! let ciphertext = encrypt_aes_gcm(b"sensitive data", &key, SecurityMode::Verified(&session))?;
//!
//! // The session can be reused for multiple operations until it expires
//! let ciphertext2 = encrypt_aes_gcm(b"more data", &key, SecurityMode::Verified(&session))?;
//!
//! // Check session validity before long-running operations
//! if session.is_valid() {
//!     // Session has not expired
//! }
//! # Ok(())
//! # }
//! ```
//!
//! **What Verified mode provides:**
//! - Session validation (checks expiration before each operation)
//! - Audit trail with session context (session ID, trust level)
//! - Extensible for policy enforcement and HSM integration
//!
//! ### SecurityMode::Unverified
//!
//! Use `Unverified` mode for opt-out scenarios where Zero Trust is not applicable:
//!
//! ```rust,no_run
//! use latticearc::unified_api::{encrypt_aes_gcm, SecurityMode};
//!
//! # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
//! let key = [0u8; 32];
//!
//! // Opt-out: No session verification performed
//! let ciphertext = encrypt_aes_gcm(b"data", &key, SecurityMode::Unverified)?;
//! # Ok(())
//! # }
//! ```
//!
//! **When to use Unverified mode:**
//! - Legacy system integration where session management is not possible
//! - Batch processing of non-sensitive data
//! - Development and testing scenarios
//! - One-off operations where session overhead is not justified
//!
//! ## Establishing a VerifiedSession
//!
//! A [`VerifiedSession`] is created through Zero Trust authentication, which proves
//! possession of the private key via challenge-response:
//!
//! ### Quick Method (Recommended)
//!
//! ```rust,no_run
//! use latticearc::unified_api::{VerifiedSession, generate_keypair};
//!
//! # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
//! let (pk, sk) = generate_keypair()?;
//! let session = VerifiedSession::establish(pk.as_slice(), sk.as_ref())?;
//!
//! // Session is valid for 30 minutes by default
//! assert!(session.is_valid());
//! assert!(session.trust_level().is_trusted());
//! # Ok(())
//! # }
//! ```
//!
//! ### Manual Method (Advanced)
//!
//! For custom authentication flows:
//!
//! ```no_run
//! # use latticearc::unified_api::{ZeroTrustAuth, ZeroTrustSession, generate_keypair};
//! # use latticearc::unified_api::error::CoreError;
//! # fn main() -> Result<(), CoreError> {
//! let (pk, sk) = generate_keypair()?;
//!
//! // Create authentication handler
//! let auth = ZeroTrustAuth::new(pk.clone(), sk)?;
//! let mut session = ZeroTrustSession::new(auth);
//!
//! // Initiate challenge-response
//! let challenge = session.initiate_authentication()?;
//!
//! // Generate and verify proof (in real systems, proof is sent to verifier)
//! let proof = session.generate_proof(&challenge)?;
//! session.verify_response(&proof)?;
//!
//! // Convert to VerifiedSession
//! let verified = session.into_verified()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Session Lifecycle
//!
//! Sessions have a limited lifetime (30 minutes by default) and should be:
//!
//! 1. **Created** at the start of a user session or workflow
//! 2. **Reused** for multiple operations within the same session
//! 3. **Validated** before critical operations using `session.is_valid()`
//! 4. **Refreshed** by establishing a new session when expired
//!
//! ```rust,no_run
//! use latticearc::unified_api::{encrypt, CryptoConfig, VerifiedSession, CoreError, EncryptKey, EncryptedOutput};
//!
//! fn perform_crypto_operation(
//!     session: &VerifiedSession,
//!     data: &[u8],
//!     pk: &latticearc::hybrid::kem_hybrid::HybridKemPublicKey,
//! ) -> Result<EncryptedOutput, CoreError> {
//!     // Validate session before operation
//!     session.verify_valid()?;  // Returns Err(SessionExpired) if expired
//!
//!     encrypt(data, EncryptKey::Hybrid(pk), CryptoConfig::new().session(session))
//! }
//! ```

/// Persistent audit storage with rotation and integrity verification.
pub mod audit;
/// Convenience APIs for high-level cryptographic operations.
pub mod convenience;
/// Type-safe encryption scheme types (EncryptKey, DecryptKey, EncryptionScheme, EncryptedOutput).
pub mod crypto_types;
/// Error types and result aliases.
pub mod error;
/// Portable key serialization format (v1).
pub mod key_format;
/// Security-conscious logging utilities.
pub mod logging;
/// Cryptographic policy engine for policy-based scheme selection.
pub mod selector;
/// Serialization utilities for cryptographic types.
pub mod serialization;
/// Fundamental cryptographic types.
pub mod types;
/// Zero-trust authentication primitives.
pub mod zero_trust;

use std::sync::atomic::{AtomicBool, Ordering};

pub use crate::types::config::{
    CoreConfig, EncryptionConfig, ProofComplexity, SignatureConfig, UseCaseConfig, ZeroTrustConfig,
};
pub use audit::{
    AuditConfig, AuditEvent, AuditEventBuilder, AuditEventType, AuditOutcome, AuditStorage,
    FileAuditStorage,
};
pub use error::{CoreError, Result};
// Hardware types re-exported directly from traits (there is no `hardware` submodule).
pub use crate::types::key_lifecycle::{
    CustodianRole, KeyCustodian, KeyLifecycleRecord, KeyLifecycleState, KeyStateMachine,
    StateTransition,
};
pub use crate::types::traits::{
    ContinuousVerifiable, DataCharacteristics, HardwareCapabilities, HardwareInfo, HardwareType,
    PatternType, ProofOfPossession, SchemeSelector, VerificationStatus, ZeroTrustAuthenticable,
};
pub use selector::{
    // Classical schemes
    CLASSICAL_AES_GCM,
    CLASSICAL_ED25519,
    // Policy engine
    CryptoPolicyEngine,
    // Hybrid schemes (default)
    DEFAULT_ENCRYPTION_SCHEME,
    // PQ-only schemes
    DEFAULT_PQ_ENCRYPTION_SCHEME,
    DEFAULT_PQ_SIGNATURE_SCHEME,
    DEFAULT_SIGNATURE_SCHEME,
    HYBRID_ENCRYPTION_512,
    HYBRID_ENCRYPTION_768,
    HYBRID_ENCRYPTION_1024,
    HYBRID_SIGNATURE_44,
    HYBRID_SIGNATURE_65,
    HYBRID_SIGNATURE_87,
    PQ_ENCRYPTION_512,
    PQ_ENCRYPTION_768,
    PQ_ENCRYPTION_1024,
    PQ_SIGNATURE_44,
    PQ_SIGNATURE_65,
    PQ_SIGNATURE_87,
    PerformanceMetrics,
};
pub use types::{
    AlgorithmSelection, ComplianceMode, CryptoConfig, CryptoContext, CryptoMode, CryptoPayload,
    CryptoScheme, DecryptKey, EncryptKey, EncryptedData, EncryptedMetadata, EncryptedOutput,
    EncryptionScheme, HashOutput, HybridComponents, KeyPair, PerformancePreference, PrivateKey,
    PublicKey, SecurityLevel, SignedData, SignedMetadata, SymmetricKey, UseCase, ZeroizedBytes,
    fips_available,
};
pub use zero_trust::{
    Challenge, ContinuousSession, ProofOfPossessionData, SecurityMode, TrustLevel, VerifiedSession,
    ZeroKnowledgeProof, ZeroTrustAuth, ZeroTrustSession,
};

// ============================================================================
// Unified API (recommended)
// ============================================================================

pub use convenience::{decrypt, encrypt, generate_signing_keypair, sign_with_key, verify};

// ============================================================================
// Hybrid Key Generation
// ============================================================================

pub use convenience::{generate_hybrid_keypair, generate_hybrid_keypair_with_level};

// ============================================================================
// Hybrid Signatures (ML-DSA-65 + Ed25519)
// ============================================================================

pub use convenience::{
    generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_with_config, sign_hybrid,
    sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_with_config,
};

// ============================================================================
// Key Generation
// ============================================================================

pub use convenience::{
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config,
    generate_fn_dsa_keypair_with_level, generate_keypair, generate_keypair_with_config,
    generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config, generate_ml_kem_keypair,
    generate_ml_kem_keypair_with_config, generate_slh_dsa_keypair,
    generate_slh_dsa_keypair_with_config,
};

// ============================================================================
// Hashing
// ============================================================================

pub use convenience::{
    derive_key, derive_key_with_config, derive_key_with_info, hash_data, hmac, hmac_check,
    hmac_check_with_config, hmac_with_config,
};

// ============================================================================
// Low-Level Primitives (for advanced use cases)
// ============================================================================

pub use convenience::{
    // AES-GCM
    decrypt_aes_gcm,
    decrypt_aes_gcm_with_aad,
    decrypt_aes_gcm_with_config,
    // PQ KEM (ML-KEM)
    decrypt_pq_ml_kem,
    decrypt_pq_ml_kem_with_config,
    encrypt_aes_gcm,
    encrypt_aes_gcm_with_aad,
    encrypt_aes_gcm_with_config,
    encrypt_pq_ml_kem,
    encrypt_pq_ml_kem_with_config,
    // Ed25519
    sign_ed25519,
    sign_ed25519_with_config,
    // PQ Signatures (ML-DSA, SLH-DSA, FN-DSA)
    sign_pq_fn_dsa,
    sign_pq_fn_dsa_with_config,
    sign_pq_ml_dsa,
    sign_pq_ml_dsa_with_config,
    sign_pq_slh_dsa,
    sign_pq_slh_dsa_with_config,
    verify_ed25519,
    verify_ed25519_with_config,
    verify_pq_fn_dsa,
    verify_pq_fn_dsa_with_config,
    verify_pq_ml_dsa,
    verify_pq_ml_dsa_with_config,
    verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config,
};

// ============================================================================
// Unverified Variants (for low-level primitives)
// ============================================================================

pub use convenience::{
    // AES-GCM
    decrypt_aes_gcm_unverified,
    decrypt_aes_gcm_with_aad_unverified,
    decrypt_aes_gcm_with_config_unverified,
    // PQ KEM
    decrypt_pq_ml_kem_unverified,
    decrypt_pq_ml_kem_with_config_unverified,
    // Hashing
    derive_key_unverified,
    derive_key_with_config_unverified,
    derive_key_with_info_unverified,
    encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_aad_unverified,
    encrypt_aes_gcm_with_config_unverified,
    encrypt_pq_ml_kem_unverified,
    encrypt_pq_ml_kem_with_config_unverified,
    // Hybrid Signatures (ML-DSA-65 + Ed25519)
    generate_hybrid_signing_keypair_unverified,
    hmac_check_unverified,
    hmac_check_with_config_unverified,
    hmac_unverified,
    hmac_with_config_unverified,
    // Ed25519
    sign_ed25519_unverified,
    sign_ed25519_with_config_unverified,
    sign_hybrid_unverified,
    // PQ Signatures
    sign_pq_fn_dsa_unverified,
    sign_pq_fn_dsa_with_config_unverified,
    sign_pq_ml_dsa_unverified,
    sign_pq_ml_dsa_with_config_unverified,
    sign_pq_slh_dsa_unverified,
    sign_pq_slh_dsa_with_config_unverified,
    verify_ed25519_unverified,
    verify_ed25519_with_config_unverified,
    verify_hybrid_signature_unverified,
    verify_pq_fn_dsa_unverified,
    verify_pq_fn_dsa_with_config_unverified,
    verify_pq_ml_dsa_unverified,
    verify_pq_ml_dsa_with_config_unverified,
    verify_pq_slh_dsa_unverified,
    verify_pq_slh_dsa_with_config_unverified,
};

// HardwareAware is re-exported from traits below

/// Library version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// FIPS 140-3 self-test status - must pass before any crypto operations
static SELF_TESTS_PASSED: AtomicBool = AtomicBool::new(false);

/// Initializes the LatticeArc library with default configuration.
///
/// This function validates the default configuration and runs FIPS 140-3
/// power-up self-tests to ensure cryptographic primitives are working correctly.
///
/// # Errors
///
/// Returns an error if:
/// - The default configuration fails validation (should not happen with defaults)
/// - Any FIPS 140-3 power-up self-test fails (SHA-3 KAT, AES-GCM, or keypair generation)
pub fn init() -> Result<()> {
    let config = CoreConfig::default();
    config.validate()?;

    // Run FIPS 140-3 power-up self-tests
    run_power_up_self_tests()?;

    Ok(())
}

/// Initializes the LatticeArc library with a custom configuration.
///
/// This function validates the provided configuration and runs FIPS 140-3
/// power-up self-tests to ensure cryptographic primitives are working correctly.
///
/// # Errors
///
/// Returns an error if:
/// - The provided configuration fails validation (e.g., conflicting security
///   and performance preferences)
/// - Any FIPS 140-3 power-up self-test fails (SHA-3 KAT, AES-GCM, or keypair generation)
pub fn init_with_config(config: &CoreConfig) -> Result<()> {
    config.validate()?;

    // Run FIPS 140-3 power-up self-tests
    run_power_up_self_tests()?;

    Ok(())
}

/// Check if FIPS 140-3 self-tests have passed
#[must_use]
pub fn self_tests_passed() -> bool {
    SELF_TESTS_PASSED.load(Ordering::SeqCst)
}

/// Run FIPS 140-3 power-up self-tests
fn run_power_up_self_tests() -> Result<()> {
    // Test 1: SHA-3 KAT — routed through the primitives wrapper so the
    // self-test exercises the same call path production code uses, rather
    // than a bare `sha3::Sha3_256` instance that could diverge over time.
    let hash = crate::primitives::hash::sha3::sha3_256(b"abc");
    let expected_sha3 = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    if !bool::from(subtle::ConstantTimeEq::ct_eq(hash.as_slice(), expected_sha3.as_slice())) {
        return Err(CoreError::SelfTestFailed {
            component: "SHA-3".to_string(),
            status: "KAT failed".to_string(),
        });
    }

    // Test 2: AES-GCM encryption/decryption via the primitives wrapper.
    // Going through AesGcm256 ensures the self-test exercises the same path
    // that production crypto code uses (ZeroizeOnDrop, zero-key warning, etc.),
    // not a bare aws-lc-rs call that could diverge over time.
    use crate::primitives::aead::AeadCipher;
    use crate::primitives::aead::aes_gcm::AesGcm256;

    let key = AesGcm256::generate_key();
    let cipher = AesGcm256::new(&*key).map_err(|e| CoreError::SelfTestFailed {
        component: "AES-GCM".to_string(),
        status: format!("key creation failed: {e}"),
    })?;
    let nonce = AesGcm256::generate_nonce();

    let plaintext = b"test message for AES-GCM";
    let (ct, tag) =
        cipher.encrypt(&nonce, plaintext, None).map_err(|e| CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: format!("encryption failed: {e}"),
        })?;
    let decrypted =
        cipher.decrypt(&nonce, &ct, &tag, None).map_err(|e| CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: format!("decryption failed: {e}"),
        })?;

    if !bool::from(subtle::ConstantTimeEq::ct_eq(decrypted.as_slice(), &plaintext[..])) {
        return Err(CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: "decryption mismatch".to_string(),
        });
    }

    // Test 3: Basic keypair generation
    generate_keypair()?;

    // All tests passed - set self-test status
    SELF_TESTS_PASSED.store(true, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications,
    deprecated
)]
mod tests;
