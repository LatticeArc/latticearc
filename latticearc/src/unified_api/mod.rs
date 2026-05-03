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
//! - **Hardware Traits**: Type definitions for hardware-capability dispatch
//!   (see [`crate::types::traits::HardwareInfo`])
//! - **Zero-Trust Authentication**: Challenge-response with continuous verification
//! - **FIPS 140-3 Compliance**: Power-up self-tests and validated implementations
//! - **Unified API**: Single API with `SecurityMode` parameter for verified/unverified operations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! // All entry points are re-exported at the crate root — prefer the short
//! // path `latticearc::{...}` over the internal `latticearc::unified_api::{...}`.
//! use latticearc::{
//!     encrypt, decrypt, CryptoConfig, VerifiedSession, generate_keypair,
//!     EncryptKey, DecryptKey, CoreError,
//! };
//!
//! # fn main() -> Result<(), CoreError> {
//! // Generate a keypair for session establishment
//! let (public_key, private_key) = generate_keypair()?;
//!
//! // Establish a Zero Trust verified session (recommended)
//! let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
//!
//! // Symmetric encryption with session verification.
//! // Generate a fresh 256-bit key from the OS CSPRNG; AEAD constructors
//! // reject all-zero keys (e.g. `[0u8; 32]`) per the McGrew/Viega NIST
//! // AES-GCM weak-key check.
//! let key = latticearc::primitives::rand::random_bytes(32);
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
//! let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
//!
//! // Step 3: Use the session for cryptographic operations.
//! // (`[0u8; 32]` is rejected by the AES-GCM constructor as a weak key —
//! // generate fresh random bytes instead.)
//! let key = latticearc::primitives::rand::random_bytes(32);
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
//! use latticearc::primitives::rand::random_bytes;
//!
//! # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
//! // Fresh 256-bit AES-GCM key — never reuse `[0u8; 32]`, the weak-key
//! // check rejects it.
//! let key = random_bytes(32);
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
//! let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())?;
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
//! use latticearc::{
//!     encrypt, CryptoConfig, VerifiedSession, CoreError, EncryptKey,
//!     EncryptedOutput, HybridKemPublicKey,
//! };
//!
//! fn perform_crypto_operation(
//!     session: &VerifiedSession,
//!     data: &[u8],
//!     pk: &HybridKemPublicKey,
//! ) -> Result<EncryptedOutput, CoreError> {
//!     // Validate session before operation
//!     session.verify_valid()?;  // Returns Err(SessionExpired) if expired
//!
//!     encrypt(data, EncryptKey::Hybrid(pk), CryptoConfig::new().session(session))
//! }
//! ```

/// Atomic + permission-restricted file writes for keys and CLI output.
pub mod atomic_write;
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
    PublicKey, SecretBytes, SecretVec, SecurityLevel, SignedData, SignedMetadata, SymmetricKey,
    UseCase, fips_available,
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

    // Test 2: AES-256-GCM Known Answer Tests against fixed NIST CAVP
    // vectors. Source: NIST Cryptographic Algorithm Validation Program
    // GCM Test Vectors, file `gcmEncryptExtIV256.rsp`. Two vectors are
    // verified — Count=0 covers the empty-PT path (GHASH-only) and
    // Count=12 covers the non-empty-PT path (exercises the AES round
    // function and counter-mode increment that the empty-PT KAT can't
    // reach). Each vector goes through encrypt + tag-check + decrypt
    // round-trip, catching backend miscompilation, table corruption,
    // S-box errors, and any drift in AesGcm256's wrapper logic —
    // failure modes a randomized roundtrip could not detect.
    use crate::primitives::aead::AeadCipher;
    use crate::primitives::aead::aes_gcm::AesGcm256;

    /// One AES-256-GCM CAVP vector for the boot-time KAT.
    struct AesGcm256Kat {
        /// Source label for error messages, e.g. `"Count=0"`.
        name: &'static str,
        /// 256-bit AES key.
        key: &'static [u8; 32],
        /// 96-bit IV.
        nonce: &'static [u8; 12],
        /// Plaintext (may be empty).
        plaintext: &'static [u8],
        /// Expected ciphertext; same length as plaintext.
        expected_ct: &'static [u8],
        /// Expected 128-bit GMAC authentication tag.
        expected_tag: &'static [u8; 16],
    }

    const AES_GCM_KAT_VECTORS: &[AesGcm256Kat] = &[
        // Count = 0: empty PT, empty AAD. Catches GHASH miscompilation
        // but not AES round-function or counter-mode bugs.
        //   Key   = b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4
        //   IV    = 516c33929df5a3284ff463d7
        //   PT    = (empty)
        //   AAD   = (empty)
        //   CT    = (empty)
        //   Tag   = bdc1ac884d332457a1d2664f168c76f0
        AesGcm256Kat {
            name: "Count=0",
            key: &[
                0xb5, 0x2c, 0x50, 0x5a, 0x37, 0xd7, 0x8e, 0xda, 0x5d, 0xd3, 0x4f, 0x20, 0xc2, 0x25,
                0x40, 0xea, 0x1b, 0x58, 0x96, 0x3c, 0xf8, 0xe5, 0xbf, 0x8f, 0xfa, 0x85, 0xf9, 0xf2,
                0x49, 0x25, 0x05, 0xb4,
            ],
            nonce: &[0x51, 0x6c, 0x33, 0x92, 0x9d, 0xf5, 0xa3, 0x28, 0x4f, 0xf4, 0x63, 0xd7],
            plaintext: &[],
            expected_ct: &[],
            expected_tag: &[
                0xbd, 0xc1, 0xac, 0x88, 0x4d, 0x33, 0x24, 0x57, 0xa1, 0xd2, 0x66, 0x4f, 0x16, 0x8c,
                0x76, 0xf0,
            ],
        },
        // Count = 12: 128-bit PT, empty AAD. Exercises the AES round
        // function and counter-mode increment paths.
        //   Key   = 31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22
        //   IV    = 0d18e06c7c725ac9e362e1ce
        //   PT    = 2db5168e932556f8089a0622981d017d
        //   AAD   = (empty)
        //   CT    = fa4362189661d163fcd6a56d8bf0405a
        //   Tag   = d636ac1bbedd5cc3ee727dc2ab4a9489
        AesGcm256Kat {
            name: "Count=12",
            key: &[
                0x31, 0xbd, 0xad, 0xd9, 0x66, 0x98, 0xc2, 0x04, 0xaa, 0x9c, 0xe1, 0x44, 0x8e, 0xa9,
                0x4a, 0xe1, 0xfb, 0x4a, 0x9a, 0x0b, 0x3c, 0x9d, 0x77, 0x3b, 0x51, 0xbb, 0x18, 0x22,
                0x66, 0x6b, 0x8f, 0x22,
            ],
            nonce: &[0x0d, 0x18, 0xe0, 0x6c, 0x7c, 0x72, 0x5a, 0xc9, 0xe3, 0x62, 0xe1, 0xce],
            plaintext: &[
                0x2d, 0xb5, 0x16, 0x8e, 0x93, 0x25, 0x56, 0xf8, 0x08, 0x9a, 0x06, 0x22, 0x98, 0x1d,
                0x01, 0x7d,
            ],
            expected_ct: &[
                0xfa, 0x43, 0x62, 0x18, 0x96, 0x61, 0xd1, 0x63, 0xfc, 0xd6, 0xa5, 0x6d, 0x8b, 0xf0,
                0x40, 0x5a,
            ],
            expected_tag: &[
                0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2, 0xab, 0x4a,
                0x94, 0x89,
            ],
        },
    ];

    for kat in AES_GCM_KAT_VECTORS {
        let cipher = AesGcm256::new(kat.key).map_err(|e| CoreError::SelfTestFailed {
            component: "AES-GCM".to_string(),
            status: format!("{} key creation failed: {e}", kat.name),
        })?;

        // Encrypt-side: ciphertext + tag must match expected exactly.
        let (ct, tag) = cipher.encrypt(kat.nonce, kat.plaintext, None).map_err(|e| {
            CoreError::SelfTestFailed {
                component: "AES-GCM".to_string(),
                status: format!("{} encryption failed: {e}", kat.name),
            }
        })?;
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&ct[..], kat.expected_ct)) {
            return Err(CoreError::SelfTestFailed {
                component: "AES-GCM".to_string(),
                status: format!(
                    "{} ciphertext mismatch (AES round-function or CTR-mode bug)",
                    kat.name
                ),
            });
        }
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&tag[..], &kat.expected_tag[..])) {
            return Err(CoreError::SelfTestFailed {
                component: "AES-GCM".to_string(),
                status: format!("{} tag mismatch", kat.name),
            });
        }

        // Decrypt-side: round-trip the expected (CT, tag) back to the
        // expected plaintext.
        let decrypted = cipher
            .decrypt(kat.nonce, kat.expected_ct, kat.expected_tag, None)
            .map_err(|e| CoreError::SelfTestFailed {
                component: "AES-GCM".to_string(),
                status: format!("{} decryption failed: {e}", kat.name),
            })?;
        if !bool::from(subtle::ConstantTimeEq::ct_eq(decrypted.as_slice(), kat.plaintext)) {
            return Err(CoreError::SelfTestFailed {
                component: "AES-GCM".to_string(),
                status: format!("{} decrypted plaintext mismatch", kat.name),
            });
        }
    }

    // Test 3: Ed25519 keypair sign/verify roundtrip plus a tamper
    // check. Discarding `generate_keypair()`'s result (the previous
    // behaviour) only proved that key generation didn't error and
    // left the signing/verify hot path untested at startup. Exercise
    // the full path so a regression in either signing or verification
    // surfaces during init rather than under a real workload.
    use crate::primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature};
    use crate::primitives::ec::traits::{EcKeyPair, EcSignature};
    const TEST_MESSAGE: &[u8] = b"latticearc-power-on-self-test-message-v1";
    let keypair = Ed25519KeyPair::generate().map_err(|e| CoreError::SelfTestFailed {
        component: "Ed25519 Keypair".to_string(),
        status: format!("keygen failed: {e}"),
    })?;
    let signature = keypair.sign(TEST_MESSAGE).map_err(|e| CoreError::SelfTestFailed {
        component: "Ed25519 Sign/Verify".to_string(),
        status: format!("Ed25519 sign failed at startup: {e}"),
    })?;
    let public_key_bytes = keypair.public_key_bytes();
    Ed25519Signature::verify(&public_key_bytes, TEST_MESSAGE, &signature).map_err(|e| {
        CoreError::SelfTestFailed {
            component: "Ed25519 Sign/Verify".to_string(),
            status: format!("valid signature was rejected at startup: {e}"),
        }
    })?;
    // Negative check: a one-byte change to the message must invalidate
    // the signature, confirming `verify()` actually checks rather than
    // returning `Ok(())` unconditionally. `TEST_MESSAGE` is a fixed-
    // length non-empty literal, so `get_mut(0)` is provably-Some.
    let mut tampered = TEST_MESSAGE.to_vec();
    if let Some(b) = tampered.get_mut(0) {
        *b ^= 0xFF;
    }
    if Ed25519Signature::verify(&public_key_bytes, &tampered, &signature).is_ok() {
        return Err(CoreError::SelfTestFailed {
            component: "Ed25519 Sign/Verify".to_string(),
            status: "tampered message was incorrectly accepted at startup".to_string(),
        });
    }

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
    unused_qualifications
)]
mod tests;

#[cfg(test)]
pub(crate) mod test_helpers;
