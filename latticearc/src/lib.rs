#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! LatticeArc - Post-Quantum Cryptography Library
//!
//! Comprehensive post-quantum cryptography library providing advanced encryption,
//! digital signatures, and security features for modern applications.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use [`SecurityMode`] to specify verification behavior.
//! This is the core abstraction for Zero Trust cryptographic operations.
//!
//! ### Basic Usage
//!
//! ```rust,ignore
//! use latticearc::{encrypt, decrypt, SecurityMode, VerifiedSession, generate_keypair};
//!
//! // Step 1: Generate a keypair (done once, typically at provisioning)
//! let (pk, sk) = generate_keypair()?;
//!
//! // Step 2: Establish a verified session (performs challenge-response)
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // Step 3: Perform cryptographic operations with SecurityMode
//! let key = [0u8; 32];
//! let encrypted = encrypt(b"secret", &key, SecurityMode::Verified(&session))?;
//! let decrypted = decrypt(&encrypted, &key, SecurityMode::Verified(&session))?;
//! ```
//!
//! ## SecurityMode Variants
//!
//! ### SecurityMode::Verified(&session)
//!
//! The recommended mode for production use. Requires a [`VerifiedSession`] reference:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, sign, SecurityMode, VerifiedSession, generate_keypair};
//!
//! let (pk, sk) = generate_keypair()?;
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // All operations validate the session before proceeding
//! let key = [0u8; 32];
//! let ciphertext = encrypt(b"data", &key, SecurityMode::Verified(&session))?;
//! let signature = sign(b"message", &sk, SecurityMode::Verified(&session))?;
//! ```
//!
//! **Benefits of Verified mode:**
//! - Session expiration is checked before each operation
//! - Provides audit context (session ID, trust level, timestamp)
//! - Enables enterprise policy enforcement
//! - Supports continuous verification workflows
//!
//! ### SecurityMode::Unverified
//!
//! Opt-out mode for scenarios where Zero Trust is not applicable:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, SecurityMode};
//!
//! let key = [0u8; 32];
//! let ciphertext = encrypt(b"data", &key, SecurityMode::Unverified)?;
//! ```
//!
//! **Use cases for Unverified mode:**
//! - Legacy system integration
//! - Batch processing of non-sensitive data
//! - Development and testing
//! - Stateless operations where session overhead is not justified
//!
//! **Enterprise warning:** In enterprise deployments, `Unverified` mode triggers
//! mandatory audit logging and may be blocked by security policy.
//!
//! ## Establishing a VerifiedSession
//!
//! [`VerifiedSession`] proves Zero Trust authentication via challenge-response:
//!
//! ```rust,ignore
//! use latticearc::{VerifiedSession, generate_keypair};
//!
//! // Generate credentials
//! let (pk, sk) = generate_keypair()?;
//!
//! // Establish session (performs challenge-response internally)
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // Session properties
//! assert!(session.is_valid());              // Not expired
//! assert!(session.trust_level().is_trusted()); // Trust established
//! let _ = session.session_id();             // Unique ID for audit
//! let _ = session.expires_at();             // When session expires
//! ```
//!
//! ## Session Lifecycle Management
//!
//! Sessions have a 30-minute default lifetime:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, SecurityMode, VerifiedSession, generate_keypair, CoreError};
//!
//! let (pk, sk) = generate_keypair()?;
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // Validate before critical operations
//! session.verify_valid()?;  // Returns Err(SessionExpired) if expired
//!
//! // Or check validity without error
//! if session.is_valid() {
//!     let key = [0u8; 32];
//!     let _ = encrypt(b"data", &key, SecurityMode::Verified(&session))?;
//! } else {
//!     // Refresh session
//!     let new_session = VerifiedSession::establish(&pk, &sk)?;
//! }
//! # Ok::<(), CoreError>(())
//! ```
//!
//! ## Complete Example
//!
//! ```rust,ignore
//! use latticearc::{
//!     encrypt, decrypt, sign, verify,
//!     SecurityMode, VerifiedSession,
//!     generate_keypair, CoreError,
//! };
//!
//! fn secure_workflow() -> Result<(), CoreError> {
//!     // Initialize credentials
//!     let (pk, sk) = generate_keypair()?;
//!
//!     // Establish Zero Trust session
//!     let session = VerifiedSession::establish(&pk, &sk)?;
//!     let mode = SecurityMode::Verified(&session);
//!
//!     // Encrypt sensitive data
//!     let key = [0u8; 32];
//!     let plaintext = b"confidential information";
//!     let ciphertext = encrypt(plaintext, &key, mode)?;
//!
//!     // Sign a message
//!     let message = b"important message";
//!     let signature = sign(message, &sk, mode)?;
//!
//!     // Verify the signature
//!     let is_valid = verify(message, &signature, &pk, mode)?;
//!     assert!(is_valid);
//!
//!     // Decrypt the data
//!     let decrypted = decrypt(&ciphertext, &key, mode)?;
//!     assert_eq!(decrypted, plaintext);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Enterprise Behavior
//!
//! In enterprise deployments (`arc-enterprise`):
//!
//! **`SecurityMode::Verified` enables:**
//! - Per-operation ABAC/RBAC policy enforcement
//! - Continuous verification with trust level tracking
//! - HSM/TPM integration for sensitive key operations
//! - Cryptographic audit trails for compliance (SOC2, HIPAA, etc.)
//!
//! **`SecurityMode::Unverified` triggers:**
//! - Mandatory audit logging (cannot be disabled)
//! - Policy evaluation (operation may be blocked)
//! - Compliance alerts for sensitive data access

pub use arc_core as core;
pub use arc_prelude as prelude;

pub use prelude::*;

// ============================================================================
// Core Types
// ============================================================================

pub use arc_core::{
    Challenge,
    ContinuousSession,
    // Traits
    ContinuousVerifiable,
    // Types
    CoreError,
    CryptoContext,
    CryptoPayload,
    CryptoScheme,
    DataCharacteristics,
    Decryptable,
    Encryptable,
    EncryptedData,
    EncryptedMetadata,
    HardwareAccelerator,
    HardwareAware,
    HardwareCapabilities,
    HardwareInfo,
    HardwareType,
    HashOutput,
    KeyDerivable,
    KeyPair,
    PatternType,
    PerformancePreference,
    PrivateKey,
    ProofOfPossession,
    ProofOfPossessionData,
    PublicKey,
    Result,
    SchemeSelector,
    SecurityLevel,
    // Zero Trust types
    SecurityMode,
    Signable,
    SignedData,
    SignedMetadata,
    SymmetricKey,
    TrustLevel,
    UseCase,
    // Constants
    VERSION,
    Verifiable,
    VerificationStatus,
    VerifiedSession,
    ZeroKnowledgeProof,
    ZeroTrustAuth,
    ZeroTrustAuthenticable,
    ZeroTrustSession,
    ZeroizedBytes,
    // Initialization
    init,
    init_with_config,
};

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

// Core encryption/decryption/signing/verification
pub use arc_core::{
    decrypt, decrypt_with_config, encrypt, encrypt_for_use_case, encrypt_with_config, sign,
    sign_with_config, verify, verify_with_config,
};

// Hybrid encryption
pub use arc_core::{
    HybridEncryptionResult, decrypt_hybrid, decrypt_hybrid_with_config, encrypt_hybrid,
    encrypt_hybrid_with_config,
};

// Key generation (no SecurityMode needed - creates credentials)
pub use arc_core::{generate_keypair, generate_keypair_with_config};

// Hashing (hash_data is stateless, others use SecurityMode)
pub use arc_core::{
    derive_key, derive_key_with_config, hash_data, hmac, hmac_check, hmac_check_with_config,
    hmac_with_config,
};

// AES-GCM
pub use arc_core::{
    decrypt_aes_gcm, decrypt_aes_gcm_with_config, encrypt_aes_gcm, encrypt_aes_gcm_with_config,
};

// Ed25519
pub use arc_core::{
    sign_ed25519, sign_ed25519_with_config, verify_ed25519, verify_ed25519_with_config,
};

// Post-Quantum KEM (ML-KEM)
pub use arc_core::{
    decrypt_pq_ml_kem, decrypt_pq_ml_kem_with_config, encrypt_pq_ml_kem,
    encrypt_pq_ml_kem_with_config,
};

// Post-Quantum Signatures (ML-DSA, SLH-DSA, FN-DSA)
pub use arc_core::{
    sign_pq_fn_dsa, sign_pq_fn_dsa_with_config, sign_pq_ml_dsa, sign_pq_ml_dsa_with_config,
    sign_pq_slh_dsa, sign_pq_slh_dsa_with_config, verify_pq_fn_dsa, verify_pq_fn_dsa_with_config,
    verify_pq_ml_dsa, verify_pq_ml_dsa_with_config, verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config,
};

// ============================================================================
// Deprecated API (Backward Compatibility)
// ============================================================================
// These functions are deprecated. Use the unified API with SecurityMode instead.

#[allow(deprecated)]
pub use arc_core::{
    decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_config_unverified, decrypt_hybrid_unverified,
    decrypt_hybrid_with_config_unverified, decrypt_pq_ml_kem_unverified,
    decrypt_pq_ml_kem_with_config_unverified, decrypt_unverified, decrypt_with_config_unverified,
    derive_key_unverified, derive_key_with_config_unverified, encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_config_unverified, encrypt_for_use_case_unverified,
    encrypt_hybrid_unverified, encrypt_hybrid_with_config_unverified, encrypt_pq_ml_kem_unverified,
    encrypt_pq_ml_kem_with_config_unverified, encrypt_unverified, encrypt_with_config_unverified,
    hmac_check_unverified, hmac_check_with_config_unverified, hmac_unverified,
    hmac_with_config_unverified, sign_ed25519_unverified, sign_ed25519_with_config_unverified,
    sign_pq_fn_dsa_unverified, sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa_unverified,
    sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa_unverified,
    sign_pq_slh_dsa_with_config_unverified, sign_unverified, sign_with_config_unverified,
    verify_ed25519_unverified, verify_ed25519_with_config_unverified, verify_pq_fn_dsa_unverified,
    verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa_unverified,
    verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa_unverified,
    verify_pq_slh_dsa_with_config_unverified, verify_unverified, verify_with_config_unverified,
};

// ============================================================================
// Hardware Accelerators
// ============================================================================

pub use arc_core::{FpgaAccelerator, GpuAccelerator, SgxAccelerator};

// ============================================================================
// Serialization Utilities
// ============================================================================

pub use arc_core::serialization::{
    deserialize_encrypted_data, deserialize_keypair, deserialize_signed_data,
    serialize_encrypted_data, serialize_keypair, serialize_signed_data,
};

// ============================================================================
// Additional Modules
// ============================================================================

/// ZKP primitives
pub use arc_zkp as zkp;

/// Performance utilities
pub use arc_perf as perf;

/// Hybrid encryption
pub use arc_hybrid as hybrid;

/// TLS utilities
pub use arc_tls::{
    TlsConfig, TlsConstraints, TlsContext, TlsMode, TlsPolicyEngine, TlsUseCase, tls_accept,
    tls_connect,
};

/// Unified API module providing main cryptographic functionality.
///
/// All functions in this module use `SecurityMode` to control Zero Trust verification.
pub mod unified_api {
    pub use super::{
        SecurityMode, TrustLevel, VerifiedSession, decrypt, decrypt_hybrid, derive_key, encrypt,
        encrypt_hybrid, generate_keypair, hash_data, hmac, sign, verify,
    };
}
