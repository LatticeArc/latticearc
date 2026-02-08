#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! LatticeArc - Post-Quantum Cryptography Library
//!
//! Comprehensive post-quantum cryptography library providing advanced encryption,
//! digital signatures, and security features for modern applications.
//!
//! ## Unified API with CryptoConfig
//!
//! All cryptographic operations use [`CryptoConfig`] for configuration. This builder
//! pattern provides automatic algorithm selection based on use case or security level,
//! with optional Zero Trust session verification.
//!
//! ### Basic Usage
//!
//! ```rust,ignore
//! use latticearc::{encrypt, decrypt, CryptoConfig};
//!
//! let key = [0u8; 32];  // 256-bit key for AES-256
//! let encrypted = encrypt(b"secret", &key, CryptoConfig::new())?;
//! let decrypted = decrypt(&encrypted, &key, CryptoConfig::new())?;
//! ```
//!
//! ### With Use Case Selection
//!
//! ```rust,ignore
//! use latticearc::{encrypt, CryptoConfig, UseCase};
//!
//! let key = [0u8; 32];
//! // Library automatically selects optimal algorithm for the use case
//! let encrypted = encrypt(b"data", &key, CryptoConfig::new()
//!     .use_case(UseCase::FileStorage))?;
//! ```
//!
//! ### With Security Level
//!
//! ```rust,ignore
//! use latticearc::{encrypt, CryptoConfig, SecurityLevel};
//!
//! let key = [0u8; 32];
//! // Explicit security level control
//! let encrypted = encrypt(b"data", &key, CryptoConfig::new()
//!     .security_level(SecurityLevel::Maximum))?;
//! ```
//!
//! ## Zero Trust Session Verification
//!
//! For production deployments, use [`VerifiedSession`] to enable Zero Trust
//! verification before each operation:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, decrypt, CryptoConfig, VerifiedSession, generate_keypair};
//!
//! // Step 1: Generate a keypair (done once, typically at provisioning)
//! let (pk, sk) = generate_keypair()?;
//!
//! // Step 2: Establish a verified session (performs challenge-response)
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // Step 3: Operations verify session before proceeding
//! let key = [0u8; 32];
//! let encrypted = encrypt(b"secret", &key, CryptoConfig::new().session(&session))?;
//! let decrypted = decrypt(&encrypted, &key, CryptoConfig::new().session(&session))?;
//! ```
//!
//! **Benefits of session verification:**
//! - Session expiration is checked before each operation
//! - Provides audit context (session ID, trust level, timestamp)
//! - Enables enterprise policy enforcement
//! - Supports continuous verification workflows
//!
//! ## Digital Signatures
//!
//! ```rust,ignore
//! use latticearc::{generate_signing_keypair, sign_with_key, verify, CryptoConfig};
//!
//! let message = b"Document to sign";
//!
//! // Generate a persistent signing keypair (ML-DSA-65 + Ed25519 hybrid)
//! let (pk, sk, scheme) = generate_signing_keypair(CryptoConfig::new())?;
//!
//! // Sign with the persistent keypair
//! let signed = sign_with_key(message, &sk, &pk, CryptoConfig::new())?;
//!
//! // Verify (uses public key embedded in SignedData)
//! let is_valid = verify(&signed, CryptoConfig::new())?;
//! ```
//!
//! ## Hybrid Encryption (ML-KEM-768 + X25519)
//!
//! ```rust,ignore
//! use latticearc::{generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid, SecurityMode};
//!
//! // Generate a hybrid keypair (ML-KEM-768 + X25519)
//! let (pk, sk) = generate_hybrid_keypair()?;
//!
//! // Encrypt (ML-KEM encapsulate + X25519 ECDH + HKDF-SHA256 + AES-256-GCM)
//! let encrypted = encrypt_hybrid(b"secret data", &pk, SecurityMode::Unverified)?;
//!
//! // Decrypt
//! let plaintext = decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified)?;
//! ```
//!
//! ## Hybrid Signatures (ML-DSA-65 + Ed25519)
//!
//! ```rust,ignore
//! use latticearc::{generate_hybrid_signing_keypair, sign_hybrid, verify_hybrid_signature, SecurityMode};
//!
//! // Generate a hybrid signing keypair (ML-DSA-65 + Ed25519)
//! let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
//!
//! // Sign (both ML-DSA and Ed25519 signatures generated)
//! let signature = sign_hybrid(b"document", &sk, SecurityMode::Unverified)?;
//!
//! // Verify (both must pass for signature to be valid)
//! let valid = verify_hybrid_signature(b"document", &signature, &pk, SecurityMode::Unverified)?;
//! ```
//!
//! ## Session Lifecycle
//!
//! Sessions have a 30-minute default lifetime:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, CryptoConfig, VerifiedSession, generate_keypair, CoreError};
//!
//! let (pk, sk) = generate_keypair()?;
//! let session = VerifiedSession::establish(&pk, &sk)?;
//!
//! // Check session properties
//! assert!(session.is_valid());  // Not expired
//! let _ = session.session_id(); // Unique ID for audit
//! let _ = session.expires_at(); // Expiration time
//!
//! // Validate before critical operations
//! session.verify_valid()?;  // Returns Err(SessionExpired) if expired
//!
//! // Refresh if expired
//! if !session.is_valid() {
//!     let new_session = VerifiedSession::establish(&pk, &sk)?;
//! }
//! ```
//!
//! ## Complete Example
//!
//! ```rust,ignore
//! use latticearc::{
//!     generate_signing_keypair, sign_with_key, verify,
//!     generate_hybrid_keypair, encrypt_hybrid, decrypt_hybrid,
//!     CryptoConfig, SecurityMode, CoreError,
//! };
//!
//! fn secure_workflow() -> Result<(), CoreError> {
//!     // --- Hybrid Encryption ---
//!     let (enc_pk, enc_sk) = generate_hybrid_keypair()?;
//!     let encrypted = encrypt_hybrid(b"confidential", &enc_pk, SecurityMode::Unverified)?;
//!     let decrypted = decrypt_hybrid(&encrypted, &enc_sk, SecurityMode::Unverified)?;
//!
//!     // --- Digital Signatures ---
//!     let (sign_pk, sign_sk, _scheme) = generate_signing_keypair(CryptoConfig::new())?;
//!     let signed = sign_with_key(b"important document", &sign_sk, &sign_pk, CryptoConfig::new())?;
//!     let is_valid = verify(&signed, CryptoConfig::new())?;
//!     assert!(is_valid);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Enterprise Behavior
//!
//! In enterprise deployments (`arc-enterprise`), session verification enables:
//! - Per-operation ABAC/RBAC policy enforcement
//! - Continuous verification with trust level tracking
//! - HSM/TPM integration for sensitive key operations
//! - Cryptographic audit trails for compliance (SOC2, HIPAA, etc.)

pub use arc_core as core;
pub use arc_prelude as prelude;

pub use prelude::*;

// ============================================================================
// Core Types
// ============================================================================

pub use arc_core::{
    // Algorithm selection types
    AlgorithmSelection,
    Challenge,
    ContinuousSession,
    // Traits
    ContinuousVerifiable,
    // Types
    CoreError,
    // Unified configuration for cryptographic operations
    CryptoConfig,
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
// Unified API (Recommended)
// ============================================================================

// Single entry points for all cryptographic operations
pub use arc_core::{decrypt, encrypt, generate_signing_keypair, sign_with_key, verify};

// Hybrid encryption (ML-KEM-768 + X25519 + HKDF + AES-256-GCM)
pub use arc_core::{
    HybridEncryptionResult, decrypt_hybrid, decrypt_hybrid_with_config, encrypt_hybrid,
    encrypt_hybrid_with_config, generate_hybrid_keypair,
};

// Hybrid signatures (ML-DSA-65 + Ed25519)
pub use arc_core::{
    generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_with_config, sign_hybrid,
    sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_with_config,
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
// Low-Level Unverified Variants (for primitives)
// ============================================================================

#[allow(deprecated)]
pub use arc_core::{
    // AES-GCM
    decrypt_aes_gcm_unverified,
    decrypt_aes_gcm_with_config_unverified,
    // Hybrid Encryption (ML-KEM-768 + X25519 + HKDF + AES-GCM)
    decrypt_hybrid_unverified,
    decrypt_hybrid_with_config_unverified,
    // PQ KEM
    decrypt_pq_ml_kem_unverified,
    decrypt_pq_ml_kem_with_config_unverified,
    // Hashing
    derive_key_unverified,
    derive_key_with_config_unverified,
    encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_config_unverified,
    encrypt_hybrid_unverified,
    encrypt_hybrid_with_config_unverified,
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

// ============================================================================
// Hardware Types (trait definitions only — real detection in enterprise)
// Re-exported from arc_core::traits above (lines 187-191)
// ============================================================================

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
