// JUSTIFICATION: Some cryptographic dependencies (fn-dsa, fips205) instantiate large
// const arrays internally. In test builds these get monomorphized into the crate,
// triggering large_stack_arrays. The arrays are in dependency code, not ours.
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

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
//! ### Basic Usage (Hybrid — Recommended)
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{encrypt, decrypt, CryptoConfig, EncryptKey, DecryptKey};
//!
//! // Hybrid encryption: ML-KEM-768 + X25519 + HKDF + AES-256-GCM
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Symmetric Encryption
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{encrypt, decrypt, CryptoConfig, CryptoScheme, EncryptKey, DecryptKey};
//!
//! let key = [0u8; 32];  // 256-bit key for AES-256-GCM
//! let encrypted = encrypt(b"secret", EncryptKey::Symmetric(&key),
//!     CryptoConfig::new().force_scheme(CryptoScheme::Symmetric))?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```
//!
//! ### With Use Case Selection
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{encrypt, CryptoConfig, UseCase, EncryptKey};
//!
//! // Library selects optimal hybrid algorithm for the use case
//! let (pk, _sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"data", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new().use_case(UseCase::FileStorage))?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Zero Trust Session Verification
//!
//! For production deployments, use [`VerifiedSession`] to enable Zero Trust
//! verification before each operation:
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{
//!     encrypt, decrypt, CryptoConfig, VerifiedSession, generate_keypair,
//!     EncryptKey, DecryptKey,
//! };
//!
//! // Step 1: Generate a keypair (done once, typically at provisioning)
//! let (pk, sk) = generate_keypair()?;
//!
//! // Step 2: Establish a verified session (performs challenge-response)
//! let session = VerifiedSession::establish(&pk, sk.as_ref())?;
//!
//! // Step 3: Hybrid encryption with session verification
//! let (enc_pk, enc_sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&enc_pk),
//!     CryptoConfig::new().session(&session))?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&enc_sk),
//!     CryptoConfig::new().session(&session))?;
//! # Ok(())
//! # }
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
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! # Ok(())
//! # }
//! ```
//!
//! ## Hybrid Encryption (ML-KEM-768 + X25519)
//!
//! Use the unified API with `EncryptKey::Hybrid` / `DecryptKey::Hybrid`:
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{encrypt, decrypt, CryptoConfig, EncryptKey, DecryptKey};
//!
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret data", EncryptKey::Hybrid(&pk), CryptoConfig::new())?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Hybrid Signatures (ML-DSA-65 + Ed25519)
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! # Ok(())
//! # }
//! ```
//!
//! ## Session Lifecycle
//!
//! Sessions have a 30-minute default lifetime:
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::{encrypt, CryptoConfig, VerifiedSession, generate_keypair, CoreError, EncryptKey};
//!
//! let (pk, sk) = generate_keypair()?;
//! let session = VerifiedSession::establish(&pk, sk.as_ref())?;
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
//!     let new_session = VerifiedSession::establish(&pk, sk.as_ref())?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Complete Example
//!
//! ```rust,no_run
//! use latticearc::{
//!     encrypt, decrypt, generate_signing_keypair, sign_with_key, verify,
//!     generate_hybrid_keypair, CryptoConfig, CoreError,
//!     EncryptKey, DecryptKey,
//! };
//!
//! fn secure_workflow() -> Result<(), CoreError> {
//!     // --- Hybrid Encryption (unified API) ---
//!     let (enc_pk, enc_sk) = generate_hybrid_keypair()?;
//!     let encrypted = encrypt(b"confidential", EncryptKey::Hybrid(&enc_pk),
//!         CryptoConfig::new())?;
//!     let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&enc_sk),
//!         CryptoConfig::new())?;
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
//! ## Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `fips` | FIPS 140-3 validated backend via aws-lc-rs. Requires CMake + Go build tools. Without this feature, aws-lc-rs uses its default non-FIPS backend (C compiler only). |
//! | `fips-self-test` | Power-up KAT self-tests for all FIPS-boundary algorithms (ML-KEM, AES-GCM, SHA-2, ML-DSA, SLH-DSA). |
//! | `zkp-serde` | Serialization support for ZKP types (enables `serde_with` for Schnorr/Sigma protocol structs). |
//! | `formal-verification` | Compilation marker: enables formal verification harness code (Kani proofs). Does not run proofs — use `cargo kani` separately. |
//! | `kani` | Compilation marker: enables Kani bounded model checking proof harnesses. Requires `cargo kani` to execute proofs. |
//! | `saw` | Compilation marker: enables SAW formal verification markers (inherited from aws-lc-rs). Does not run SAW proofs at build time. |
//!
//! ## Enterprise Behavior
//!
//! In enterprise deployments (`arc-enterprise`), session verification enables:
//! - Per-operation ABAC/RBAC policy enforcement
//! - Continuous verification with trust level tracking
//! - HSM/TPM integration for sensitive key operations
//! - Cryptographic audit trails for compliance (SOC2, HIPAA, etc.)

// ============================================================================
// Module Declarations
// ============================================================================

/// Pure-Rust domain types, traits, configuration, and policy engine.
pub mod types;

/// Common prelude with error handling, domain constants, and testing infrastructure.
pub mod prelude;

/// Core cryptographic primitives (KEM, signatures, AEAD, hash, KDF, MAC).
pub mod primitives;

/// Hybrid cryptography combining post-quantum and classical algorithms.
pub mod hybrid;

/// Unified cryptographic API with Zero-Trust security.
pub mod unified_api;

/// TLS 1.3 with post-quantum key exchange support.
pub mod tls;

/// Zero-knowledge proof primitives (Schnorr, Sigma protocols, Pedersen commitments).
/// Non-FIPS: uses non-approved EC operations.
#[cfg(not(feature = "fips"))]
pub mod zkp;

/// Performance monitoring and benchmarking utilities.
pub mod perf;

// ============================================================================
// Backward-compatible module aliases
// ============================================================================

/// Alias for `unified_api` module (backward compatibility with `latticearc::core::*`).
pub use unified_api as core;

// Explicit re-export of LatticeArcError for error compatibility.
// All other prelude types are accessible via `latticearc::prelude::*`.
pub use prelude::prelude::LatticeArcError;

// ============================================================================
// Core Types
// ============================================================================

pub use unified_api::{
    // Algorithm selection types
    AlgorithmSelection,
    Challenge,
    // Compliance
    ComplianceMode,
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
    // Type-safe encryption key types (no silent degradation)
    DecryptKey,
    Decryptable,
    EncryptKey,
    Encryptable,
    EncryptedData,
    EncryptedMetadata,
    // Type-safe encrypted output (replaces string-based scheme dispatch)
    EncryptedOutput,
    EncryptionScheme,
    HardwareAccelerator,
    HardwareAware,
    HardwareCapabilities,
    HardwareInfo,
    HardwareType,
    HashOutput,
    // Hybrid encryption components (ML-KEM ciphertext + ECDH ephemeral key)
    HybridComponents,
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
    // Compile-time feature detection
    fips_available,
    // Initialization
    init,
    init_with_config,
};

// ============================================================================
// Unified API (Recommended)
// ============================================================================

// Single entry points for all cryptographic operations
pub use unified_api::{decrypt, encrypt, generate_signing_keypair, sign_with_key, verify};

// Hybrid key generation (ML-KEM + X25519)
pub use unified_api::{generate_hybrid_keypair, generate_hybrid_keypair_with_level};

// Hybrid signatures (ML-DSA-65 + Ed25519)
pub use unified_api::{
    generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_with_config, sign_hybrid,
    sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_with_config,
};

// Key generation (no SecurityMode needed - creates credentials)
pub use unified_api::{
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config,
    generate_fn_dsa_keypair_with_level, generate_keypair, generate_keypair_with_config,
    generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config, generate_ml_kem_keypair,
    generate_ml_kem_keypair_with_config, generate_slh_dsa_keypair,
    generate_slh_dsa_keypair_with_config,
};

// Hashing (hash_data is stateless, others use SecurityMode)
pub use unified_api::{
    derive_key, derive_key_with_config, derive_key_with_info, hash_data, hmac, hmac_check,
    hmac_check_with_config, hmac_with_config,
};

// AES-GCM
pub use unified_api::{
    decrypt_aes_gcm, decrypt_aes_gcm_with_aad, decrypt_aes_gcm_with_config, encrypt_aes_gcm,
    encrypt_aes_gcm_with_aad, encrypt_aes_gcm_with_config,
};

// Ed25519
pub use unified_api::{
    sign_ed25519, sign_ed25519_with_config, verify_ed25519, verify_ed25519_with_config,
};

// Post-Quantum KEM (ML-KEM)
pub use unified_api::{
    decrypt_pq_ml_kem, decrypt_pq_ml_kem_with_config, encrypt_pq_ml_kem,
    encrypt_pq_ml_kem_with_config,
};

// Post-Quantum Signatures (ML-DSA, SLH-DSA, FN-DSA)
pub use unified_api::{
    sign_pq_fn_dsa, sign_pq_fn_dsa_with_config, sign_pq_ml_dsa, sign_pq_ml_dsa_with_config,
    sign_pq_slh_dsa, sign_pq_slh_dsa_with_config, verify_pq_fn_dsa, verify_pq_fn_dsa_with_config,
    verify_pq_ml_dsa, verify_pq_ml_dsa_with_config, verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config,
};

// ============================================================================
// Low-Level Unverified Variants (for primitives)
// ============================================================================

pub use unified_api::{
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

// ============================================================================
// Serialization Utilities
// ============================================================================

pub use unified_api::serialization::{
    deserialize_encrypted_data, deserialize_encrypted_output, deserialize_keypair,
    deserialize_signed_data, serialize_encrypted_data, serialize_encrypted_output,
    serialize_keypair, serialize_signed_data,
};

// ============================================================================
// TLS Utilities
// ============================================================================

pub use tls::{
    TlsConfig, TlsConstraints, TlsContext, TlsMode, TlsPolicyEngine, TlsUseCase, tls_accept,
    tls_connect,
};
