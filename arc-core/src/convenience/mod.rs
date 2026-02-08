//! Convenience API for cryptographic operations
//!
//! This module provides a unified, high-level API for encryption, decryption,
//! signing, and verification with automatic algorithm selection.
//!
//! ## Unified API
//!
//! All operations use `CryptoConfig` for configuration:
//!
//! ```rust,ignore
//! use latticearc::{
//!     encrypt, decrypt, generate_signing_keypair, sign_with_key, verify,
//!     CryptoConfig, UseCase,
//! };
//!
//! // Encrypt with use case (recommended)
//! let encrypted = encrypt(data, &key, CryptoConfig::new()
//!     .use_case(UseCase::FileStorage))?;
//!
//! // Decrypt
//! let plaintext = decrypt(&encrypted, &key, CryptoConfig::new())?;
//!
//! // Sign (generate keypair once, sign with persistent key)
//! let (pk, sk, scheme) = generate_signing_keypair(CryptoConfig::new())?;
//! let signed = sign_with_key(message, &sk, &pk, CryptoConfig::new())?;
//!
//! // Verify
//! let is_valid = verify(&signed, CryptoConfig::new())?;
//! ```
//!
//! ## With Zero Trust Session
//!
//! ```rust,ignore
//! use latticearc::{encrypt, CryptoConfig, UseCase, VerifiedSession};
//!
//! let session = VerifiedSession::establish(&pk, &sk)?;
//! let encrypted = encrypt(data, &key, CryptoConfig::new()
//!     .session(&session)
//!     .use_case(UseCase::FileStorage))?;
//! ```

mod aes_gcm;
mod api;
pub(crate) mod ed25519;
mod hashing;
mod hybrid;
mod hybrid_sig;
mod keygen;
mod pq_kem;
mod pq_sig;

// ============================================================================
// Unified API
// ============================================================================

pub use api::{decrypt, encrypt, generate_signing_keypair, sign_with_key, verify};

// ============================================================================
// Hybrid Encryption
// ============================================================================

pub use hybrid::{
    HybridEncryptionResult, decrypt_hybrid, decrypt_hybrid_with_config, encrypt_hybrid,
    encrypt_hybrid_with_config, generate_hybrid_keypair,
};

// ============================================================================
// Hybrid Signatures (ML-DSA-65 + Ed25519)
// ============================================================================

pub use hybrid_sig::{
    generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_with_config, sign_hybrid,
    sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_with_config,
};

// ============================================================================
// Key Generation (no options needed - creates credentials)
// ============================================================================

pub use keygen::{
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config, generate_keypair,
    generate_keypair_with_config, generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config,
    generate_ml_kem_keypair, generate_ml_kem_keypair_with_config, generate_slh_dsa_keypair,
    generate_slh_dsa_keypair_with_config,
};

// ============================================================================
// Hashing (stateless operations)
// ============================================================================

pub use hashing::{
    derive_key, derive_key_with_config, hash_data, hmac, hmac_check, hmac_check_with_config,
    hmac_with_config,
};

// ============================================================================
// Low-Level Primitives (for advanced use cases)
// ============================================================================

// Ed25519
pub use ed25519::{
    sign_ed25519, sign_ed25519_with_config, verify_ed25519, verify_ed25519_with_config,
};

// AES-GCM
pub use aes_gcm::{
    decrypt_aes_gcm, decrypt_aes_gcm_with_config, encrypt_aes_gcm, encrypt_aes_gcm_with_config,
};

// Post-Quantum KEM (ML-KEM)
pub use pq_kem::{
    decrypt_pq_ml_kem, decrypt_pq_ml_kem_with_config, encrypt_pq_ml_kem,
    encrypt_pq_ml_kem_with_config,
};

// Post-Quantum Signatures (ML-DSA, SLH-DSA, FN-DSA)
pub use pq_sig::{
    sign_pq_fn_dsa, sign_pq_fn_dsa_with_config, sign_pq_ml_dsa, sign_pq_ml_dsa_with_config,
    sign_pq_slh_dsa, sign_pq_slh_dsa_with_config, verify_pq_fn_dsa, verify_pq_fn_dsa_with_config,
    verify_pq_ml_dsa, verify_pq_ml_dsa_with_config, verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config,
};

// ============================================================================
// Unverified Variants (for backward compatibility with low-level primitives)
// ============================================================================

pub use hashing::{
    derive_key_unverified, derive_key_with_config_unverified, hmac_check_unverified,
    hmac_check_with_config_unverified, hmac_unverified, hmac_with_config_unverified,
};

pub use ed25519::{
    sign_ed25519_unverified, sign_ed25519_with_config_unverified, verify_ed25519_unverified,
    verify_ed25519_with_config_unverified,
};

pub use aes_gcm::{
    decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_config_unverified, encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_config_unverified,
};

pub use pq_kem::{
    decrypt_pq_ml_kem_unverified, decrypt_pq_ml_kem_with_config_unverified,
    encrypt_pq_ml_kem_unverified, encrypt_pq_ml_kem_with_config_unverified,
};

pub use pq_sig::{
    sign_pq_fn_dsa_unverified, sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa_unverified,
    sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa_unverified,
    sign_pq_slh_dsa_with_config_unverified, verify_pq_fn_dsa_unverified,
    verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa_unverified,
    verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa_unverified,
    verify_pq_slh_dsa_with_config_unverified,
};

pub use hybrid::{
    decrypt_hybrid_unverified, decrypt_hybrid_with_config_unverified, encrypt_hybrid_unverified,
    encrypt_hybrid_with_config_unverified,
};

pub use hybrid_sig::{
    generate_hybrid_signing_keypair_unverified, sign_hybrid_unverified,
    verify_hybrid_signature_unverified,
};
