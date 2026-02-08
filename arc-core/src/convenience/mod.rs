//! Convenience API for cryptographic operations
//!
//! This module provides a unified, high-level API for encryption, decryption,
//! signing, and verification with automatic algorithm selection.
//!
//! ## Unified API
//!
//! All operations use `CryptoOptions` for configuration:
//!
//! ```rust,ignore
//! use latticearc::{encrypt, decrypt, sign, verify, CryptoOptions, UseCase};
//!
//! // Encrypt with use case (recommended)
//! let encrypted = encrypt(data, &key, CryptoOptions::new()
//!     .use_case(UseCase::FileStorage))?;
//!
//! // Decrypt
//! let plaintext = decrypt(&encrypted, &key, CryptoOptions::new())?;
//!
//! // Sign
//! let signed = sign(message, CryptoOptions::new()
//!     .use_case(UseCase::FinancialTransactions))?;
//!
//! // Verify
//! let is_valid = verify(&signed, CryptoOptions::new())?;
//! ```
//!
//! ## With Zero Trust Session
//!
//! ```rust,ignore
//! use latticearc::{encrypt, CryptoOptions, UseCase, VerifiedSession};
//!
//! let session = VerifiedSession::establish(&pk, &sk)?;
//! let encrypted = encrypt(data, &key, CryptoOptions::new()
//!     .session(&session)
//!     .use_case(UseCase::FileStorage))?;
//! ```

mod aes_gcm;
mod api;
pub(crate) mod ed25519;
mod hashing;
mod hybrid;
mod keygen;
mod pq_kem;
mod pq_sig;

// ============================================================================
// Unified API
// ============================================================================

pub use api::{decrypt, encrypt, sign, verify};

// ============================================================================
// Hybrid Encryption
// ============================================================================

pub use hybrid::{
    HybridEncryptionResult, TrueHybridEncryptionResult, decrypt_hybrid, decrypt_hybrid_with_config,
    decrypt_true_hybrid, encrypt_hybrid, encrypt_hybrid_with_config, encrypt_true_hybrid,
    generate_true_hybrid_keypair,
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
