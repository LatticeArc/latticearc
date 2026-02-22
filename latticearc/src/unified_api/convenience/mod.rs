//! Convenience API for cryptographic operations
//!
//! This module provides a unified, high-level API for encryption, decryption,
//! signing, and verification with automatic algorithm selection.
//!
//! ## Unified API
//!
//! All operations use `CryptoConfig` for configuration:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{
//!     encrypt, decrypt, generate_signing_keypair, sign_with_key, verify,
//!     CryptoConfig, UseCase, EncryptKey, DecryptKey,
//! };
//! # let message = b"example message";
//!
//! // Hybrid encryption (recommended - ML-KEM-768 + X25519 + AES-256-GCM)
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"data", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new().use_case(UseCase::FileStorage))?;
//! let plaintext = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
//!
//! // Symmetric encryption (AES-256-GCM)
//! let key = [0u8; 32];
//! let encrypted = encrypt(b"data", EncryptKey::Symmetric(&key),
//!     CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric))?;
//! let plaintext = decrypt(&encrypted, DecryptKey::Symmetric(&key), CryptoConfig::new())?;
//!
//! // Sign (generate keypair once, sign with persistent key)
//! let (pk, sk, scheme) = generate_signing_keypair(CryptoConfig::new())?;
//! let signed = sign_with_key(message, sk.as_ref(), pk.as_ref(), CryptoConfig::new())?;
//!
//! // Verify
//! let is_valid = verify(&signed, CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```
//!
//! ## With Zero Trust Session
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{encrypt, CryptoConfig, UseCase, VerifiedSession, EncryptKey};
//! # let pk_ed = [0u8; 32];
//! # let sk_ed = [0u8; 32];
//!
//! let session = VerifiedSession::establish(&pk_ed, &sk_ed)?;
//! let (pk, _sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"data", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new()
//!         .session(&session)
//!         .use_case(UseCase::FileStorage))?;
//! # Ok(())
//! # }
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
// Hybrid Key Generation (ML-KEM + X25519)
// ============================================================================

pub use hybrid::{generate_hybrid_keypair, generate_hybrid_keypair_with_level};

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
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config,
    generate_fn_dsa_keypair_with_level, generate_keypair, generate_keypair_with_config,
    generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config, generate_ml_kem_keypair,
    generate_ml_kem_keypair_with_config, generate_slh_dsa_keypair,
    generate_slh_dsa_keypair_with_config,
};

// ============================================================================
// Hashing (stateless operations)
// ============================================================================

pub use hashing::{
    derive_key, derive_key_with_config, derive_key_with_info, hash_data, hmac, hmac_check,
    hmac_check_with_config, hmac_with_config,
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
pub use aes_gcm::{decrypt_aes_gcm_with_aad, encrypt_aes_gcm_with_aad};

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
// Unverified Variants (for low-level primitives)
// ============================================================================

pub use hashing::{
    derive_key_unverified, derive_key_with_config_unverified, derive_key_with_info_unverified,
    hmac_check_unverified, hmac_check_with_config_unverified, hmac_unverified,
    hmac_with_config_unverified,
};

pub use ed25519::{
    sign_ed25519_unverified, sign_ed25519_with_config_unverified, verify_ed25519_unverified,
    verify_ed25519_with_config_unverified,
};

pub use aes_gcm::{
    decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_aad_unverified,
    decrypt_aes_gcm_with_config_unverified, encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_aad_unverified, encrypt_aes_gcm_with_config_unverified,
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

pub use hybrid_sig::{
    generate_hybrid_signing_keypair_unverified, sign_hybrid_unverified,
    verify_hybrid_signature_unverified,
};
