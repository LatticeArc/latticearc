//! Convenience API for cryptographic operations
//!
//! This module provides high-level, easy-to-use functions for common
//! cryptographic operations including encryption, decryption, signing,
//! verification, and key management.
//!
//! ## Unified API with SecurityMode
//!
//! All cryptographic operations use `SecurityMode` to specify verification behavior:
//!
//! ```rust,ignore
//! use arc_core::{encrypt, SecurityMode, VerifiedSession, generate_keypair};
//!
//! let (pk, sk) = generate_keypair()?;
//! let key = [0u8; 32];
//!
//! // With Zero Trust (recommended)
//! let session = VerifiedSession::establish(&pk, &sk)?;
//! let encrypted = encrypt(b"secret", &key, SecurityMode::Verified(&session))?;
//!
//! // Without verification (opt-out)
//! let encrypted = encrypt(b"secret", &key, SecurityMode::Unverified)?;
//! ```
//!
//! ## Enterprise Behavior
//!
//! In enterprise deployments:
//! - `Verified`: Enables policy enforcement, continuous verification
//! - `Unverified`: Triggers mandatory audit trail; may be blocked by policy
//!
//! ## Module Organization
//!
//! - [`aes_gcm`] - AES-GCM symmetric encryption
//! - [`hashing`] - Hashing and HMAC operations
//! - [`ed25519`] - Ed25519 signature operations
//! - [`hybrid`] - Hybrid KEM encryption
//! - [`api`] - High-level encryption/signing API
//! - [`keygen`] - Key generation for all schemes
//! - [`pq_kem`] - Post-quantum KEM operations (ML-KEM)
//! - [`pq_sig`] - Post-quantum signature operations (ML-DSA, SLH-DSA, FN-DSA)

mod aes_gcm;
mod api;
pub(crate) mod ed25519;
mod hashing;
mod hybrid;
mod keygen;
mod pq_kem;
mod pq_sig;

// ============================================================================
// Unified API with SecurityMode
// ============================================================================

// Re-export high-level API
pub use api::{
    decrypt, decrypt_with_config, encrypt, encrypt_for_use_case, encrypt_with_config, sign,
    sign_with_config, verify, verify_with_config,
};

// Re-export hybrid encryption
pub use hybrid::{
    HybridEncryptionResult, decrypt_hybrid, decrypt_hybrid_with_config, encrypt_hybrid,
    encrypt_hybrid_with_config,
};

// Re-export key generation (no session needed - creates credentials)
pub use keygen::{
    generate_fn_dsa_keypair, generate_fn_dsa_keypair_with_config, generate_keypair,
    generate_keypair_with_config, generate_ml_dsa_keypair, generate_ml_dsa_keypair_with_config,
    generate_ml_kem_keypair, generate_ml_kem_keypair_with_config, generate_slh_dsa_keypair,
    generate_slh_dsa_keypair_with_config,
};

// Re-export hashing (hash_data is stateless)
pub use hashing::{
    derive_key, derive_key_with_config, hash_data, hmac, hmac_check, hmac_check_with_config,
    hmac_with_config,
};

// Re-export Ed25519
pub use ed25519::{
    sign_ed25519, sign_ed25519_with_config, verify_ed25519, verify_ed25519_with_config,
};

// Re-export AES-GCM
pub use aes_gcm::{
    decrypt_aes_gcm, decrypt_aes_gcm_with_config, encrypt_aes_gcm, encrypt_aes_gcm_with_config,
};

// Re-export PQ KEM
pub use pq_kem::{
    decrypt_pq_ml_kem, decrypt_pq_ml_kem_with_config, encrypt_pq_ml_kem,
    encrypt_pq_ml_kem_with_config,
};

// Re-export PQ signatures
pub use pq_sig::{
    sign_pq_fn_dsa, sign_pq_fn_dsa_with_config, sign_pq_ml_dsa, sign_pq_ml_dsa_with_config,
    sign_pq_slh_dsa, sign_pq_slh_dsa_with_config, verify_pq_fn_dsa, verify_pq_fn_dsa_with_config,
    verify_pq_ml_dsa, verify_pq_ml_dsa_with_config, verify_pq_slh_dsa,
    verify_pq_slh_dsa_with_config,
};

// ============================================================================
// Unverified API (Opt-Out)
// ============================================================================
// These functions skip Zero Trust session validation. They are a valid choice
// for scenarios where session management is not needed or not possible.
// In enterprise deployments, usage is logged for audit purposes.

// Re-export unverified high-level API
pub use api::{
    decrypt_unverified, decrypt_with_config_unverified, encrypt_for_use_case_unverified,
    encrypt_unverified, encrypt_with_config_unverified, sign_unverified,
    sign_with_config_unverified, verify_unverified, verify_with_config_unverified,
};

// Re-export unverified hybrid encryption
pub use hybrid::{
    decrypt_hybrid_unverified, decrypt_hybrid_with_config_unverified, encrypt_hybrid_unverified,
    encrypt_hybrid_with_config_unverified,
};

// Re-export unverified hashing
pub use hashing::{
    derive_key_unverified, derive_key_with_config_unverified, hmac_check_unverified,
    hmac_check_with_config_unverified, hmac_unverified, hmac_with_config_unverified,
};

// Re-export unverified Ed25519
pub use ed25519::{
    sign_ed25519_unverified, sign_ed25519_with_config_unverified, verify_ed25519_unverified,
    verify_ed25519_with_config_unverified,
};

// Re-export unverified AES-GCM
pub use aes_gcm::{
    decrypt_aes_gcm_unverified, decrypt_aes_gcm_with_config_unverified, encrypt_aes_gcm_unverified,
    encrypt_aes_gcm_with_config_unverified,
};

// Re-export unverified PQ KEM
pub use pq_kem::{
    decrypt_pq_ml_kem_unverified, decrypt_pq_ml_kem_with_config_unverified,
    encrypt_pq_ml_kem_unverified, encrypt_pq_ml_kem_with_config_unverified,
};

// Re-export unverified PQ signatures
pub use pq_sig::{
    sign_pq_fn_dsa_unverified, sign_pq_fn_dsa_with_config_unverified, sign_pq_ml_dsa_unverified,
    sign_pq_ml_dsa_with_config_unverified, sign_pq_slh_dsa_unverified,
    sign_pq_slh_dsa_with_config_unverified, verify_pq_fn_dsa_unverified,
    verify_pq_fn_dsa_with_config_unverified, verify_pq_ml_dsa_unverified,
    verify_pq_ml_dsa_with_config_unverified, verify_pq_slh_dsa_unverified,
    verify_pq_slh_dsa_with_config_unverified,
};
