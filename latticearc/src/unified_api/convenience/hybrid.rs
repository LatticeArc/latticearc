//! Hybrid key generation (ML-KEM + X25519)
//!
//! For hybrid encryption/decryption, use the unified API:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::unified_api::{encrypt, decrypt, CryptoConfig, UseCase, EncryptKey, DecryptKey};
//!
//! let (pk, sk) = latticearc::generate_hybrid_keypair()?;
//! let encrypted = encrypt(b"secret", EncryptKey::Hybrid(&pk),
//!     CryptoConfig::new().use_case(UseCase::FileStorage))?;
//! let decrypted = decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())?;
//! # Ok(())
//! # }
//! ```

use crate::hybrid::kem_hybrid::{
    self as kem, HybridPublicKey as KemHybridPublicKey, HybridSecretKey as KemHybridSecretKey,
};
use crate::primitives::kem::ml_kem::MlKemSecurityLevel;

use crate::unified_api::error::{CoreError, Result};

/// Generate a hybrid keypair at ML-KEM-768 (default security level).
///
/// Returns a public key (for encryption) and a secret key (for decryption).
/// The keypair combines post-quantum and classical algorithms for defense in depth.
///
/// For other security levels, use [`generate_hybrid_keypair_with_level`].
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_hybrid_keypair() -> Result<(KemHybridPublicKey, KemHybridSecretKey)> {
    generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768)
}

/// Generate a hybrid keypair at a specific ML-KEM security level.
///
/// # Arguments
///
/// * `level` - ML-KEM security level:
///   - `MlKem512` — NIST Category 1 (AES-128 equivalent, 800-byte PK)
///   - `MlKem768` — NIST Category 3 (AES-192 equivalent, 1184-byte PK)
///   - `MlKem1024` — NIST Category 5 (AES-256 equivalent, 1568-byte PK)
///
/// # Errors
///
/// Returns an error if key generation fails.
pub fn generate_hybrid_keypair_with_level(
    level: MlKemSecurityLevel,
) -> Result<(KemHybridPublicKey, KemHybridSecretKey)> {
    super::api::fips_verify_operational()?;
    let mut rng = rand::rngs::OsRng;
    kem::generate_keypair_with_level(&mut rng, level).map_err(|e| {
        CoreError::EncryptionFailed(format!("Hybrid keypair generation failed: {}", e))
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::panic_in_result_fn)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair_default_is_768() -> Result<()> {
        let (pk, _sk) = generate_hybrid_keypair()?;
        assert_eq!(pk.ml_kem_pk.len(), 1184); // ML-KEM-768 PK size
        assert_eq!(pk.ecdh_pk.len(), 32); // X25519 PK size
        assert_eq!(pk.security_level, MlKemSecurityLevel::MlKem768);
        Ok(())
    }

    #[test]
    fn test_hybrid_keypair_512() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem512)?;
        assert_eq!(pk.ml_kem_pk.len(), 800);
        assert_eq!(pk.security_level, MlKemSecurityLevel::MlKem512);
        assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem512);
        Ok(())
    }

    #[test]
    fn test_hybrid_keypair_768() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem768)?;
        assert_eq!(pk.ml_kem_pk.len(), 1184);
        assert_eq!(pk.security_level, MlKemSecurityLevel::MlKem768);
        assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem768);
        Ok(())
    }

    #[test]
    fn test_hybrid_keypair_1024() -> Result<()> {
        let (pk, sk) = generate_hybrid_keypair_with_level(MlKemSecurityLevel::MlKem1024)?;
        assert_eq!(pk.ml_kem_pk.len(), 1568);
        assert_eq!(pk.security_level, MlKemSecurityLevel::MlKem1024);
        assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem1024);
        Ok(())
    }

    #[test]
    fn test_hybrid_keypair_non_deterministic() -> Result<()> {
        let (pk1, _sk1) = generate_hybrid_keypair()?;
        let (pk2, _sk2) = generate_hybrid_keypair()?;
        assert_ne!(pk1.ml_kem_pk, pk2.ml_kem_pk);
        assert_ne!(pk1.ecdh_pk, pk2.ecdh_pk);
        Ok(())
    }
}
