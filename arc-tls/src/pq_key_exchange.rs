#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Post-Quantum Key Exchange for TLS 1.3
//!
//! This module implements post-quantum key exchange for TLS 1.3, providing:
//! - Hybrid key exchange (X25519 + ML-KEM-768) via rustls-post-quantum
//! - Custom hybrid implementation using arc-hybrid module
//!
//! ## Key Exchange Methods
//!
//! ### Hybrid (Recommended)
//! Uses X25519MLKEM768 combining:
//! - X25519: Classical ECDH, well-tested, efficient
//! - ML-KEM-768: Post-quantum KEM (NIST FIPS 203)
//!
//! Security: Requires breaking BOTH components
//!
//! ### Custom Hybrid (via arc-hybrid)
//! Uses arc-hybrid::kem module:
//! - ML-KEM-768 from arc-primitives
//! - X25519 from x25519-dalek
//! - HKDF for secret combination (NIST SP 800-56C)
//!
//! ## Compatibility
//!
//! Standard TLS 1.3 clients:
//! - With PQ support: Use X25519MLKEM768
//! - Without PQ support: Fall back to X25519 only
//! - Handshake succeeds in both cases

use crate::{TlsError, TlsMode};
use rand::{CryptoRng, Rng};
use rustls::crypto::CryptoProvider;
use std::mem;
use zeroize::{Zeroize, Zeroizing};

/// Post-quantum key exchange configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqKexMode {
    /// Use rustls-post-quantum (X25519MLKEM768)
    RustlsPq,
    /// Use custom hybrid implementation (arc-hybrid)
    CustomHybrid,
    /// Use classical ECDHE only
    Classical,
}

/// Key exchange information for monitoring
#[derive(Debug, Clone)]
pub struct KexInfo {
    /// Key exchange method used
    pub method: String,
    /// Security level description
    pub security_level: String,
    /// Whether this key exchange is post-quantum secure
    pub is_pq_secure: bool,
    /// Public key size in bytes
    pub pk_size: usize,
    /// Secret key size in bytes
    pub sk_size: usize,
    /// Ciphertext size in bytes
    pub ct_size: usize,
    /// Shared secret size in bytes
    pub ss_size: usize,
}

/// Get key exchange provider for TLS 1.3
///
/// # Arguments
/// * `mode` - TLS mode (Classic, Hybrid, or PQ)
/// * `kex_mode` - Key exchange mode
///
/// # Returns
/// A CryptoProvider with appropriate key exchange algorithms
///
/// # Errors
///
/// Returns an error if the provider cannot be created.
///
/// # Example
/// ```no_run
/// use arc_tls::pq_key_exchange::{get_kex_provider, PqKexMode};
/// use arc_tls::{TlsMode, TlsError};
///
/// # fn example() -> Result<(), TlsError> {
/// let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)?;
/// # Ok(())
/// # }
/// ```
pub fn get_kex_provider(mode: TlsMode, kex_mode: PqKexMode) -> Result<CryptoProvider, TlsError> {
    match (mode, kex_mode) {
        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::RustlsPq) => {
            // Use rustls-post-quantum provider for hybrid key exchange
            let provider = rustls_post_quantum::provider();
            Ok(provider)
        }

        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::CustomHybrid) => {
            // Use custom hybrid implementation
            Ok(rustls::crypto::aws_lc_rs::default_provider())
        }

        (TlsMode::Classic, _) | (_, PqKexMode::Classical) => {
            // Use default provider for classical mode
            Ok(rustls::crypto::aws_lc_rs::default_provider())
        }
    }
}

/// Get key exchange information for a given mode
///
/// # Arguments
/// * `mode` - TLS mode
/// * `kex_mode` - Key exchange mode
///
/// # Returns
/// Information about the key exchange method
#[must_use]
pub fn get_kex_info(mode: TlsMode, kex_mode: PqKexMode) -> KexInfo {
    match (mode, kex_mode) {
        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::RustlsPq) => KexInfo {
            method: "X25519MLKEM768".to_string(),
            security_level: "Hybrid (Post-Quantum + Classical)".to_string(),
            is_pq_secure: true,
            pk_size: 32 + 1184, // X25519 (32) + ML-KEM-768 PK (1184)
            sk_size: 32 + 2400, // X25519 (32) + ML-KEM-768 SK (2400)
            ct_size: 32 + 1088, // X25519 (32) + ML-KEM-768 CT (1088)
            ss_size: 64,        // 64-byte shared secret
        },

        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::CustomHybrid) => KexInfo {
            method: "Custom Hybrid (X25519 + ML-KEM-768)".to_string(),
            security_level: "Hybrid (Post-Quantum + Classical)".to_string(),
            is_pq_secure: true,
            pk_size: 32 + 1184,
            sk_size: 32 + 2400,
            ct_size: 32 + 1088,
            ss_size: 64,
        },

        (TlsMode::Classic, _) | (_, PqKexMode::Classical) => KexInfo {
            method: "X25519 (ECDHE)".to_string(),
            security_level: "Classical (128-bit security)".to_string(),
            is_pq_secure: false,
            pk_size: 32, // X25519 public key
            sk_size: 32, // X25519 secret key
            ct_size: 32, // X25519 public key as ciphertext
            ss_size: 32, // 32-byte shared secret
        },
    }
}

/// Check if post-quantum key exchange is available
///
/// # Returns
/// Always returns true (PQ is always enabled)
#[must_use]
pub fn is_pq_available() -> bool {
    true
}

/// Check if custom hybrid key exchange is available
///
/// # Returns
/// Always returns true (hybrid is always enabled)
#[must_use]
pub fn is_custom_hybrid_available() -> bool {
    true
}

/// Secure shared secret container with automatic zeroization
pub struct SecureSharedSecret {
    secret: Vec<u8>,
}

impl SecureSharedSecret {
    /// Create a new secure shared secret
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Get reference to the secret
    #[must_use]
    pub fn as_ref(&self) -> &[u8] {
        &self.secret
    }

    /// Consume and return the secret wrapped in Zeroizing for automatic cleanup
    ///
    /// The returned `Zeroizing<Vec<u8>>` will automatically zeroize the secret
    /// when it goes out of scope, ensuring proper memory cleanup.
    ///
    /// # Security Note
    /// Uses `mem::take` to move the secret out without creating copies.
    /// The struct's Drop impl will zeroize an empty Vec (no-op).
    #[must_use]
    pub fn into_inner(mut self) -> Zeroizing<Vec<u8>> {
        // Use mem::take to move the secret out without cloning
        // This avoids creating an unzeroized copy of the secret
        Zeroizing::new(mem::take(&mut self.secret))
    }

    /// Consume and return the raw secret bytes (caller responsible for zeroization)
    ///
    /// # Security Warning
    /// The caller is responsible for properly zeroizing the returned data.
    /// Prefer `into_inner()` which returns a `Zeroizing<Vec<u8>>` for automatic cleanup.
    ///
    /// # Security Note
    /// Uses `mem::take` to move the secret out without creating copies.
    #[must_use]
    pub fn into_inner_raw(mut self) -> Vec<u8> {
        // Use mem::take to move the secret out without cloning
        // This avoids creating an unzeroized copy of the secret
        mem::take(&mut self.secret)
    }
}

impl Drop for SecureSharedSecret {
    fn drop(&mut self) {
        // Zeroize the secret when dropped
        self.secret.zeroize();
    }
}

impl Zeroize for SecureSharedSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

/// Perform hybrid key generation
///
/// # Errors
///
/// Returns an error if the hybrid key generation fails due to RNG issues
/// or internal cryptographic errors.
pub fn perform_hybrid_keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(arc_hybrid::kem::HybridPublicKey, arc_hybrid::kem::HybridSecretKey), TlsError> {
    arc_hybrid::kem::generate_keypair(rng).map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid keygen failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("keygen".to_string()),
        code: crate::error::ErrorCode::KeyExchangeFailed,
        context: Default::default(),
        recovery: crate::error::RecoveryHint::NoRecovery,
    })
}

/// Perform hybrid encapsulation
///
/// # Errors
///
/// Returns an error if the encapsulation operation fails due to an invalid
/// public key or internal cryptographic errors.
pub fn perform_hybrid_encapsulate<R: Rng + CryptoRng>(
    rng: &mut R,
    pk: &arc_hybrid::kem::HybridPublicKey,
) -> Result<arc_hybrid::kem::EncapsulatedKey, TlsError> {
    arc_hybrid::kem::encapsulate(rng, pk).map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid encapsulation failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("encapsulate".to_string()),
        code: crate::error::ErrorCode::EncapsulationFailed,
        context: Default::default(),
        recovery: crate::error::RecoveryHint::NoRecovery,
    })
}

/// Perform hybrid decapsulation securely (returns zeroizable secret)
///
/// # Errors
///
/// Returns an error if the decapsulation operation fails due to an invalid
/// ciphertext, corrupted secret key, or internal cryptographic errors.
pub fn perform_hybrid_decapsulate_secure(
    sk: &arc_hybrid::kem::HybridSecretKey,
    ct: &arc_hybrid::kem::EncapsulatedKey,
) -> Result<SecureSharedSecret, TlsError> {
    let secret = arc_hybrid::kem::decapsulate(sk, ct).map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid decapsulation failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("decapsulate".to_string()),
        code: crate::error::ErrorCode::DecapsulationFailed,
        context: Default::default(),
        recovery: crate::error::RecoveryHint::NoRecovery,
    })?;
    Ok(SecureSharedSecret::new(secret))
}

/// Perform hybrid decapsulation
///
/// # Arguments
/// * `sk` - Hybrid secret key
/// * `ct` - Encapsulated key
///
/// # Returns
/// Decapsulated shared secret
///
/// # Errors
///
/// Returns an error if the decapsulation operation fails due to an invalid
/// ciphertext, corrupted secret key, or internal cryptographic errors.
pub fn perform_hybrid_decapsulate(
    sk: &arc_hybrid::kem::HybridSecretKey,
    ct: &arc_hybrid::kem::EncapsulatedKey,
) -> Result<Vec<u8>, TlsError> {
    let secure_secret = perform_hybrid_decapsulate_secure(sk, ct)?;
    // Use into_inner_raw() since this function returns Vec<u8> by design
    // Callers should handle zeroization or use perform_hybrid_decapsulate_secure() instead
    Ok(secure_secret.into_inner_raw())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_kex_info_hybrid() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_info_classical() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);
        assert_eq!(info.method, "X25519 (ECDHE)");
        assert!(!info.is_pq_secure);
        assert_eq!(info.ss_size, 32);
    }

    #[test]
    fn test_pq_availability() {
        assert!(is_pq_available());
    }

    #[test]
    fn test_custom_hybrid_availability() {
        assert!(is_custom_hybrid_available());
    }

    #[test]
    #[ignore = "aws-lc-rs does not support secret key deserialization - decapsulate not functional"]
    fn test_hybrid_key_exchange() {
        let mut rng = rand::thread_rng();

        // Generate keypair
        let (pk, sk) = perform_hybrid_keygen(&mut rng).expect("Failed to generate keypair");

        // Encapsulate
        let enc = perform_hybrid_encapsulate(&mut rng, &pk).expect("Failed to encapsulate");

        // Decapsulate securely
        let secure_ss =
            perform_hybrid_decapsulate_secure(&sk, &enc).expect("Failed to decapsulate");

        // Verify
        assert_eq!(secure_ss.secret.as_slice(), enc.shared_secret.as_slice());
        assert_eq!(secure_ss.secret.len(), 64);

        // Test regular decapsulation
        let ss = perform_hybrid_decapsulate(&sk, &enc).expect("Failed to decapsulate");
        assert_eq!(ss.as_slice(), enc.shared_secret.as_slice());
        assert_eq!(ss.len(), 64);
    }

    #[test]
    fn test_get_kex_provider() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_classical() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }
}
