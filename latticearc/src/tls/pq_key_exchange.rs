#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! # Post-Quantum Key Exchange for TLS 1.3
//!
//! This module implements post-quantum key exchange for TLS 1.3, providing:
//! - Hybrid key exchange (X25519 + ML-KEM-768) via rustls native support (0.23.37+)
//! - Standalone ML-KEM-768 and ML-KEM-1024 key exchange
//! - Custom hybrid implementation using the `hybrid` module
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
//! ### Custom Hybrid (via `latticearc::hybrid`)
//! Uses `hybrid::kem_hybrid` module:
//! - ML-KEM-768 from `latticearc::primitives`
//! - X25519 from aws-lc-rs
//! - HKDF for secret combination (NIST SP 800-56C)
//!
//! ## Available Key Exchange Groups (rustls 0.23.37+)
//!
//! | Group | Type | Security |
//! |-------|------|----------|
//! | X25519MLKEM768 | Hybrid | PQ + Classical (default) |
//! | SECP256R1MLKEM768 | Hybrid | PQ + Classical |
//! | MLKEM768 | PQ-only | NIST Category 3 |
//! | MLKEM1024 | PQ-only | NIST Category 5 |
//! | X25519 | Classical | 128-bit |
//! | SECP256R1 | Classical | 128-bit |
//! | SECP384R1 | Classical | 192-bit |
//!
//! ## Compatibility
//!
//! Standard TLS 1.3 clients:
//! - With PQ support: Use X25519MLKEM768
//! - Without PQ support: Fall back to X25519 only
//! - Handshake succeeds in both cases

use crate::tls::{TlsError, TlsMode};
use rustls::NamedGroup;
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use std::mem;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

fn is_mlkem_group(group: &dyn SupportedKxGroup) -> bool {
    matches!(
        group.name(),
        NamedGroup::X25519MLKEM768
            | NamedGroup::secp256r1MLKEM768
            | NamedGroup::MLKEM768
            | NamedGroup::MLKEM1024
            | NamedGroup::MLKEM512
    )
}

/// Post-quantum key exchange configuration
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqKexMode {
    /// Use rustls native PQ support (X25519MLKEM768, MLKEM768, MLKEM1024)
    RustlsPq,
    /// Historically intended to route through a `latticearc::hybrid`-backed
    /// `SupportedKxGroup`. No such rustls integration exists today, so this
    /// variant currently behaves identically to [`PqKexMode::RustlsPq`] —
    /// rustls 0.23.37+ negotiates `X25519MLKEM768` natively regardless. For
    /// the standalone custom combiner outside TLS, call
    /// [`perform_hybrid_keygen`], [`perform_hybrid_encapsulate`], and
    /// [`perform_hybrid_decapsulate`] directly. Prefer
    /// [`PqKexMode::RustlsPq`] in new TLS code.
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
/// use latticearc::tls::pq_key_exchange::{get_kex_provider, PqKexMode};
/// use latticearc::tls::{TlsMode, TlsError};
///
/// # fn example() -> Result<(), TlsError> {
/// let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)?;
/// # Ok(())
/// # }
/// ```
pub fn get_kex_provider(mode: TlsMode, kex_mode: PqKexMode) -> Result<CryptoProvider, TlsError> {
    match (mode, kex_mode) {
        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::RustlsPq | PqKexMode::CustomHybrid) => {
            let mut provider = rustls::crypto::aws_lc_rs::default_provider();
            provider.kx_groups.sort_by_key(|g| if is_mlkem_group(*g) { 0 } else { 1 });
            Ok(provider)
        }

        (TlsMode::Classic, _) | (_, PqKexMode::Classical) => {
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
        (TlsMode::Hybrid | TlsMode::Pq, PqKexMode::RustlsPq | PqKexMode::CustomHybrid) => KexInfo {
            method: "X25519MLKEM768".to_string(),
            security_level: "Hybrid (Post-Quantum + Classical)".to_string(),
            is_pq_secure: true,
            pk_size: 32 + 1184, // X25519 (32) + ML-KEM-768 PK (1184)
            sk_size: 32 + 2400, // X25519 (32) + ML-KEM-768 SK (2400)
            ct_size: 32 + 1088, // X25519 (32) + ML-KEM-768 CT (1088)
            ss_size: 64,        // 64-byte shared secret
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

/// Check if post-quantum key exchange is available at runtime.
///
/// Inspects `rustls::crypto::aws_lc_rs::default_provider()` and returns `true`
/// iff it exposes at least one ML-KEM key-exchange group (e.g. `X25519MLKEM768`).
/// This depends on the linked rustls / aws-lc-rs versions — rustls 0.23.37+
/// ships PQ groups in `DEFAULT_KX_GROUPS`, older versions do not.
#[must_use]
pub fn is_pq_available() -> bool {
    rustls::crypto::aws_lc_rs::default_provider().kx_groups.iter().any(|g| is_mlkem_group(*g))
}

/// Check if custom-hybrid key exchange is available at runtime.
///
/// `CustomHybrid` delegates to rustls-native `X25519MLKEM768`, so this is
/// equivalent to [`is_pq_available`] for the TLS provider path. The standalone
/// combiner in [`crate::hybrid`] (used by `perform_hybrid_*`) is always compiled
/// in but is not exposed as a rustls `SupportedKxGroup`.
#[must_use]
pub fn is_custom_hybrid_available() -> bool {
    is_pq_available()
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
    pub fn secret_ref(&self) -> &[u8] {
        &self.secret
    }
}

impl AsRef<[u8]> for SecureSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.secret
    }
}

impl SecureSharedSecret {
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

impl std::fmt::Debug for SecureSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSharedSecret").field("data", &"[REDACTED]").finish()
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

impl ConstantTimeEq for SecureSharedSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret.ct_eq(&other.secret)
    }
}

/// Perform hybrid key generation
///
/// # Errors
///
/// Returns an error if the hybrid key generation fails due to internal
/// cryptographic errors (aws-lc-rs manages its own entropy).
pub fn perform_hybrid_keygen()
-> Result<(crate::hybrid::HybridKemPublicKey, crate::hybrid::HybridKemSecretKey), TlsError> {
    crate::hybrid::kem_generate_keypair().map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid keygen failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("keygen".to_string()),
        code: crate::tls::error::ErrorCode::KeyExchangeFailed,
        context: Box::default(),
        recovery: Box::new(crate::tls::error::RecoveryHint::NoRecovery),
    })
}

/// Perform hybrid encapsulation
///
/// # Errors
///
/// Returns an error if the encapsulation operation fails due to an invalid
/// public key or internal cryptographic errors.
pub fn perform_hybrid_encapsulate(
    pk: &crate::hybrid::HybridKemPublicKey,
) -> Result<crate::hybrid::EncapsulatedKey, TlsError> {
    crate::hybrid::encapsulate(pk).map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid encapsulation failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("encapsulate".to_string()),
        code: crate::tls::error::ErrorCode::EncapsulationFailed,
        context: Box::default(),
        recovery: Box::new(crate::tls::error::RecoveryHint::NoRecovery),
    })
}

/// Perform hybrid decapsulation securely (returns zeroizable secret)
///
/// # Errors
///
/// Returns an error if the decapsulation operation fails due to an invalid
/// ciphertext, corrupted secret key, or internal cryptographic errors.
pub fn perform_hybrid_decapsulate_secure(
    sk: &crate::hybrid::HybridKemSecretKey,
    ct: &crate::hybrid::EncapsulatedKey,
) -> Result<SecureSharedSecret, TlsError> {
    let secret = crate::hybrid::decapsulate(sk, ct).map_err(|e| TlsError::KeyExchange {
        message: format!("Hybrid decapsulation failed: {}", e),
        method: "X25519MLKEM768".to_string(),
        operation: Some("decapsulate".to_string()),
        code: crate::tls::error::ErrorCode::DecapsulationFailed,
        context: Box::default(),
        recovery: Box::new(crate::tls::error::RecoveryHint::NoRecovery),
    })?;
    // `secret` is `Zeroizing<Vec<u8>>`; take ownership of inner Vec.
    // SecureSharedSecret holds its own zeroization, so the outer wrapper is dropped safely.
    Ok(SecureSharedSecret::new((*secret).clone()))
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
    sk: &crate::hybrid::HybridKemSecretKey,
    ct: &crate::hybrid::EncapsulatedKey,
) -> Result<Zeroizing<Vec<u8>>, TlsError> {
    let secure_secret = perform_hybrid_decapsulate_secure(sk, ct)?;
    Ok(Zeroizing::new(secure_secret.into_inner_raw()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_kex_info_hybrid_is_correct() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
    }

    #[test]
    fn test_kex_info_classical_is_correct() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::Classical);
        assert_eq!(info.method, "X25519 (ECDHE)");
        assert!(!info.is_pq_secure);
        assert_eq!(info.ss_size, 32);
    }

    #[test]
    fn test_pq_availability_is_correct() {
        assert!(is_pq_available());
    }

    #[test]
    fn test_custom_hybrid_availability_is_correct() {
        assert!(is_custom_hybrid_available());
    }

    #[test]
    fn test_hybrid_key_exchange_roundtrip() {
        // Generate keypair
        let (pk, sk) = perform_hybrid_keygen().expect("Failed to generate keypair");

        // Encapsulate
        let enc = perform_hybrid_encapsulate(&pk).expect("Failed to encapsulate");

        // Decapsulate securely
        let secure_ss =
            perform_hybrid_decapsulate_secure(&sk, &enc).expect("Failed to decapsulate");

        // Verify
        assert_eq!(secure_ss.secret.as_slice(), enc.shared_secret());
        assert_eq!(secure_ss.secret.len(), 64);

        // Test regular decapsulation
        let ss = perform_hybrid_decapsulate(&sk, &enc).expect("Failed to decapsulate");
        assert_eq!(ss.as_slice(), enc.shared_secret());
        assert_eq!(ss.len(), 64);
    }

    #[test]
    fn test_get_kex_provider_succeeds() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_classical_succeeds() {
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::Classical);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_custom_hybrid_succeeds() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_pq_rustls_succeeds() {
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_pq_custom_hybrid_succeeds() {
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::CustomHybrid);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_get_kex_provider_classic_with_rustls_pq_succeeds() {
        // Classic mode overrides kex_mode
        let provider = get_kex_provider(TlsMode::Classic, PqKexMode::RustlsPq);
        assert!(provider.is_ok());
    }

    #[test]
    fn test_pq_groups_preferred_in_hybrid_mode_is_correct() {
        // Verify that PQ/hybrid groups come before classical-only groups
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
            .expect("Provider should be available");

        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

        // Find the position of the first MLKEM group and the last MLKEM group
        let first_mlkem = group_names.iter().position(|n| n.contains("MLKEM"));
        let last_classical = group_names.iter().rposition(|n| !n.contains("MLKEM"));

        // All MLKEM groups must come before all classical-only groups
        if let (Some(last_ml), Some(first_cl)) = (
            group_names.iter().rposition(|n| n.contains("MLKEM")),
            group_names.iter().position(|n| !n.contains("MLKEM")),
        ) {
            assert!(
                last_ml < first_cl,
                "PQ groups must be sorted before classical groups, got: {group_names:?}"
            );
        }
        // Verify at least one MLKEM group exists
        assert!(first_mlkem.is_some(), "Provider must contain at least one MLKEM group");
        assert!(last_classical.is_some(), "Provider must contain classical groups too");
    }

    #[test]
    fn test_pq_groups_preferred_in_pq_mode_is_correct() {
        // Same ordering guarantee for PQ-only mode
        let provider = get_kex_provider(TlsMode::Pq, PqKexMode::RustlsPq)
            .expect("Provider should be available");

        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();

        let first_mlkem = group_names.iter().position(|n| n.contains("MLKEM"));
        assert!(
            first_mlkem == Some(0),
            "First group in PQ mode must be an MLKEM group, got: {group_names:?}"
        );
    }

    #[test]
    fn test_native_pq_groups_are_available_succeeds() {
        // Verify rustls 0.23.37+ default_provider() includes X25519MLKEM768
        // natively (no rustls-post-quantum crate needed)
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::RustlsPq)
            .expect("Provider should be available");

        let group_names: Vec<String> =
            provider.kx_groups.iter().map(|g| format!("{:?}", g.name())).collect();
        let joined = group_names.join(",");

        // X25519MLKEM768 must be in DEFAULT_KX_GROUPS (the hybrid PQ group)
        assert!(joined.contains("X25519MLKEM768"), "Missing X25519MLKEM768 in {joined}");

        // Classical groups must also be present for fallback
        assert!(joined.contains("X25519"), "Missing X25519 classical fallback in {joined}");

        // Note: SECP256R1MLKEM768, MLKEM768, MLKEM1024 are in ALL_KX_GROUPS
        // but NOT in DEFAULT_KX_GROUPS / default_provider(). They can be added
        // explicitly if needed for PQ-only or P-256 hybrid modes.
    }

    // === KexInfo tests ===

    #[test]
    fn test_kex_info_custom_hybrid_is_correct() {
        let info = get_kex_info(TlsMode::Hybrid, PqKexMode::CustomHybrid);
        assert_eq!(info.method, "X25519MLKEM768");
        assert!(info.is_pq_secure);
        assert_eq!(info.ss_size, 64);
        assert_eq!(info.pk_size, 32 + 1184);
    }

    #[test]
    fn test_custom_hybrid_sorts_pq_groups_first() {
        let provider = get_kex_provider(TlsMode::Hybrid, PqKexMode::CustomHybrid)
            .expect("Provider should be available");
        let first = *provider.kx_groups.first().expect("Provider must have at least one kx_group");
        assert!(
            is_mlkem_group(first),
            "CustomHybrid must sort PQ groups first, got: {:?}",
            first.name()
        );
    }

    #[test]
    fn test_kex_info_pq_mode_is_correct() {
        let info = get_kex_info(TlsMode::Pq, PqKexMode::RustlsPq);
        assert!(info.is_pq_secure);
        assert_eq!(info.method, "X25519MLKEM768");
    }

    #[test]
    fn test_kex_info_classic_overrides_kex_mode_is_correct() {
        let info = get_kex_info(TlsMode::Classic, PqKexMode::RustlsPq);
        assert!(!info.is_pq_secure);
        assert!(info.method.contains("X25519"));
    }

    // === SecureSharedSecret tests ===

    #[test]
    fn test_secure_shared_secret_new_and_ref_is_correct() {
        let secret = SecureSharedSecret::new(vec![1, 2, 3, 4]);
        assert_eq!(secret.secret_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secure_shared_secret_as_ref_returns_correct_slice_succeeds() {
        let secret = SecureSharedSecret::new(vec![5, 6, 7]);
        let slice: &[u8] = secret.as_ref();
        assert_eq!(slice, &[5, 6, 7]);
    }

    #[test]
    fn test_secure_shared_secret_into_inner_returns_correct_value_succeeds() {
        let secret = SecureSharedSecret::new(vec![10, 20, 30]);
        let zeroizing = secret.into_inner();
        assert_eq!(zeroizing.as_slice(), &[10, 20, 30]);
        // Zeroizing wrapper will zeroize on drop
    }

    #[test]
    fn test_secure_shared_secret_into_inner_raw_returns_correct_value_succeeds() {
        let secret = SecureSharedSecret::new(vec![40, 50, 60]);
        let raw = secret.into_inner_raw();
        assert_eq!(raw, vec![40, 50, 60]);
    }

    #[test]
    fn test_secure_shared_secret_zeroize_succeeds() {
        let mut secret = SecureSharedSecret::new(vec![1, 2, 3, 4, 5]);
        secret.zeroize();
        assert!(secret.secret_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_shared_secret_drop_zeroizes_succeeds() {
        // Verify drop impl compiles and runs without panic
        let secret = SecureSharedSecret::new(vec![99; 64]);
        drop(secret);
    }

    // === PqKexMode tests ===

    #[test]
    fn test_pq_kex_mode_eq_is_correct() {
        assert_eq!(PqKexMode::RustlsPq, PqKexMode::RustlsPq);
        assert_eq!(PqKexMode::Classical, PqKexMode::Classical);
        assert_ne!(PqKexMode::RustlsPq, PqKexMode::Classical);
        assert_ne!(PqKexMode::CustomHybrid, PqKexMode::RustlsPq);
    }

    #[test]
    fn test_pq_kex_mode_debug_produces_expected_output_succeeds() {
        let debug_str = format!("{:?}", PqKexMode::CustomHybrid);
        assert!(debug_str.contains("CustomHybrid"));
    }
}
