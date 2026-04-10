#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Hybrid Encryption Module
//!
//! This module provides hybrid encryption combining post-quantum (ML-KEM) key
//! encapsulation with AES-256-GCM symmetric encryption for quantum-resistant
//! data encryption with classical performance characteristics.
//!
//! # Overview
//!
//! The hybrid encryption scheme uses:
//! - **ML-KEM-768** (FIPS 203) for post-quantum key encapsulation
//! - **AES-256-GCM** for authenticated symmetric encryption
//! - **HKDF-SHA256** for key derivation with domain separation
//!
//! # Security Properties
//!
//! - IND-CCA2 security from ML-KEM
//! - Authenticated encryption with associated data (AEAD)
//! - Domain separation via HPKE-style key derivation
//!
//! # Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::encrypt_hybrid::{encrypt, decrypt, HybridEncryptionContext};
//! # let ml_kem_pk = vec![0u8; 1184]; // ML-KEM-768 public key (placeholder)
//! # let ml_kem_sk = vec![0u8; 2400]; // ML-KEM-768 secret key (placeholder)
//!
//! let plaintext = b"Secret message";
//! let context = HybridEncryptionContext::default();
//!
//! // Encrypt with ML-KEM public key
//! let ciphertext = encrypt(&ml_kem_pk, plaintext, Some(&context))?;
//!
//! // Decrypt with ML-KEM secret key
//! let decrypted = decrypt(&ml_kem_sk, &ciphertext, Some(&context))?;
//! # Ok(())
//! # }
//! ```

use crate::hybrid::kem_hybrid::{self, EncapsulatedKey, HybridKemPublicKey, HybridKemSecretKey};
use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, NONCE_LEN, TAG_LEN};
use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Error types for hybrid encryption operations.
///
/// This enum captures all possible error conditions that can occur during
/// hybrid encryption and decryption operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HybridEncryptionError {
    /// Error during key encapsulation mechanism operations.
    #[error("KEM error: {0}")]
    KemError(String),
    /// Error during symmetric encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Error during symmetric decryption or authentication failure.
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Error during key derivation function operations.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid input parameters provided to the operation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Key length mismatch error.
    #[error("Key length error: expected {expected}, got {actual}")]
    KeyLengthError {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length provided.
        actual: usize,
    },
}

/// Hybrid ciphertext containing both KEM and symmetric encryption components.
///
/// This structure holds all the data needed to decrypt a hybrid-encrypted message:
/// - The KEM ciphertext for key decapsulation
/// - The symmetric ciphertext containing the encrypted message
/// - The nonce used for AES-GCM encryption
/// - The authentication tag for integrity verification
#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    /// ML-KEM ciphertext for key decapsulation (1088 bytes for ML-KEM-768).
    kem_ciphertext: Vec<u8>,
    /// X25519 ephemeral public key for ECDH (32 bytes). Empty for legacy ML-KEM-only ciphertexts.
    ecdh_ephemeral_pk: Vec<u8>,
    /// AES-256-GCM encrypted message data.
    symmetric_ciphertext: Vec<u8>,
    /// 12-byte nonce used for AES-GCM encryption.
    nonce: Vec<u8>,
    /// 16-byte AES-GCM authentication tag.
    tag: Vec<u8>,
}

impl HybridCiphertext {
    /// Construct a new `HybridCiphertext` from its components.
    ///
    /// # Parameters
    ///
    /// - `kem_ciphertext`: ML-KEM ciphertext for key decapsulation (1088 bytes for ML-KEM-768).
    /// - `ecdh_ephemeral_pk`: X25519 ephemeral public key (32 bytes). Pass `vec![]` for legacy
    ///   ML-KEM-only ciphertexts that do not include an ECDH component.
    /// - `symmetric_ciphertext`: AES-256-GCM encrypted message data.
    /// - `nonce`: 12-byte nonce used for AES-GCM encryption.
    /// - `tag`: 16-byte AES-GCM authentication tag.
    #[must_use]
    pub fn new(
        kem_ciphertext: Vec<u8>,
        ecdh_ephemeral_pk: Vec<u8>,
        symmetric_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        tag: Vec<u8>,
    ) -> Self {
        Self { kem_ciphertext, ecdh_ephemeral_pk, symmetric_ciphertext, nonce, tag }
    }

    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn kem_ciphertext(&self) -> &[u8] {
        &self.kem_ciphertext
    }

    /// Returns the X25519 ephemeral public key bytes.
    /// Empty for legacy ML-KEM-only ciphertexts.
    #[must_use]
    pub fn ecdh_ephemeral_pk(&self) -> &[u8] {
        &self.ecdh_ephemeral_pk
    }

    /// Returns the AES-256-GCM symmetric ciphertext bytes.
    #[must_use]
    pub fn symmetric_ciphertext(&self) -> &[u8] {
        &self.symmetric_ciphertext
    }

    /// Returns the 12-byte AES-GCM nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Returns the 16-byte AES-GCM authentication tag.
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Returns a mutable reference to the ML-KEM ciphertext bytes.
    pub fn kem_ciphertext_mut(&mut self) -> &mut Vec<u8> {
        &mut self.kem_ciphertext
    }

    /// Returns a mutable reference to the X25519 ephemeral public key bytes.
    pub fn ecdh_ephemeral_pk_mut(&mut self) -> &mut Vec<u8> {
        &mut self.ecdh_ephemeral_pk
    }

    /// Returns a mutable reference to the AES-256-GCM symmetric ciphertext bytes.
    pub fn symmetric_ciphertext_mut(&mut self) -> &mut Vec<u8> {
        &mut self.symmetric_ciphertext
    }

    /// Returns a mutable reference to the 12-byte AES-GCM nonce.
    pub fn nonce_mut(&mut self) -> &mut Vec<u8> {
        &mut self.nonce
    }

    /// Returns a mutable reference to the 16-byte AES-GCM authentication tag.
    pub fn tag_mut(&mut self) -> &mut Vec<u8> {
        &mut self.tag
    }
}

/// HPKE-style context information for hybrid encryption.
///
/// This structure provides domain separation and additional authenticated data
/// for the key derivation and encryption operations, following RFC 9180 (HPKE).
#[derive(Debug, Clone)]
pub struct HybridEncryptionContext {
    /// Application-specific info string for key derivation domain separation.
    pub info: Vec<u8>,
    /// Additional authenticated data (AAD) for AEAD encryption.
    pub aad: Vec<u8>,
}

impl Default for HybridEncryptionContext {
    fn default() -> Self {
        Self { info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(), aad: vec![] }
    }
}

/// HPKE-style key derivation for hybrid encryption.
///
/// Delegates to the primitives HKDF wrapper (`primitives::kdf::hkdf::hkdf`)
/// which is backed by aws-lc-rs HMAC-SHA256 under the hood, so all callers share
/// the same FIPS-validated implementation, zeroization guarantees, and
/// instrumentation.
///
/// # Security
///
/// The context's AAD is bound in two places: (1) mixed into the HKDF info
/// parameter here, so different AAD values derive different encryption keys,
/// and (2) passed to AES-GCM as authenticated data during encrypt/decrypt.
/// This dual binding ensures AAD provides both key separation and ciphertext
/// authentication.
///
/// # Errors
///
/// Returns an error if the shared secret is not exactly 32 or 64 bytes,
/// or if HKDF expansion fails.
pub fn derive_encryption_key(
    shared_secret: &[u8],
    context: &HybridEncryptionContext,
) -> Result<Zeroizing<[u8; 32]>, HybridEncryptionError> {
    if shared_secret.len() != 32 && shared_secret.len() != 64 {
        return Err(HybridEncryptionError::KdfError(
            "Shared secret must be 32 bytes (ML-KEM) or 64 bytes (hybrid)".to_string(),
        ));
    }

    // Reject inputs that would overflow our length prefixes. u32 covers every
    // realistic context, and the early check keeps the `as u32` conversions
    // below non-truncating.
    if context.info.len() > u32::MAX as usize || context.aad.len() > u32::MAX as usize {
        return Err(HybridEncryptionError::KdfError(
            "HKDF info or AAD field exceeds 2^32 bytes".to_string(),
        ));
    }

    // Build a length-prefixed HKDF info payload to prevent canonicalization
    // collisions between the two variable-length fields (info, aad). Naive
    // concatenation `info || "||" || aad` is ambiguous when the source data
    // can contain the separator bytes; length-prefixing is the standard fix
    // (HPKE §5.1, RFC 9180 "LabeledExtract").
    //
    // Wire layout: [info_len: u32 BE][info][aad_len: u32 BE][aad]
    let info_len = context.info.len();
    let aad_len = context.aad.len();
    let total = 4usize.saturating_add(info_len).saturating_add(4).saturating_add(aad_len);
    let mut info = Vec::with_capacity(total);
    // Safe: bounds-checked above — `try_from` cannot fail after the length
    // guards, but we use it to silence `cast_possible_truncation` and prove
    // the non-truncation invariant to the compiler.
    let info_len_u32 = u32::try_from(info_len).map_err(|_e| {
        HybridEncryptionError::KdfError("HKDF info field exceeds 2^32 bytes".to_string())
    })?;
    let aad_len_u32 = u32::try_from(aad_len).map_err(|_e| {
        HybridEncryptionError::KdfError("HKDF AAD field exceeds 2^32 bytes".to_string())
    })?;
    info.extend_from_slice(&info_len_u32.to_be_bytes());
    info.extend_from_slice(&context.info);
    info.extend_from_slice(&aad_len_u32.to_be_bytes());
    info.extend_from_slice(&context.aad);

    // HKDF-SHA256 via primitives wrapper (backed by aws-lc-rs HMAC).
    let hkdf_result = hkdf(shared_secret, None, Some(&info), 32)
        .map_err(|e| HybridEncryptionError::KdfError(format!("HKDF failed: {e}")))?;

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(hkdf_result.key());
    Ok(key)
}

/// Hybrid encryption using ML-KEM + AES-256-GCM with HPKE-style key derivation.
///
/// # Security
///
/// - AES-256-GCM nonce generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - HKDF key derivation uses `HYBRID_ENCRYPTION_INFO` domain separation (SP 800-56C)
/// - ML-KEM shared secret is zeroized after key derivation
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM public key is not 1184 bytes (ML-KEM-768)
/// - ML-KEM encapsulation fails
/// - Key derivation fails
/// - AES-GCM encryption fails
pub fn encrypt(
    ml_kem_pk: &[u8],
    plaintext: &[u8],
    context: Option<&HybridEncryptionContext>,
) -> Result<HybridCiphertext, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate inputs
    if ml_kem_pk.len() != 1184 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 public key must be 1184 bytes".to_string(),
        ));
    }

    // ML-KEM encapsulation
    let ml_kem_pk_struct = MlKemPublicKey::new(MlKemSecurityLevel::MlKem768, ml_kem_pk.to_vec())
        .map_err(|e| HybridEncryptionError::KemError(format!("{e}")))?;
    let (shared_secret, kem_ct_struct) = MlKem::encapsulate(&ml_kem_pk_struct)
        .map_err(|e| HybridEncryptionError::KemError(format!("{e}")))?;
    let kem_ct = kem_ct_struct.into_bytes();

    // Derive encryption key using HPKE-style KDF (via primitives wrapper)
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), ctx)?;

    // Generate random nonce for AES-GCM via the primitives layer.
    let nonce_bytes = AesGcm256::generate_nonce();

    // AES-256-GCM via primitives wrapper. AesGcm256 holds key bytes in
    // Zeroizing storage (via ZeroizeOnDrop) and runs the zero-key guard.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|e| {
        HybridEncryptionError::EncryptionError(format!("Failed to create AES key: {e}"))
    })?;
    let (ciphertext, tag) =
        cipher.encrypt(&nonce_bytes, plaintext, Some(&ctx.aad)).map_err(|e| {
            HybridEncryptionError::EncryptionError(format!("AES-GCM encryption failed: {e}"))
        })?;

    Ok(HybridCiphertext::new(
        kem_ct,
        vec![], // Legacy ML-KEM-only path — no ECDH
        ciphertext,
        nonce_bytes.to_vec(),
        tag.to_vec(),
    ))
}

/// Hybrid decryption using ML-KEM + AES-256-GCM with HPKE-style key derivation.
///
/// # Errors
///
/// Returns an error if:
/// - The ML-KEM secret key is not 2400 bytes (ML-KEM-768)
/// - The ciphertext components have invalid lengths
/// - ML-KEM decapsulation fails
/// - Key derivation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt(
    ml_kem_sk: &[u8],
    ciphertext: &HybridCiphertext,
    context: Option<&HybridEncryptionContext>,
) -> Result<Zeroizing<Vec<u8>>, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate inputs
    if ml_kem_sk.len() != 2400 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 secret key must be 2400 bytes".to_string(),
        ));
    }
    if ciphertext.kem_ciphertext().len() != 1088 {
        return Err(HybridEncryptionError::InvalidInput(
            "ML-KEM-768 ciphertext must be 1088 bytes".to_string(),
        ));
    }
    if ciphertext.nonce().len() != 12 {
        return Err(HybridEncryptionError::InvalidInput("Nonce must be 12 bytes".to_string()));
    }
    if ciphertext.tag().len() != 16 {
        return Err(HybridEncryptionError::InvalidInput("Tag must be 16 bytes".to_string()));
    }

    // ML-KEM decapsulation
    let ml_kem_sk_struct = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, ml_kem_sk.to_vec())
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{e}")))?;
    let ml_kem_ct_struct =
        MlKemCiphertext::new(MlKemSecurityLevel::MlKem768, ciphertext.kem_ciphertext().to_vec())
            .map_err(|e| HybridEncryptionError::DecryptionError(format!("{e}")))?;
    let shared_secret = MlKem::decapsulate(&ml_kem_sk_struct, &ml_kem_ct_struct)
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{e}")))?;

    // Derive encryption key using HPKE-style KDF (via primitives wrapper)
    let encryption_key = derive_encryption_key(shared_secret.as_bytes(), ctx)?;

    let nonce_bytes: [u8; NONCE_LEN] = ciphertext.nonce().try_into().map_err(|e| {
        HybridEncryptionError::DecryptionError(format!("Invalid nonce length: {e}"))
    })?;
    let tag_bytes: [u8; TAG_LEN] = ciphertext
        .tag()
        .try_into()
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("Invalid tag length: {e}")))?;

    // AES-256-GCM via primitives wrapper.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|e| {
        HybridEncryptionError::DecryptionError(format!("Failed to create AES key: {e}"))
    })?;
    // `cipher.decrypt` already returns `Zeroizing<Vec<u8>>` — propagate directly.
    let plaintext = cipher
        .decrypt(&nonce_bytes, ciphertext.symmetric_ciphertext(), &tag_bytes, Some(&ctx.aad))
        .map_err(|_aead_err| {
            // SECURITY: Opaque error per SP 800-38D §5.2.2 — do not propagate
            // the underlying error to prevent padding/MAC oracle attacks.
            HybridEncryptionError::DecryptionError("hybrid decryption failed".to_string())
        })?;

    Ok(plaintext)
}

/// True hybrid encryption using ML-KEM-768 + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key encapsulation (combining post-quantum
/// ML-KEM with classical X25519 ECDH via HKDF) before AES-256-GCM encryption.
/// Security holds if *either* ML-KEM or X25519 remains secure.
///
/// # Security
///
/// - Hybrid security: breaks only if BOTH ML-KEM and X25519 are compromised
/// - AES-256-GCM nonce generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - HKDF dual-PRF combiner with domain separation (SP 800-56C)
/// - All shared secrets are zeroized after key derivation
///
/// # Errors
///
/// Returns an error if:
/// - Hybrid KEM encapsulation fails
/// - Key derivation fails
/// - AES-GCM encryption fails
pub fn encrypt_hybrid(
    hybrid_pk: &HybridKemPublicKey,
    plaintext: &[u8],
    context: Option<&HybridEncryptionContext>,
) -> Result<HybridCiphertext, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Hybrid KEM encapsulation (ML-KEM-768 + X25519 ECDH + HKDF)
    let encapsulated = kem_hybrid::encapsulate(hybrid_pk)
        .map_err(|e| HybridEncryptionError::KemError(format!("{e}")))?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret
    let encryption_key = derive_encryption_key(encapsulated.shared_secret(), ctx)?;

    // Generate random nonce for AES-GCM via the primitives layer.
    let nonce_bytes = AesGcm256::generate_nonce();

    // AES-256-GCM via primitives wrapper.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|e| {
        HybridEncryptionError::EncryptionError(format!("Failed to create AES key: {e}"))
    })?;
    let (ciphertext, tag) =
        cipher.encrypt(&nonce_bytes, plaintext, Some(&ctx.aad)).map_err(|e| {
            HybridEncryptionError::EncryptionError(format!("AES-GCM encryption failed: {e}"))
        })?;

    Ok(HybridCiphertext::new(
        encapsulated.ml_kem_ct().to_vec(),
        encapsulated.ecdh_pk().to_vec(),
        ciphertext,
        nonce_bytes.to_vec(),
        tag.to_vec(),
    ))
}

/// True hybrid decryption using ML-KEM + X25519 + AES-256-GCM.
///
/// This function performs real hybrid key decapsulation (ML-KEM decapsulation +
/// X25519 ECDH agreement, combined via HKDF) before AES-256-GCM decryption.
/// The ML-KEM security level is determined by the secret key.
///
/// # Errors
///
/// Returns an error if:
/// - The ciphertext components have invalid lengths
/// - Hybrid KEM decapsulation fails
/// - Key derivation fails
/// - AES-GCM decryption or authentication fails
pub fn decrypt_hybrid(
    hybrid_sk: &HybridKemSecretKey,
    ciphertext: &HybridCiphertext,
    context: Option<&HybridEncryptionContext>,
) -> Result<Zeroizing<Vec<u8>>, HybridEncryptionError> {
    let default_ctx = HybridEncryptionContext::default();
    let ctx = context.unwrap_or(&default_ctx);

    // Validate ciphertext structure against the secret key's security level
    let expected_ct_size = hybrid_sk.security_level().ciphertext_size();
    if ciphertext.kem_ciphertext().len() != expected_ct_size {
        return Err(HybridEncryptionError::InvalidInput(format!(
            "{} ciphertext must be {} bytes, got {}",
            hybrid_sk.security_level().name(),
            expected_ct_size,
            ciphertext.kem_ciphertext().len()
        )));
    }
    if ciphertext.ecdh_ephemeral_pk().len() != 32 {
        return Err(HybridEncryptionError::InvalidInput(
            "X25519 ephemeral public key must be 32 bytes".to_string(),
        ));
    }
    if ciphertext.nonce().len() != 12 {
        return Err(HybridEncryptionError::InvalidInput("Nonce must be 12 bytes".to_string()));
    }
    if ciphertext.tag().len() != 16 {
        return Err(HybridEncryptionError::InvalidInput("Tag must be 16 bytes".to_string()));
    }

    // Reconstruct EncapsulatedKey for kem_hybrid::decapsulate
    let encapsulated = EncapsulatedKey::new(
        ciphertext.kem_ciphertext().to_vec(),
        ciphertext.ecdh_ephemeral_pk().to_vec(),
        Zeroizing::new(vec![]), // placeholder — decapsulate recovers this
    );

    // Hybrid KEM decapsulation (ML-KEM + X25519 ECDH + HKDF)
    let shared_secret = kem_hybrid::decapsulate(hybrid_sk, &encapsulated)
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("{e}")))?;

    // Derive AES-256 encryption key from 64-byte hybrid shared secret
    let encryption_key = derive_encryption_key(&shared_secret, ctx)?;

    let nonce_bytes: [u8; NONCE_LEN] = ciphertext.nonce().try_into().map_err(|e| {
        HybridEncryptionError::DecryptionError(format!("Invalid nonce length: {e}"))
    })?;
    let tag_bytes: [u8; TAG_LEN] = ciphertext
        .tag()
        .try_into()
        .map_err(|e| HybridEncryptionError::DecryptionError(format!("Invalid tag length: {e}")))?;

    // AES-256-GCM via primitives wrapper.
    let cipher = AesGcm256::new(&*encryption_key).map_err(|e| {
        HybridEncryptionError::DecryptionError(format!("Failed to create AES key: {e}"))
    })?;
    // `cipher.decrypt` already returns `Zeroizing<Vec<u8>>` — propagate directly.
    let plaintext = cipher
        .decrypt(&nonce_bytes, ciphertext.symmetric_ciphertext(), &tag_bytes, Some(&ctx.aad))
        .map_err(|_aead_err| {
            // SECURITY: Opaque error per SP 800-38D §5.2.2 — do not propagate
            // the underlying error to prevent padding/MAC oracle attacks.
            HybridEncryptionError::DecryptionError("hybrid decryption failed".to_string())
        })?;

    Ok(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        // Generate ML-KEM keypair for testing
        let (ml_kem_pk, ml_kem_sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Hello, hybrid encryption with HPKE!";
        let context = HybridEncryptionContext::default();

        // Test encryption
        let ct = encrypt(ml_kem_pk.as_bytes(), plaintext, Some(&context));
        assert!(ct.is_ok(), "Encryption should succeed");

        let ct = ct.unwrap();
        assert_eq!(ct.kem_ciphertext().len(), 1088, "KEM ciphertext should be 1088 bytes");
        assert!(!ct.symmetric_ciphertext().is_empty(), "Symmetric ciphertext should not be empty");
        assert_eq!(ct.nonce().len(), 12, "Nonce should be 12 bytes");
        assert_eq!(ct.tag().len(), 16, "Tag should be 16 bytes");

        // Test decryption
        let decrypted = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&context));
        assert!(decrypted.is_ok(), "Decryption should succeed");
        assert_eq!(
            decrypted.unwrap().as_slice(),
            plaintext.as_slice(),
            "Decrypted text should match original"
        );
    }

    #[test]
    fn test_hybrid_encryption_with_aad_succeeds() {
        let (ml_kem_pk, ml_kem_sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Secret message with AAD";
        let aad = b"Additional authenticated data";
        let context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: aad.to_vec(),
        };

        // Encrypt with AAD
        let ct = encrypt(ml_kem_pk.as_bytes(), plaintext, Some(&context)).unwrap();

        // Decrypt with correct AAD
        let decrypted = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&context)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decryption with correct AAD should succeed"
        );

        // Decrypt with wrong AAD should fail
        let wrong_context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: b"Wrong AAD".to_vec(),
        };
        let result = decrypt(ml_kem_sk.as_bytes(), &ct, Some(&wrong_context));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_invalid_key_lengths_fail_fails() {
        let plaintext = b"Test message";

        // Test invalid ML-KEM public key length
        let invalid_pk = vec![1u8; 1000]; // Wrong length
        let result = encrypt(&invalid_pk, plaintext, None);
        assert!(result.is_err(), "Should reject invalid public key length");

        // Test invalid ML-KEM secret key length
        let invalid_sk = vec![1u8; 1000]; // Wrong length
        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 100],
            vec![3u8; 12],
            vec![4u8; 16],
        );
        let result = decrypt(&invalid_sk, &ct, None);
        assert!(result.is_err(), "Should reject invalid secret key length");
    }

    #[test]
    fn test_invalid_ciphertext_components_fail_decryption_fails() {
        let valid_sk = vec![1u8; 2400];

        // Test invalid nonce length
        let invalid_nonce_ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 100],
            vec![3u8; 11], // Invalid length
            vec![4u8; 16],
        );
        let result = decrypt(&valid_sk, &invalid_nonce_ct, None);
        assert!(result.is_err(), "Should reject invalid nonce length");

        // Test invalid tag length
        let invalid_tag_ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 100],
            vec![3u8; 12],
            vec![4u8; 15], // Invalid length
        );
        let result = decrypt(&valid_sk, &invalid_tag_ct, None);
        assert!(result.is_err(), "Should reject invalid tag length");

        // Test invalid KEM ciphertext length
        let invalid_kem_ct = HybridCiphertext::new(
            vec![1u8; 1000], // Invalid length
            vec![],
            vec![2u8; 100],
            vec![3u8; 12],
            vec![4u8; 16],
        );
        let result = decrypt(&valid_sk, &invalid_kem_ct, None);
        assert!(result.is_err(), "Should reject invalid KEM ciphertext length");
    }

    #[test]
    fn test_key_derivation_properties_are_deterministic_and_unique() {
        let shared_secret = vec![1u8; 32];
        let context1 =
            HybridEncryptionContext { info: b"Context1".to_vec(), aad: b"AAD1".to_vec() };
        let context2 =
            HybridEncryptionContext { info: b"Context2".to_vec(), aad: b"AAD2".to_vec() };

        let key1 = derive_encryption_key(&shared_secret, &context1).unwrap();
        let key2 = derive_encryption_key(&shared_secret, &context2).unwrap();

        // Different contexts should produce different keys
        assert_ne!(key1, key2, "Different contexts should produce different keys");

        // Same context should produce same key (deterministic)
        let key1_again = derive_encryption_key(&shared_secret, &context1).unwrap();
        assert_eq!(key1, key1_again, "Key derivation should be deterministic");

        // Test invalid shared secret length
        let invalid_secret = vec![1u8; 31]; // Wrong length
        let result = derive_encryption_key(&invalid_secret, &context1);
        assert!(result.is_err(), "Should reject invalid shared secret length");

        // Test 64-byte hybrid shared secret is accepted
        let hybrid_secret = vec![1u8; 64];
        let result = derive_encryption_key(&hybrid_secret, &context1);
        assert!(result.is_ok(), "Should accept 64-byte hybrid shared secret");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_roundtrip() {
        // Generate hybrid keypair (ML-KEM-768 + X25519)
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Hello, true hybrid encryption!";
        let context = HybridEncryptionContext::default();

        // Encrypt with true hybrid (ML-KEM + X25519 + HKDF + AES-GCM)
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&context)).unwrap();

        assert_eq!(ct.kem_ciphertext().len(), 1088, "ML-KEM-768 ciphertext should be 1088 bytes");
        assert_eq!(ct.ecdh_ephemeral_pk().len(), 32, "X25519 ephemeral PK should be 32 bytes");
        assert!(!ct.symmetric_ciphertext().is_empty(), "Symmetric ciphertext should not be empty");
        assert_eq!(ct.nonce().len(), 12, "Nonce should be 12 bytes");
        assert_eq!(ct.tag().len(), 16, "Tag should be 16 bytes");

        // Decrypt with true hybrid
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decrypted text should match original"
        );
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_with_aad_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Secret message with AAD";
        let aad = b"Additional authenticated data";
        let context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: aad.to_vec(),
        };

        // Encrypt with AAD
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&context)).unwrap();

        // Decrypt with correct AAD
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&context)).unwrap();
        assert_eq!(
            decrypted.as_slice(),
            plaintext.as_slice(),
            "Decryption with correct AAD should succeed"
        );

        // Decrypt with wrong AAD should fail
        let wrong_context = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: b"Wrong AAD".to_vec(),
        };
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&wrong_context));
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_kem_ecdh_hybrid_encryption_different_ciphertexts_for_same_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Same plaintext, different ciphertexts";

        let ct1 = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let ct2 = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();

        // Ciphertexts should differ (randomized encapsulation + nonce)
        assert_ne!(ct1.kem_ciphertext(), ct2.kem_ciphertext());
        assert_ne!(ct1.ecdh_ephemeral_pk(), ct2.ecdh_ephemeral_pk());

        // Both should decrypt correctly
        let dec1 = decrypt_hybrid(&hybrid_sk, &ct1, None).unwrap();
        let dec2 = decrypt_hybrid(&hybrid_sk, &ct2, None).unwrap();
        assert_eq!(dec1.as_slice(), plaintext.as_slice());
        assert_eq!(dec2.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_error_display_variants_produce_nonempty_strings_fails() {
        let kem_err = HybridEncryptionError::KemError("kem fail".to_string());
        assert!(kem_err.to_string().contains("kem fail"));

        let enc_err = HybridEncryptionError::EncryptionError("enc fail".to_string());
        assert!(enc_err.to_string().contains("enc fail"));

        let dec_err = HybridEncryptionError::DecryptionError("dec fail".to_string());
        assert!(dec_err.to_string().contains("dec fail"));

        let kdf_err = HybridEncryptionError::KdfError("kdf fail".to_string());
        assert!(kdf_err.to_string().contains("kdf fail"));

        let input_err = HybridEncryptionError::InvalidInput("bad input".to_string());
        assert!(input_err.to_string().contains("bad input"));

        let key_err = HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 };
        let msg = key_err.to_string();
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_error_eq_and_clone_work_correctly_fails() {
        let err1 = HybridEncryptionError::KemError("test".to_string());
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = HybridEncryptionError::KemError("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_hybrid_ciphertext_clone_debug_work_correctly_succeeds() {
        let ct = HybridCiphertext::new(
            vec![1, 2, 3],
            vec![4, 5],
            vec![6, 7, 8],
            vec![9; 12],
            vec![10; 16],
        );
        let ct2 = ct.clone();
        assert_eq!(ct.kem_ciphertext(), ct2.kem_ciphertext());
        assert_eq!(ct.ecdh_ephemeral_pk(), ct2.ecdh_ephemeral_pk());

        let debug_str = format!("{:?}", ct);
        assert!(debug_str.contains("HybridCiphertext"));
    }

    #[test]
    fn test_encryption_context_default_sets_expected_fields_succeeds() {
        let ctx = HybridEncryptionContext::default();
        assert_eq!(ctx.info, crate::types::domains::HYBRID_ENCRYPTION_INFO);
        assert!(ctx.aad.is_empty());
    }

    #[test]
    fn test_encryption_context_clone_debug_work_correctly_succeeds() {
        let ctx =
            HybridEncryptionContext { info: b"custom-info".to_vec(), aad: b"custom-aad".to_vec() };
        let ctx2 = ctx.clone();
        assert_eq!(ctx.info, ctx2.info);
        assert_eq!(ctx.aad, ctx2.aad);

        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("HybridEncryptionContext"));
    }

    #[test]
    fn test_derive_key_invalid_lengths_fail_fails() {
        let ctx = HybridEncryptionContext::default();

        // Too short (31 bytes)
        assert!(derive_encryption_key(&[0u8; 31], &ctx).is_err());

        // Too long (65 bytes)
        assert!(derive_encryption_key(&[0u8; 65], &ctx).is_err());

        // 1 byte
        assert!(derive_encryption_key(&[0u8; 1], &ctx).is_err());

        // Empty
        assert!(derive_encryption_key(&[], &ctx).is_err());

        // 33 bytes (between valid sizes)
        assert!(derive_encryption_key(&[0u8; 33], &ctx).is_err());
    }

    #[test]
    fn test_derive_key_different_secrets_produce_different_keys_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];

        let key_a = derive_encryption_key(&secret_a, &ctx).unwrap();
        let key_b = derive_encryption_key(&secret_b, &ctx).unwrap();

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_64_byte_hybrid_secret_succeeds() {
        let ctx = HybridEncryptionContext::default();
        let secret = [42u8; 64];
        let key = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key.len(), 32);

        // Deterministic
        let key2 = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_decrypt_hybrid_invalid_kem_ct_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 500],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 16],
        ); // Wrong: KEM CT should be 1088
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_ecdh_pk_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 16],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 16],
        ); // Wrong: ECDH PK should be 32
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
    }

    #[test]
    fn test_decrypt_hybrid_invalid_nonce_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 8],
            vec![5u8; 16],
        ); // Wrong: nonce should be 12
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_invalid_tag_length_fails() {
        let (_hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![2u8; 32],
            vec![3u8; 64],
            vec![4u8; 12],
            vec![5u8; 10],
        ); // Wrong: tag should be 16
        let result = decrypt_hybrid(&hybrid_sk, &ct, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hybrid_tampered_ciphertext_fails() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Test message for tampering";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();

        // Tamper with symmetric ciphertext
        let mut tampered = ct.clone();
        if let Some(byte) = tampered.symmetric_ciphertext_mut().first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered, None).is_err());

        // Tamper with tag
        let mut tampered_tag = ct;
        if let Some(byte) = tampered_tag.tag.first_mut() {
            *byte ^= 0xFF;
        }
        assert!(decrypt_hybrid(&hybrid_sk, &tampered_tag, None).is_err());
    }

    #[test]
    fn test_encrypt_hybrid_empty_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_hybrid_large_plaintext_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = vec![0xABu8; 10_000];
        let ct = encrypt_hybrid(&hybrid_pk, &plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    // --- ML-KEM-only encrypt() tests (encapsulation works, decapsulation blocked) ---

    #[test]
    fn test_ml_kem_encrypt_succeeds() {
        let (ml_kem_pk, _ml_kem_sk) =
            MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Encrypt-only test";
        let ct = encrypt(ml_kem_pk.as_bytes(), plaintext, None);
        assert!(ct.is_ok(), "ML-KEM-only encrypt should succeed");

        let ct = ct.unwrap();
        assert_eq!(ct.kem_ciphertext().len(), 1088);
        assert!(ct.ecdh_ephemeral_pk().is_empty(), "ML-KEM-only path has no ECDH key");
        assert!(!ct.symmetric_ciphertext().is_empty());
        assert_eq!(ct.nonce().len(), 12);
        assert_eq!(ct.tag().len(), 16);
    }

    #[test]
    fn test_ml_kem_encrypt_with_custom_context_succeeds() {
        let (ml_kem_pk, _) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let ctx = HybridEncryptionContext {
            info: b"Custom-Info-Domain".to_vec(),
            aad: b"Custom-AAD".to_vec(),
        };
        let ct = encrypt(ml_kem_pk.as_bytes(), b"test data", Some(&ctx));
        assert!(ct.is_ok(), "Should encrypt with custom context");
    }

    #[test]
    fn test_ml_kem_encrypt_produces_unique_ciphertexts_are_unique() {
        let (ml_kem_pk, _) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let plaintext = b"Determinism test";
        let ct1 = encrypt(ml_kem_pk.as_bytes(), plaintext, None).unwrap();
        let ct2 = encrypt(ml_kem_pk.as_bytes(), plaintext, None).unwrap();

        // Randomized: different KEM ciphertext and nonce each time
        assert_ne!(ct1.kem_ciphertext(), ct2.kem_ciphertext());
        assert_ne!(ct1.nonce(), ct2.nonce());
    }

    #[test]
    fn test_ml_kem_encrypt_empty_plaintext_succeeds() {
        let (ml_kem_pk, _) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        let ct = encrypt(ml_kem_pk.as_bytes(), b"", None);
        assert!(ct.is_ok(), "Should encrypt empty plaintext");
        let ct = ct.unwrap();
        assert!(ct.symmetric_ciphertext().is_empty(), "Empty plaintext → empty ciphertext");
        assert_eq!(ct.tag().len(), 16, "Tag is always 16 bytes");
    }

    #[test]
    fn test_decrypt_invalid_ml_kem_sk_length_fails() {
        let sk = vec![0u8; 100]; // Wrong length
        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 64],
            vec![3u8; 12],
            vec![4u8; 16],
        );
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("2400"));
    }

    #[test]
    fn test_decrypt_invalid_kem_ciphertext_length_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![1u8; 500],
            vec![],
            vec![2u8; 64],
            vec![3u8; 12],
            vec![4u8; 16],
        ); // Wrong KEM CT length
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("1088"));
    }

    #[test]
    fn test_decrypt_invalid_nonce_length_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 64],
            vec![3u8; 10],
            vec![4u8; 16],
        ); // Wrong nonce length
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("12"));
    }

    #[test]
    fn test_decrypt_invalid_tag_length_fails() {
        let sk = vec![0u8; 2400];
        let ct = HybridCiphertext::new(
            vec![1u8; 1088],
            vec![],
            vec![2u8; 64],
            vec![3u8; 12],
            vec![4u8; 8],
        ); // Wrong tag length
        let err = decrypt(&sk, &ct, None).unwrap_err();
        assert!(matches!(err, HybridEncryptionError::InvalidInput(_)));
        assert!(err.to_string().contains("16"));
    }

    #[test]
    fn test_encrypt_hybrid_with_none_context_uses_default_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let plaintext = b"Default context test";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, None).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_hybrid_with_none_context_uses_default_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let default_ctx = HybridEncryptionContext::default();
        let ct = encrypt_hybrid(&hybrid_pk, b"ctx test", Some(&default_ctx)).unwrap();
        // Decrypt with None context should also use default
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, None).unwrap();
        assert_eq!(decrypted.as_slice(), b"ctx test");
    }

    #[test]
    fn test_encrypt_with_none_context_uses_default_succeeds() {
        let (ml_kem_pk, _) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).unwrap();

        // encrypt() with None should use default context internally
        let ct = encrypt(ml_kem_pk.as_bytes(), b"none ctx", None);
        assert!(ct.is_ok());
    }

    // ========================================================================
    // Additional coverage: derive_encryption_key and error paths
    // ========================================================================

    #[test]
    fn test_derive_encryption_key_with_64_byte_secret_succeeds() {
        let secret = [0xAA; 64]; // Hybrid 64-byte shared secret
        let ctx = HybridEncryptionContext::default();
        let key = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_encryption_key_invalid_length_fails() {
        let ctx = HybridEncryptionContext::default();
        // 16 bytes is neither 32 nor 64
        let result = derive_encryption_key(&[0u8; 16], &ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_derive_encryption_key_is_deterministic() {
        let secret = [0xBB; 32];
        let ctx = HybridEncryptionContext::default();
        let k1 = derive_encryption_key(&secret, &ctx).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx).unwrap();
        assert_eq!(k1, k2, "Same inputs must produce same key");
    }

    #[test]
    fn test_derive_encryption_key_different_contexts_produce_different_keys_succeeds() {
        let secret = [0xCC; 32];
        let ctx1 = HybridEncryptionContext { info: b"ctx1".to_vec(), aad: vec![] };
        let ctx2 = HybridEncryptionContext { info: b"ctx2".to_vec(), aad: vec![] };
        let k1 = derive_encryption_key(&secret, &ctx1).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx2).unwrap();
        assert_ne!(k1, k2, "Different contexts must produce different keys");
    }

    #[test]
    fn test_derive_encryption_key_with_aad_succeeds() {
        let secret = [0xDD; 32];
        let ctx_no_aad = HybridEncryptionContext::default();
        let ctx_with_aad = HybridEncryptionContext {
            info: crate::types::domains::HYBRID_ENCRYPTION_INFO.to_vec(),
            aad: b"extra-data".to_vec(),
        };
        let k1 = derive_encryption_key(&secret, &ctx_no_aad).unwrap();
        let k2 = derive_encryption_key(&secret, &ctx_with_aad).unwrap();
        assert_ne!(k1, k2, "Different AAD must produce different keys");
    }

    #[test]
    fn test_encrypt_hybrid_custom_context_succeeds() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ctx = HybridEncryptionContext {
            info: b"custom-app-info".to_vec(),
            aad: b"custom-aad".to_vec(),
        };

        let plaintext = b"Custom context encryption";
        let ct = encrypt_hybrid(&hybrid_pk, plaintext, Some(&ctx)).unwrap();
        let decrypted = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx)).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_decrypt_hybrid_wrong_context_fails() {
        let (hybrid_pk, hybrid_sk) = kem_hybrid::generate_keypair().unwrap();

        let ctx1 = HybridEncryptionContext { info: b"context-1".to_vec(), aad: b"aad-1".to_vec() };
        let ctx2 = HybridEncryptionContext { info: b"context-2".to_vec(), aad: b"aad-2".to_vec() };

        let ct = encrypt_hybrid(&hybrid_pk, b"test", Some(&ctx1)).unwrap();
        let result = decrypt_hybrid(&hybrid_sk, &ct, Some(&ctx2));
        assert!(result.is_err(), "Wrong context must fail decryption");
    }

    #[test]
    fn test_hybrid_encryption_error_display_all_variants_are_nonempty_fails() {
        let errors = vec![
            HybridEncryptionError::KemError("kem".into()),
            HybridEncryptionError::EncryptionError("enc".into()),
            HybridEncryptionError::DecryptionError("dec".into()),
            HybridEncryptionError::InvalidInput("inp".into()),
            HybridEncryptionError::KdfError("kdf".into()),
            HybridEncryptionError::KeyLengthError { expected: 32, actual: 16 },
        ];
        for err in &errors {
            let msg = format!("{}", err);
            assert!(!msg.is_empty());
        }
    }
}
