#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! PQ-Only Encryption Module
//!
//! Provides post-quantum-only encryption using ML-KEM key encapsulation
//! combined with AES-256-GCM symmetric encryption, without any classical
//! (X25519) component. This is the PQ-only counterpart to the hybrid
//! encryption in [`crate::hybrid::encrypt_hybrid`].
//!
//! # When to Use
//!
//! - CNSA 2.0 compliance (pure PQ required)
//! - Government/defense use cases mandating no classical algorithms
//! - Post-transition deployments where classical is no longer needed
//!
//! # Security Properties
//!
//! - IND-CCA2 security from ML-KEM (FIPS 203)
//! - Authenticated encryption via AES-256-GCM (FIPS validated)
//! - HKDF-SHA256 key derivation with domain separation
//!
//! # Differences from Hybrid
//!
//! | Property | Hybrid | PQ-Only |
//! |----------|--------|---------|
//! | KEM | ML-KEM + X25519 | ML-KEM only |
//! | Key derivation | HKDF over both shared secrets | HKDF over ML-KEM shared secret |
//! | Security guarantee | Secure if EITHER is secure | Secure if ML-KEM is secure |
//! | CNSA 2.0 compliant | No (contains classical) | Yes |

use crate::log_crypto_operation_error;
use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, TAG_LEN};
use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemPublicKey, MlKemSecretKey, MlKemSecurityLevel,
};
use crate::unified_api::logging::op;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

/// Error types for PQ-only encryption operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PqOnlyError {
    /// Error during ML-KEM key encapsulation.
    #[error("KEM error: {0}")]
    KemError(String),
    /// Error during symmetric encryption.
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    /// Error during symmetric decryption or authentication failure.
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    /// Error during key derivation.
    #[error("Key derivation error: {0}")]
    KdfError(String),
    /// Invalid input parameters.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    /// Key generation failure.
    #[error("Key generation error: {0}")]
    KeyGenError(String),
}

// ============================================================================
// PQ-Only Key Types
// ============================================================================

/// PQ-only public key wrapping an ML-KEM public key.
///
/// Unlike [`HybridKemPublicKey`](crate::hybrid::kem_hybrid::HybridKemPublicKey),
/// this type contains only the ML-KEM component — no X25519.
#[derive(Clone)]
pub struct PqOnlyPublicKey {
    /// The ML-KEM public key.
    ml_kem_pk: MlKemPublicKey,
    /// The security level this key was generated at.
    security_level: MlKemSecurityLevel,
}

impl std::fmt::Debug for PqOnlyPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqOnlyPublicKey")
            .field("security_level", &self.security_level)
            .field("pk_len", &self.ml_kem_pk.as_bytes().len())
            .finish()
    }
}

impl PqOnlyPublicKey {
    /// Create a `PqOnlyPublicKey` from raw ML-KEM public key bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key bytes are invalid for the specified security level.
    pub fn from_bytes(level: MlKemSecurityLevel, pk_bytes: &[u8]) -> Result<Self, PqOnlyError> {
        let ml_kem_pk = MlKemPublicKey::new(level, pk_bytes.to_vec())
            .map_err(|e| PqOnlyError::InvalidInput(format!("Invalid ML-KEM public key: {e}")))?;
        Ok(Self { ml_kem_pk, security_level: level })
    }

    /// Returns the ML-KEM security level.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Returns the raw ML-KEM public key bytes.
    #[must_use]
    pub fn ml_kem_pk_bytes(&self) -> &[u8] {
        self.ml_kem_pk.as_bytes()
    }

    /// Returns a reference to the inner ML-KEM public key.
    #[must_use]
    pub fn ml_kem_pk(&self) -> &MlKemPublicKey {
        &self.ml_kem_pk
    }
}

/// PQ-only secret key wrapping an ML-KEM secret key.
///
/// Unlike [`HybridKemSecretKey`](crate::hybrid::kem_hybrid::HybridKemSecretKey),
/// this type contains only the ML-KEM component — no X25519.
///
/// # Security
///
/// - The inner `MlKemSecretKey` is zeroized on drop by its own `Drop` impl.
/// - `Clone` is intentionally NOT implemented to prevent copies of secret material.
/// - Debug output is redacted to prevent accidental key leakage.
pub struct PqOnlySecretKey {
    /// The ML-KEM secret key (zeroized on drop by `MlKemSecretKey`).
    ml_kem_sk: MlKemSecretKey,
    /// The corresponding ML-KEM public key (encapsulation key) bytes.
    ///
    /// Stored alongside the secret key so that the HKDF info on
    /// decryption can bind to the recipient's static public key
    /// (HPKE / RFC 9180 §5.1 channel binding). Without this, the only
    /// channel binding is the KEM ciphertext itself; under that
    /// construction an adversary who broke ML-KEM IND-CCA2 could swap
    /// the recipient on a fresh ciphertext and the decapsulation would
    /// still produce a usable shared secret. Binding the PK closes
    /// that defense-in-depth gap.
    ///
    /// Public-key material is non-secret, so this field is a plain `Vec<u8>`
    /// and is included in the public-API constructor signature
    /// (`from_bytes(level, sk_bytes, pk_bytes)`).
    ml_kem_pk_bytes: Vec<u8>,
    /// The security level this key was generated at.
    security_level: MlKemSecurityLevel,
}

impl std::fmt::Debug for PqOnlySecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqOnlySecretKey")
            .field("security_level", &self.security_level)
            .field("sk", &"[REDACTED]")
            .finish()
    }
}

impl ConstantTimeEq for PqOnlySecretKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.ml_kem_sk.ct_eq(&other.ml_kem_sk)
    }
}

impl PqOnlySecretKey {
    /// Create a `PqOnlySecretKey` from raw ML-KEM secret + public key bytes.
    ///
    /// Both components are required: the secret-key bytes drive
    /// decapsulation, and the public-key bytes are folded into the
    /// HKDF info string at decryption time so the derived AEAD key is
    /// bound to the recipient identity (HPKE / RFC 9180 §5.1 channel
    /// binding). Without `pk_bytes` the binding is to the KEM
    /// ciphertext only, which depends on ML-KEM IND-CCA2 holding for
    /// substitution resistance.
    ///
    /// # Errors
    ///
    /// Returns [`PqOnlyError::InvalidInput`] if `sk_bytes` is malformed
    /// for the specified security level, or if `pk_bytes` length does
    /// not match the expected public-key size for that level.
    pub fn from_bytes(
        level: MlKemSecurityLevel,
        sk_bytes: &[u8],
        pk_bytes: &[u8],
    ) -> Result<Self, PqOnlyError> {
        let ml_kem_sk = MlKemSecretKey::new(level, sk_bytes.to_vec())
            .map_err(|e| PqOnlyError::InvalidInput(format!("Invalid ML-KEM secret key: {e}")))?;
        let expected_pk_len = level.public_key_size();
        if pk_bytes.len() != expected_pk_len {
            return Err(PqOnlyError::InvalidInput(format!(
                "ML-KEM public key length {} does not match expected {} for {}",
                pk_bytes.len(),
                expected_pk_len,
                level.name()
            )));
        }
        // cross-check the supplied PK against the PK
        // embedded in the ML-KEM SK (FIPS 203 §6.1 layout). The PK is
        // passed in for backwards-compat with callers that already
        // had it on hand, but the authoritative source is the SK
        // itself — a substituted `pk_bytes` (e.g. from unauthenticated
        // metadata) would silently corrupt the channel binding.
        let embedded = ml_kem_sk
            .embedded_public_key_bytes()
            .map_err(|e| PqOnlyError::InvalidInput(format!("ML-KEM SK does not embed PK: {e}")))?;
        // Constant-time comparison so the caller cannot probe equality
        // bit-by-bit.
        use subtle::ConstantTimeEq;
        if embedded.ct_eq(pk_bytes).unwrap_u8() != 1 {
            return Err(PqOnlyError::InvalidInput(
                "supplied ML-KEM PK does not match SK-embedded PK \
                 (SK is authoritative; mismatched metadata is rejected)"
                    .to_string(),
            ));
        }
        Ok(Self { ml_kem_sk, ml_kem_pk_bytes: pk_bytes.to_vec(), security_level: level })
    }

    /// construct from SK bytes only — derive the PK from
    /// the SK's embedded layout (FIPS 203 §6.1). Eliminates the
    /// metadata-trust attack from earlier rounds: a file-write
    /// attacker that swaps the `ml_kem_pk` field of an unencrypted
    /// keyfile no longer breaks the channel binding because the PK
    /// comes from inside the (cryptographically-authenticated) SK
    /// blob itself.
    ///
    /// # Errors
    ///
    /// Returns [`PqOnlyError::InvalidInput`] if `sk_bytes` is malformed
    /// for the specified security level.
    pub fn from_sk_bytes(level: MlKemSecurityLevel, sk_bytes: &[u8]) -> Result<Self, PqOnlyError> {
        let ml_kem_sk = MlKemSecretKey::new(level, sk_bytes.to_vec())
            .map_err(|e| PqOnlyError::InvalidInput(format!("Invalid ML-KEM secret key: {e}")))?;
        let pk_bytes = ml_kem_sk
            .embedded_public_key_bytes()
            .map_err(|e| PqOnlyError::InvalidInput(format!("ML-KEM SK does not embed PK: {e}")))?
            .to_vec();
        Ok(Self { ml_kem_sk, ml_kem_pk_bytes: pk_bytes, security_level: level })
    }

    /// Borrow the recipient's ML-KEM public key bytes.
    ///
    /// Used by the decryption path to construct the HKDF info string
    /// with the same `(recipient_pk, kem_ciphertext)` binding that the
    /// sender used at encryption.
    #[must_use]
    pub fn recipient_pk_bytes(&self) -> &[u8] {
        &self.ml_kem_pk_bytes
    }

    /// Returns the ML-KEM security level.
    #[must_use]
    pub fn security_level(&self) -> MlKemSecurityLevel {
        self.security_level
    }

    /// Expose the ML-KEM secret key bytes.
    ///
    /// Sealed accessor per Secret Type Invariant I-8
    /// (`docs/SECRET_TYPE_INVARIANTS.md`).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.ml_kem_sk.expose_secret()
    }

    /// Returns a reference to the inner ML-KEM secret key.
    #[must_use]
    pub fn ml_kem_sk(&self) -> &MlKemSecretKey {
        &self.ml_kem_sk
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Build the HKDF `info` string for PQ-only encryption.
///
/// Thin wrapper over [`crate::types::domains::hkdf_kem_info_with_pk`] that
/// pins the domain-separation label to
/// [`HkdfKemLabel::PqOnlyEncryption`](crate::types::domains::HkdfKemLabel::PqOnlyEncryption).
/// The shared helper is also used by
/// [`crate::unified_api::convenience::pq_kem`] so encrypt/decrypt
/// drift across the two parallel APIs is structurally impossible
///.
fn pq_only_encryption_info(
    recipient_pk: &[u8],
    kem_ciphertext: &[u8],
) -> Result<Vec<u8>, PqOnlyError> {
    crate::types::domains::hkdf_kem_info_with_pk(
        crate::types::domains::HkdfKemLabel::PqOnlyEncryption,
        recipient_pk,
        kem_ciphertext,
    )
    .map_err(|e| PqOnlyError::KdfError(e.to_string()))
}

/// Generate a PQ-only keypair at ML-KEM-768 (default security level).
///
/// Returns `(public_key, secret_key)` for PQ-only encryption.
///
/// # Errors
///
/// Returns an error if key generation fails.
#[must_use = "generated keypair must be stored or used"]
pub fn generate_pq_keypair() -> Result<(PqOnlyPublicKey, PqOnlySecretKey), PqOnlyError> {
    generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem768)
}

/// Generate a PQ-only keypair at a specific ML-KEM security level.
///
/// # Arguments
///
/// * `level` - ML-KEM security level:
///   - `MlKem512` — NIST Category 1
///   - `MlKem768` — NIST Category 3
///   - `MlKem1024` — NIST Category 5
///
/// # Errors
///
/// Returns an error if key generation fails.
#[must_use = "generated keypair must be stored or used"]
pub fn generate_pq_keypair_with_level(
    level: MlKemSecurityLevel,
) -> Result<(PqOnlyPublicKey, PqOnlySecretKey), PqOnlyError> {
    let (pk, sk) = MlKem::generate_keypair(level)
        .map_err(|e| PqOnlyError::KeyGenError(format!("ML-KEM keygen failed: {e}")))?;

    let pk_bytes = pk.as_bytes().to_vec();
    Ok((
        PqOnlyPublicKey { ml_kem_pk: pk, security_level: level },
        PqOnlySecretKey { ml_kem_sk: sk, ml_kem_pk_bytes: pk_bytes, security_level: level },
    ))
}

// ============================================================================
// PQ-Only Encrypt / Decrypt
// ============================================================================

/// PQ-only encrypted output components.
///
/// Returned by [`encrypt_pq_only`] for integration with [`EncryptedOutput`](crate::unified_api::crypto_types::EncryptedOutput).
pub struct PqOnlyCiphertext {
    /// ML-KEM ciphertext (for decapsulation).
    ml_kem_ciphertext: Vec<u8>,
    /// Symmetric ciphertext (AES-256-GCM encrypted payload).
    symmetric_ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    nonce: [u8; 12],
    /// AES-256-GCM authentication tag (16 bytes).
    tag: [u8; TAG_LEN],
}

impl PqOnlyCiphertext {
    /// Returns the ML-KEM ciphertext bytes.
    #[must_use]
    pub fn ml_kem_ciphertext(&self) -> &[u8] {
        &self.ml_kem_ciphertext
    }

    /// Returns the symmetric ciphertext bytes.
    #[must_use]
    pub fn symmetric_ciphertext(&self) -> &[u8] {
        &self.symmetric_ciphertext
    }

    /// Returns the AES-256-GCM nonce (12 bytes).
    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Returns the AES-256-GCM authentication tag (16 bytes).
    #[must_use]
    pub fn tag(&self) -> &[u8; TAG_LEN] {
        &self.tag
    }

    /// Consumes self and returns `(ml_kem_ciphertext, symmetric_ciphertext, nonce, tag)`.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, [u8; 12], [u8; TAG_LEN]) {
        (self.ml_kem_ciphertext, self.symmetric_ciphertext, self.nonce, self.tag)
    }
}

/// Encrypt data using PQ-only ML-KEM + HKDF + AES-256-GCM.
///
/// # Algorithm
///
/// 1. ML-KEM encapsulate with the public key → (shared_secret, kem_ciphertext)
/// 2. HKDF-SHA256(shared_secret, info=`PQ_ONLY_ENCRYPTION_INFO || 0x00 || kem_ciphertext`) → 32-byte AES key
/// 3. AES-256-GCM encrypt(plaintext) → (ciphertext, nonce, tag)
///
/// The `info` string binds the KEM ciphertext into the AEAD-key
/// derivation per RFC 9180 §5.1 (HPKE channel binding). The exact
/// byte layout is `LABEL || 0x00 || kem_ciphertext`, where
/// `LABEL = "LatticeArc-PqOnly-Encryption-v1"`
/// (see `crate::types::domains::PQ_ONLY_ENCRYPTION_INFO`). Encrypt and
/// decrypt MUST construct `info` identically; both go through
/// `pq_only_encryption_info()` (private to this module) to keep the
/// two paths in lockstep.
///
/// # Security
///
/// - IND-CCA2 security from ML-KEM (FIPS 203)
/// - AES-256-GCM nonce generated internally from OS CSPRNG (SP 800-38D §8.2)
/// - HKDF info binds `PQ_ONLY_ENCRYPTION_INFO` domain separator + KEM
///   ciphertext (HPKE-style channel binding; SP 800-56C label usage)
/// - ML-KEM shared secret is not exposed to callers
///
/// # Errors
///
/// Returns an error if encapsulation, key derivation, or encryption fails.
pub fn encrypt_pq_only(
    pk: &PqOnlyPublicKey,
    plaintext: &[u8],
) -> Result<PqOnlyCiphertext, PqOnlyError> {
    encrypt_pq_only_with_aad(pk, plaintext, &[])
}

/// PQ-only encrypt with associated data bound into the AEAD tag.
///
/// `aad` is authenticated but not encrypted — it must be supplied
/// byte-identical at decrypt time. Pass `&[]` if the caller has no
/// associated data (equivalent to [`encrypt_pq_only`]).
///
/// # Errors
///
/// Returns an error if encapsulation, key derivation, or encryption fails.
pub fn encrypt_pq_only_with_aad(
    pk: &PqOnlyPublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<PqOnlyCiphertext, PqOnlyError> {
    // Encrypt-side opacity (defense-in-depth per Pattern 6).
    let (shared_secret, kem_ct) = MlKem::encapsulate(pk.ml_kem_pk()).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_ENCRYPT, "ML-KEM encapsulation failed");
        PqOnlyError::KemError("encapsulation failed".to_string())
    })?;

    // HPKE / RFC 9180 §5.1 channel binding. Bind both:
    //   - the recipient's static public key (so an adversary who
    //     substitutes the recipient cannot reuse the ciphertext), and
    //   - the KEM ciphertext (so an adversary who finds two ciphertexts
    //     decapsulating to the same shared secret cannot swap them).
    //
    // The decryption path constructs the same info from
    // `sk.recipient_pk_bytes()` and the wire `kem_ciphertext`. Both
    // paths agree byte-for-byte on the transcript.
    let info = pq_only_encryption_info(pk.ml_kem_pk_bytes(), kem_ct.as_bytes())
        .map_err(|_e| PqOnlyError::KdfError("KDF info construction failed".to_string()))?;
    let hkdf_result = hkdf(shared_secret.expose_secret(), None, Some(&info), 32).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_ENCRYPT, "HKDF failed");
        PqOnlyError::KdfError("KDF failed".to_string())
    })?;

    let cipher = AesGcm256::new(hkdf_result.expose_secret()).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_ENCRYPT, "AES-256 init failed");
        PqOnlyError::EncryptionError("encryption failed".to_string())
    })?;
    let nonce = AesGcm256::generate_nonce();
    // `Some(&[])` and `None` produce byte-identical AES-GCM output —
    // empty AAD just means a zero-byte GHASH input. Pass through
    // unconditionally rather than branching on `aad.is_empty()`.
    let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, Some(aad)).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_ENCRYPT, "AES-GCM seal failed");
        PqOnlyError::EncryptionError("encryption failed".to_string())
    })?;

    Ok(PqOnlyCiphertext {
        ml_kem_ciphertext: kem_ct.into_bytes(),
        symmetric_ciphertext: ciphertext,
        nonce,
        tag,
    })
}

/// Decrypt data encrypted by [`encrypt_pq_only`].
///
/// # Algorithm
///
/// 1. ML-KEM decapsulate(kem_ciphertext, secret_key) → shared_secret
/// 2. HKDF-SHA256(shared_secret, info=`PQ_ONLY_ENCRYPTION_INFO || 0x00 ||
///    pk_len_be32 || recipient_pk || ct_len_be32 || kem_ciphertext`) →
///    32-byte AES key
/// 3. AES-256-GCM decrypt(ciphertext, nonce, tag) → plaintext
///
/// `info` matches `encrypt_pq_only` byte-for-byte — both paths build
/// it via `pq_only_encryption_info(recipient_pk, kem_ciphertext)`.
/// Substituting a different recipient PK or KEM ciphertext produces a
/// different AEAD key, so the AEAD tag fails (HPKE-style channel
/// binding, RFC 9180 §5.1). updated this doc
/// to reflect the prior PK-binding migration that the prose had
/// stayed silent about.
///
/// # Security
///
/// - Decrypt errors are opaque ("decryption failed") per SP 800-38D §5.2.2
/// - ML-KEM shared secret is wrapped and not exposed to callers
/// - HKDF info binds `PQ_ONLY_ENCRYPTION_INFO` domain separator + KEM
///   ciphertext (HPKE-style channel binding)
/// - Plaintext is returned in `Zeroizing<Vec<u8>>` for automatic cleanup
///
/// # Errors
///
/// Returns an error if decapsulation, key derivation, or decryption fails.
pub fn decrypt_pq_only(
    sk: &PqOnlySecretKey,
    kem_ciphertext: &[u8],
    symmetric_ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; TAG_LEN],
) -> Result<Zeroizing<Vec<u8>>, PqOnlyError> {
    decrypt_pq_only_with_aad(sk, kem_ciphertext, symmetric_ciphertext, nonce, tag, &[])
}

/// PQ-only decrypt with associated data — must match the value supplied
/// at encrypt time.
///
/// # Errors
///
/// Returns an opaque `DecryptionError` for all adversary-reachable
/// failure paths (KEM parse / decapsulation / KDF / AEAD tag mismatch),
/// matching the opacity of [`decrypt_pq_only`].
pub fn decrypt_pq_only_with_aad(
    sk: &PqOnlySecretKey,
    kem_ciphertext: &[u8],
    symmetric_ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PqOnlyError> {
    // All adversary-reachable failure paths collapse to one opaque RETURNED
    // error. Adversary controls `kem_ciphertext`, `symmetric_ciphertext`,
    // `nonce`, `tag`, and `aad`; distinguishing "parse fail" vs "crypto
    // fail" vs "AEAD tag fail" would be a per-stage oracle. Internal
    // tracing logs keep the specific reason so operators can debug via
    // correlation IDs.
    let opaque = || PqOnlyError::DecryptionError("decryption failed".to_string());

    let ct = MlKemCiphertext::new(sk.security_level(), kem_ciphertext.to_vec()).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "invalid ML-KEM ciphertext");
        opaque()
    })?;
    let shared_secret = MlKem::decapsulate(sk.ml_kem_sk(), &ct).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "ML-KEM decapsulation failed");
        opaque()
    })?;

    // HKDF params must match encrypt_pq_only (salt=None, identical info).
    // The encrypt path binds both `recipient_pk` and `kem_ciphertext`
    // into the info string (HPKE / RFC 9180 §5.1). The recipient PK
    // comes from the secret key — a substituted recipient cannot
    // produce a colliding info string, so the AEAD tag fails.
    let info =
        pq_only_encryption_info(sk.recipient_pk_bytes(), kem_ciphertext).map_err(|_e| opaque())?;
    let hkdf_result = hkdf(shared_secret.expose_secret(), None, Some(&info), 32).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "HKDF failed");
        opaque()
    })?;

    let cipher = AesGcm256::new(hkdf_result.expose_secret()).map_err(|_e| {
        log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "AES-256 init failed");
        opaque()
    })?;
    cipher.decrypt(nonce, symmetric_ciphertext, tag, Some(aad)).map_err(|_aead_err| {
        log_crypto_operation_error!(op::PQ_ONLY_DECRYPT, "AEAD authentication failed");
        opaque()
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pq_keypair_default_succeeds() {
        let (pk, sk) = generate_pq_keypair().expect("keygen should succeed");
        assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem768);
        assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem768);
    }

    #[test]
    fn test_generate_pq_keypair_all_levels_succeeds() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, sk) = generate_pq_keypair_with_level(level).expect("keygen should succeed");
            assert_eq!(pk.security_level(), level);
            assert_eq!(sk.security_level(), level);
        }
    }

    #[test]
    fn test_encrypt_decrypt_pq_only_roundtrip_768() {
        let (pk, sk) = generate_pq_keypair().unwrap();
        let plaintext = b"PQ-only roundtrip test data";

        let ct = encrypt_pq_only(&pk, plaintext).expect("encrypt should succeed");
        let decrypted = decrypt_pq_only(
            &sk,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        )
        .expect("decrypt should succeed");

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_pq_only_all_levels_roundtrip() {
        for level in [
            MlKemSecurityLevel::MlKem512,
            MlKemSecurityLevel::MlKem768,
            MlKemSecurityLevel::MlKem1024,
        ] {
            let (pk, sk) = generate_pq_keypair_with_level(level).unwrap();
            let plaintext = b"Test all security levels";

            let ct = encrypt_pq_only(&pk, plaintext).expect("encrypt should succeed");
            let decrypted = decrypt_pq_only(
                &sk,
                ct.ml_kem_ciphertext(),
                ct.symmetric_ciphertext(),
                ct.nonce(),
                ct.tag(),
            )
            .expect("decrypt should succeed");

            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn test_encrypt_pq_only_empty_data_succeeds() {
        let (pk, sk) = generate_pq_keypair().unwrap();
        let ct = encrypt_pq_only(&pk, b"").expect("empty data should encrypt");
        let decrypted = decrypt_pq_only(
            &sk,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        )
        .expect("empty data should decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_pq_only_wrong_key_fails() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let (_pk2, sk2) = generate_pq_keypair().unwrap();
        let ct = encrypt_pq_only(&pk, b"secret").unwrap();

        let result = decrypt_pq_only(
            &sk2,
            ct.ml_kem_ciphertext(),
            ct.symmetric_ciphertext(),
            ct.nonce(),
            ct.tag(),
        );
        assert!(result.is_err(), "Wrong key should fail");
    }

    #[test]
    fn test_encrypt_pq_only_different_ciphertexts() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let ct1 = encrypt_pq_only(&pk, b"same data").unwrap();
        let ct2 = encrypt_pq_only(&pk, b"same data").unwrap();
        assert_ne!(
            ct1.ml_kem_ciphertext(),
            ct2.ml_kem_ciphertext(),
            "Random KEM should produce different ciphertexts"
        );
    }

    #[test]
    fn test_pq_only_public_key_debug_no_leak() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let debug = format!("{:?}", pk);
        assert!(debug.contains("PqOnlyPublicKey"));
        assert!(debug.contains("MlKem768"));
    }

    #[test]
    fn test_pq_only_secret_key_debug_redacted() {
        let (_pk, sk) = generate_pq_keypair().unwrap();
        let debug = format!("{:?}", sk);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_pq_only_public_key_from_bytes_wrong_length_fails() {
        let result = PqOnlyPublicKey::from_bytes(MlKemSecurityLevel::MlKem768, &[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_only_secret_key_from_bytes_wrong_length_fails() {
        // Bad SK length, valid PK length → SK error.
        let pk_len = MlKemSecurityLevel::MlKem768.public_key_size();
        let pk_bytes = vec![0u8; pk_len];
        let result =
            PqOnlySecretKey::from_bytes(MlKemSecurityLevel::MlKem768, &[0u8; 10], &pk_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_pq_only_secret_key_from_bytes_wrong_pk_length_fails() {
        // Use a real keypair so the SK bytes are valid; pass a bogus PK
        // length so the constructor refuses for the PK reason.
        let (_pk, sk) = generate_pq_keypair().unwrap();
        let sk_bytes = sk.expose_secret().to_vec();
        let result = PqOnlySecretKey::from_bytes(sk.security_level(), &sk_bytes, &[0u8; 10]);
        assert!(matches!(result, Err(PqOnlyError::InvalidInput(_))));
    }

    #[test]
    fn test_pq_only_public_key_from_bytes_roundtrip() {
        let (pk, _sk) = generate_pq_keypair().unwrap();
        let bytes = pk.ml_kem_pk_bytes().to_vec();
        let pk2 = PqOnlyPublicKey::from_bytes(pk.security_level(), &bytes).unwrap();
        assert_eq!(pk2.security_level(), pk.security_level());
        assert_eq!(pk2.ml_kem_pk_bytes(), pk.ml_kem_pk_bytes());
    }
}
