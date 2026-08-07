//! Shared AES-256-GCM envelope plumbing for the hybrid and PQ-only paths.
//!
//! Both `encrypt_hybrid`/`decrypt_hybrid` and `encrypt_pq_only_with_aad`/
//! `decrypt_pq_only_with_aad` derive a 32-byte key through their own,
//! deliberately domain-separated KDF constructions, then run the identical
//! AES-256-GCM seal/open sequence. That sequence lives here once so a future
//! change (cipher init, nonce policy, AAD pass-through) cannot silently drift
//! between the two paths.
//!
//! Error handling contract: the helpers return [`EnvelopeStage`] naming which
//! step failed. Callers map every stage to their own opaque Pattern-6 error
//! and log the stage message under their own operation label — the stage enum
//! never reaches a public error, so per-stage information stays out of
//! adversary-visible surfaces.

use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, NONCE_LEN, TAG_LEN};
use zeroize::Zeroizing;

/// Which envelope step failed. Internal only — callers log the message and
/// collapse to their opaque error.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EnvelopeStage {
    /// AES-256 cipher construction rejected the key.
    CipherInit,
    /// AEAD seal failed.
    Seal,
    /// AEAD open (authentication) failed.
    Open,
}

impl EnvelopeStage {
    /// Stage description for the caller's internal trace line. Matches the
    /// strings the per-path implementations logged before consolidation so
    /// operator dashboards keep their signal.
    pub(crate) fn msg(self) -> &'static str {
        match self {
            Self::CipherInit => "AES-256 init failed",
            Self::Seal => "AES-GCM seal failed",
            Self::Open => "AEAD authentication failed",
        }
    }
}

/// `(ciphertext, nonce, tag)` produced by a successful seal.
pub(crate) type SealedParts = (Vec<u8>, [u8; NONCE_LEN], [u8; TAG_LEN]);

/// Seal `plaintext` under `key` with a fresh CSPRNG nonce.
///
/// `Some(&[])` and `None` AAD produce byte-identical AES-GCM output, so the
/// AAD is passed through unconditionally.
pub(crate) fn seal_aes256_gcm(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedParts, EnvelopeStage> {
    let cipher = AesGcm256::new(key).map_err(|_e| EnvelopeStage::CipherInit)?;
    let nonce = AesGcm256::generate_nonce();
    let (ciphertext, tag) =
        cipher.encrypt(&nonce, plaintext, Some(aad)).map_err(|_e| EnvelopeStage::Seal)?;
    Ok((ciphertext, nonce, tag))
}

/// Open `ciphertext` under `key`. Returns the plaintext in `Zeroizing` so a
/// caller cannot accidentally hold an unscrubbed copy.
pub(crate) fn open_aes256_gcm(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EnvelopeStage> {
    let cipher = AesGcm256::new(key).map_err(|_e| EnvelopeStage::CipherInit)?;
    cipher.decrypt(nonce, ciphertext, tag, Some(aad)).map_err(|_e| EnvelopeStage::Open)
}
