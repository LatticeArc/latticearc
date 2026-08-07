//! `KeyData`: the key-material container (single, composite/hybrid, or
//! passphrase-encrypted), plus its zeroizing `Drop`, redacted `Debug`, and
//! constant-time equality.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::serialization::decode_b64_opaque;

/// Pair of zeroizing byte buffers returned by [`KeyData::decode_composite_zeroized`].
///
/// Each element is automatically wiped from memory when dropped.
pub type ZeroizingKeyPair = (zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>);

// ============================================================================
// KeyData
// ============================================================================

/// Key material container — single, composite (hybrid), or passphrase-encrypted.
///
/// In JSON: uses base64-encoded strings.
/// In CBOR: uses raw byte strings (`bstr`) — no base64 encoding.
///
/// Uses untagged serde. Variants are disambiguated by their field names:
/// `"enc"` (with KDF metadata) → [`KeyData::Encrypted`], `"raw"` → [`KeyData::Single`],
/// `"pq"` + `"classical"` → [`KeyData::Composite`]. `Encrypted` is listed first
/// so serde matches it before falling back to Single/Composite.
/// `derive(Clone)` is intentionally NOT implemented. When this variant
/// is `Single` or `Composite` for a secret-key payload, the base64
/// string holds secret-key bytes; an implicit clone would silently
/// duplicate secret material on the heap. Public-key variants are
/// safe to duplicate but the type erases that distinction at
/// construction (`key_type` lives on `PortableKey`, not on
/// `KeyData`), so the conservative choice is no `Clone` for the whole
/// enum. External callers that genuinely need duplication go through
/// [`PortableKey::clone_for_transmission`](super::PortableKey::clone_for_transmission).
#[non_exhaustive]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyData {
    /// Passphrase-encrypted key material.
    ///
    /// The inner `KeyData` (`Single` or `Composite`) is serialized to JSON and
    /// then encrypted with AES-256-GCM using a key derived from a user
    /// passphrase via PBKDF2-HMAC-SHA256 (SP 800-132). Layout:
    ///
    /// 1. Derive 32-byte AES key: `PBKDF2-HMAC-SHA256(passphrase, salt, iters)`
    /// 2. Serialize plaintext `KeyData` to JSON bytes
    /// 3. Encrypt JSON bytes with AES-256-GCM using a fresh random nonce.
    ///    AAD binds every envelope field (version, algorithm, key_type,
    ///    KDF name, iteration count, salt, AEAD name) plus the enclosing
    ///    `PortableKey`'s `algorithm` and `key_type`, so tampering with
    ///    any metadata on disk causes AEAD authentication to fail.
    /// 4. Store KDF params, nonce, and `ciphertext || tag` base64-encoded
    ///
    /// Format version `1` fixes the algorithm choices to
    /// `PBKDF2-HMAC-SHA256` + `AES-256-GCM`; future versions may add alternatives.
    Encrypted {
        /// Envelope format version (currently `1`).
        enc: u32,
        /// KDF identifier (currently `"PBKDF2-HMAC-SHA256"`).
        kdf: String,
        /// PBKDF2 iteration count (recommended ≥ 600_000 per OWASP 2023).
        kdf_iterations: u32,
        /// Base64-encoded PBKDF2 salt (16 bytes recommended).
        kdf_salt: String,
        /// AEAD identifier (currently `"AES-256-GCM"`).
        aead: String,
        /// Base64-encoded AES-GCM nonce (12 bytes).
        nonce: String,
        /// Base64-encoded `ciphertext || tag` (tag is the trailing 16 bytes).
        ciphertext: String,
    },
    /// Single-component key (e.g., ML-KEM public key, AES symmetric key).
    Single {
        /// Base64-encoded key bytes (JSON) or raw bytes (CBOR).
        raw: String,
    },
    /// Composite hybrid key with separate PQ and classical components.
    Composite {
        /// Base64-encoded post-quantum key component.
        pq: String,
        /// Base64-encoded classical key component.
        classical: String,
    },
}

impl std::fmt::Debug for KeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single { .. } => f.debug_struct("Single").field("raw", &"[...]").finish(),
            Self::Composite { .. } => f
                .debug_struct("Composite")
                .field("pq", &"[...]")
                .field("classical", &"[...]")
                .finish(),
            Self::Encrypted { enc, kdf, kdf_iterations, aead, .. } => f
                .debug_struct("Encrypted")
                .field("enc", enc)
                .field("kdf", kdf)
                .field("kdf_iterations", kdf_iterations)
                .field("aead", aead)
                .field("kdf_salt", &"[...]")
                .field("nonce", &"[...]")
                .field("ciphertext", &"[REDACTED]")
                .finish(),
        }
    }
}

impl Drop for KeyData {
    fn drop(&mut self) {
        match self {
            Self::Single { raw } => {
                raw.zeroize();
            }
            Self::Composite { pq, classical } => {
                pq.zeroize();
                classical.zeroize();
            }
            Self::Encrypted { ciphertext, nonce, kdf_salt, .. } => {
                // The ciphertext is already encrypted, but zeroize the base64
                // string residue anyway so nothing lingers in memory.
                ciphertext.zeroize();
                nonce.zeroize();
                kdf_salt.zeroize();
            }
        }
    }
}

impl KeyData {
    /// Audited duplication path. See
    /// [`PortableKey::clone_for_transmission`](super::PortableKey::clone_for_transmission) for the rationale —
    /// `derive(Clone)` is intentionally not implemented because
    /// variants can hold base64 of secret-key bytes.
    #[must_use]
    pub fn clone_for_transmission(&self) -> Self {
        match self {
            Self::Single { raw } => Self::Single { raw: raw.clone() },
            Self::Composite { pq, classical } => {
                Self::Composite { pq: pq.clone(), classical: classical.clone() }
            }
            Self::Encrypted { enc, kdf, kdf_iterations, kdf_salt, aead, nonce, ciphertext } => {
                Self::Encrypted {
                    enc: *enc,
                    kdf: kdf.clone(),
                    kdf_iterations: *kdf_iterations,
                    kdf_salt: kdf_salt.clone(),
                    aead: aead.clone(),
                    nonce: nonce.clone(),
                    ciphertext: ciphertext.clone(),
                }
            }
        }
    }

    /// Decode the single raw key bytes (returns error if composite or encrypted).
    ///
    /// # Security
    ///
    /// The returned `Vec<u8>` is **not** automatically zeroized on drop. When
    /// this method is called for secret or symmetric key material, callers are
    /// responsible for zeroizing the returned bytes after use. Prefer
    /// [`decode_raw_zeroized`](Self::decode_raw_zeroized) for secret key data.
    ///
    /// # Errors
    /// Returns an error if this is a composite key, the key is passphrase-encrypted
    /// (call [`PortableKey::decrypt_with_passphrase`](super::PortableKey::decrypt_with_passphrase) first), or Base64 decoding fails.
    pub fn decode_raw(&self) -> Result<Vec<u8>> {
        match self {
            Self::Single { raw } => decode_b64_opaque(raw, "key.raw"),
            Self::Composite { .. } => Err(CoreError::InvalidKey(
                "Expected single key data but found composite".to_string(),
            )),
            Self::Encrypted { .. } => Err(CoreError::InvalidKey(
                "Key is passphrase-encrypted; call PortableKey::decrypt_with_passphrase first"
                    .to_string(),
            )),
        }
    }

    /// Decode the single raw key bytes into a zeroizing buffer (returns error if composite).
    ///
    /// Equivalent to [`decode_raw`](Self::decode_raw) but wraps the result in
    /// [`zeroize::Zeroizing`] so the bytes are wiped from memory when dropped.
    /// Use this variant whenever the data may be secret key material.
    ///
    /// # Errors
    /// Returns an error if this is a composite key or Base64 decoding fails.
    pub fn decode_raw_zeroized(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.decode_raw().map(zeroize::Zeroizing::new)
    }

    /// Decode composite key components (returns error if single or encrypted).
    ///
    /// # Security
    ///
    /// The returned `Vec<u8>` values are **not** automatically zeroized on drop.
    /// When this method is called for secret or symmetric key material, callers
    /// are responsible for zeroizing the returned bytes after use. Prefer
    /// [`decode_composite_zeroized`](Self::decode_composite_zeroized) for
    /// secret key data.
    ///
    /// # Errors
    /// Returns an error if this is a single key, the key is passphrase-encrypted
    /// (call [`PortableKey::decrypt_with_passphrase`](super::PortableKey::decrypt_with_passphrase) first), or Base64 decoding fails.
    pub fn decode_composite(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Self::Composite { pq, classical } => {
                let pq_bytes = decode_b64_opaque(pq, "key.composite.pq")?;
                let classical_bytes = decode_b64_opaque(classical, "key.composite.classical")?;
                Ok((pq_bytes, classical_bytes))
            }
            Self::Single { .. } => Err(CoreError::InvalidKey(
                "Expected composite key data but found single".to_string(),
            )),
            Self::Encrypted { .. } => Err(CoreError::InvalidKey(
                "Key is passphrase-encrypted; call PortableKey::decrypt_with_passphrase first"
                    .to_string(),
            )),
        }
    }

    /// Decode composite key components into zeroizing buffers (returns error if single).
    ///
    /// Equivalent to [`decode_composite`](Self::decode_composite) but wraps
    /// each component in [`zeroize::Zeroizing`] so the bytes are wiped from
    /// memory when dropped. Use this variant whenever either component may be
    /// secret key material.
    ///
    /// # Errors
    /// Returns an error if this is a single key or Base64 decoding fails.
    pub fn decode_composite_zeroized(&self) -> Result<ZeroizingKeyPair> {
        let (pq, classical) = self.decode_composite()?;
        Ok((zeroize::Zeroizing::new(pq), zeroize::Zeroizing::new(classical)))
    }

    /// Create single key data from raw bytes.
    #[must_use]
    pub fn from_raw(bytes: &[u8]) -> Self {
        Self::Single { raw: BASE64_ENGINE.encode(bytes) }
    }

    /// Create composite key data from PQ and classical components.
    #[must_use]
    pub fn from_composite(pq_bytes: &[u8], classical_bytes: &[u8]) -> Self {
        Self::Composite {
            pq: BASE64_ENGINE.encode(pq_bytes),
            classical: BASE64_ENGINE.encode(classical_bytes),
        }
    }
}

impl subtle::ConstantTimeEq for KeyData {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        use subtle::Choice;

        match (self, other) {
            (Self::Single { raw: a }, Self::Single { raw: b }) => a.as_bytes().ct_eq(b.as_bytes()),
            (
                Self::Composite { pq: a_pq, classical: a_cl },
                Self::Composite { pq: b_pq, classical: b_cl },
            ) => a_pq.as_bytes().ct_eq(b_pq.as_bytes()) & a_cl.as_bytes().ct_eq(b_cl.as_bytes()),
            (
                Self::Encrypted {
                    enc: a_enc,
                    kdf: a_kdf,
                    kdf_iterations: a_iter,
                    kdf_salt: a_salt,
                    aead: a_aead,
                    nonce: a_nonce,
                    ciphertext: a_ct,
                },
                Self::Encrypted {
                    enc: b_enc,
                    kdf: b_kdf,
                    kdf_iterations: b_iter,
                    kdf_salt: b_salt,
                    aead: b_aead,
                    nonce: b_nonce,
                    ciphertext: b_ct,
                },
            ) => {
                // All envelope fields are stored in plaintext, so none are
                // strictly secret. We short-circuit on the algorithm-identifier
                // fields (fast path) and fall through to a CT compare on the
                // variable-length byte fields for a uniform pattern with the
                // other arms.
                if a_enc != b_enc || a_kdf != b_kdf || a_iter != b_iter || a_aead != b_aead {
                    return Choice::from(0);
                }
                a_salt.as_bytes().ct_eq(b_salt.as_bytes())
                    & a_nonce.as_bytes().ct_eq(b_nonce.as_bytes())
                    & a_ct.as_bytes().ct_eq(b_ct.as_bytes())
            }
            // Variant mismatches, enumerated explicitly (no `_` wildcard) so
            // that adding a new `KeyData` variant fails to compile here —
            // forcing the author to decide how it compares against every
            // existing variant rather than silently defaulting to not-equal.
            (Self::Single { .. }, Self::Composite { .. } | Self::Encrypted { .. })
            | (Self::Composite { .. }, Self::Single { .. } | Self::Encrypted { .. })
            | (Self::Encrypted { .. }, Self::Single { .. } | Self::Composite { .. }) => {
                Choice::from(0)
            }
        }
    }
}
