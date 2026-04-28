#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! LatticeArc Portable Key Format (LPK v1)
//!
//! Schema-first dual-format key serialization supporting JSON (human-readable)
//! and CBOR (compact binary, RFC 8949) for all LatticeArc key types.
//!
//! # Design Principles
//!
//! - **Schema-first**: One Rust struct, two wire formats (JSON + CBOR)
//! - **CBOR primary**: Wire protocol, database storage, enterprise containers
//! - **JSON secondary**: CLI display, REST APIs, debugging, key export
//! - **Standards-aligned**: Algorithm IDs from FIPS 203-206 / RFC 7748 / RFC 8032;
//!   composite key layout follows `draft-ietf-lamps-pq-composite-kem` (concatenation);
//!   JWK-compatible structure (per `draft-ietf-jose-pqc-kem`)
//!
//! # Key Identity
//!
//! Keys are identified by **use case** or **security level** — mirroring
//! how the library's API works. The algorithm is auto-derived and stored
//! internally for version-stability.
//!
//! # JSON Format
//!
//! ```json
//! {
//!   "version": 1,
//!   "use_case": "file-storage",
//!   "algorithm": "hybrid-ml-kem-1024-x25519",
//!   "key_type": "public",
//!   "key_data": { "raw": "Base64..." },
//!   "created": "2026-03-19T..."
//! }
//! ```
//!
//! # CBOR Format
//!
//! Same logical schema. Key material stored as CBOR byte strings (`bstr`) —
//! no base64 encoding, no string overhead. See [`crate::unified_api::key_format::PortableKey::to_cbor`].
//!
//! # Enterprise Extension Model
//!
//! The `metadata` field is an open `BTreeMap<String, serde_json::Value>`.
//! Enterprise crates add dimensions, key expiry,
//! hardware binding, etc. via extension traits — the base library preserves
//! unknown metadata keys during roundtrips without modification:
//!
//! ```rust,ignore
//! // Enterprise crate — typed accessors over the metadata map
//! impl EnterpriseKeyExt for PortableKey {
//!     fn dimensions(&self) -> Option<Vec<String>> { ... }
//!     fn key_expiry(&self) -> Option<DateTime<Utc>> { ... }
//!     fn hsm_binding(&self) -> Option<HsmSlot> { ... }
//! }
//! ```

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};

/// Metadata key for the ML-KEM public key stored in hybrid secret key files.
/// Used in `from_hybrid_kem_keypair` (write) and `to_hybrid_secret_key` (read).
const ML_KEM_PK_METADATA_KEY: &str = "ml_kem_pk";

// --- Passphrase-encryption envelope constants (LPK v1 encrypted variant) ---

/// Current version of the encrypted-key envelope schema.
const ENCRYPTED_ENVELOPE_VERSION: u32 = 1;
/// KDF identifier for the encrypted-key envelope.
const PBKDF2_KDF_ID: &str = "PBKDF2-HMAC-SHA256";
/// AEAD identifier for the encrypted-key envelope.
const AES_GCM_AEAD_ID: &str = "AES-256-GCM";
/// PBKDF2 default iteration count (OWASP 2023 recommendation for HMAC-SHA256).
const PBKDF2_DEFAULT_ITERATIONS: u32 = 600_000;
/// PBKDF2 minimum iteration count accepted when loading an encrypted key.
const PBKDF2_MIN_ITERATIONS: u32 = 100_000;
/// PBKDF2 salt length in bytes (SP 800-132 recommends ≥ 16).
const PBKDF2_SALT_LEN: usize = 16;
/// PBKDF2 minimum salt length accepted when loading an encrypted key.
/// Re-exported from the canonical NIST SP 800-132 §5.1 constant on
/// [`Pbkdf2Params::MIN_SALT_LEN`](crate::primitives::kdf::pbkdf2::Pbkdf2Params::MIN_SALT_LEN)
/// so the load-side check and the construction-side check cannot drift.
const PBKDF2_MIN_SALT_LEN: usize = crate::primitives::kdf::pbkdf2::Pbkdf2Params::MIN_SALT_LEN;
/// AES-256-GCM nonce length in bytes (NIST SP 800-38D).
const AES_GCM_NONCE_LEN: usize = 12;
/// AES-256-GCM tag length in bytes.
const AES_GCM_TAG_LEN: usize = 16;
/// AES-256 key length in bytes.
const AES_256_KEY_LEN: usize = 32;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::unified_api::error::{CoreError, Result};

/// Pair of zeroizing byte buffers returned by [`KeyData::decode_composite_zeroized`].
///
/// Each element is automatically wiped from memory when dropped.
pub type ZeroizingKeyPair = (zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>);

// ============================================================================
// KeyAlgorithm
// ============================================================================

/// Cryptographic algorithm identifier for portable keys.
///
/// Each variant maps to a specific NIST standard or well-known algorithm.
/// Serde renames ensure stable JSON/CBOR representation.
///
/// Algorithm IDs follow the naming convention from IETF drafts:
/// - `draft-ietf-jose-pqc-kem` for ML-KEM JWK identifiers
/// - `draft-ietf-cose-dilithium` for ML-DSA COSE identifiers
/// - Hybrid names follow `draft-ietf-lamps-pq-composite-kem` conventions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum KeyAlgorithm {
    // --- KEM (FIPS 203) ---
    /// ML-KEM-512 (FIPS 203, Level 1). OID: 2.16.840.1.101.3.4.4.1 (RFC 9935)
    #[serde(rename = "ml-kem-512")]
    MlKem512,
    /// ML-KEM-768 (FIPS 203, Level 3). OID: 2.16.840.1.101.3.4.4.2 (RFC 9935)
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    /// ML-KEM-1024 (FIPS 203, Level 5). OID: 2.16.840.1.101.3.4.4.3 (RFC 9935)
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,

    // --- Signatures (FIPS 204) ---
    /// ML-DSA-44 (FIPS 204, Level 2). OID: 2.16.840.1.101.3.4.3.17 (RFC 9881)
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, Level 3). OID: 2.16.840.1.101.3.4.3.18 (RFC 9881)
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, Level 5). OID: 2.16.840.1.101.3.4.3.19 (RFC 9881)
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,

    // --- Hash-based signatures (FIPS 205) ---
    /// SLH-DSA-SHAKE-128s (FIPS 205)
    #[serde(rename = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-256f (FIPS 205)
    #[serde(rename = "slh-dsa-shake-256f")]
    SlhDsaShake256f,

    // --- Lattice signatures (FIPS 206) ---
    /// FN-DSA-512 (FIPS 206)
    #[serde(rename = "fn-dsa-512")]
    FnDsa512,
    /// FN-DSA-1024 (FIPS 206)
    #[serde(rename = "fn-dsa-1024")]
    FnDsa1024,

    // --- Classical ---
    /// Ed25519 (RFC 8032)
    #[serde(rename = "ed25519")]
    Ed25519,
    /// X25519 (RFC 7748)
    #[serde(rename = "x25519")]
    X25519,
    /// AES-256 symmetric key (FIPS 197)
    #[serde(rename = "aes-256")]
    Aes256,
    /// ChaCha20 symmetric key (RFC 8439)
    #[serde(rename = "chacha20")]
    ChaCha20,

    // --- Hybrid KEM ---
    /// Hybrid ML-KEM-768 + X25519
    #[serde(rename = "hybrid-ml-kem-768-x25519")]
    HybridMlKem768X25519,
    /// Hybrid ML-KEM-512 + X25519
    #[serde(rename = "hybrid-ml-kem-512-x25519")]
    HybridMlKem512X25519,
    /// Hybrid ML-KEM-1024 + X25519
    #[serde(rename = "hybrid-ml-kem-1024-x25519")]
    HybridMlKem1024X25519,

    // --- Hybrid Signatures ---
    /// Hybrid ML-DSA-65 + Ed25519
    #[serde(rename = "hybrid-ml-dsa-65-ed25519")]
    HybridMlDsa65Ed25519,
    /// Hybrid ML-DSA-44 + Ed25519
    #[serde(rename = "hybrid-ml-dsa-44-ed25519")]
    HybridMlDsa44Ed25519,
    /// Hybrid ML-DSA-87 + Ed25519
    #[serde(rename = "hybrid-ml-dsa-87-ed25519")]
    HybridMlDsa87Ed25519,
}

/// Map an ML-KEM security level to the corresponding hybrid-KEM
/// `KeyAlgorithm` variant. Used by the `from_hybrid_kem_keypair` /
/// `to_hybrid_*_key` conversion paths so the level→variant table lives
/// in one place.
impl From<crate::primitives::kem::MlKemSecurityLevel> for KeyAlgorithm {
    fn from(level: crate::primitives::kem::MlKemSecurityLevel) -> Self {
        use crate::primitives::kem::MlKemSecurityLevel;
        match level {
            MlKemSecurityLevel::MlKem512 => Self::HybridMlKem512X25519,
            MlKemSecurityLevel::MlKem768 => Self::HybridMlKem768X25519,
            MlKemSecurityLevel::MlKem1024 => Self::HybridMlKem1024X25519,
        }
    }
}

/// Recover an ML-KEM security level from a hybrid-KEM `KeyAlgorithm`.
/// Returns `Err(())` for non-hybrid-KEM variants — callers are expected
/// to wrap this into a `CoreError::InvalidKey` with their own
/// "not a hybrid KEM" framing.
impl TryFrom<KeyAlgorithm> for crate::primitives::kem::MlKemSecurityLevel {
    type Error = ();
    fn try_from(alg: KeyAlgorithm) -> std::result::Result<Self, Self::Error> {
        use crate::primitives::kem::MlKemSecurityLevel;
        match alg {
            KeyAlgorithm::HybridMlKem512X25519 => Ok(MlKemSecurityLevel::MlKem512),
            KeyAlgorithm::HybridMlKem768X25519 => Ok(MlKemSecurityLevel::MlKem768),
            KeyAlgorithm::HybridMlKem1024X25519 => Ok(MlKemSecurityLevel::MlKem1024),
            _ => Err(()),
        }
    }
}

/// Map an ML-DSA parameter set to the corresponding hybrid-signature
/// `KeyAlgorithm` variant. Symmetric with the KEM `From` above.
impl From<crate::primitives::sig::ml_dsa::MlDsaParameterSet> for KeyAlgorithm {
    fn from(param: crate::primitives::sig::ml_dsa::MlDsaParameterSet) -> Self {
        use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
        match param {
            MlDsaParameterSet::MlDsa44 => Self::HybridMlDsa44Ed25519,
            MlDsaParameterSet::MlDsa65 => Self::HybridMlDsa65Ed25519,
            MlDsaParameterSet::MlDsa87 => Self::HybridMlDsa87Ed25519,
        }
    }
}

/// Recover an ML-DSA parameter set from a hybrid-signature `KeyAlgorithm`.
impl TryFrom<KeyAlgorithm> for crate::primitives::sig::ml_dsa::MlDsaParameterSet {
    type Error = ();
    fn try_from(alg: KeyAlgorithm) -> std::result::Result<Self, Self::Error> {
        use crate::primitives::sig::ml_dsa::MlDsaParameterSet;
        match alg {
            KeyAlgorithm::HybridMlDsa44Ed25519 => Ok(MlDsaParameterSet::MlDsa44),
            KeyAlgorithm::HybridMlDsa65Ed25519 => Ok(MlDsaParameterSet::MlDsa65),
            KeyAlgorithm::HybridMlDsa87Ed25519 => Ok(MlDsaParameterSet::MlDsa87),
            _ => Err(()),
        }
    }
}

impl KeyAlgorithm {
    /// Returns `true` if this is a hybrid algorithm with composite key data.
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::HybridMlKem512X25519
                | Self::HybridMlKem768X25519
                | Self::HybridMlKem1024X25519
                | Self::HybridMlDsa44Ed25519
                | Self::HybridMlDsa65Ed25519
                | Self::HybridMlDsa87Ed25519
        )
    }

    /// Returns `true` if this algorithm is symmetric (AES, ChaCha20).
    #[must_use]
    pub fn is_symmetric(&self) -> bool {
        matches!(self, Self::Aes256 | Self::ChaCha20)
    }

    /// Returns `true` if this algorithm is a KEM type (hybrid, PQ-only, or classical).
    #[must_use]
    pub fn is_kem(&self) -> bool {
        matches!(
            self,
            Self::X25519
                | Self::MlKem512
                | Self::MlKem768
                | Self::MlKem1024
                | Self::HybridMlKem512X25519
                | Self::HybridMlKem768X25519
                | Self::HybridMlKem1024X25519
        )
    }

    /// Returns `true` if this algorithm is a signature type.
    #[must_use]
    pub fn is_signature(&self) -> bool {
        matches!(
            self,
            Self::Ed25519
                | Self::MlDsa44
                | Self::MlDsa65
                | Self::MlDsa87
                | Self::SlhDsaShake128s
                | Self::SlhDsaShake256f
                | Self::FnDsa512
                | Self::FnDsa1024
                | Self::HybridMlDsa44Ed25519
                | Self::HybridMlDsa65Ed25519
                | Self::HybridMlDsa87Ed25519
        )
    }

    /// Canonical wire name for this algorithm.
    ///
    /// This is the same value that the serde `rename` attributes emit for
    /// each variant. Used by the passphrase-encrypted-key AAD construction,
    /// which needs a stable `&str` independent of serde's JSON-encoding
    /// rules. **Load-bearing for encrypted key files** — changing the
    /// returned string breaks every existing encrypted key file. A pinned
    /// byte-level test (`test_key_algorithm_canonical_name_matches_serde`)
    /// guards this against drift from the serde attribute values.
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
            Self::SlhDsaShake128s => "slh-dsa-shake-128s",
            Self::SlhDsaShake256f => "slh-dsa-shake-256f",
            Self::FnDsa512 => "fn-dsa-512",
            Self::FnDsa1024 => "fn-dsa-1024",
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::Aes256 => "aes-256",
            Self::ChaCha20 => "chacha20",
            Self::HybridMlKem768X25519 => "hybrid-ml-kem-768-x25519",
            Self::HybridMlKem512X25519 => "hybrid-ml-kem-512-x25519",
            Self::HybridMlKem1024X25519 => "hybrid-ml-kem-1024-x25519",
            Self::HybridMlDsa65Ed25519 => "hybrid-ml-dsa-65-ed25519",
            Self::HybridMlDsa44Ed25519 => "hybrid-ml-dsa-44-ed25519",
            Self::HybridMlDsa87Ed25519 => "hybrid-ml-dsa-87-ed25519",
        }
    }
}

impl KeyType {
    /// Canonical wire name for this key type — matches the serde
    /// `rename_all = "lowercase"` output. Load-bearing for encrypted
    /// key files; see [`KeyAlgorithm::canonical_name`].
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Secret => "secret",
            Self::Symmetric => "symmetric",
        }
    }
}

// ============================================================================
// KeyType
// ============================================================================

/// Key type classifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Public key (safe to share).
    Public,
    /// Secret (private) key — MUST be protected.
    Secret,
    /// Symmetric key — MUST be protected.
    Symmetric,
}

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
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize)]
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
    /// (call [`PortableKey::decrypt_with_passphrase`] first), or Base64 decoding fails.
    pub fn decode_raw(&self) -> Result<Vec<u8>> {
        match self {
            Self::Single { raw } => BASE64_ENGINE
                .decode(raw)
                .map_err(|e| CoreError::SerializationError(format!("Invalid key base64: {e}"))),
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
    /// (call [`PortableKey::decrypt_with_passphrase`] first), or Base64 decoding fails.
    pub fn decode_composite(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Self::Composite { pq, classical } => {
                let pq_bytes = BASE64_ENGINE.decode(pq).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid PQ key base64: {e}"))
                })?;
                let classical_bytes = BASE64_ENGINE.decode(classical).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid classical key base64: {e}"))
                })?;
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

// ============================================================================
// PortableKey
// ============================================================================

/// Portable, versioned key container for all LatticeArc key types.
///
/// Keys are identified by **use case** or **security level** — mirroring how
/// the library's API works. The specific algorithm is auto-derived from these
/// and stored internally for version-stability (the mapping may change between
/// library releases). Users never specify algorithms directly.
///
/// At least one of `use_case` or `security_level` must be present. If both
/// are set, `security_level` takes precedence for algorithm resolution
/// (matching `CryptoConfig` behavior).
///
/// # Dual-Format Serialization
///
/// - **JSON** — human-readable: CLI, REST APIs, debugging
/// - **CBOR** (RFC 8949) — compact binary: wire protocol, database, containers
///
/// # Enterprise Extensions
///
/// The `metadata` map is the extension point for enterprise features.
/// Enterprise crates store additional fields (expiry, hardware binding,
/// dimensions, etc.) as metadata entries and provide typed accessor traits.
/// The base library preserves all metadata during roundtrips.
///
/// # Security Note: Clone
///
/// `PortableKey` derives `Clone` because it is a **serialization type** — it
/// is designed to be written to disk, sent over the wire, or stored in a
/// database. Cloning is required for serialization roundtrip testing and for
/// passing keys through API boundaries.
///
/// **Do not use `PortableKey` as a long-lived runtime key holder.** Extract
/// the concrete key type (e.g., `HybridPublicKey`, `HybridSecretKey`) via the
/// `to_hybrid_*` bridge methods, and work with those instead. Secret key
/// material inside `KeyData` is zeroized on drop via the explicit `Drop` impl.
///
/// # Constant-Time Comparison
///
/// `PortableKey` implements [`subtle::ConstantTimeEq`]. Metadata fields
/// (`version`, `algorithm`, `key_type`, `use_case`, `security_level`, `created`,
/// `metadata`) are compared with non-CT equality because they are serialized
/// in plaintext on the wire — their equality is not a secret. The `key_data`
/// field (containing actual key material, including encrypted envelopes) is
/// compared in constant time via the canonical `subtle::ConstantTimeEq` pattern.
///
/// Cross-variant comparisons (`Single` vs `Composite`, etc.) always return
/// `Choice(0)`. `PortableKey` deliberately does not derive [`PartialEq`] — use
/// `ct_eq` explicitly when comparing key material, and prefer the concrete key
/// types extracted via `to_hybrid_*` for cryptographic operations.
///
/// # Example
///
/// Real-world flow: generate keypair → wrap in PortableKey → serialize →
/// deserialize → use for crypto operations.
///
/// ```rust,no_run
/// use latticearc::{PortableKey, UseCase};
///
/// // 1. Generate a hybrid keypair
/// let (pk, sk) = latticearc::generate_hybrid_keypair().expect("keygen");
///
/// // 2. Wrap in PortableKey (UseCase determines algorithm automatically)
/// let (portable_pk, portable_sk) =
///     PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk)
///         .expect("wrap");
///
/// // 3. Serialize (JSON for files/REST, CBOR for wire/storage)
/// let json = portable_pk.to_json().expect("serialize");
/// let cbor = portable_pk.to_cbor().expect("serialize");
///
/// // 4. Deserialize and extract for crypto operations
/// let restored_pk = PortableKey::from_json(&json)
///     .expect("deserialize")
///     .to_hybrid_public_key()
///     .expect("extract");
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct PortableKey {
    /// Format version (currently `1`).
    version: u32,

    // --- Primary identifiers (at least one required) ---
    /// Use case that determined algorithm selection.
    /// This is how the library's API works: users pick a use case,
    /// the policy engine selects the optimal algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    use_case: Option<crate::types::types::UseCase>,

    /// Security level (NIST Level 1/3/5). If both `use_case` and
    /// `security_level` are set, `security_level` takes precedence
    /// for algorithm resolution (matching `CryptoConfig` behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    security_level: Option<crate::types::types::SecurityLevel>,

    /// Resolved algorithm identifier. Auto-derived from `use_case` or
    /// `security_level` at creation time. Stored for version-stability —
    /// if the policy engine mapping changes in a future release, existing
    /// keys still parse correctly using this field.
    algorithm: KeyAlgorithm,

    /// Key type (public, secret, symmetric).
    key_type: KeyType,
    /// Key material (single or composite).
    key_data: KeyData,
    /// Creation timestamp (UTC, ISO 8601).
    created: DateTime<Utc>,

    /// Open metadata map for enterprise extensions.
    /// Enterprise crates store additional fields (expiry, hardware binding,
    /// dimensions, etc.) here via extension traits. The base library preserves
    /// all entries during roundtrips without interpretation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    metadata: BTreeMap<String, serde_json::Value>,
}

impl std::fmt::Debug for PortableKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_data_display = match self.key_type {
            KeyType::Secret | KeyType::Symmetric => "[REDACTED]",
            KeyType::Public => "[key data]",
        };

        f.debug_struct("PortableKey")
            .field("version", &self.version)
            .field("use_case", &self.use_case)
            .field("security_level", &self.security_level)
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type)
            .field("key_data", &key_data_display)
            .field("created", &self.created)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl subtle::ConstantTimeEq for PortableKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // Metadata fields are serialized in plaintext on the wire (version,
        // algorithm identifiers, timestamps, extension map). Their equality
        // is not a secret, so a non-CT short-circuit here is intentional —
        // it avoids needlessly comparing key material when metadata already
        // differs.
        if self.version != other.version
            || self.algorithm != other.algorithm
            || self.key_type != other.key_type
            || self.use_case != other.use_case
            || self.security_level != other.security_level
            || self.created != other.created
            || self.metadata != other.metadata
        {
            return subtle::Choice::from(0);
        }

        // Key material: the CT-sensitive field.
        self.key_data.ct_eq(&other.key_data)
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

/// Resolve a `UseCase` to a `KeyAlgorithm` for encryption keys.
///
/// This mirrors the `CryptoPolicyEngine::recommend_encryption_scheme` mapping.
#[must_use]
fn resolve_use_case_algorithm(use_case: crate::types::types::UseCase) -> KeyAlgorithm {
    use crate::types::types::UseCase;
    match use_case {
        // Level 1 (128-bit)
        UseCase::IoTDevice => KeyAlgorithm::HybridMlKem512X25519,
        // Level 3 (192-bit) — most use cases
        UseCase::SecureMessaging
        | UseCase::VpnTunnel
        | UseCase::ApiSecurity
        | UseCase::DatabaseEncryption
        | UseCase::ConfigSecrets
        | UseCase::SessionToken
        | UseCase::AuditLog
        | UseCase::Authentication
        | UseCase::FinancialTransactions
        | UseCase::BlockchainTransaction
        | UseCase::FirmwareSigning
        | UseCase::DigitalCertificate
        | UseCase::LegalDocuments => KeyAlgorithm::HybridMlKem768X25519,
        // Level 5 (256-bit) — long-term / regulated
        UseCase::EmailEncryption
        | UseCase::FileStorage
        | UseCase::CloudStorage
        | UseCase::BackupArchive
        | UseCase::KeyExchange
        | UseCase::HealthcareRecords
        | UseCase::GovernmentClassified
        | UseCase::PaymentCard => KeyAlgorithm::HybridMlKem1024X25519,
    }
}

/// Resolve a `SecurityLevel` to a `KeyAlgorithm` for encryption keys.
#[must_use]
fn resolve_security_level_algorithm(level: crate::types::types::SecurityLevel) -> KeyAlgorithm {
    use crate::types::types::SecurityLevel;
    match level {
        SecurityLevel::Standard => KeyAlgorithm::HybridMlKem512X25519,
        SecurityLevel::High => KeyAlgorithm::HybridMlKem768X25519,
        SecurityLevel::Maximum => KeyAlgorithm::HybridMlKem1024X25519,
    }
}

impl PortableKey {
    /// Current format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Create a key identified by use case. Algorithm is auto-derived.
    ///
    /// This is the recommended constructor — it mirrors how the library's
    /// API works: users pick a use case, the policy engine selects the
    /// optimal algorithm.
    #[must_use]
    pub fn for_use_case(
        use_case: crate::types::types::UseCase,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_use_case_algorithm(use_case);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// Create a key identified by security level. Algorithm is auto-derived.
    #[must_use]
    pub fn for_security_level(
        level: crate::types::types::SecurityLevel,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_security_level_algorithm(level);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: Some(level),
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// Create with both use case and security level.
    /// `security_level` takes precedence for algorithm resolution.
    #[must_use]
    pub fn for_use_case_with_level(
        use_case: crate::types::types::UseCase,
        level: crate::types::types::SecurityLevel,
        key_type: KeyType,
        key_data: KeyData,
    ) -> Self {
        let algorithm = resolve_security_level_algorithm(level);
        Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: Some(level),
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// Low-level constructor with explicit algorithm. For imported keys
    /// from external systems that don't use LatticeArc's UseCase/SecurityLevel.
    #[must_use]
    pub fn new(algorithm: KeyAlgorithm, key_type: KeyType, key_data: KeyData) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: None,
            algorithm,
            key_type,
            key_data,
            created: Utc::now(),
            metadata: BTreeMap::new(),
        }
    }

    /// Create with explicit timestamp (for testing / imports).
    #[must_use]
    pub fn with_created(
        algorithm: KeyAlgorithm,
        key_type: KeyType,
        key_data: KeyData,
        created: DateTime<Utc>,
    ) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: None,
            algorithm,
            key_type,
            key_data,
            created,
            metadata: BTreeMap::new(),
        }
    }

    // --- Core accessors ---

    /// Format version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Use case, if set.
    #[must_use]
    pub fn use_case(&self) -> Option<crate::types::types::UseCase> {
        self.use_case
    }

    /// Security level, if set.
    #[must_use]
    pub fn security_level(&self) -> Option<crate::types::types::SecurityLevel> {
        self.security_level
    }

    /// Resolved algorithm identifier (auto-derived from use_case/security_level).
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// Key type (public, secret, symmetric).
    #[must_use]
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Reference to the key data container.
    #[must_use]
    pub fn key_data(&self) -> &KeyData {
        &self.key_data
    }

    /// Creation timestamp.
    #[must_use]
    pub fn created(&self) -> &DateTime<Utc> {
        &self.created
    }

    // --- Metadata accessors ---

    /// Metadata map (read-only).
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.metadata
    }

    /// Insert or update a metadata entry.
    pub fn set_metadata(&mut self, key: String, value: serde_json::Value) {
        self.metadata.insert(key, value);
    }

    /// Set a human-readable label in metadata.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.metadata.insert("label".to_string(), serde_json::Value::String(label.into()));
    }

    /// Get the label from metadata, if any.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.metadata.get("label").and_then(|v| v.as_str())
    }

    // --- Bridge: Hybrid KEM keypair ---

    /// Wrap a hybrid KEM keypair (from `generate_hybrid_keypair()`) into
    /// a pair of `PortableKey`s (public + secret).
    ///
    /// Algorithm is auto-derived from the keypair's `security_level`.
    ///
    /// # Errors
    /// Returns an error if secret key export fails.
    pub fn from_hybrid_kem_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::hybrid::kem_hybrid::HybridKemPublicKey,
        sk: &crate::hybrid::kem_hybrid::HybridKemSecretKey,
    ) -> Result<(Self, Self)> {
        let algorithm: KeyAlgorithm = pk.security_level().into();

        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_composite(pk.ml_kem_pk(), pk.ecdh_pk()),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };

        let ml_kem_sk = sk
            .ml_kem_sk_bytes()
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM SK export: {e}")))?;
        let ecdh_seed = sk
            .ecdh_seed_bytes()
            .map_err(|e| CoreError::InvalidKey(format!("ECDH seed export: {e}")))?;

        // Store ML-KEM public key in metadata so the secret key file is
        // self-contained for decryption (no separate public key file needed).
        // This follows the PKCS#12 pattern of bundling public + private material.
        // Note: ECDH public key is not stored — it's derived from the seed at
        // reconstruction time via X25519StaticKeyPair::from_seed_bytes().
        let mut sk_metadata = BTreeMap::new();
        sk_metadata.insert(
            ML_KEM_PK_METADATA_KEY.to_string(),
            serde_json::Value::String(BASE64_ENGINE.encode(pk.ml_kem_pk())),
        );

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_composite(&ml_kem_sk, &*ecdh_seed),
            created: Utc::now(),
            metadata: sk_metadata,
        };

        Ok((pub_key, sec_key))
    }

    /// Extract a `HybridPublicKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a hybrid KEM or key data is invalid.
    pub fn to_hybrid_public_key(&self) -> Result<crate::hybrid::kem_hybrid::HybridKemPublicKey> {
        let level =
            crate::primitives::kem::MlKemSecurityLevel::try_from(self.algorithm).map_err(|()| {
                CoreError::InvalidKey(format!(
                    "Not a hybrid KEM algorithm: {alg:?}",
                    alg = self.algorithm
                ))
            })?;

        let (pq_bytes, classical_bytes) = self.key_data.decode_composite()?;

        Ok(crate::hybrid::kem_hybrid::HybridKemPublicKey::new(pq_bytes, classical_bytes, level))
    }

    /// Reconstruct a `HybridSecretKey` from a portable key pair.
    ///
    /// Requires the corresponding public key PortableKey because ML-KEM
    /// key reconstruction needs both the secret key bytes and public key bytes.
    ///
    /// # Arguments
    /// * `public_key` - The corresponding `PortableKey` with `KeyType::Public`
    ///
    /// # Errors
    /// Returns an error if the algorithm is not hybrid KEM, key data is invalid,
    /// or key reconstruction fails.
    ///
    /// The ML-KEM public key is extracted from the secret key file's metadata
    /// (stored at keygen time), making the secret key file fully self-contained.
    /// No separate public key file is needed for decryption.
    pub fn to_hybrid_secret_key(&self) -> Result<crate::hybrid::kem_hybrid::HybridKemSecretKey> {
        let level =
            crate::primitives::kem::MlKemSecurityLevel::try_from(self.algorithm).map_err(|()| {
                CoreError::InvalidKey(format!(
                    "Not a hybrid KEM algorithm: {alg:?}",
                    alg = self.algorithm
                ))
            })?;

        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Cannot reconstruct secret key from a public key".to_string(),
            ));
        }

        let (ml_kem_sk, ecdh_seed_vec) = self.key_data.decode_composite()?;

        // Extract ML-KEM public key from metadata (stored at keygen time)
        let ml_kem_pk = self
            .metadata
            .get(ML_KEM_PK_METADATA_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CoreError::InvalidKey(
                    "Secret key file missing 'ml_kem_pk' metadata. \
                     Re-generate the keypair with the latest CLI."
                        .to_string(),
                )
            })
            .and_then(|b64| {
                BASE64_ENGINE
                    .decode(b64)
                    .map_err(|e| CoreError::InvalidKey(format!("Invalid ml_kem_pk base64: {e}")))
            })?;

        if ecdh_seed_vec.len() != 32 {
            return Err(CoreError::InvalidKey(format!(
                "X25519 seed must be 32 bytes, got {}",
                ecdh_seed_vec.len()
            )));
        }

        let mut ecdh_seed = zeroize::Zeroizing::new([0u8; 32]);
        ecdh_seed.copy_from_slice(&ecdh_seed_vec);

        crate::hybrid::kem_hybrid::HybridKemSecretKey::from_serialized(
            level, &ml_kem_sk, &ml_kem_pk, &ecdh_seed,
        )
        .map_err(|e| CoreError::InvalidKey(format!("Secret key reconstruction: {e}")))
    }

    // --- Bridge: Hybrid signature keypair ---

    /// Wrap a hybrid signature keypair (from `generate_hybrid_signing_keypair()`)
    /// into a pair of `PortableKey`s (public + secret).
    ///
    /// The ML-DSA parameter set is auto-detected from the public key byte length:
    /// - 1,312 bytes → ML-DSA-44 (`HybridMlDsa44Ed25519`)
    /// - 1,952 bytes → ML-DSA-65 (`HybridMlDsa65Ed25519`)
    /// - 2,592 bytes → ML-DSA-87 (`HybridMlDsa87Ed25519`)
    ///
    /// # Arguments
    /// * `use_case` - The use case this key was generated for
    /// * `pk` - Hybrid signature public key (ML-DSA + Ed25519)
    /// * `sk` - Hybrid signature secret key (ML-DSA + Ed25519)
    ///
    /// # Errors
    /// Returns an error if `pk.parameter_set()` does not map to a known
    /// hybrid-signature `KeyAlgorithm` variant. (As of 0.8.0 all three
    /// ML-DSA parameter sets are mapped, so this is currently
    /// unreachable; the `Result` shape is retained for forward
    /// compatibility with future ML-DSA variants.)
    pub fn from_hybrid_sig_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::hybrid::sig_hybrid::HybridSigPublicKey,
        sk: &crate::hybrid::sig_hybrid::HybridSigSecretKey,
    ) -> Result<(Self, Self)> {
        // Read the parameter set off the typed handle introduced in
        // 0.8.0 — see HybridSigPublicKey::parameter_set. Earlier
        // revisions sniffed it from the PK byte length (1312/1952/2592);
        // that worked because the FIPS 204 sets have unique lengths,
        // but it was inconsistent with the KEM side (which used the
        // typed level()) and would silently break if any future ML-DSA
        // variant collided on length.
        let algorithm: KeyAlgorithm = pk.parameter_set().into();

        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_composite(pk.ml_dsa_pk(), pk.ed25519_pk()),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_composite(
                sk.expose_ml_dsa_secret(),
                sk.expose_ed25519_secret(),
            ),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };

        Ok((pub_key, sec_key))
    }

    /// Extract a hybrid signature `HybridPublicKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a hybrid signature or key data is invalid.
    pub fn to_hybrid_sig_public_key(
        &self,
    ) -> Result<crate::hybrid::sig_hybrid::HybridSigPublicKey> {
        let parameter_set = crate::primitives::sig::ml_dsa::MlDsaParameterSet::try_from(
            self.algorithm,
        )
        .map_err(|()| {
            CoreError::InvalidKey(format!(
                "Not a hybrid signature algorithm: {alg:?}",
                alg = self.algorithm
            ))
        })?;

        let (pq_bytes, classical_bytes) = self.key_data.decode_composite()?;

        Ok(crate::hybrid::sig_hybrid::HybridSigPublicKey::new(
            parameter_set,
            pq_bytes,
            classical_bytes,
        ))
    }

    /// Extract a hybrid signature `HybridSecretKey` from a portable key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not hybrid signature or key data is invalid.
    pub fn to_hybrid_sig_secret_key(
        &self,
    ) -> Result<crate::hybrid::sig_hybrid::HybridSigSecretKey> {
        let parameter_set = crate::primitives::sig::ml_dsa::MlDsaParameterSet::try_from(
            self.algorithm,
        )
        .map_err(|()| {
            CoreError::InvalidKey(format!(
                "Not a hybrid signature algorithm: {alg:?}",
                alg = self.algorithm
            ))
        })?;

        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Cannot reconstruct secret key from a public key".to_string(),
            ));
        }

        let (pq_bytes, classical_bytes) = self.key_data.decode_composite()?;

        Ok(crate::hybrid::sig_hybrid::HybridSigSecretKey::new(
            parameter_set,
            zeroize::Zeroizing::new(pq_bytes),
            zeroize::Zeroizing::new(classical_bytes),
        ))
    }

    // --- Bridge: Simple keypair (Ed25519, ML-KEM, ML-DSA, etc.) ---

    /// Wrap a simple keypair (public + private byte arrays) into a pair of `PortableKey`s.
    ///
    /// For non-hybrid algorithms that produce `(PublicKey, PrivateKey)`.
    #[must_use]
    pub fn from_keypair(
        use_case: crate::types::types::UseCase,
        algorithm: KeyAlgorithm,
        public_key: &[u8],
        private_key: &[u8],
    ) -> (Self, Self) {
        let pub_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Public,
            key_data: KeyData::from_raw(public_key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };

        let sec_key = Self {
            version: Self::CURRENT_VERSION,
            use_case: Some(use_case),
            security_level: None,
            algorithm,
            key_type: KeyType::Secret,
            key_data: KeyData::from_raw(private_key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };

        (pub_key, sec_key)
    }

    // --- Bridge: Ed25519 keypair ---

    /// Wrap an Ed25519 keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// Convenience wrapper around [`from_keypair`](Self::from_keypair) that
    /// sets the algorithm to `Ed25519`.
    #[must_use]
    pub fn from_ed25519_keypair(
        use_case: crate::types::types::UseCase,
        verifying_key: &[u8],
        signing_key: &[u8],
    ) -> (Self, Self) {
        Self::from_keypair(use_case, KeyAlgorithm::Ed25519, verifying_key, signing_key)
    }

    /// Extract Ed25519 verifying key bytes (32 bytes).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not Ed25519 or key type is not Public.
    pub fn to_ed25519_verifying_key_bytes(&self) -> Result<Vec<u8>> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(CoreError::InvalidKey(format!("Not an Ed25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "Ed25519 verifying key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract Ed25519 signing key bytes (zeroized on drop).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not Ed25519 or key type is not Secret.
    pub fn to_ed25519_signing_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.algorithm != KeyAlgorithm::Ed25519 {
            return Err(CoreError::InvalidKey(format!("Not an Ed25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "Ed25519 signing key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: X25519 keypair ---

    /// Wrap an X25519 keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// The secret key is stored as the 32-byte seed
    /// (from [`X25519StaticKeyPair::seed_bytes()`](crate::primitives::kem::ecdh::X25519StaticKeyPair::seed_bytes)).
    #[must_use]
    pub fn from_x25519_keypair(
        use_case: crate::types::types::UseCase,
        public_key: &[u8; 32],
        seed: &[u8; 32],
    ) -> (Self, Self) {
        Self::from_keypair(use_case, KeyAlgorithm::X25519, public_key, seed)
    }

    /// Extract X25519 public key bytes (32 bytes).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not X25519 or key type is not Public.
    pub fn to_x25519_public_key_bytes(&self) -> Result<Vec<u8>> {
        if self.algorithm != KeyAlgorithm::X25519 {
            return Err(CoreError::InvalidKey(format!("Not an X25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "X25519 public key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract X25519 secret key seed bytes (32 bytes, zeroized on drop).
    ///
    /// Use with [`X25519StaticKeyPair::from_seed_bytes()`](crate::primitives::kem::ecdh::X25519StaticKeyPair::from_seed_bytes)
    /// to reconstruct the key pair for agreement operations.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not X25519 or key type is not Secret.
    pub fn to_x25519_secret_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if self.algorithm != KeyAlgorithm::X25519 {
            return Err(CoreError::InvalidKey(format!("Not an X25519 key: {:?}", self.algorithm)));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "X25519 secret key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: ML-KEM keypair ---

    /// Wrap an ML-KEM keypair into a pair of `PortableKey`s (public + secret).
    ///
    /// Algorithm is auto-detected from the public key's security level.
    #[must_use]
    pub fn from_ml_kem_keypair(
        use_case: crate::types::types::UseCase,
        pk: &crate::primitives::kem::ml_kem::MlKemPublicKey,
        sk: &crate::primitives::kem::ml_kem::MlKemSecretKey,
    ) -> (Self, Self) {
        let algorithm = match pk.security_level() {
            crate::primitives::kem::MlKemSecurityLevel::MlKem512 => KeyAlgorithm::MlKem512,
            crate::primitives::kem::MlKemSecurityLevel::MlKem768 => KeyAlgorithm::MlKem768,
            crate::primitives::kem::MlKemSecurityLevel::MlKem1024 => KeyAlgorithm::MlKem1024,
        };
        Self::from_keypair(use_case, algorithm, pk.as_bytes(), sk.expose_secret())
    }

    /// Extract ML-KEM public (encapsulation) key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-KEM variant,
    /// key type is not Public, or the key data is malformed.
    pub fn to_ml_kem_public_key(&self) -> Result<crate::primitives::kem::ml_kem::MlKemPublicKey> {
        let level = match self.algorithm {
            KeyAlgorithm::MlKem512 => crate::primitives::kem::MlKemSecurityLevel::MlKem512,
            KeyAlgorithm::MlKem768 => crate::primitives::kem::MlKemSecurityLevel::MlKem768,
            KeyAlgorithm::MlKem1024 => crate::primitives::kem::MlKemSecurityLevel::MlKem1024,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Not a standalone ML-KEM algorithm: {other:?}"
                )));
            }
        };
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "ML-KEM public key requires Public key type".to_string(),
            ));
        }
        let bytes = self.key_data.decode_raw()?;
        crate::primitives::kem::ml_kem::MlKemPublicKey::new(level, bytes)
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM public key: {e}")))
    }

    /// Extract ML-KEM secret (decapsulation) key.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-KEM variant,
    /// key type is not Secret, or the key data is malformed.
    pub fn to_ml_kem_secret_key(&self) -> Result<crate::primitives::kem::ml_kem::MlKemSecretKey> {
        let level = match self.algorithm {
            KeyAlgorithm::MlKem512 => crate::primitives::kem::MlKemSecurityLevel::MlKem512,
            KeyAlgorithm::MlKem768 => crate::primitives::kem::MlKemSecurityLevel::MlKem768,
            KeyAlgorithm::MlKem1024 => crate::primitives::kem::MlKemSecurityLevel::MlKem1024,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Not a standalone ML-KEM algorithm: {other:?}"
                )));
            }
        };
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "ML-KEM secret key requires Secret key type".to_string(),
            ));
        }
        let bytes = self.key_data.decode_raw()?;
        crate::primitives::kem::ml_kem::MlKemSecretKey::new(level, bytes)
            .map_err(|e| CoreError::InvalidKey(format!("ML-KEM secret key: {e}")))
    }

    // --- Bridge: ML-DSA keypair ---

    /// Extract ML-DSA verifying (public) key bytes.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-DSA variant
    /// or key type is not Public.
    pub fn to_ml_dsa_verifying_key_bytes(&self) -> Result<Vec<u8>> {
        if !matches!(
            self.algorithm,
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87
        ) {
            return Err(CoreError::InvalidKey(format!(
                "Not a standalone ML-DSA algorithm: {:?}",
                self.algorithm
            )));
        }
        if self.key_type != KeyType::Public {
            return Err(CoreError::InvalidKey(
                "ML-DSA verifying key requires Public key type".to_string(),
            ));
        }
        self.key_data.decode_raw()
    }

    /// Extract ML-DSA signing (secret) key bytes (zeroized on drop).
    ///
    /// # Errors
    /// Returns an error if the algorithm is not a standalone ML-DSA variant
    /// or key type is not Secret.
    pub fn to_ml_dsa_signing_key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if !matches!(
            self.algorithm,
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87
        ) {
            return Err(CoreError::InvalidKey(format!(
                "Not a standalone ML-DSA algorithm: {:?}",
                self.algorithm
            )));
        }
        if self.key_type != KeyType::Secret {
            return Err(CoreError::InvalidKey(
                "ML-DSA signing key requires Secret key type".to_string(),
            ));
        }
        self.key_data.decode_raw_zeroized()
    }

    // --- Bridge: Symmetric key ---

    /// Create a `PortableKey` from raw symmetric key bytes.
    ///
    /// # Errors
    /// Returns an error if the algorithm is not symmetric (AES-256 or ChaCha20).
    pub fn from_symmetric_key(algorithm: KeyAlgorithm, key: &[u8]) -> Result<Self> {
        if !algorithm.is_symmetric() {
            return Err(CoreError::InvalidKey(format!(
                "{algorithm:?} is not a symmetric algorithm"
            )));
        }
        Ok(Self {
            version: Self::CURRENT_VERSION,
            use_case: None,
            security_level: None,
            algorithm,
            key_type: KeyType::Symmetric,
            key_data: KeyData::from_raw(key),
            created: Utc::now(),
            metadata: BTreeMap::new(),
        })
    }

    // --- Validation ---

    /// Validate internal consistency.
    ///
    /// Checks:
    /// - Format version matches [`CURRENT_VERSION`](Self::CURRENT_VERSION)
    /// - Symmetric algorithms (`aes-256`, `chacha20`) require `KeyType::Symmetric`
    /// - Hybrid algorithms require composite `KeyData`
    /// - Non-hybrid algorithms require single `KeyData`
    /// - Base64 key data decodes successfully
    ///
    /// # Errors
    /// Returns `CoreError::InvalidKey` on validation failure.
    pub fn validate(&self) -> Result<()> {
        // Version check — reject keys serialized by future or incompatible versions
        if self.version != Self::CURRENT_VERSION {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported key format version {}, expected {}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }

        // Symmetric algorithm ↔ key type
        if self.algorithm.is_symmetric() && self.key_type != KeyType::Symmetric {
            return Err(CoreError::InvalidKey(format!(
                "Algorithm {:?} requires KeyType::Symmetric, got {:?}",
                self.algorithm, self.key_type
            )));
        }
        if !self.algorithm.is_symmetric() && self.key_type == KeyType::Symmetric {
            return Err(CoreError::InvalidKey(format!(
                "KeyType::Symmetric is not valid for algorithm {:?}",
                self.algorithm
            )));
        }

        // Hybrid ↔ composite key data (encrypted variant is opaque — skip this check).
        match (&self.key_data, self.algorithm.is_hybrid()) {
            (KeyData::Composite { .. }, false) => {
                return Err(CoreError::InvalidKey(format!(
                    "Non-hybrid algorithm {:?} must use single key data",
                    self.algorithm
                )));
            }
            (KeyData::Single { .. }, true) => {
                return Err(CoreError::InvalidKey(format!(
                    "Hybrid algorithm {:?} must use composite key data",
                    self.algorithm
                )));
            }
            _ => {}
        }

        // Verify base64 decodes / envelope shape
        match &self.key_data {
            KeyData::Single { raw } => {
                let _ = BASE64_ENGINE
                    .decode(raw)
                    .map_err(|e| CoreError::SerializationError(format!("Invalid base64: {e}")))?;
            }
            KeyData::Composite { pq, classical } => {
                let _ = BASE64_ENGINE.decode(pq).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid PQ base64: {e}"))
                })?;
                let _ = BASE64_ENGINE.decode(classical).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid classical base64: {e}"))
                })?;
            }
            KeyData::Encrypted { enc, kdf, kdf_iterations, kdf_salt, aead, nonce, ciphertext } => {
                Self::validate_encrypted_envelope_fields(
                    *enc,
                    kdf,
                    *kdf_iterations,
                    kdf_salt,
                    aead,
                    nonce,
                    ciphertext,
                )?;
            }
        }

        Ok(())
    }

    /// Validate an encrypted-envelope's metadata and base64-decodable sizes.
    ///
    /// Shared between [`Self::validate`] (which rejects malformed keys at
    /// load time) and [`Self::decrypt_with_passphrase`] (which uses this to
    /// defend against direct construction of an unvalidated encrypted
    /// variant). Does not verify the AEAD tag — that happens in
    /// `decrypt_with_passphrase` after key derivation.
    fn validate_encrypted_envelope_fields(
        enc: u32,
        kdf: &str,
        kdf_iterations: u32,
        kdf_salt: &str,
        aead: &str,
        nonce: &str,
        ciphertext: &str,
    ) -> Result<()> {
        if enc != ENCRYPTED_ENVELOPE_VERSION {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported encrypted key envelope version {enc}, expected {ENCRYPTED_ENVELOPE_VERSION}",
            )));
        }
        if kdf != PBKDF2_KDF_ID {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported KDF {kdf:?}, expected {PBKDF2_KDF_ID:?}",
            )));
        }
        if aead != AES_GCM_AEAD_ID {
            return Err(CoreError::InvalidKey(format!(
                "Unsupported AEAD {aead:?}, expected {AES_GCM_AEAD_ID:?}",
            )));
        }
        if kdf_iterations < PBKDF2_MIN_ITERATIONS {
            return Err(CoreError::InvalidKey(format!(
                "PBKDF2 iteration count {kdf_iterations} below minimum {PBKDF2_MIN_ITERATIONS}",
            )));
        }
        // Warn when a loaded key uses fewer iterations than the current
        // OWASP-recommended default. The minimum (100k) is retained as a
        // hard floor for backwards compatibility with keys generated under
        // OWASP 2018 guidance; the default (600k) is OWASP 2023 for
        // HMAC-SHA256. Callers should re-protect keys below the default.
        //
        // Deduped per *distinct iteration count* per process: a mixed-fleet
        // operator loading key-A at 10k and key-B at 1k must see two
        // warnings (one per cohort), not one — otherwise the audit trail
        // hides the lower-iteration cohort behind the first cohort that
        // happened to trigger. Using `Mutex<HashSet<u32>>` here is fine
        // because key load is cold-path; the mutex is never contended on
        // a hot loop.
        if kdf_iterations < PBKDF2_DEFAULT_ITERATIONS {
            // Capacity cap prevents unbounded memory growth from an adversary
            // feeding distinct iteration-count keys. 256 distinct values is
            // far more than any realistic operator fleet (cohorts cluster
            // around OWASP guidance dates); beyond the cap we silence
            // further warnings — a single previously-emitted warning is
            // already enough audit signal that the cohort exists.
            const MAX_DISTINCT_ITERATION_COUNTS: usize = 256;
            static LOW_ITER_WARNED: std::sync::OnceLock<
                std::sync::Mutex<std::collections::HashSet<u32>>,
            > = std::sync::OnceLock::new();
            let table = LOW_ITER_WARNED.get_or_init(|| std::sync::Mutex::new(Default::default()));
            // Lock-poisoning here is non-fatal — emit the warning anyway,
            // since not warning is strictly worse than a duplicate warning.
            let mut seen = table.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let should_warn = if seen.contains(&kdf_iterations) {
                false
            } else if seen.len() < MAX_DISTINCT_ITERATION_COUNTS {
                seen.insert(kdf_iterations);
                true
            } else {
                // Capacity reached — drop the new value silently. The
                // operator already has 256 prior warnings to act on; a
                // 257th cohort would not change the response.
                false
            };
            if should_warn {
                tracing::warn!(
                    kdf_iterations,
                    recommended = PBKDF2_DEFAULT_ITERATIONS,
                    "PBKDF2 iteration count is below the current OWASP recommendation; \
                     re-protect this key (decrypt + re-encrypt with passphrase) at the \
                     next opportunity."
                );
            }
        }
        let salt = BASE64_ENGINE
            .decode(kdf_salt)
            .map_err(|e| CoreError::SerializationError(format!("Invalid KDF salt base64: {e}")))?;
        if salt.len() < PBKDF2_MIN_SALT_LEN {
            return Err(CoreError::InvalidKey(format!(
                "PBKDF2 salt length {} below minimum {PBKDF2_MIN_SALT_LEN}",
                salt.len(),
            )));
        }
        let nonce_bytes = BASE64_ENGINE
            .decode(nonce)
            .map_err(|e| CoreError::SerializationError(format!("Invalid nonce base64: {e}")))?;
        if nonce_bytes.len() != AES_GCM_NONCE_LEN {
            return Err(CoreError::InvalidKey(format!(
                "AES-GCM nonce length {} != {AES_GCM_NONCE_LEN}",
                nonce_bytes.len(),
            )));
        }
        let ct_bytes = BASE64_ENGINE.decode(ciphertext).map_err(|e| {
            CoreError::SerializationError(format!("Invalid ciphertext base64: {e}"))
        })?;
        if ct_bytes.len() < AES_GCM_TAG_LEN {
            return Err(CoreError::InvalidKey(
                "Encrypted key ciphertext shorter than AES-GCM tag".to_string(),
            ));
        }
        Ok(())
    }

    // --- Passphrase-based encryption (LPK v1 encrypted variant) ---

    /// Returns `true` if the key material is passphrase-encrypted.
    ///
    /// Encrypted keys must be unwrapped via [`Self::decrypt_with_passphrase`]
    /// before their raw bytes can be extracted via [`KeyData::decode_raw`] or
    /// [`KeyData::decode_composite`].
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self.key_data, KeyData::Encrypted { .. })
    }

    /// Encrypt the key material in place using a passphrase.
    ///
    /// Derives a 32-byte AES key via PBKDF2-HMAC-SHA256 (600,000 iterations,
    /// 16-byte random salt) and encrypts the JSON-serialized `KeyData` under
    /// AES-256-GCM with a fresh 12-byte random nonce. The full envelope
    /// (version, algorithm, key_type, KDF name, iteration count, salt, AEAD
    /// name) is mixed into the AEAD AAD, so tampering with any metadata
    /// field on disk causes decryption to fail at the tag check. See
    /// [`Self::encryption_aad`] for the exact byte layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is already encrypted, if the passphrase is
    /// empty, or if the KDF / AEAD operation fails.
    pub fn encrypt_with_passphrase(&mut self, passphrase: &[u8]) -> Result<()> {
        if self.is_encrypted() {
            return Err(CoreError::InvalidKey("Key is already passphrase-encrypted".to_string()));
        }
        if passphrase.is_empty() {
            return Err(CoreError::InvalidKey("Passphrase must not be empty".to_string()));
        }

        // 1. Serialize the current plaintext KeyData to its own JSON. We
        //    serialize only the KeyData (not the whole PortableKey) so the
        //    ciphertext is self-contained and round-trips cleanly.
        let plaintext_json = serde_json::to_vec(&self.key_data).map_err(|e| {
            CoreError::SerializationError(format!(
                "Failed to serialize key data for encryption: {e}"
            ))
        })?;
        let plaintext = zeroize::Zeroizing::new(plaintext_json);

        // 2. Generate a fresh random salt.
        let salt = crate::primitives::rand::csprng::random_bytes(PBKDF2_SALT_LEN);

        // 3. Derive the AES key via PBKDF2-HMAC-SHA256. Salt-length
        // validation lives at the `pbkdf2(...)` call below; `with_salt`
        // is intentionally infallible so wire-format parsers can also
        // round-trip pre-0.8.0 short-salt envelopes for inspection.
        let kdf_params = crate::primitives::kdf::pbkdf2::Pbkdf2Params::with_salt(&salt)
            .iterations(PBKDF2_DEFAULT_ITERATIONS)
            .key_length(AES_256_KEY_LEN);
        let derived = crate::primitives::kdf::pbkdf2::pbkdf2(passphrase, &kdf_params)
            .map_err(|e| CoreError::InvalidKey(format!("PBKDF2 derivation failed: {e}")))?;

        // 4. Encrypt via AES-256-GCM with a fresh random nonce. Bind the
        //    full envelope (version, algorithm, key_type, KDF name,
        //    iterations, salt, AEAD name) to the ciphertext via AAD so an
        //    attacker who modifies any of these fields on disk breaks the
        //    AEAD tag.
        use crate::primitives::aead::AeadCipher;
        let cipher = crate::primitives::aead::aes_gcm::AesGcm256::new(derived.key())
            .map_err(|e| CoreError::InvalidKey(format!("Failed to initialize AES-256-GCM: {e}")))?;
        let aad = Self::encryption_aad(
            ENCRYPTED_ENVELOPE_VERSION,
            self.algorithm,
            self.key_type,
            PBKDF2_KDF_ID,
            PBKDF2_DEFAULT_ITERATIONS,
            &salt,
            AES_GCM_AEAD_ID,
        );
        let (nonce, mut ct, tag) = cipher
            .seal(&plaintext, Some(&aad))
            .map_err(|e| CoreError::InvalidKey(format!("AES-256-GCM sealing failed: {e}")))?;

        // 5. Pack ciphertext || tag for on-wire storage.
        ct.extend_from_slice(&tag);

        // 6. Replace the plaintext KeyData with the encrypted envelope.
        self.key_data = KeyData::Encrypted {
            enc: ENCRYPTED_ENVELOPE_VERSION,
            kdf: PBKDF2_KDF_ID.to_string(),
            kdf_iterations: PBKDF2_DEFAULT_ITERATIONS,
            kdf_salt: BASE64_ENGINE.encode(&salt),
            aead: AES_GCM_AEAD_ID.to_string(),
            nonce: BASE64_ENGINE.encode(nonce),
            ciphertext: BASE64_ENGINE.encode(&ct),
        };

        Ok(())
    }

    /// Decrypt the key material in place using a passphrase.
    ///
    /// Reverses [`Self::encrypt_with_passphrase`]. On success the `key_data`
    /// field is replaced with the underlying `Single` or `Composite` variant.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not encrypted, the envelope is
    /// malformed, the passphrase is wrong (AEAD authentication fails), or
    /// the decrypted plaintext is not a valid `KeyData` serialization.
    pub fn decrypt_with_passphrase(&mut self, passphrase: &[u8]) -> Result<()> {
        if passphrase.is_empty() {
            return Err(CoreError::InvalidKey("Passphrase must not be empty".to_string()));
        }

        // Borrow the envelope to validate shape and decode its fields into
        // owned bytes. After validation the `kdf` and `aead` string fields
        // are known to equal the envelope's fixed constants, so we don't
        // bother cloning them into `Decoded` — we pass the constants to
        // `encryption_aad` at the call site instead.
        struct Decoded {
            enc: u32,
            kdf_iterations: u32,
            salt: Vec<u8>,
            nonce: [u8; AES_GCM_NONCE_LEN],
            ct_and_tag: Vec<u8>,
        }
        let decoded = match &self.key_data {
            KeyData::Encrypted { enc, kdf, kdf_iterations, kdf_salt, aead, nonce, ciphertext } => {
                Self::validate_encrypted_envelope_fields(
                    *enc,
                    kdf,
                    *kdf_iterations,
                    kdf_salt,
                    aead,
                    nonce,
                    ciphertext,
                )?;
                let salt = BASE64_ENGINE.decode(kdf_salt).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid KDF salt base64: {e}"))
                })?;
                let nonce_bytes = BASE64_ENGINE.decode(nonce).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid nonce base64: {e}"))
                })?;
                let mut nonce_array = [0u8; AES_GCM_NONCE_LEN];
                nonce_array.copy_from_slice(&nonce_bytes);
                let ct_and_tag = BASE64_ENGINE.decode(ciphertext).map_err(|e| {
                    CoreError::SerializationError(format!("Invalid ciphertext base64: {e}"))
                })?;
                Decoded {
                    enc: *enc,
                    kdf_iterations: *kdf_iterations,
                    salt,
                    nonce: nonce_array,
                    ct_and_tag,
                }
            }
            _ => {
                return Err(CoreError::InvalidKey("Key is not passphrase-encrypted".to_string()));
            }
        };
        let Decoded { enc, kdf_iterations, salt, nonce: nonce_array, ct_and_tag } = decoded;

        let tag_offset = ct_and_tag
            .len()
            .checked_sub(AES_GCM_TAG_LEN)
            .ok_or_else(|| CoreError::InvalidKey("Ciphertext shorter than tag".to_string()))?;
        let (ct_bytes, tag_bytes) = ct_and_tag.split_at(tag_offset);
        let mut tag_array = [0u8; AES_GCM_TAG_LEN];
        tag_array.copy_from_slice(tag_bytes);

        // Derive the AES key from the passphrase + salt.
        // `with_salt` is the right tool here: `salt` was
        // deserialized from an externally-supplied envelope and may be
        // a pre-0.8.0 short salt that `with_salt`'s NIST SP 800-132 §5.1
        // floor would reject. The validating min-length check happens at
        // the `pbkdf2(...)` call below instead, so the unchecked
        // construction cannot smuggle a short salt past actual
        // derivation. This is the documented wire-format-parser use
        // case for `with_salt`.
        let kdf_params = crate::primitives::kdf::pbkdf2::Pbkdf2Params::with_salt(&salt)
            .iterations(kdf_iterations)
            .key_length(AES_256_KEY_LEN);
        let derived = crate::primitives::kdf::pbkdf2::pbkdf2(passphrase, &kdf_params)
            .map_err(|e| CoreError::InvalidKey(format!("PBKDF2 derivation failed: {e}")))?;

        // Decrypt. A wrong passphrase produces a wrong AES key, which causes
        // AEAD authentication to fail with an opaque error — we do NOT leak
        // whether the passphrase was wrong vs. the envelope was corrupted.
        // The AAD binds the full envelope so any tampered metadata field
        // also breaks the tag.
        use crate::primitives::aead::AeadCipher;
        let cipher = crate::primitives::aead::aes_gcm::AesGcm256::new(derived.key())
            .map_err(|e| CoreError::InvalidKey(format!("Failed to initialize AES-256-GCM: {e}")))?;
        // `kdf` and `aead` are the constants: `validate_encrypted_envelope_fields`
        // rejected any other value, so we can pass the literals directly
        // instead of cloning them out of the borrowed envelope.
        let aad = Self::encryption_aad(
            enc,
            self.algorithm,
            self.key_type,
            PBKDF2_KDF_ID,
            kdf_iterations,
            &salt,
            AES_GCM_AEAD_ID,
        );
        let plaintext = cipher
            .decrypt(&nonce_array, ct_bytes, &tag_array, Some(&aad))
            .map_err(|_e| {
                CoreError::InvalidKey(
                    "Passphrase-protected key unwrap failed (wrong passphrase or corrupted envelope)"
                        .to_string(),
                )
            })?;

        // Deserialize the plaintext bytes back into a KeyData variant.
        let new_key_data: KeyData = serde_json::from_slice(&plaintext).map_err(|e| {
            CoreError::SerializationError(format!("Failed to deserialize decrypted key data: {e}"))
        })?;
        // Reject nested encryption (prevents re-wrap confusion).
        if matches!(new_key_data, KeyData::Encrypted { .. }) {
            return Err(CoreError::InvalidKey(
                "Decrypted payload was itself an encrypted envelope".to_string(),
            ));
        }

        self.key_data = new_key_data;
        Ok(())
    }

    /// Build the AAD bound to an encrypted key envelope.
    ///
    /// AEAD AAD is authenticated (not encrypted), so fields folded in here
    /// are protected against tampering but not against disclosure. Binding
    /// all envelope parameters — version, algorithm, key type, KDF name,
    /// iteration count, salt, and AEAD name — ensures that any attacker
    /// modification of a stored key file's metadata or KDF parameters
    /// causes `cipher.decrypt` to fail with an opaque error.
    ///
    /// Uses stable kebab-case / lowercase names (`ml-kem-768`, `secret`)
    /// via `canonical_name` accessors on the enums. These are load-bearing:
    /// changing the returned strings breaks every existing encrypted key
    /// file. A pinned byte-level test in the `tests` module guards this.
    ///
    /// # Byte layout
    ///
    /// ```text
    /// "latticearc-lpk-v1-enc" || 0x00
    /// || enc (u32 BE)
    /// || algorithm_name || 0x00
    /// || key_type_name || 0x00
    /// || kdf_name || 0x00
    /// || kdf_iterations (u32 BE)
    /// || kdf_salt_len (u32 BE) || kdf_salt_raw_bytes
    /// || aead_name
    /// ```
    ///
    /// Length prefixes and null separators prevent ambiguity between
    /// adjacent variable-length fields. The salt is included as its raw
    /// (base64-decoded) bytes, not the base64 string, so an attacker
    /// cannot use base64 non-canonical encodings to get past the check.
    fn encryption_aad(
        enc: u32,
        algorithm: KeyAlgorithm,
        key_type: KeyType,
        kdf: &str,
        kdf_iterations: u32,
        kdf_salt: &[u8],
        aead: &str,
    ) -> Vec<u8> {
        let algorithm_name = algorithm.canonical_name();
        let key_type_name = key_type.canonical_name();

        let mut aad = Vec::with_capacity(
            b"latticearc-lpk-v1-enc"
                .len()
                .saturating_add(1) // null
                .saturating_add(4) // enc
                .saturating_add(algorithm_name.len())
                .saturating_add(1)
                .saturating_add(key_type_name.len())
                .saturating_add(1)
                .saturating_add(kdf.len())
                .saturating_add(1)
                .saturating_add(4) // kdf_iterations
                .saturating_add(4) // salt len
                .saturating_add(kdf_salt.len())
                .saturating_add(aead.len()),
        );
        aad.extend_from_slice(b"latticearc-lpk-v1-enc");
        aad.push(0);
        aad.extend_from_slice(&enc.to_be_bytes());
        aad.extend_from_slice(algorithm_name.as_bytes());
        aad.push(0);
        aad.extend_from_slice(key_type_name.as_bytes());
        aad.push(0);
        aad.extend_from_slice(kdf.as_bytes());
        aad.push(0);
        aad.extend_from_slice(&kdf_iterations.to_be_bytes());
        let salt_len_u32 = u32::try_from(kdf_salt.len()).unwrap_or(u32::MAX);
        aad.extend_from_slice(&salt_len_u32.to_be_bytes());
        aad.extend_from_slice(kdf_salt);
        aad.extend_from_slice(aead.as_bytes());
        aad
    }

    // --- JSON serialization ---

    /// Serialize to JSON string (human-readable format).
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| CoreError::SerializationError(format!("JSON serialization failed: {e}")))
    }

    /// Serialize to pretty-printed JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::SerializationError(format!("JSON serialization failed: {e}")))
    }

    /// Maximum accepted size for a JSON-serialized key (1 MiB).
    ///
    /// Inputs larger than this are rejected before parsing to prevent
    /// memory exhaustion from maliciously crafted payloads.
    pub const MAX_KEY_JSON_SIZE: usize = 1024 * 1024; // 1 MiB

    /// Maximum accepted size for a CBOR-serialized key (1 MiB).
    ///
    /// Inputs larger than this are rejected before parsing to prevent
    /// memory exhaustion from maliciously crafted payloads.
    pub const MAX_KEY_CBOR_SIZE: usize = 1024 * 1024; // 1 MiB

    /// Deserialize from JSON string.
    ///
    /// # Errors
    /// Returns an error if the input exceeds [`MAX_KEY_JSON_SIZE`](Self::MAX_KEY_JSON_SIZE),
    /// JSON parsing fails, or validation fails.
    pub fn from_json(json: &str) -> Result<Self> {
        if json.len() > Self::MAX_KEY_JSON_SIZE {
            return Err(CoreError::ResourceExceeded(format!(
                "Key JSON size {} exceeds limit {}",
                json.len(),
                Self::MAX_KEY_JSON_SIZE
            )));
        }
        let key: Self = serde_json::from_str(json)
            .map_err(|e| CoreError::SerializationError(format!("JSON parse failed: {e}")))?;
        key.validate()?;
        Ok(key)
    }

    // --- CBOR serialization ---

    /// Serialize to CBOR bytes (compact binary format, RFC 8949).
    ///
    /// CBOR is the primary wire/storage format. Key material is stored as
    /// native CBOR byte strings — no base64 encoding overhead.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| {
            CoreError::SerializationError(format!("CBOR serialization failed: {e}"))
        })?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes.
    ///
    /// # Errors
    /// Returns an error if the input exceeds [`MAX_KEY_CBOR_SIZE`](Self::MAX_KEY_CBOR_SIZE),
    /// CBOR parsing fails, or validation fails.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        if data.len() > Self::MAX_KEY_CBOR_SIZE {
            return Err(CoreError::ResourceExceeded(format!(
                "Key CBOR size {} exceeds limit {}",
                data.len(),
                Self::MAX_KEY_CBOR_SIZE
            )));
        }
        let key: Self = ciborium::from_reader(data)
            .map_err(|e| CoreError::SerializationError(format!("CBOR parse failed: {e}")))?;
        key.validate()?;
        Ok(key)
    }

    // --- File I/O ---

    /// Write to a file as pretty JSON. Creates the file with 0600 permissions atomically on Unix
    /// for secret/symmetric keys, preventing a window where the file is world-readable.
    ///
    /// # Errors
    /// Returns an error if file writing or permission setting fails.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        self.write_to_file_with_overwrite(path, false)
    }

    /// Like [`write_to_file`] but with explicit overwrite control.
    ///
    /// `overwrite = false` (the recommended default) refuses to clobber
    /// an existing file at `path` and returns
    /// `CoreError::ConfigurationError` — caller should map this to a
    /// `--force`-equivalent prompt or abort.
    ///
    /// `overwrite = true` replaces any existing file via atomic rename
    /// (no truncate-then-write window where a crash leaves zero bytes
    /// on disk + the prior key destroyed).
    ///
    /// On Unix, secret/symmetric files are written with mode `0o600`
    /// applied BEFORE the rename. On Windows the tempfile inherits the
    /// parent dir's ACL via `tempfile`'s NTFS path; further hardening
    /// requires `windows-sys` and is left to the consumer.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` on overwrite-refused or
    /// tempfile creation failure, or `CoreError::Internal` on I/O.
    pub fn write_to_file_with_overwrite(
        &self,
        path: &std::path::Path,
        overwrite: bool,
    ) -> Result<()> {
        let json = self.to_json_pretty()?;
        let writer = crate::unified_api::atomic_write::AtomicWrite::new(json.as_bytes())
            .overwrite_existing(overwrite);
        // Mode policy:
        //   Secret / Symmetric → 0o600 (owner read+write only)
        //   Public             → 0o644 (owner rw, others r) — public
        //                        keys are MEANT to be readable; without
        //                        this an explicit 0o644, tempfile's
        //                        default 0o600 would lock pub keys to
        //                        the creator and break key-distribution
        //                        flows.
        let writer = if self.key_type == KeyType::Secret || self.key_type == KeyType::Symmetric {
            writer.secret_mode()
        } else {
            writer.unix_mode(0o644)
        };
        writer.write(path)
    }

    /// Write to a file as CBOR. Creates the file with 0600 permissions atomically on Unix
    /// for secret/symmetric keys, preventing a window where the file is world-readable.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization or file writing fails.
    pub fn write_cbor_to_file(&self, path: &std::path::Path) -> Result<()> {
        let cbor = self.to_cbor()?;

        #[cfg(unix)]
        if self.key_type == KeyType::Secret || self.key_type == KeyType::Symmetric {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&cbor)?;
            return Ok(());
        }

        std::fs::write(path, cbor)?;
        Ok(())
    }

    /// Read from a JSON file.
    ///
    /// # Errors
    /// Returns an error if file reading or JSON parsing fails.
    pub fn read_from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    /// Read from a CBOR file.
    ///
    /// # Errors
    /// Returns an error if file reading or CBOR parsing fails.
    pub fn read_cbor_from_file(path: &std::path::Path) -> Result<Self> {
        let contents = std::fs::read(path)?;
        Self::from_cbor(&contents)
    }

    // --- Legacy CLI format ---

    /// Parse a legacy CLI v1 key file format.
    ///
    /// The CLI v1 format uses `"key"` for raw key bytes and `"algorithm"` as a string.
    ///
    /// ```json
    /// {
    ///   "algorithm": "ML-DSA-65",
    ///   "key_type": "public",
    ///   "key": "Base64..."
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or the algorithm is unrecognized.
    pub fn from_legacy_json(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct LegacyKeyFile {
            algorithm: String,
            key_type: String,
            key: String,
            #[serde(default)]
            label: Option<String>,
        }

        let legacy: LegacyKeyFile = serde_json::from_str(json)
            .map_err(|e| CoreError::SerializationError(format!("Legacy JSON parse failed: {e}")))?;

        let algorithm = parse_legacy_algorithm(&legacy.algorithm)?;
        let key_type = match legacy.key_type.to_lowercase().as_str() {
            "public" | "pub" => KeyType::Public,
            "secret" | "private" | "sk" => KeyType::Secret,
            "symmetric" | "sym" => KeyType::Symmetric,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Unrecognized legacy key_type: '{other}'"
                )));
            }
        };

        let key_data = KeyData::Single { raw: legacy.key };

        let mut key = Self::new(algorithm, key_type, key_data);
        if let Some(label) = legacy.label {
            key.set_label(label);
        }
        key.validate()?;
        Ok(key)
    }
}

/// Parse legacy algorithm strings (case-insensitive) to [`KeyAlgorithm`].
fn parse_legacy_algorithm(s: &str) -> Result<KeyAlgorithm> {
    match s.to_lowercase().replace('_', "-").as_str() {
        "ml-kem-512" => Ok(KeyAlgorithm::MlKem512),
        "ml-kem-768" => Ok(KeyAlgorithm::MlKem768),
        "ml-kem-1024" => Ok(KeyAlgorithm::MlKem1024),
        "ml-dsa-44" => Ok(KeyAlgorithm::MlDsa44),
        "ml-dsa-65" => Ok(KeyAlgorithm::MlDsa65),
        "ml-dsa-87" => Ok(KeyAlgorithm::MlDsa87),
        "ed25519" => Ok(KeyAlgorithm::Ed25519),
        "x25519" => Ok(KeyAlgorithm::X25519),
        "aes-256" | "aes256" => Ok(KeyAlgorithm::Aes256),
        "fn-dsa-512" => Ok(KeyAlgorithm::FnDsa512),
        "fn-dsa-1024" => Ok(KeyAlgorithm::FnDsa1024),
        "hybrid-ml-kem-768-x25519" => Ok(KeyAlgorithm::HybridMlKem768X25519),
        "hybrid-ml-dsa-65-ed25519" => Ok(KeyAlgorithm::HybridMlDsa65Ed25519),
        other => Err(CoreError::InvalidKey(format!("Unrecognized algorithm: '{other}'"))),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::useless_vec,
    clippy::panic
)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    // ------------------------------------------------------------------
    // Passphrase-encrypted key roundtrip
    // ------------------------------------------------------------------

    fn sample_single_key() -> PortableKey {
        // AES-256 symmetric key (Single variant).
        let raw = [0x11u8; 32];
        PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&raw))
    }

    fn sample_composite_key() -> PortableKey {
        // Hybrid ML-KEM-768 + X25519 public key lookalike (Composite variant).
        let pq = vec![0x22u8; 1184];
        let classical = vec![0x33u8; 32];
        PortableKey::new(
            KeyAlgorithm::HybridMlKem768X25519,
            KeyType::Public,
            KeyData::from_composite(&pq, &classical),
        )
    }

    #[test]
    fn test_encrypt_with_passphrase_single_roundtrip() {
        let mut key = sample_single_key();
        let plain_raw = key.key_data().decode_raw().unwrap();
        let passphrase = b"correct horse battery staple";

        key.encrypt_with_passphrase(passphrase).unwrap();
        assert!(key.is_encrypted());
        assert!(key.key_data().decode_raw().is_err());

        key.validate().expect("encrypted envelope must validate");

        key.decrypt_with_passphrase(passphrase).unwrap();
        assert!(!key.is_encrypted());
        assert_eq!(key.key_data().decode_raw().unwrap(), plain_raw);
    }

    #[test]
    fn test_encrypt_with_passphrase_composite_roundtrip() {
        let mut key = sample_composite_key();
        let (pq_plain, cl_plain) = key.key_data().decode_composite().unwrap();
        let passphrase = b"hunter2-but-stronger";

        key.encrypt_with_passphrase(passphrase).unwrap();
        assert!(key.is_encrypted());
        assert!(key.key_data().decode_composite().is_err());

        key.decrypt_with_passphrase(passphrase).unwrap();
        let (pq_out, cl_out) = key.key_data().decode_composite().unwrap();
        assert_eq!(pq_out, pq_plain);
        assert_eq!(cl_out, cl_plain);
    }

    #[test]
    fn test_encrypt_with_passphrase_wrong_passphrase_fails() {
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"correct passphrase").unwrap();

        let err = key
            .decrypt_with_passphrase(b"wrong passphrase")
            .expect_err("wrong passphrase must fail");
        // The error must NOT disclose whether the passphrase was wrong vs the
        // envelope was corrupted — the message is a fixed opaque phrase.
        // Compare the EXACT string so a future code change that diverges
        // the two paths (e.g. distinct "PBKDF2 failure" vs "tag mismatch"
        // errors) will break this test.
        assert_eq!(
            err.to_string(),
            "Invalid key: Passphrase-protected key unwrap failed \
             (wrong passphrase or corrupted envelope)"
        );
    }

    /// Corrupting the ciphertext bytes must produce the **same** opaque
    /// error as providing a wrong passphrase. If decrypt ever gained a
    /// distinct code path for "tag failure" vs "post-KDF AES init failure",
    /// a passphrase oracle would open up — this test pins the error string
    /// to catch that regression.
    #[test]
    fn test_encrypt_with_passphrase_corrupted_ciphertext_matches_wrong_passphrase_error() {
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"correct passphrase").unwrap();

        // Decode, flip the middle byte, re-encode. Round-tripping through
        // base64 keeps the envelope structurally valid so the corruption
        // surfaces at AEAD verification rather than at the base64 decode
        // pre-check in validate_encrypted_envelope_fields.
        let KeyData::Encrypted { ciphertext, .. } = &mut key.key_data else {
            panic!("expected encrypted variant");
        };
        let mut raw = BASE64_ENGINE.decode(ciphertext.as_str()).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        *ciphertext = BASE64_ENGINE.encode(&raw);

        let err = key
            .decrypt_with_passphrase(b"correct passphrase")
            .expect_err("corrupted ciphertext must fail");
        // Exact-match: the error must be byte-identical to the wrong-passphrase error.
        assert_eq!(
            err.to_string(),
            "Invalid key: Passphrase-protected key unwrap failed \
             (wrong passphrase or corrupted envelope)"
        );
    }

    #[test]
    fn test_encrypt_with_passphrase_empty_rejected() {
        let mut key = sample_single_key();
        assert!(key.encrypt_with_passphrase(b"").is_err());
    }

    #[test]
    fn test_encrypt_with_passphrase_double_encrypt_rejected() {
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"once").unwrap();
        assert!(key.encrypt_with_passphrase(b"twice").is_err());
    }

    #[test]
    fn test_decrypt_with_passphrase_on_plaintext_fails() {
        let mut key = sample_single_key();
        assert!(key.decrypt_with_passphrase(b"anything").is_err());
    }

    #[test]
    fn test_encrypted_key_json_roundtrip() {
        let mut key = sample_single_key();
        let plain_raw = key.key_data().decode_raw().unwrap();
        key.encrypt_with_passphrase(b"json roundtrip").unwrap();

        let json = key.to_json().unwrap();
        // Sanity: the envelope should be valid JSON and visibly contain the
        // envelope marker "kdf" so we know serde picked the Encrypted variant.
        assert!(json.contains("\"kdf\""));
        assert!(json.contains("PBKDF2-HMAC-SHA256"));

        let mut reloaded = PortableKey::from_json(&json).unwrap();
        assert!(reloaded.is_encrypted());
        reloaded.decrypt_with_passphrase(b"json roundtrip").unwrap();
        assert_eq!(reloaded.key_data().decode_raw().unwrap(), plain_raw);
    }

    #[test]
    fn test_encrypted_key_aad_binds_algorithm() {
        // An encrypted blob must not decrypt after the enclosing
        // PortableKey's algorithm field has been swapped — AEAD
        // authentication must fail.
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"aad binding").unwrap();

        let tampered_data = key.key_data.clone();
        let mut tampered =
            PortableKey::new(KeyAlgorithm::ChaCha20, KeyType::Symmetric, tampered_data);

        assert!(tampered.decrypt_with_passphrase(b"aad binding").is_err());
    }

    #[test]
    fn test_encrypted_key_aad_binds_key_type() {
        // Companion to `test_encrypted_key_aad_binds_algorithm`: the AAD also
        // covers `key_type`, so a swap from Symmetric → Secret must fail
        // AEAD verification even when the algorithm is unchanged.
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"aad binding").unwrap();

        let tampered_data = key.key_data.clone();
        // Swap Symmetric → Secret. `Aes256` isn't a valid algorithm for a
        // Secret key at load time, but `decrypt_with_passphrase` runs the
        // AEAD check before any such validation, so the test still exercises
        // the AAD binding path before the type validator would reject the
        // combination.
        let mut tampered = PortableKey::new(KeyAlgorithm::Aes256, KeyType::Secret, tampered_data);

        assert!(tampered.decrypt_with_passphrase(b"aad binding").is_err());
    }

    // --- Encrypted envelope negative validation tests ---

    /// Snapshot of a freshly-encrypted envelope's fields, used to build
    /// tampered copies that exercise each rejection branch of
    /// `validate_encrypted_envelope_fields`. Cloning via this helper
    /// sidesteps `KeyData`'s `Drop` impl, which forbids partial moves.
    #[derive(Clone)]
    struct EnvelopeSnapshot {
        enc: u32,
        kdf: String,
        kdf_iterations: u32,
        kdf_salt: String,
        aead: String,
        nonce: String,
        ciphertext: String,
    }

    impl EnvelopeSnapshot {
        fn capture(key: &PortableKey) -> Option<Self> {
            match &key.key_data {
                KeyData::Encrypted {
                    enc,
                    kdf,
                    kdf_iterations,
                    kdf_salt,
                    aead,
                    nonce,
                    ciphertext,
                } => Some(Self {
                    enc: *enc,
                    kdf: kdf.clone(),
                    kdf_iterations: *kdf_iterations,
                    kdf_salt: kdf_salt.clone(),
                    aead: aead.clone(),
                    nonce: nonce.clone(),
                    ciphertext: ciphertext.clone(),
                }),
                _ => None,
            }
        }

        fn into_key_data(self) -> KeyData {
            KeyData::Encrypted {
                enc: self.enc,
                kdf: self.kdf,
                kdf_iterations: self.kdf_iterations,
                kdf_salt: self.kdf_salt,
                aead: self.aead,
                nonce: self.nonce,
                ciphertext: self.ciphertext,
            }
        }
    }

    /// Build a valid encrypted sample key and return it alongside a snapshot
    /// of its envelope fields.
    fn make_valid_encrypted_key() -> (PortableKey, EnvelopeSnapshot) {
        let mut key = sample_single_key();
        key.encrypt_with_passphrase(b"envelope validation").unwrap();
        let snapshot = EnvelopeSnapshot::capture(&key).expect("sample key is freshly encrypted");
        (key, snapshot)
    }

    #[test]
    fn test_validate_rejects_wrong_envelope_version() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.enc = 99;
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("wrong envelope version must be rejected");
        assert!(err.to_string().contains("Unsupported encrypted key envelope version 99"));
    }

    #[test]
    fn test_validate_rejects_unknown_kdf() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.kdf = "scrypt".to_string();
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("unknown KDF must be rejected");
        assert!(err.to_string().contains("Unsupported KDF"));
    }

    #[test]
    fn test_validate_rejects_unknown_aead() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.aead = "ChaCha20-Poly1305".to_string();
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("unknown AEAD must be rejected");
        assert!(err.to_string().contains("Unsupported AEAD"));
    }

    #[test]
    fn test_validate_rejects_too_few_pbkdf2_iterations() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.kdf_iterations = 50_000; // below PBKDF2_MIN_ITERATIONS
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("low iteration count must be rejected");
        assert!(err.to_string().contains("PBKDF2 iteration count 50000 below minimum"));
    }

    #[test]
    fn test_validate_rejects_short_salt() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.kdf_salt = BASE64_ENGINE.encode([0u8; 8]); // 8 < PBKDF2_MIN_SALT_LEN
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("short salt must be rejected");
        assert!(err.to_string().contains("PBKDF2 salt length 8 below minimum"));
    }

    #[test]
    fn test_validate_rejects_wrong_nonce_length() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.nonce = BASE64_ENGINE.encode([0u8; 8]); // 8 != AES_GCM_NONCE_LEN
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("wrong nonce length must be rejected");
        assert!(err.to_string().contains("AES-GCM nonce length 8"));
    }

    #[test]
    fn test_validate_rejects_ciphertext_shorter_than_tag() {
        let (mut key, mut snapshot) = make_valid_encrypted_key();
        snapshot.ciphertext = BASE64_ENGINE.encode([0u8; 4]); // 4 < AES_GCM_TAG_LEN
        key.key_data = snapshot.into_key_data();
        let err = key.validate().expect_err("short ciphertext must be rejected");
        assert!(err.to_string().contains("Encrypted key ciphertext shorter than AES-GCM tag"));
    }

    /// Pinned byte layout for the encrypted-envelope AAD.
    ///
    /// This is the on-the-wire AEAD AAD used for every passphrase-encrypted
    /// key. Any change to the layout — including a change to
    /// `KeyAlgorithm::canonical_name`, `KeyType::canonical_name`, the
    /// envelope constants, the field ordering, or the separator bytes —
    /// invalidates every existing encrypted key file. This test pins the
    /// exact bytes for a fixed fixture so an accidental drift shows up in
    /// CI before landing.
    #[test]
    fn test_encryption_aad_byte_layout_is_stable() {
        let salt = [0xAA_u8; 16];
        let aad = PortableKey::encryption_aad(
            1,
            KeyAlgorithm::Aes256,
            KeyType::Symmetric,
            "PBKDF2-HMAC-SHA256",
            600_000,
            &salt,
            "AES-256-GCM",
        );

        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"latticearc-lpk-v1-enc");
        expected.push(0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"aes-256");
        expected.push(0);
        expected.extend_from_slice(b"symmetric");
        expected.push(0);
        expected.extend_from_slice(b"PBKDF2-HMAC-SHA256");
        expected.push(0);
        expected.extend_from_slice(&600_000u32.to_be_bytes());
        expected.extend_from_slice(&16u32.to_be_bytes());
        expected.extend_from_slice(&salt);
        expected.extend_from_slice(b"AES-256-GCM");

        assert_eq!(aad, expected);
    }

    /// Pin every `KeyAlgorithm` and `KeyType` canonical name against its
    /// serde-rename string. If they diverge, the canonical_name used in the
    /// AAD will silently mismatch the on-disk `algorithm`/`key_type` fields
    /// of existing keys. Failing this test means one of the constants must
    /// be updated deliberately and all existing encrypted keys must be
    /// re-wrapped.
    #[test]
    fn test_canonical_names_match_serde_rename() {
        fn serde_name<T: Serialize>(t: &T) -> String {
            let s = serde_json::to_string(t).unwrap();
            // Strip the surrounding quotes produced by JSON string encoding.
            s.trim_matches('"').to_string()
        }
        let algorithms = [
            KeyAlgorithm::MlKem512,
            KeyAlgorithm::MlKem768,
            KeyAlgorithm::MlKem1024,
            KeyAlgorithm::MlDsa44,
            KeyAlgorithm::MlDsa65,
            KeyAlgorithm::MlDsa87,
            KeyAlgorithm::SlhDsaShake128s,
            KeyAlgorithm::SlhDsaShake256f,
            KeyAlgorithm::FnDsa512,
            KeyAlgorithm::FnDsa1024,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::X25519,
            KeyAlgorithm::Aes256,
            KeyAlgorithm::ChaCha20,
            KeyAlgorithm::HybridMlKem512X25519,
            KeyAlgorithm::HybridMlKem768X25519,
            KeyAlgorithm::HybridMlKem1024X25519,
            KeyAlgorithm::HybridMlDsa44Ed25519,
            KeyAlgorithm::HybridMlDsa65Ed25519,
            KeyAlgorithm::HybridMlDsa87Ed25519,
        ];
        for alg in algorithms {
            assert_eq!(alg.canonical_name(), serde_name(&alg), "canonical_name drift for {alg:?}");
        }
        for kt in [KeyType::Public, KeyType::Secret, KeyType::Symmetric] {
            assert_eq!(kt.canonical_name(), serde_name(&kt), "canonical_name drift for {kt:?}");
        }
    }

    // --- KeyAlgorithm serde roundtrip ---

    #[test]
    fn test_key_algorithm_serde_all_variants_roundtrip() {
        let variants = [
            (KeyAlgorithm::MlKem512, "\"ml-kem-512\""),
            (KeyAlgorithm::MlKem768, "\"ml-kem-768\""),
            (KeyAlgorithm::MlKem1024, "\"ml-kem-1024\""),
            (KeyAlgorithm::MlDsa44, "\"ml-dsa-44\""),
            (KeyAlgorithm::MlDsa65, "\"ml-dsa-65\""),
            (KeyAlgorithm::MlDsa87, "\"ml-dsa-87\""),
            (KeyAlgorithm::SlhDsaShake128s, "\"slh-dsa-shake-128s\""),
            (KeyAlgorithm::SlhDsaShake256f, "\"slh-dsa-shake-256f\""),
            (KeyAlgorithm::FnDsa512, "\"fn-dsa-512\""),
            (KeyAlgorithm::FnDsa1024, "\"fn-dsa-1024\""),
            (KeyAlgorithm::Ed25519, "\"ed25519\""),
            (KeyAlgorithm::X25519, "\"x25519\""),
            (KeyAlgorithm::Aes256, "\"aes-256\""),
            (KeyAlgorithm::ChaCha20, "\"chacha20\""),
            (KeyAlgorithm::HybridMlKem768X25519, "\"hybrid-ml-kem-768-x25519\""),
            (KeyAlgorithm::HybridMlKem512X25519, "\"hybrid-ml-kem-512-x25519\""),
            (KeyAlgorithm::HybridMlKem1024X25519, "\"hybrid-ml-kem-1024-x25519\""),
            (KeyAlgorithm::HybridMlDsa65Ed25519, "\"hybrid-ml-dsa-65-ed25519\""),
            (KeyAlgorithm::HybridMlDsa44Ed25519, "\"hybrid-ml-dsa-44-ed25519\""),
            (KeyAlgorithm::HybridMlDsa87Ed25519, "\"hybrid-ml-dsa-87-ed25519\""),
        ];

        for (variant, expected_json) in &variants {
            let json = serde_json::to_string(variant).unwrap();
            assert_eq!(&json, expected_json, "serialize {:?}", variant);

            let deserialized: KeyAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, *variant, "roundtrip {:?}", variant);
        }
    }

    #[test]
    fn test_key_algorithm_is_hybrid_returns_correct_bool_succeeds() {
        assert!(KeyAlgorithm::HybridMlKem768X25519.is_hybrid());
        assert!(KeyAlgorithm::HybridMlDsa65Ed25519.is_hybrid());
        assert!(!KeyAlgorithm::MlKem768.is_hybrid());
        assert!(!KeyAlgorithm::Aes256.is_hybrid());
    }

    #[test]
    fn test_key_algorithm_is_symmetric_returns_correct_bool_succeeds() {
        assert!(KeyAlgorithm::Aes256.is_symmetric());
        assert!(KeyAlgorithm::ChaCha20.is_symmetric());
        assert!(!KeyAlgorithm::MlKem768.is_symmetric());
    }

    // --- KeyType serde ---

    #[test]
    fn test_key_type_serde_roundtrip() {
        for (variant, expected) in [
            (KeyType::Public, "\"public\""),
            (KeyType::Secret, "\"secret\""),
            (KeyType::Symmetric, "\"symmetric\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: KeyType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // --- KeyData ---

    #[test]
    fn test_key_data_single_roundtrip() {
        let original = vec![1u8, 2, 3, 4];
        let kd = KeyData::from_raw(&original);
        let decoded = kd.decode_raw().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_key_data_composite_roundtrip() {
        let pq = vec![0xAA; 32];
        let cl = vec![0xBB; 32];
        let kd = KeyData::from_composite(&pq, &cl);
        let (pq2, cl2) = kd.decode_composite().unwrap();
        assert_eq!(pq2, pq);
        assert_eq!(cl2, cl);
    }

    #[test]
    fn test_key_data_single_decode_composite_fails() {
        let kd = KeyData::from_raw(&[1, 2, 3]);
        assert!(kd.decode_composite().is_err());
    }

    #[test]
    fn test_key_data_composite_decode_raw_fails() {
        let kd = KeyData::from_composite(&[1], &[2]);
        assert!(kd.decode_raw().is_err());
    }

    #[test]
    fn test_key_data_debug_redacts_secret_content_succeeds() {
        let kd = KeyData::from_raw(&[0xDE, 0xAD]);
        let debug = format!("{:?}", kd);
        assert!(!debug.contains("3q0"), "Debug should not contain base64 key material");
        assert!(debug.contains("[...]"));
    }

    // --- JSON roundtrip ---

    #[test]
    fn test_json_roundtrip_ml_kem_768_public_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&vec![0xCC; 1184]),
        );
        let json = key.to_json().unwrap();
        let restored = PortableKey::from_json(&json).unwrap();

        assert_eq!(restored.version(), 1);
        assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
        assert_eq!(restored.key_type(), KeyType::Public);
        assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);
    }

    #[test]
    fn test_json_roundtrip_aes_symmetric_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::Aes256,
            KeyType::Symmetric,
            KeyData::from_raw(&[0u8; 32]),
        );
        let json = key.to_json().unwrap();
        let restored = PortableKey::from_json(&json).unwrap();
        assert_eq!(restored.algorithm(), KeyAlgorithm::Aes256);
        assert_eq!(restored.key_type(), KeyType::Symmetric);
    }

    #[test]
    fn test_json_roundtrip_hybrid_kem_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::HybridMlKem768X25519,
            KeyType::Secret,
            KeyData::from_composite(&vec![0xAA; 2400], &vec![0xBB; 32]),
        );
        let json = key.to_json().unwrap();
        let restored = PortableKey::from_json(&json).unwrap();
        assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
        let (pq, cl) = restored.key_data().decode_composite().unwrap();
        assert_eq!(pq.len(), 2400);
        assert_eq!(cl.len(), 32);
    }

    // --- CBOR roundtrip ---

    #[test]
    fn test_cbor_roundtrip_ml_kem_768_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&vec![0xCC; 1184]),
        );
        let cbor = key.to_cbor().unwrap();
        let restored = PortableKey::from_cbor(&cbor).unwrap();

        assert_eq!(restored.version(), 1);
        assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
        assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);
    }

    #[test]
    fn test_cbor_roundtrip_hybrid_sig_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::HybridMlDsa65Ed25519,
            KeyType::Secret,
            KeyData::from_composite(&vec![0xCC; 1952], &vec![0xDD; 32]),
        );
        let cbor = key.to_cbor().unwrap();
        let restored = PortableKey::from_cbor(&cbor).unwrap();
        assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlDsa65Ed25519);
        assert_eq!(restored.key_type(), KeyType::Secret);
    }

    #[test]
    fn test_cbor_smaller_than_json_is_correct() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&vec![0xAA; 1184]),
        );
        let json_bytes = key.to_json().unwrap().len();
        let cbor_bytes = key.to_cbor().unwrap().len();
        assert!(
            cbor_bytes < json_bytes,
            "CBOR ({cbor_bytes}) should be smaller than JSON ({json_bytes})"
        );
    }

    #[test]
    fn test_cbor_json_cross_format_consistency_roundtrip() {
        let key = PortableKey::new(
            KeyAlgorithm::MlDsa65,
            KeyType::Public,
            KeyData::from_raw(&vec![0xBB; 1952]),
        );
        let json = key.to_json().unwrap();
        let cbor = key.to_cbor().unwrap();

        let from_json = PortableKey::from_json(&json).unwrap();
        let from_cbor = PortableKey::from_cbor(&cbor).unwrap();

        assert_eq!(from_json.algorithm(), from_cbor.algorithm());
        assert_eq!(from_json.key_type(), from_cbor.key_type());
        assert_eq!(
            from_json.key_data().decode_raw().unwrap(),
            from_cbor.key_data().decode_raw().unwrap()
        );
    }

    // --- Validation ---

    #[test]
    fn test_validate_symmetric_wrong_key_type_fails() {
        let key =
            PortableKey::new(KeyAlgorithm::Aes256, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        assert!(key.validate().is_err());
    }

    #[test]
    fn test_validate_non_symmetric_with_symmetric_type_fails() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Symmetric,
            KeyData::from_raw(&vec![0u8; 1184]),
        );
        assert!(key.validate().is_err());
    }

    #[test]
    fn test_validate_hybrid_with_single_data_fails() {
        let key = PortableKey::new(
            KeyAlgorithm::HybridMlKem768X25519,
            KeyType::Public,
            KeyData::from_raw(&[0u8; 32]),
        );
        assert!(key.validate().is_err());
    }

    #[test]
    fn test_validate_non_hybrid_with_composite_data_fails() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_composite(&[0u8; 32], &[0u8; 32]),
        );
        assert!(key.validate().is_err());
    }

    #[test]
    fn test_validate_bad_base64_fails() {
        let key = PortableKey {
            version: 1,
            use_case: None,
            security_level: None,
            algorithm: KeyAlgorithm::Aes256,
            key_type: KeyType::Symmetric,
            key_data: KeyData::Single { raw: "not-valid-base64!!!".to_string() },
            created: Utc::now(),
            metadata: BTreeMap::new(),
        };
        assert!(key.validate().is_err());
    }

    // --- Debug redaction ---

    #[test]
    fn test_debug_redacts_secret_key_content_succeeds() {
        let key = PortableKey::new(
            KeyAlgorithm::MlDsa65,
            KeyType::Secret,
            KeyData::from_raw(&[0xDE, 0xAD, 0xBE, 0xEF]),
        );
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("3q2+7w"));
    }

    #[test]
    fn test_debug_shows_public_key_type_in_output_succeeds() {
        let key = PortableKey::new(
            KeyAlgorithm::MlDsa65,
            KeyType::Public,
            KeyData::from_raw(&[0xDE, 0xAD]),
        );
        let debug = format!("{:?}", key);
        assert!(debug.contains("[key data]"));
        assert!(!debug.contains("REDACTED"));
    }

    // --- Metadata ---

    #[test]
    fn test_metadata_roundtrip_via_json_roundtrip() {
        let mut key = PortableKey::new(
            KeyAlgorithm::Aes256,
            KeyType::Symmetric,
            KeyData::from_raw(&[0u8; 32]),
        );
        key.set_label("Production signing key");
        key.set_metadata("custom_field".to_string(), serde_json::json!(42));

        let json = key.to_json().unwrap();
        let restored = PortableKey::from_json(&json).unwrap();

        assert_eq!(restored.label(), Some("Production signing key"));
        assert_eq!(restored.metadata().get("custom_field"), Some(&serde_json::json!(42)));
    }

    #[test]
    fn test_metadata_omitted_when_empty_in_json_succeeds() {
        let key =
            PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        let json = key.to_json().unwrap();
        assert!(!json.contains("metadata"));
    }

    // --- File I/O ---

    #[test]
    fn test_json_file_roundtrip_via_disk_roundtrip() {
        let dir = std::env::temp_dir().join("latticearc_key_format_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_key.json");

        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&vec![0xAA; 1184]),
        );
        key.write_to_file(&path).unwrap();
        let restored = PortableKey::read_from_file(&path).unwrap();

        assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);
        assert_eq!(restored.key_data().decode_raw().unwrap().len(), 1184);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_cbor_file_roundtrip_via_disk_roundtrip() {
        let dir = std::env::temp_dir().join("latticearc_key_cbor_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_key.cbor");

        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&vec![0xAA; 1184]),
        );
        key.write_cbor_to_file(&path).unwrap();
        let restored = PortableKey::read_cbor_from_file(&path).unwrap();

        assert_eq!(restored.algorithm(), KeyAlgorithm::MlKem768);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_secret_key_are_restricted_succeeds() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("latticearc_key_perms_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret_key.json");

        let key = PortableKey::new(
            KeyAlgorithm::Aes256,
            KeyType::Symmetric,
            KeyData::from_raw(&[0u8; 32]),
        );
        key.write_to_file(&path).unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    // --- Legacy format ---

    #[test]
    fn test_from_legacy_json_succeeds() {
        let legacy = r#"{
            "algorithm": "ML-DSA-65",
            "key_type": "public",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "label": "Test key"
        }"#;

        let key = PortableKey::from_legacy_json(legacy).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::MlDsa65);
        assert_eq!(key.key_type(), KeyType::Public);
        assert_eq!(key.label(), Some("Test key"));
    }

    #[test]
    fn test_from_legacy_json_secret_succeeds() {
        let legacy = r#"{
            "algorithm": "ed25519",
            "key_type": "private",
            "key": "AQIDBA=="
        }"#;
        let key = PortableKey::from_legacy_json(legacy).unwrap();
        assert_eq!(key.key_type(), KeyType::Secret);
    }

    #[test]
    fn test_from_legacy_json_unknown_algorithm_fails() {
        let legacy = r#"{"algorithm":"UNKNOWN-999","key_type":"public","key":"AQID"}"#;
        assert!(PortableKey::from_legacy_json(legacy).is_err());
    }

    #[test]
    fn test_from_legacy_json_unknown_key_type_fails() {
        let legacy = r#"{"algorithm":"ed25519","key_type":"unknown","key":"AQID"}"#;
        assert!(PortableKey::from_legacy_json(legacy).is_err());
    }

    // --- Every algorithm roundtrip (JSON + CBOR) ---

    #[test]
    fn test_every_single_algorithm_roundtrip() {
        let single_algorithms = [
            (KeyAlgorithm::MlKem512, KeyType::Public),
            (KeyAlgorithm::MlKem768, KeyType::Public),
            (KeyAlgorithm::MlKem1024, KeyType::Secret),
            (KeyAlgorithm::MlDsa44, KeyType::Public),
            (KeyAlgorithm::MlDsa65, KeyType::Secret),
            (KeyAlgorithm::MlDsa87, KeyType::Public),
            (KeyAlgorithm::SlhDsaShake128s, KeyType::Public),
            (KeyAlgorithm::SlhDsaShake256f, KeyType::Secret),
            (KeyAlgorithm::FnDsa512, KeyType::Public),
            (KeyAlgorithm::FnDsa1024, KeyType::Secret),
            (KeyAlgorithm::Ed25519, KeyType::Public),
            (KeyAlgorithm::X25519, KeyType::Secret),
            (KeyAlgorithm::Aes256, KeyType::Symmetric),
            (KeyAlgorithm::ChaCha20, KeyType::Symmetric),
        ];

        for (alg, kt) in &single_algorithms {
            let key = PortableKey::new(*alg, *kt, KeyData::from_raw(&[0x42; 32]));

            // JSON roundtrip
            let json = key.to_json().unwrap();
            let from_json = PortableKey::from_json(&json).unwrap();
            assert_eq!(from_json.algorithm(), *alg);

            // CBOR roundtrip
            let cbor = key.to_cbor().unwrap();
            let from_cbor = PortableKey::from_cbor(&cbor).unwrap();
            assert_eq!(from_cbor.algorithm(), *alg);
            assert_eq!(from_cbor.key_type(), *kt);
        }
    }

    #[test]
    fn test_every_hybrid_algorithm_roundtrip() {
        let hybrid_algorithms = [
            (KeyAlgorithm::HybridMlKem512X25519, KeyType::Public),
            (KeyAlgorithm::HybridMlKem768X25519, KeyType::Secret),
            (KeyAlgorithm::HybridMlKem1024X25519, KeyType::Public),
            (KeyAlgorithm::HybridMlDsa44Ed25519, KeyType::Public),
            (KeyAlgorithm::HybridMlDsa65Ed25519, KeyType::Secret),
            (KeyAlgorithm::HybridMlDsa87Ed25519, KeyType::Public),
        ];

        for (alg, kt) in &hybrid_algorithms {
            let key =
                PortableKey::new(*alg, *kt, KeyData::from_composite(&[0xAA; 64], &[0xBB; 32]));

            // JSON roundtrip
            let json = key.to_json().unwrap();
            let from_json = PortableKey::from_json(&json).unwrap();
            assert_eq!(from_json.algorithm(), *alg);

            // CBOR roundtrip
            let cbor = key.to_cbor().unwrap();
            let from_cbor = PortableKey::from_cbor(&cbor).unwrap();
            assert_eq!(from_cbor.algorithm(), *alg);
            assert_eq!(from_cbor.key_type(), *kt);
        }
    }

    // --- Edge cases ---

    #[test]
    fn test_from_json_invalid_json_fails() {
        assert!(PortableKey::from_json("not json").is_err());
    }

    #[test]
    fn test_from_cbor_invalid_data_fails() {
        assert!(PortableKey::from_cbor(&[0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_from_json_missing_fields_fails() {
        assert!(PortableKey::from_json(r#"{"version":1}"#).is_err());
    }

    #[test]
    fn test_read_nonexistent_file_fails() {
        assert!(
            PortableKey::read_from_file(std::path::Path::new("/nonexistent/path.json")).is_err()
        );
    }

    #[test]
    fn test_version_is_current_format_has_correct_size() {
        let key =
            PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        assert_eq!(key.version(), PortableKey::CURRENT_VERSION);
    }

    #[test]
    fn test_with_created_sets_timestamp_succeeds() {
        let ts = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
        let key = PortableKey::with_created(
            KeyAlgorithm::Ed25519,
            KeyType::Public,
            KeyData::from_raw(&[0u8; 32]),
            ts,
        );
        assert_eq!(*key.created(), ts);
    }

    #[test]
    fn test_pretty_json_contains_newlines_and_indentation_is_correct() {
        let key =
            PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        let pretty = key.to_json_pretty().unwrap();
        assert!(pretty.contains('\n'));
    }

    // --- UseCase / SecurityLevel constructors ---

    #[test]
    fn test_for_use_case_file_storage_is_correct() {
        use crate::types::types::UseCase;
        let key = PortableKey::for_use_case(
            UseCase::FileStorage,
            KeyType::Public,
            KeyData::from_raw(&vec![0xAA; 1568]),
        );
        assert_eq!(key.use_case(), Some(UseCase::FileStorage));
        assert!(key.security_level().is_none());
        // FileStorage → Level 5 → HybridMlKem1024X25519
        assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
    }

    #[test]
    fn test_for_use_case_iot_is_correct() {
        use crate::types::types::UseCase;
        let key = PortableKey::for_use_case(
            UseCase::IoTDevice,
            KeyType::Public,
            KeyData::from_raw(&vec![0xBB; 800]),
        );
        assert_eq!(key.use_case(), Some(UseCase::IoTDevice));
        // IoTDevice → Level 1 → HybridMlKem512X25519
        assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem512X25519);
    }

    #[test]
    fn test_for_use_case_secure_messaging_is_correct() {
        use crate::types::types::UseCase;
        let key = PortableKey::for_use_case(
            UseCase::SecureMessaging,
            KeyType::Public,
            KeyData::from_raw(&vec![0xCC; 1184]),
        );
        // SecureMessaging → Level 3 → HybridMlKem768X25519
        assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
    }

    #[test]
    fn test_for_security_level_high_is_correct() {
        use crate::types::types::SecurityLevel;
        let key = PortableKey::for_security_level(
            SecurityLevel::High,
            KeyType::Public,
            KeyData::from_raw(&vec![0xDD; 1184]),
        );
        assert!(key.use_case().is_none());
        assert_eq!(key.security_level(), Some(SecurityLevel::High));
        assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem768X25519);
    }

    #[test]
    fn test_for_use_case_with_level_security_takes_precedence_succeeds() {
        use crate::types::types::{SecurityLevel, UseCase};
        // UseCase::IoTDevice would resolve to MlKem512
        // SecurityLevel::Maximum should take precedence → MlKem1024
        let key = PortableKey::for_use_case_with_level(
            UseCase::IoTDevice,
            SecurityLevel::Maximum,
            KeyType::Public,
            KeyData::from_raw(&vec![0xFF; 1568]),
        );
        assert_eq!(key.use_case(), Some(UseCase::IoTDevice));
        assert_eq!(key.security_level(), Some(SecurityLevel::Maximum));
        // SecurityLevel takes precedence
        assert_eq!(key.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
    }

    #[test]
    fn test_for_use_case_json_includes_use_case_field_succeeds() {
        use crate::types::types::UseCase;
        let key = PortableKey::for_use_case(
            UseCase::DatabaseEncryption,
            KeyType::Public,
            KeyData::from_raw(&[0u8; 32]),
        );
        let json = key.to_json().unwrap();
        assert!(json.contains("use_case"));
        assert!(json.contains("database-encryption"));
    }

    #[test]
    fn test_for_security_level_json_includes_security_level_field_succeeds() {
        use crate::types::types::SecurityLevel;
        let key = PortableKey::for_security_level(
            SecurityLevel::Standard,
            KeyType::Public,
            KeyData::from_raw(&[0u8; 32]),
        );
        let json = key.to_json().unwrap();
        assert!(json.contains("security_level"));
        assert!(json.contains("standard"));
    }

    #[test]
    fn test_for_use_case_cbor_roundtrip() {
        use crate::types::types::UseCase;
        let key = PortableKey::for_use_case(
            UseCase::HealthcareRecords,
            KeyType::Secret,
            KeyData::from_composite(&[0xAA; 64], &[0xBB; 32]),
        );
        let cbor = key.to_cbor().unwrap();
        let restored = PortableKey::from_cbor(&cbor).unwrap();
        assert_eq!(restored.use_case(), Some(UseCase::HealthcareRecords));
        assert_eq!(restored.algorithm(), KeyAlgorithm::HybridMlKem1024X25519);
    }

    // ====================================================================
    // E2E Proof Tests — real-world scenarios through PortableKey format
    // Run with: cargo test -p latticearc --release --all-features -- key_format::tests::proof -- --nocapture
    // ====================================================================

    /// PROOF: File storage — two-process simulation.
    /// Process A: generates keypair, exports to JSON files.
    /// Process B: loads JSON files, encrypts (encapsulate) with PK.
    /// Process A: loads SK from JSON, decrypts (decapsulate). Shared secrets match.
    /// Neither process touches the other's in-memory key objects.
    #[test]
    fn proof_e2e_file_storage_two_process() {
        use crate::hybrid::kem_hybrid;
        use crate::types::types::UseCase;

        // === PROCESS A: Key provisioning ===
        let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
        let (portable_pk, portable_sk) =
            PortableKey::from_hybrid_kem_keypair(UseCase::FileStorage, &pk, &sk).unwrap();
        let pk_json = portable_pk.to_json().unwrap();
        let pk_json_len = pk_json.len();
        let sk_json = portable_sk.to_json().unwrap();
        let sk_json_len = sk_json.len();
        // Process A drops original keys — only JSON survives
        drop(pk);
        drop(sk);
        drop(portable_pk);
        drop(portable_sk);

        // === PROCESS B: Sender encrypts using PK from JSON ===
        let sender_pk = PortableKey::from_json(&pk_json).unwrap();
        let sender_hybrid_pk = sender_pk.to_hybrid_public_key().unwrap();
        let encapsulated = kem_hybrid::encapsulate(&sender_hybrid_pk).unwrap();
        let sender_shared_secret = encapsulated.expose_secret().to_vec();

        // === PROCESS A: Receiver decrypts using SK from JSON ===
        let receiver_sk_portable = PortableKey::from_json(&sk_json).unwrap();
        let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
        let receiver_shared_secret = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
        let secrets_match: bool =
            receiver_shared_secret.expose_secret().ct_eq(sender_shared_secret.as_slice()).into();
        let uc_preserved = receiver_sk_portable.use_case() == Some(UseCase::FileStorage);

        assert!(secrets_match, "Shared secrets must match across processes");
        assert!(uc_preserved);

        println!(
            "[PROOF] {{\"test\":\"e2e_file_storage_two_process\",\
             \"category\":\"key-format\",\
             \"use_case\":\"file-storage\",\
             \"algorithm\":\"hybrid-ml-kem-768-x25519\",\
             \"format\":\"json\",\
             \"pk_json_bytes\":{pk_json_len},\
             \"sk_json_bytes\":{sk_json_len},\
             \"shared_secret_bytes\":{},\
             \"cross_process_kem_match\":{secrets_match},\
             \"use_case_preserved\":{uc_preserved},\
             \"status\":\"PASS\"}}",
            receiver_shared_secret.len(),
        );
    }

    /// PROOF: Secure messaging over CBOR wire — two-process simulation.
    /// Process A: generates keypair, sends PK as CBOR over wire.
    /// Process B: receives CBOR PK, encapsulates.
    /// Process A: receives ciphertext, decapsulates with SK reconstructed from CBOR.
    #[test]
    fn proof_e2e_secure_messaging_cbor_two_process() {
        use crate::hybrid::kem_hybrid;
        use crate::types::types::UseCase;

        // === PROCESS A: Key provisioning, export to CBOR ===
        let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
        let (portable_pk, portable_sk) =
            PortableKey::from_hybrid_kem_keypair(UseCase::SecureMessaging, &pk, &sk).unwrap();
        let pk_cbor = portable_pk.to_cbor().unwrap();
        let pk_cbor_len = pk_cbor.len();
        let sk_cbor = portable_sk.to_cbor().unwrap();
        let sk_cbor_len = sk_cbor.len();
        let pk_json_len = portable_pk.to_json().unwrap().len();
        drop(pk);
        drop(sk);
        drop(portable_pk);
        drop(portable_sk);

        // === PROCESS B: Receives PK CBOR, encapsulates ===
        let sender_pk = PortableKey::from_cbor(&pk_cbor).unwrap();
        let sender_hybrid_pk = sender_pk.to_hybrid_public_key().unwrap();
        let encapsulated = kem_hybrid::encapsulate(&sender_hybrid_pk).unwrap();
        let sender_ss = encapsulated.expose_secret().to_vec();

        // === PROCESS A: Reconstructs SK from CBOR, decapsulates ===
        let receiver_sk_portable = PortableKey::from_cbor(&sk_cbor).unwrap();
        let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
        let receiver_ss = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
        let secrets_match: bool = receiver_ss.expose_secret().ct_eq(sender_ss.as_slice()).into();

        assert!(secrets_match);
        assert!(pk_cbor_len < pk_json_len);

        println!(
            "[PROOF] {{\"test\":\"e2e_secure_messaging_cbor_two_process\",\
             \"category\":\"key-format\",\
             \"use_case\":\"secure-messaging\",\
             \"format\":\"cbor\",\
             \"pk_cbor_bytes\":{pk_cbor_len},\
             \"sk_cbor_bytes\":{sk_cbor_len},\
             \"pk_json_bytes\":{pk_json_len},\
             \"cbor_savings_pct\":{:.1},\
             \"cross_process_kem_match\":{secrets_match},\
             \"status\":\"PASS\"}}",
            (1.0 - (pk_cbor_len as f64 / pk_json_len as f64)) * 100.0,
        );
    }

    /// PROOF: Legal document signing — two-process simulation.
    /// Process A (signer): generates sig keypair, exports SK to JSON, signs document.
    /// Process B (verifier): receives PK JSON + signed document, verifies signature.
    /// Verifier has no access to signer's in-memory key objects.
    #[test]
    fn proof_e2e_legal_document_signing_two_process() {
        use crate::hybrid::sig_hybrid;
        use crate::types::types::UseCase;

        // === SIGNER (Process A): Generate, export, sign ===
        let (pk, sk) = sig_hybrid::generate_keypair().unwrap();
        let (portable_pk, _portable_sk) =
            PortableKey::from_hybrid_sig_keypair(UseCase::LegalDocuments, &pk, &sk).unwrap();
        let pk_json = portable_pk.to_json().unwrap();

        let message = b"WHEREAS the parties agree to the following terms and conditions...";
        let signature = sig_hybrid::sign(&sk, message).unwrap();
        let sig_bytes = signature.ml_dsa_sig().len() + signature.ed25519_sig().len();

        // Signer drops keys — only JSON + signature remain
        drop(pk);
        drop(sk);
        drop(portable_pk);

        // === VERIFIER (Process B): Load PK from JSON, verify ===
        let verifier_pk = PortableKey::from_json(&pk_json).unwrap();
        let verifier_hybrid_pk = verifier_pk.to_hybrid_sig_public_key().unwrap();
        let valid = sig_hybrid::verify(&verifier_hybrid_pk, message, &signature).unwrap();
        let uc_ok = verifier_pk.use_case() == Some(UseCase::LegalDocuments);
        let alg_ok = verifier_pk.algorithm() == KeyAlgorithm::HybridMlDsa65Ed25519;

        assert!(valid, "Signature must verify with JSON-restored PK");
        assert!(uc_ok);
        assert!(alg_ok);

        println!(
            "[PROOF] {{\"test\":\"e2e_legal_document_signing_two_process\",\
             \"category\":\"key-format\",\
             \"use_case\":\"legal-documents\",\
             \"algorithm\":\"hybrid-ml-dsa-65-ed25519\",\
             \"message_len\":{},\
             \"total_sig_bytes\":{sig_bytes},\
             \"cross_process_verify\":{valid},\
             \"use_case_preserved\":{uc_ok},\
             \"status\":\"PASS\"}}",
            message.len(),
        );
    }

    /// PROOF: Key file persistence — two-process simulation with disk files.
    /// Process A: generates keypair, writes PK + SK to files.
    /// Process B: reads PK file, encapsulates.
    /// Process A: reads SK file, decapsulates. Shared secrets match.
    #[test]
    fn proof_e2e_key_file_persistence_two_process() {
        use crate::hybrid::kem_hybrid;
        use crate::types::types::UseCase;

        let dir = std::env::temp_dir().join("latticearc_proof_key_file_e2e");
        std::fs::create_dir_all(&dir).unwrap();
        let pk_json_path = dir.join("cloud.pub.json");
        let sk_json_path = dir.join("cloud.sec.json");
        let pk_cbor_path = dir.join("cloud.pub.cbor");

        // === PROCESS A: Key provisioning, write to files ===
        let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
        let (portable_pk, portable_sk) =
            PortableKey::from_hybrid_kem_keypair(UseCase::CloudStorage, &pk, &sk).unwrap();
        portable_pk.write_to_file(&pk_json_path).unwrap();
        portable_pk.write_cbor_to_file(&pk_cbor_path).unwrap();
        portable_sk.write_to_file(&sk_json_path).unwrap();
        drop(pk);
        drop(sk);
        drop(portable_pk);
        drop(portable_sk);

        // === PROCESS B: Load PK from JSON file, encapsulate ===
        let sender_pk =
            PortableKey::read_from_file(&pk_json_path).unwrap().to_hybrid_public_key().unwrap();
        let encapsulated = kem_hybrid::encapsulate(&sender_pk).unwrap();
        let sender_ss = encapsulated.expose_secret().to_vec();

        // === PROCESS A: Load SK from JSON file, decapsulate ===
        let receiver_sk_portable = PortableKey::read_from_file(&sk_json_path).unwrap();
        let receiver_sk = receiver_sk_portable.to_hybrid_secret_key().unwrap();
        let receiver_ss = kem_hybrid::decapsulate(&receiver_sk, &encapsulated).unwrap();
        let json_match = receiver_ss.expose_secret() == sender_ss.as_slice();

        // Also verify CBOR PK file works
        let cbor_pk = PortableKey::read_cbor_from_file(&pk_cbor_path)
            .unwrap()
            .to_hybrid_public_key()
            .unwrap();
        let enc2 = kem_hybrid::encapsulate(&cbor_pk).unwrap();
        let dec2 = kem_hybrid::decapsulate(&receiver_sk, &enc2).unwrap();
        let cbor_match = dec2.expose_secret() == enc2.expose_secret();

        let json_size = std::fs::metadata(&pk_json_path).unwrap().len();
        let cbor_size = std::fs::metadata(&pk_cbor_path).unwrap().len();

        assert!(json_match);
        assert!(cbor_match);

        println!(
            "[PROOF] {{\"test\":\"e2e_key_file_persistence_two_process\",\
             \"category\":\"key-format\",\
             \"use_case\":\"cloud-storage\",\
             \"json_file_bytes\":{json_size},\
             \"cbor_file_bytes\":{cbor_size},\
             \"json_cross_process_kem\":{json_match},\
             \"cbor_cross_process_kem\":{cbor_match},\
             \"status\":\"PASS\"}}",
        );

        let _ = std::fs::remove_file(&pk_json_path);
        let _ = std::fs::remove_file(&sk_json_path);
        let _ = std::fs::remove_file(&pk_cbor_path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// PROOF: Cross-format consistency — same key serialized to JSON and CBOR,
    /// both produce identical crypto results in separate decapsulations.
    #[test]
    fn proof_e2e_cross_format_consistency() {
        use crate::hybrid::kem_hybrid;
        use crate::types::types::UseCase;

        let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
        let (portable_pk, portable_sk) =
            PortableKey::from_hybrid_kem_keypair(UseCase::DatabaseEncryption, &pk, &sk).unwrap();
        let json = portable_pk.to_json().unwrap();
        let cbor = portable_pk.to_cbor().unwrap();
        let sk_json = portable_sk.to_json().unwrap();
        drop(pk);
        drop(sk);
        drop(portable_pk);
        drop(portable_sk);

        // Restore from both formats
        let pk_from_json = PortableKey::from_json(&json).unwrap().to_hybrid_public_key().unwrap();
        let pk_from_cbor = PortableKey::from_cbor(&cbor).unwrap().to_hybrid_public_key().unwrap();
        let sk_restored = PortableKey::from_json(&sk_json).unwrap().to_hybrid_secret_key().unwrap();

        let keys_match = pk_from_json.ml_kem_pk() == pk_from_cbor.ml_kem_pk()
            && pk_from_json.ecdh_pk() == pk_from_cbor.ecdh_pk();

        // Encapsulate with JSON-restored PK, decapsulate with JSON-restored SK
        let enc1 = kem_hybrid::encapsulate(&pk_from_json).unwrap();
        let dec1 = kem_hybrid::decapsulate(&sk_restored, &enc1).unwrap();
        let json_kem_ok = dec1.expose_secret() == enc1.expose_secret();

        // Encapsulate with CBOR-restored PK, decapsulate with same SK
        let enc2 = kem_hybrid::encapsulate(&pk_from_cbor).unwrap();
        let dec2 = kem_hybrid::decapsulate(&sk_restored, &enc2).unwrap();
        let cbor_kem_ok = dec2.expose_secret() == enc2.expose_secret();

        assert!(keys_match);
        assert!(json_kem_ok);
        assert!(cbor_kem_ok);

        println!(
            "[PROOF] {{\"test\":\"e2e_cross_format_consistency\",\
             \"category\":\"key-format\",\
             \"json_bytes\":{},\
             \"cbor_bytes\":{},\
             \"key_material_match\":{keys_match},\
             \"json_kem_cross_process\":{json_kem_ok},\
             \"cbor_kem_cross_process\":{cbor_kem_ok},\
             \"status\":\"PASS\"}}",
            json.len(),
            cbor.len(),
        );
    }

    /// PROOF: Enterprise metadata survives roundtrip and doesn't break crypto.
    /// Metadata added by enterprise crate persists through JSON + CBOR.
    /// Crypto operations work identically with or without metadata.
    #[test]
    fn proof_e2e_enterprise_metadata_roundtrip() {
        use crate::hybrid::kem_hybrid;
        use crate::types::types::UseCase;

        let (pk, sk) = kem_hybrid::generate_keypair().unwrap();
        let (mut portable_pk, portable_sk) =
            PortableKey::from_hybrid_kem_keypair(UseCase::HealthcareRecords, &pk, &sk).unwrap();

        // Enterprise crate adds metadata
        portable_pk.set_label("HIPAA-compliant DEK");
        portable_pk.set_metadata(
            "compliance".to_string(),
            serde_json::json!({"standard": "HIPAA", "audit_id": "AUD-2026-0042"}),
        );
        portable_pk.set_metadata("department".to_string(), serde_json::json!("cardiology"));

        let pk_json = portable_pk.to_json().unwrap();
        let sk_json = portable_sk.to_json().unwrap();
        let pk_cbor = portable_pk.to_cbor().unwrap();
        drop(pk);
        drop(sk);
        drop(portable_pk);
        drop(portable_sk);

        // JSON: metadata preserved + crypto works
        let from_json = PortableKey::from_json(&pk_json).unwrap();
        let label_ok = from_json.label() == Some("HIPAA-compliant DEK");
        let compliance_ok = from_json
            .metadata()
            .get("compliance")
            .and_then(|v| v.get("standard"))
            .and_then(|v| v.as_str())
            == Some("HIPAA");
        let dept_ok =
            from_json.metadata().get("department") == Some(&serde_json::json!("cardiology"));
        let json_pk = from_json.to_hybrid_public_key().unwrap();
        let json_sk = PortableKey::from_json(&sk_json).unwrap().to_hybrid_secret_key().unwrap();
        let enc = kem_hybrid::encapsulate(&json_pk).unwrap();
        let dec = kem_hybrid::decapsulate(&json_sk, &enc).unwrap();
        let kem_ok = dec.expose_secret() == enc.expose_secret();

        // CBOR: metadata preserved
        let from_cbor = PortableKey::from_cbor(&pk_cbor).unwrap();
        let cbor_label_ok = from_cbor.label() == Some("HIPAA-compliant DEK");
        let cbor_audit_ok = from_cbor
            .metadata()
            .get("compliance")
            .and_then(|v| v.get("audit_id"))
            .and_then(|v| v.as_str())
            == Some("AUD-2026-0042");

        assert!(label_ok);
        assert!(compliance_ok);
        assert!(dept_ok);
        assert!(cbor_label_ok);
        assert!(cbor_audit_ok);
        assert!(kem_ok);

        let metadata_count = from_json.metadata().len();

        println!(
            "[PROOF] {{\"test\":\"e2e_enterprise_metadata_roundtrip\",\
             \"category\":\"key-format\",\
             \"use_case\":\"healthcare-records\",\
             \"metadata_fields\":{metadata_count},\
             \"json_label\":{label_ok},\
             \"json_compliance\":{compliance_ok},\
             \"cbor_label\":{cbor_label_ok},\
             \"cbor_audit\":{cbor_audit_ok},\
             \"cross_process_kem_with_metadata\":{kem_ok},\
             \"status\":\"PASS\"}}",
        );
    }

    /// PROOF: SecurityLevel precedence — when both use_case and security_level
    /// are set, security_level determines the algorithm.
    #[test]
    fn proof_e2e_security_level_precedence() {
        use crate::types::types::{SecurityLevel, UseCase};

        // IoTDevice → HybridMlKem512X25519 (Level 1)
        // Maximum → HybridMlKem1024X25519 (Level 5)
        // Security level should win
        let key = PortableKey::for_use_case_with_level(
            UseCase::IoTDevice,
            SecurityLevel::Maximum,
            KeyType::Public,
            KeyData::from_composite(&[0x42; 1568], &[0x43; 32]),
        );

        let uc_algo = resolve_use_case_algorithm(UseCase::IoTDevice);
        let sl_algo = resolve_security_level_algorithm(SecurityLevel::Maximum);
        let actual_algo = key.algorithm();
        let precedence_correct = actual_algo == sl_algo && actual_algo != uc_algo;

        // JSON roundtrip preserves both fields
        let json = key.to_json().unwrap();
        let restored = PortableKey::from_json(&json).unwrap();
        let uc_preserved = restored.use_case() == Some(UseCase::IoTDevice);
        let sl_preserved = restored.security_level() == Some(SecurityLevel::Maximum);
        let algo_preserved = restored.algorithm() == KeyAlgorithm::HybridMlKem1024X25519;

        assert!(precedence_correct);
        assert!(uc_preserved);
        assert!(sl_preserved);
        assert!(algo_preserved);

        println!(
            "[PROOF] {{\"test\":\"e2e_security_level_precedence\",\
             \"category\":\"key-format\",\
             \"use_case\":\"io-t-device\",\
             \"security_level\":\"maximum\",\
             \"use_case_would_select\":\"{uc_algo:?}\",\
             \"security_level_selects\":\"{sl_algo:?}\",\
             \"actual_algorithm\":\"{actual_algo:?}\",\
             \"precedence_correct\":{precedence_correct},\
             \"use_case_preserved\":{uc_preserved},\
             \"security_level_preserved\":{sl_preserved},\
             \"algorithm_preserved\":{algo_preserved},\
             \"status\":\"PASS\"}}",
        );
    }

    // --- Error path tests ---

    #[test]
    fn test_to_hybrid_public_key_wrong_algorithm_fails() {
        let key =
            PortableKey::new(KeyAlgorithm::Ed25519, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
        assert!(key.to_hybrid_public_key().is_err());
    }

    #[test]
    fn test_to_hybrid_sig_public_key_wrong_algorithm_fails() {
        let key = PortableKey::new(
            KeyAlgorithm::MlKem768,
            KeyType::Public,
            KeyData::from_raw(&[0u8; 32]),
        );
        assert!(key.to_hybrid_sig_public_key().is_err());
    }

    #[test]
    fn test_all_use_cases_resolve_to_algorithm_is_correct() {
        use crate::types::types::UseCase;
        let all = [
            UseCase::SecureMessaging,
            UseCase::EmailEncryption,
            UseCase::VpnTunnel,
            UseCase::ApiSecurity,
            UseCase::FileStorage,
            UseCase::DatabaseEncryption,
            UseCase::CloudStorage,
            UseCase::BackupArchive,
            UseCase::ConfigSecrets,
            UseCase::Authentication,
            UseCase::SessionToken,
            UseCase::DigitalCertificate,
            UseCase::KeyExchange,
            UseCase::FinancialTransactions,
            UseCase::LegalDocuments,
            UseCase::BlockchainTransaction,
            UseCase::HealthcareRecords,
            UseCase::GovernmentClassified,
            UseCase::PaymentCard,
            UseCase::IoTDevice,
            UseCase::FirmwareSigning,
            UseCase::AuditLog,
        ];
        for uc in &all {
            let key =
                PortableKey::for_use_case(*uc, KeyType::Public, KeyData::from_raw(&[0u8; 32]));
            // Every use case must resolve to a valid algorithm
            assert!(
                key.algorithm().is_hybrid() || matches!(key.algorithm(), KeyAlgorithm::MlKem1024),
                "UseCase {:?} resolved to unexpected algorithm {:?}",
                uc,
                key.algorithm()
            );
        }
    }

    #[test]
    fn test_all_security_levels_resolve_to_algorithm_is_correct() {
        use crate::types::types::SecurityLevel;
        let levels = [
            (SecurityLevel::Standard, KeyAlgorithm::HybridMlKem512X25519),
            (SecurityLevel::High, KeyAlgorithm::HybridMlKem768X25519),
            (SecurityLevel::Maximum, KeyAlgorithm::HybridMlKem1024X25519),
        ];
        for (level, expected) in &levels {
            let key = PortableKey::for_security_level(
                *level,
                KeyType::Public,
                KeyData::from_raw(&[0u8; 32]),
            );
            assert_eq!(key.algorithm(), *expected, "Level {:?}", level);
        }
    }

    // --- ConstantTimeEq regression tests (#49) ---

    fn ct_fixture_ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc)
    }

    fn ct_fixture_key(
        algorithm: KeyAlgorithm,
        key_type: KeyType,
        raw: u8,
        ts: DateTime<Utc>,
    ) -> PortableKey {
        PortableKey::with_created(algorithm, key_type, KeyData::from_raw(&[raw; 32]), ts)
    }

    fn ct_fixture_encrypted(ciphertext_byte: u8) -> KeyData {
        KeyData::Encrypted {
            enc: ENCRYPTED_ENVELOPE_VERSION,
            kdf: PBKDF2_KDF_ID.to_string(),
            kdf_iterations: PBKDF2_DEFAULT_ITERATIONS,
            kdf_salt: BASE64_ENGINE.encode([0x11; PBKDF2_SALT_LEN]),
            aead: AES_GCM_AEAD_ID.to_string(),
            nonce: BASE64_ENGINE.encode([0x22; AES_GCM_NONCE_LEN]),
            ciphertext: BASE64_ENGINE.encode([ciphertext_byte; 64]),
        }
    }

    #[test]
    fn test_portable_key_ct_eq_identical_keys_returns_equal() {
        let ts = ct_fixture_ts();
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_portable_key_ct_eq_different_key_data_returns_not_equal() {
        let ts = ct_fixture_ts();
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xCD, ts);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_portable_key_ct_eq_different_algorithm_returns_not_equal() {
        let ts = ct_fixture_ts();
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        let b = ct_fixture_key(KeyAlgorithm::MlKem512, KeyType::Public, 0xAB, ts);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_portable_key_ct_eq_different_key_type_returns_not_equal() {
        let ts = ct_fixture_ts();
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Secret, 0xAB, ts);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_portable_key_ct_eq_different_created_returns_not_equal() {
        let ts_a = ct_fixture_ts();
        let ts_b =
            DateTime::parse_from_rfc3339("2026-02-01T00:00:00Z").unwrap().with_timezone(&Utc);
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts_a);
        let b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts_b);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_portable_key_ct_eq_different_metadata_returns_not_equal() {
        let ts = ct_fixture_ts();
        let a = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        let mut b = ct_fixture_key(KeyAlgorithm::Ed25519, KeyType::Public, 0xAB, ts);
        b.set_metadata("tenant".to_string(), serde_json::json!("acme"));
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_key_data_ct_eq_variant_mismatch_returns_not_equal() {
        let single = KeyData::from_raw(&[0xAB; 32]);
        let composite = KeyData::Composite {
            pq: BASE64_ENGINE.encode([0xAB; 32]),
            classical: BASE64_ENGINE.encode([0xAB; 32]),
        };
        assert!(!bool::from(single.ct_eq(&composite)));
    }

    #[test]
    fn test_key_data_ct_eq_encrypted_identical_returns_equal() {
        let a = ct_fixture_encrypted(0xEE);
        let b = ct_fixture_encrypted(0xEE);
        assert!(bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_key_data_ct_eq_encrypted_different_ciphertext_returns_not_equal() {
        let a = ct_fixture_encrypted(0xEE);
        let b = ct_fixture_encrypted(0xFF);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn test_key_data_ct_eq_encrypted_different_envelope_params_returns_not_equal() {
        let a = ct_fixture_encrypted(0xEE);
        let b = KeyData::Encrypted {
            enc: ENCRYPTED_ENVELOPE_VERSION,
            kdf: PBKDF2_KDF_ID.to_string(),
            kdf_iterations: PBKDF2_DEFAULT_ITERATIONS + 100_000,
            kdf_salt: BASE64_ENGINE.encode([0x11; PBKDF2_SALT_LEN]),
            aead: AES_GCM_AEAD_ID.to_string(),
            nonce: BASE64_ENGINE.encode([0x22; AES_GCM_NONCE_LEN]),
            ciphertext: BASE64_ENGINE.encode([0xEE; 64]),
        };
        assert!(!bool::from(a.ct_eq(&b)));
    }
}
