//! `KeyAlgorithm`: the cryptographic algorithm identifier enum, its
//! canonical wire-name mappings, and its conversions to/from the
//! primitive-layer security-level / parameter-set types.

use serde::{Deserialize, Serialize};

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
    //
    // Only the "small" (`s`) parameter sets are exposed; the `f` (fast)
    // variants are FIPS-defined but not currently implemented by the
    // `fips205` backend.
    /// SLH-DSA-SHAKE-128s (FIPS 205, Category 1).
    #[serde(rename = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-192s (FIPS 205, Category 3).
    #[serde(rename = "slh-dsa-shake-192s")]
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-256s (FIPS 205, Category 5).
    #[serde(rename = "slh-dsa-shake-256s")]
    SlhDsaShake256s,

    // --- Lattice signatures (draft FIPS 206) ---
    /// FN-DSA-512 (draft FIPS 206)
    #[serde(rename = "fn-dsa-512")]
    FnDsa512,
    /// FN-DSA-1024 (draft FIPS 206)
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

    // --- Classical (appended post-0.8.3 to preserve prior discriminants) ---
    /// secp256k1 ECDSA / Schnorr signature key.
    ///
    /// Used by Bitcoin, Ethereum, the LatticeArc ZKP dimension, and other
    /// blockchain-adjacent contexts. **Not a NIST-categorised algorithm**;
    /// [`nist_security_level`](Self::nist_security_level) approximates the
    /// ~128-bit classical strength of the curve. Quantum-vulnerable.
    #[serde(rename = "secp256k1")]
    Secp256k1,
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
    fn try_from(alg: KeyAlgorithm) -> Result<Self, Self::Error> {
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
    fn try_from(alg: KeyAlgorithm) -> Result<Self, Self::Error> {
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
                | Self::SlhDsaShake192s
                | Self::SlhDsaShake256s
                | Self::FnDsa512
                | Self::FnDsa1024
                | Self::Secp256k1
                | Self::HybridMlDsa44Ed25519
                | Self::HybridMlDsa65Ed25519
                | Self::HybridMlDsa87Ed25519
        )
    }

    /// NIST security level for this algorithm.
    ///
    /// Used by [`PortableKey::new`](super::PortableKey::new) to satisfy the documented invariant
    /// that every wire-format key carries either a `use_case` or a
    /// `security_level`.
    ///
    /// PQC parameter sets follow FIPS 203/204/205/206 directly. Classical
    /// algorithms (Ed25519, X25519) map to `Standard` by their classical
    /// 128-bit-equivalent strength. Symmetric primitives (AES-256,
    /// ChaCha20) map to `Maximum` by post-Grover security margin —
    /// ChaCha20 is not NIST-categorised and is approximated here for
    /// internal bookkeeping only.
    #[must_use]
    pub fn nist_security_level(self) -> crate::types::types::SecurityLevel {
        use crate::types::types::SecurityLevel;
        match self {
            Self::MlKem512
            | Self::MlDsa44
            | Self::SlhDsaShake128s
            | Self::FnDsa512
            | Self::Ed25519
            | Self::X25519
            | Self::Secp256k1
            | Self::HybridMlKem512X25519
            | Self::HybridMlDsa44Ed25519 => SecurityLevel::Standard,

            Self::MlKem768
            | Self::MlDsa65
            | Self::SlhDsaShake192s
            | Self::HybridMlKem768X25519
            | Self::HybridMlDsa65Ed25519 => SecurityLevel::High,

            Self::MlKem1024
            | Self::MlDsa87
            | Self::SlhDsaShake256s
            | Self::FnDsa1024
            | Self::Aes256
            | Self::ChaCha20
            | Self::HybridMlKem1024X25519
            | Self::HybridMlDsa87Ed25519 => SecurityLevel::Maximum,
        }
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
            Self::SlhDsaShake192s => "slh-dsa-shake-192s",
            Self::SlhDsaShake256s => "slh-dsa-shake-256s",
            Self::FnDsa512 => "fn-dsa-512",
            Self::FnDsa1024 => "fn-dsa-1024",
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::Aes256 => "aes-256",
            Self::ChaCha20 => "chacha20",
            Self::Secp256k1 => "secp256k1",
            Self::HybridMlKem768X25519 => "hybrid-ml-kem-768-x25519",
            Self::HybridMlKem512X25519 => "hybrid-ml-kem-512-x25519",
            Self::HybridMlKem1024X25519 => "hybrid-ml-kem-1024-x25519",
            Self::HybridMlDsa65Ed25519 => "hybrid-ml-dsa-65-ed25519",
            Self::HybridMlDsa44Ed25519 => "hybrid-ml-dsa-44-ed25519",
            Self::HybridMlDsa87Ed25519 => "hybrid-ml-dsa-87-ed25519",
        }
    }

    /// Inverse of [`canonical_name`](Self::canonical_name): parse a wire
    /// name back into its variant. Case-insensitive; underscores are
    /// folded to hyphens; common aliases (e.g. `aes256`, `chacha20-poly1305`)
    /// are accepted.
    ///
    /// Returns `None` for unrecognized inputs. Used by the CLI keyfile
    /// parser and by `from_legacy_json` so both sites share one source
    /// of truth — when a new variant is added, this match is the only
    /// place that needs an arm.
    #[must_use]
    pub fn from_canonical_name(name: &str) -> Option<Self> {
        match name.to_lowercase().replace('_', "-").as_str() {
            "ml-kem-512" => Some(Self::MlKem512),
            "ml-kem-768" => Some(Self::MlKem768),
            "ml-kem-1024" => Some(Self::MlKem1024),
            "ml-dsa-44" => Some(Self::MlDsa44),
            "ml-dsa-65" => Some(Self::MlDsa65),
            "ml-dsa-87" => Some(Self::MlDsa87),
            "slh-dsa-shake-128s" => Some(Self::SlhDsaShake128s),
            "slh-dsa-shake-192s" => Some(Self::SlhDsaShake192s),
            "slh-dsa-shake-256s" => Some(Self::SlhDsaShake256s),
            // Bare "fn-dsa" is a earlier legacy alias that the
            // unified-API dispatch already accepts as Level512. Accept
            // it here too so round-tripping legacy keys through the
            // shared `from_canonical_name` path works at the keyfile
            // boundary as well.
            "fn-dsa" | "fn-dsa-512" => Some(Self::FnDsa512),
            "fn-dsa-1024" => Some(Self::FnDsa1024),
            "ed25519" => Some(Self::Ed25519),
            "x25519" => Some(Self::X25519),
            "aes-256" | "aes256" => Some(Self::Aes256),
            "chacha20" | "chacha20-poly1305" => Some(Self::ChaCha20),
            "secp256k1" => Some(Self::Secp256k1),
            "hybrid-ml-kem-512-x25519" => Some(Self::HybridMlKem512X25519),
            "hybrid-ml-kem-768-x25519" => Some(Self::HybridMlKem768X25519),
            "hybrid-ml-kem-1024-x25519" => Some(Self::HybridMlKem1024X25519),
            "hybrid-ml-dsa-44-ed25519" => Some(Self::HybridMlDsa44Ed25519),
            "hybrid-ml-dsa-65-ed25519" => Some(Self::HybridMlDsa65Ed25519),
            "hybrid-ml-dsa-87-ed25519" => Some(Self::HybridMlDsa87Ed25519),
            _ => None,
        }
    }
}
