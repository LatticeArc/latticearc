//! Domain Separation Constants for HKDF
//!
//! This module provides domain separation strings used in HKDF key derivation
//! to ensure cryptographic isolation between different cryptographic operations.
//!
//! Domain separation prevents key reuse across different protocols and ensures
//! that keys derived for one purpose cannot be used for another.

/// Domain for hybrid KEM key derivation.
///
/// Used when deriving keys from hybrid key encapsulation mechanisms
/// combining X25519 classical key exchange with ML-KEM-1024 post-quantum KEM.
pub const HYBRID_KEM: &[u8] = b"LatticeArc-v1-HybridKEM-X25519-MLKEM1024";

/// Domain for cascaded encryption outer layer.
///
/// Used for the outer encryption layer when applying cascaded encryption
/// with ChaCha20-Poly1305 for defense in depth.
pub const CASCADE_OUTER: &[u8] = b"LatticeArc-v1-Cascade-ChaCha20Poly1305";

/// Domain for cascaded encryption inner layer.
///
/// Used for the inner encryption layer when applying cascaded encryption
/// with AES-256-GCM for defense in depth.
pub const CASCADE_INNER: &[u8] = b"LatticeArc-v1-Cascade-AES256GCM";

/// Domain for signature binding.
///
/// Used when binding dual signatures combining Ed25519 classical signatures
/// with ML-DSA-87 post-quantum signatures for hybrid authentication.
pub const SIGNATURE_BIND: &[u8] = b"LatticeArc-v1-DualSignature-Ed25519-MlDsa87";

/// Domain string for HPKE-style hybrid encryption HKDF info field.
///
/// Used as the default `info` argument when `derive_encryption_key` is
/// called without a caller-supplied `HybridEncryptionContext`. Binds all
/// derived AES-256 keys to the "hybrid encryption" protocol so that the same
/// KEM shared secret cannot be repurposed for a different HKDF info.
pub const HYBRID_ENCRYPTION_INFO: &[u8] = b"LatticeArc-Hybrid-Encryption-v1";

/// Domain string mixed into the final HKDF pass of `derive_hybrid_shared_secret`.
///
/// Appended to the `(ML-KEM shared secret || ECDH shared secret)` IKM so the
/// resulting 64-byte hybrid secret is bound to this specific construction.
///
/// **Versioning:** the `-v1` suffix is mandatory and matches every other
/// domain label in this module. A future v2 hybrid combiner (different
/// component KEMs, different KDF chain, etc.) MUST bump this to `-v2` so
/// the same component keys cannot derive identical hybrid secrets across
/// versions. Changing this label invalidates every previously derived
/// hybrid secret.
pub const HYBRID_KEM_SS_INFO: &[u8] = b"LatticeArc-Hybrid-KEM-SS-v1";

/// Domain for convenience API `derive_key` HKDF calls.
///
/// Binds derived keys from the convenience layer to the LatticeArc crate
/// so that the same password/salt pair cannot collide with other callers.
pub const DERIVE_KEY_INFO: &[u8] = b"LatticeArc-DeriveKey-v1";

/// HMAC key used by the FIPS 140-3 module integrity self-test.
///
/// This is NOT a secret — it is a public, fixed label that binds the module
/// integrity check to the LatticeArc crate identity per FIPS 140-3 §7.10.2.
pub const MODULE_INTEGRITY_HMAC_KEY: &[u8] = b"LatticeArc-FIPS-140-3-Module-Integrity-Key-v1";

/// Domain for PQ-KEM convenience API HKDF key derivation.
///
/// Used in `encrypt_pq_ml_kem_internal` / `decrypt_pq_ml_kem_internal` to derive
/// AES-256 keys from ML-KEM shared secrets with domain separation.
pub const PQ_KEM_AEAD_KEY_INFO: &[u8] = b"LatticeArc-PqKem-AeadKey-v1";

/// Domain for PQ-only unified API encryption HKDF key derivation.
///
/// Used in `encrypt_pq_only` / `decrypt_pq_only` to derive AES-256 keys from
/// ML-KEM shared secrets. Distinct from [`PQ_KEM_AEAD_KEY_INFO`] because
/// the unified API produces structured `EncryptedOutput` (separate nonce/tag/ciphertext
/// fields), while the convenience API produces a concatenated wire format.
pub const PQ_ONLY_ENCRYPTION_INFO: &[u8] = b"LatticeArc-PqOnly-Encryption-v1";

/// Domain-separation label tag for [`hkdf_kem_info`].
///
/// Closed enum — only crate-controlled labels can be passed to the
/// HKDF info builder, so a future caller cannot accidentally pass an
/// arbitrary `&[u8]` containing `0x00` and break the NUL-separator
/// disambiguation in [`hkdf_kem_info`]. The tests below assert each
/// variant maps to a NUL-free byte string, locking the invariant the
/// separator depends on.
#[derive(Clone, Copy, Debug)]
pub(crate) enum HkdfKemLabel {
    /// `pq_kem` convenience-API AEAD key derivation
    /// → [`PQ_KEM_AEAD_KEY_INFO`].
    PqKemAead,
    /// `pq_only` hybrid-module encryption derivation
    /// → [`PQ_ONLY_ENCRYPTION_INFO`].
    PqOnlyEncryption,
}

impl HkdfKemLabel {
    /// Map the variant to its canonical NUL-free domain-separation
    /// byte string. The set of permitted labels is closed by this
    /// match arm — adding a new variant requires reviewer attention
    /// here.
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::PqKemAead => PQ_KEM_AEAD_KEY_INFO,
            Self::PqOnlyEncryption => PQ_ONLY_ENCRYPTION_INFO,
        }
    }
}

/// Build the HKDF `info` string used by KEM-derived AEAD key derivations.
///
/// Encodes `label || 0x00 || kem_ciphertext` — binding the KEM
/// ciphertext into the per-message AEAD key derivation per RFC 9180
/// §5.1 (HPKE channel binding). Without this binding, an adversary who
/// finds two KEM ciphertexts that decapsulate to the same shared
/// secret could swap them on the wire and the AEAD tag would still
/// pass.
///
/// Used by both [`crate::hybrid::pq_only`] and
/// [`crate::unified_api::convenience::pq_kem`]. A single canonical
/// helper avoids encrypt/decrypt drift between the two paths and
/// guarantees they agree byte-for-byte on the channel-binding
/// transcript.
///
/// The label is a closed [`HkdfKemLabel`] enum rather than `&[u8]` so
/// callers cannot accidentally pass a NUL-containing byte string,
/// which would break the `0x00` separator's disambiguation guarantee
/// (post-85e2bd79e L2 audit fix — closes the structural footgun
/// against future internal callers).
pub(crate) fn hkdf_kem_info(label: HkdfKemLabel, kem_ciphertext: &[u8]) -> Vec<u8> {
    let label_bytes = label.as_bytes();
    // saturating_add avoids the workspace `clippy::arithmetic_side_effects`
    // lint; in practice neither term ever approaches `usize::MAX`.
    let cap = label_bytes.len().saturating_add(1).saturating_add(kem_ciphertext.len());
    let mut info = Vec::with_capacity(cap);
    info.extend_from_slice(label_bytes);
    info.push(0x00); // domain separator between label and binding payload
    info.extend_from_slice(kem_ciphertext);
    info
}

#[cfg(test)]
mod hkdf_kem_label_tests {
    use super::*;

    /// Locks the NUL-freeness invariant the `0x00` separator depends
    /// on. Adding a new `HkdfKemLabel` variant whose byte string
    /// contains `0x00` would break the separator's disambiguation
    /// guarantee — this test catches that at CI time. See L2 audit
    /// fix in [`hkdf_kem_info`].
    #[test]
    fn all_label_variants_are_nul_free() {
        for label in [HkdfKemLabel::PqKemAead, HkdfKemLabel::PqOnlyEncryption] {
            let bytes = label.as_bytes();
            assert!(
                !bytes.contains(&0u8),
                "HkdfKemLabel::{:?} maps to a byte string containing 0x00 \
                 ({:?}) — this breaks the NUL separator in hkdf_kem_info",
                label,
                bytes,
            );
        }
    }
}

// Formal verification with Kani
#[cfg(kani)]
#[allow(clippy::indexing_slicing)]
mod kani_proofs {
    use super::*;

    /// Proves all 10 HKDF domain constants are pairwise distinct (C(10,2)=45 pairs).
    /// Security: collision would cause key reuse across protocols (NIST SP 800-108).
    #[kani::proof]
    fn domain_constants_pairwise_distinct() {
        let constants: &[&[u8]] = &[
            HYBRID_KEM,
            CASCADE_OUTER,
            CASCADE_INNER,
            SIGNATURE_BIND,
            HYBRID_ENCRYPTION_INFO,
            HYBRID_KEM_SS_INFO,
            DERIVE_KEY_INFO,
            MODULE_INTEGRITY_HMAC_KEY,
            PQ_KEM_AEAD_KEY_INFO,
            PQ_ONLY_ENCRYPTION_INFO,
        ];
        let n = constants.len();
        let mut i = 0;
        while i < n {
            let mut j = i + 1;
            while j < n {
                kani::assert(
                    constants[i] != constants[j],
                    "All HKDF domain constants must be pairwise distinct",
                );
                j += 1;
            }
            i += 1;
        }
    }
}
