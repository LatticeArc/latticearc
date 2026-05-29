//! Domain Separation Constants for HKDF
//!
//! This module provides domain separation strings used in HKDF key derivation
//! to ensure cryptographic isolation between different cryptographic operations.
//!
//! Domain separation prevents key reuse across different protocols and ensures
//! that keys derived for one purpose cannot be used for another.

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

// ============================================================================
// Signature scheme domain-separation contexts (H1 / M1 / M5)
// ============================================================================
//
// Every signature path passes a scheme-specific context to the underlying
// primitive so the signed transcript binds the scheme identifier. Without this
// binding, an attacker who holds a valid envelope under one scheme can
// re-label and truncate components to forge a valid envelope under another
// scheme (e.g. hybrid → PQ-only downgrade). The contexts are NUL-free and
// versioned (`-v1`); a future change to the binding must bump to `-v2` and
// document the wire-format break in CHANGELOG.

/// ML-DSA-44 (FIPS 204) per-scheme context.
pub(crate) const SIG_CONTEXT_ML_DSA_44: &[u8] = b"LatticeArc-Sig-ml-dsa-44-v1";
/// ML-DSA-65 (FIPS 204) per-scheme context.
pub(crate) const SIG_CONTEXT_ML_DSA_65: &[u8] = b"LatticeArc-Sig-ml-dsa-65-v1";
/// ML-DSA-87 (FIPS 204) per-scheme context.
pub(crate) const SIG_CONTEXT_ML_DSA_87: &[u8] = b"LatticeArc-Sig-ml-dsa-87-v1";
/// SLH-DSA-SHAKE-128s (FIPS 205) per-scheme context.
pub(crate) const SIG_CONTEXT_SLH_DSA_SHAKE_128S: &[u8] = b"LatticeArc-Sig-slh-dsa-shake-128s-v1";
/// SLH-DSA-SHAKE-192s (FIPS 205) per-scheme context.
pub(crate) const SIG_CONTEXT_SLH_DSA_SHAKE_192S: &[u8] = b"LatticeArc-Sig-slh-dsa-shake-192s-v1";
/// SLH-DSA-SHAKE-256s (FIPS 205) per-scheme context.
pub(crate) const SIG_CONTEXT_SLH_DSA_SHAKE_256S: &[u8] = b"LatticeArc-Sig-slh-dsa-shake-256s-v1";
/// FN-DSA-512 (draft FIPS 206) per-scheme context.
///
/// FN-DSA's underlying `fn-dsa` crate does not expose a context parameter, so
/// this label is prefix-padded onto the message before signing rather than
/// passed natively. The wire effect is equivalent: the signed bytes are bound
/// to the scheme.
pub(crate) const SIG_CONTEXT_FN_DSA_512: &[u8] = b"LatticeArc-Sig-fn-dsa-512-v1";
/// FN-DSA-1024 (draft FIPS 206) per-scheme context. See [`SIG_CONTEXT_FN_DSA_512`].
pub(crate) const SIG_CONTEXT_FN_DSA_1024: &[u8] = b"LatticeArc-Sig-fn-dsa-1024-v1";
/// Hybrid ML-DSA-44 + Ed25519 per-scheme context.
///
/// Each leg of the hybrid signature is bound to this context independently:
/// the ML-DSA leg via the FIPS-204 context parameter, the Ed25519 leg via
/// prefix-padding (Ed25519/RFC 8032 has no native context).
pub(crate) const SIG_CONTEXT_HYBRID_ML_DSA_44_ED25519: &[u8] =
    b"LatticeArc-Sig-hybrid-ml-dsa-44-ed25519-v1";
/// Hybrid ML-DSA-65 + Ed25519 per-scheme context. See [`SIG_CONTEXT_HYBRID_ML_DSA_44_ED25519`].
pub(crate) const SIG_CONTEXT_HYBRID_ML_DSA_65_ED25519: &[u8] =
    b"LatticeArc-Sig-hybrid-ml-dsa-65-ed25519-v1";
/// Hybrid ML-DSA-87 + Ed25519 per-scheme context. See [`SIG_CONTEXT_HYBRID_ML_DSA_44_ED25519`].
pub(crate) const SIG_CONTEXT_HYBRID_ML_DSA_87_ED25519: &[u8] =
    b"LatticeArc-Sig-hybrid-ml-dsa-87-ed25519-v1";
/// Pure Ed25519 per-scheme context. Bound via prefix-padding.
pub(crate) const SIG_CONTEXT_ED25519: &[u8] = b"LatticeArc-Sig-ed25519-v1";

// ============================================================================
// SP 800-108 Counter-mode KDF labels (DP-M1 fix)
// ============================================================================
//
// `primitives::kdf::sp800_108_counter_kdf::Sp800_108CounterKdfParams::for_*`
// constructors previously embedded these labels inline at the call site.
// Pattern 2 (Domain Separation Registry) requires every domain label live in
// this module so the crate has a single auditable inventory. SP 800-108 is a
// structurally distinct KDF from HKDF; these labels are NOT part of the HKDF
// pairwise-distinctness proof and use their plain SP 800-108 §5.1 spelling
// (no `LatticeArc-…-v1` prefix) so they remain interoperable with external
// SP 800-108 KAT vectors.
//
// Naming kept identical to the spec-cited convenience identifiers to preserve
// KAT compatibility.

/// SP 800-108 counter-KDF label for encryption-key derivation.
pub(crate) const SP800_108_LABEL_ENCRYPTION: &[u8] = b"Encryption Key";
/// SP 800-108 counter-KDF label for MAC-key derivation.
pub(crate) const SP800_108_LABEL_MAC: &[u8] = b"MAC Key";
/// SP 800-108 counter-KDF label for IV / nonce derivation.
pub(crate) const SP800_108_LABEL_IV: &[u8] = b"IV Generation";

/// Closed enum of signature schemes whose transcripts the apache library binds.
///
/// Closed (`pub(crate)`) so the set of recognised schemes is structurally
/// fixed at compile time. Used both for context lookup at sign/verify time
/// and as the M5 deserialization allowlist: any `scheme` field on a
/// `SignedData` envelope that does not map to a variant here is rejected
/// before the verifier dispatches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigSchemeLabel {
    /// `ml-dsa-44`
    MlDsa44,
    /// `ml-dsa-65`
    MlDsa65,
    /// `ml-dsa-87`
    MlDsa87,
    /// `slh-dsa-shake-128s`
    SlhDsaShake128s,
    /// `slh-dsa-shake-192s`
    SlhDsaShake192s,
    /// `slh-dsa-shake-256s`
    SlhDsaShake256s,
    /// `fn-dsa-512` (also accepts the alias `fn-dsa`)
    FnDsa512,
    /// `fn-dsa-1024`
    FnDsa1024,
    /// `hybrid-ml-dsa-44-ed25519` (also accepts `ml-dsa-44-hybrid-ed25519`)
    HybridMlDsa44Ed25519,
    /// `hybrid-ml-dsa-65-ed25519` (also accepts `ml-dsa-65-hybrid-ed25519`)
    HybridMlDsa65Ed25519,
    /// `hybrid-ml-dsa-87-ed25519` (also accepts `ml-dsa-87-hybrid-ed25519`)
    HybridMlDsa87Ed25519,
    /// `ed25519`
    Ed25519,
}

impl SigSchemeLabel {
    /// Returns the per-scheme NUL-free domain-separation context. Mirrors the
    /// [`HkdfKemLabel::as_bytes`] pattern for sealed crate-controlled labels.
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::MlDsa44 => SIG_CONTEXT_ML_DSA_44,
            Self::MlDsa65 => SIG_CONTEXT_ML_DSA_65,
            Self::MlDsa87 => SIG_CONTEXT_ML_DSA_87,
            Self::SlhDsaShake128s => SIG_CONTEXT_SLH_DSA_SHAKE_128S,
            Self::SlhDsaShake192s => SIG_CONTEXT_SLH_DSA_SHAKE_192S,
            Self::SlhDsaShake256s => SIG_CONTEXT_SLH_DSA_SHAKE_256S,
            Self::FnDsa512 => SIG_CONTEXT_FN_DSA_512,
            Self::FnDsa1024 => SIG_CONTEXT_FN_DSA_1024,
            Self::HybridMlDsa44Ed25519 => SIG_CONTEXT_HYBRID_ML_DSA_44_ED25519,
            Self::HybridMlDsa65Ed25519 => SIG_CONTEXT_HYBRID_ML_DSA_65_ED25519,
            Self::HybridMlDsa87Ed25519 => SIG_CONTEXT_HYBRID_ML_DSA_87_ED25519,
            Self::Ed25519 => SIG_CONTEXT_ED25519,
        }
    }

    /// Parse a wire-format `scheme` string into a label. Aliases that the
    /// codebase already emits (`pq-ml-dsa-65` for ML-DSA-65,
    /// `ml-dsa-65-hybrid-ed25519` for the hybrid) are accepted; unknown
    /// strings return `None` and are rejected by the deserializer (M5).
    pub(crate) fn from_scheme_str(scheme: &str) -> Option<Self> {
        match scheme {
            "ml-dsa-44" | "pq-ml-dsa-44" => Some(Self::MlDsa44),
            "ml-dsa-65" | "pq-ml-dsa-65" => Some(Self::MlDsa65),
            "ml-dsa-87" | "pq-ml-dsa-87" => Some(Self::MlDsa87),
            "slh-dsa-shake-128s" => Some(Self::SlhDsaShake128s),
            "slh-dsa-shake-192s" => Some(Self::SlhDsaShake192s),
            "slh-dsa-shake-256s" => Some(Self::SlhDsaShake256s),
            "fn-dsa-512" | "fn-dsa" => Some(Self::FnDsa512),
            "fn-dsa-1024" => Some(Self::FnDsa1024),
            "hybrid-ml-dsa-44-ed25519" | "ml-dsa-44-hybrid-ed25519" => {
                Some(Self::HybridMlDsa44Ed25519)
            }
            "hybrid-ml-dsa-65-ed25519" | "ml-dsa-65-hybrid-ed25519" => {
                Some(Self::HybridMlDsa65Ed25519)
            }
            "hybrid-ml-dsa-87-ed25519" | "ml-dsa-87-hybrid-ed25519" => {
                Some(Self::HybridMlDsa87Ed25519)
            }
            "ed25519" => Some(Self::Ed25519),
            _ => None,
        }
    }
}

/// Convenience accessor for the per-scheme context.
#[inline]
pub(crate) const fn sig_context(label: SigSchemeLabel) -> &'static [u8] {
    label.as_bytes()
}

/// Domain-separated SHA-512 digest for signature primitives without a native
/// context parameter — Ed25519 (RFC 8032 §5.1) and FN-DSA (`fn-dsa 0.3`).
///
/// Returns `SHA-512(scheme_ctx || 0x00 || message)`. The 64-byte fixed-size
/// output is bound to the scheme (via `scheme_ctx`) while sidestepping the
/// per-primitive message-size cap that would otherwise reject the
/// prefix-padded form for messages near the cap (the cap is sized for the
/// caller's message, not for our internal scheme-binding overhead).
///
/// SHA-512 is collision-resistant under the standard assumptions, so signing
/// the digest is cryptographically equivalent to signing the prefix-padded
/// form for unforgeability purposes; the same construction is used on
/// verify, so legitimate signatures round-trip.
pub(crate) fn hash_with_context(scheme_ctx: &[u8], message: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(scheme_ctx);
    hasher.update([0x00]);
    hasher.update(message);
    hasher.finalize().into()
}

/// Domain-separation label tag for [`hkdf_kem_info_with_pk`].
///
/// Closed enum — only crate-controlled labels can be passed to the
/// HKDF info builder, so a future caller cannot accidentally pass an
/// arbitrary `&[u8]` containing `0x00` and break the NUL-separator
/// disambiguation in [`hkdf_kem_info_with_pk`]. The tests below assert each
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

// The label-only `hkdf_kem_info` helper was removed once
// `convenience::pq_kem` was migrated to the PK-binding variant. Every
// internal KEM-AEAD path now uses `hkdf_kem_info_with_pk` so
// encrypt/decrypt drift across parallel APIs is structurally
// impossible. The original doc comment for that
// function described the label-only encoding (`label || 0x00 ||
// kem_ciphertext`) which no longer exists in the codebase.

/// Build the HKDF `info` string with both recipient public key and KEM
/// ciphertext binding (HPKE / RFC 9180 §5.1 channel binding).
///
/// Encodes
/// `label || 0x00 || pk_len_be32 || recipient_pk || ct_len_be32 || kem_ciphertext`.
/// Length-prefixing both fields prevents prefix-free ambiguity between
/// adjacent variable-length values. The previous label-only
/// `hkdf_kem_info` helper was removed; every internal KEM-AEAD path
/// now uses this PK-binding variant so encrypt/decrypt drift across
/// parallel APIs is structurally impossible.
pub(crate) fn hkdf_kem_info_with_pk(
    label: HkdfKemLabel,
    recipient_pk: &[u8],
    kem_ciphertext: &[u8],
) -> Result<Vec<u8>, crate::prelude::error::LatticeArcError> {
    let label_bytes = label.as_bytes();
    // Runtime belt-and-suspenders guard against the test-time invariant
    // below. The `HkdfKemLabel` enum is closed and pub(crate), and the
    // `domain_labels_contain_no_nul_separator` test pins every variant
    // to a NUL-free byte string. If a future variant is added that
    // contains 0x00 without updating the test (or the test is removed
    // outright), the separator `label || 0x00 || payload` becomes
    // ambiguous with `label_that_ends_in_0x00 || payload` — an HPKE
    // channel-binding collision. The debug_assert! catches that in
    // any debug build; the explicit return-Err catches it in release.
    debug_assert!(
        !label_bytes.contains(&0x00),
        "HkdfKemLabel::as_bytes() must be NUL-free; the 0x00 separator below would collide"
    );
    if label_bytes.contains(&0x00) {
        return Err(crate::prelude::error::LatticeArcError::ValidationError {
            message: "HKDF label contains a NUL byte; would collide with the domain separator"
                .to_string(),
        });
    }
    let cap = label_bytes
        .len()
        .saturating_add(1)
        .saturating_add(4)
        .saturating_add(recipient_pk.len())
        .saturating_add(4)
        .saturating_add(kem_ciphertext.len());
    let mut info = Vec::with_capacity(cap);
    info.extend_from_slice(label_bytes);
    info.push(0x00); // domain separator between label and the PK || ct payload
    // hard-error on length-prefix overflow
    // instead of saturating to `u32::MAX`. Saturation collapses every
    // PK or ciphertext above 4 GiB onto the same prefix, breaking
    // HPKE channel binding's prefix-injectivity guarantee. In
    // practice no real KEM ciphertext or PK approaches the 4 GiB
    // line, but the audit-grade defensive fix is to fail loudly so a
    // future bug that introduces such inputs surfaces immediately.
    let pk_len_u32 = u32::try_from(recipient_pk.len()).map_err(|_overflow| {
        crate::prelude::error::LatticeArcError::InvalidInput(
            "recipient PK exceeds 4 GiB".to_string(),
        )
    })?;
    info.extend_from_slice(&pk_len_u32.to_be_bytes());
    info.extend_from_slice(recipient_pk);
    let ct_len_u32 = u32::try_from(kem_ciphertext.len()).map_err(|_overflow| {
        crate::prelude::error::LatticeArcError::InvalidInput(
            "KEM ciphertext exceeds 4 GiB".to_string(),
        )
    })?;
    info.extend_from_slice(&ct_len_u32.to_be_bytes());
    info.extend_from_slice(kem_ciphertext);
    Ok(info)
}

/// AAD-binding sibling of [`hkdf_kem_info_with_pk`] (M3 fix).
///
/// Encodes
/// `label || 0x00 || aad_len_be32 || aad || pk_len_be32 || recipient_pk
///  || ct_len_be32 || kem_ciphertext`.
///
/// `encrypt_hybrid::derive_encryption_key` already mixed AAD into the HKDF
/// info as a length-prefixed segment, but the `pq_only` path only included
/// it in the AEAD tag — leaving AAD's key-separation role to chance. This
/// helper adds AAD as a third length-prefixed segment between the label and
/// the recipient PK. Wire format is **different** from
/// [`hkdf_kem_info_with_pk`]; callers picking the wrong helper would derive
/// different keys and the AEAD tag check would fail closed.
///
/// Empty AAD is encoded as a `0_be32` length prefix followed by zero
/// payload bytes — distinct from "no AAD field" (which would produce a
/// shorter info string). This keeps the prefix-injectivity guarantee
/// (HPKE §5.1) intact.
pub(crate) fn hkdf_kem_info_with_pk_and_aad(
    label: HkdfKemLabel,
    aad: &[u8],
    recipient_pk: &[u8],
    kem_ciphertext: &[u8],
) -> Result<Vec<u8>, crate::prelude::error::LatticeArcError> {
    let label_bytes = label.as_bytes();
    debug_assert!(
        !label_bytes.contains(&0x00),
        "HkdfKemLabel::as_bytes() must be NUL-free; the 0x00 separator below would collide"
    );
    if label_bytes.contains(&0x00) {
        return Err(crate::prelude::error::LatticeArcError::ValidationError {
            message: "HKDF label contains a NUL byte; would collide with the domain separator"
                .to_string(),
        });
    }
    let cap = label_bytes
        .len()
        .saturating_add(1)
        .saturating_add(4)
        .saturating_add(aad.len())
        .saturating_add(4)
        .saturating_add(recipient_pk.len())
        .saturating_add(4)
        .saturating_add(kem_ciphertext.len());
    let mut info = Vec::with_capacity(cap);
    info.extend_from_slice(label_bytes);
    info.push(0x00); // domain separator between label and the AAD || PK || CT payload
    let aad_len_u32 = u32::try_from(aad.len()).map_err(|_overflow| {
        crate::prelude::error::LatticeArcError::InvalidInput("AAD exceeds 4 GiB".to_string())
    })?;
    info.extend_from_slice(&aad_len_u32.to_be_bytes());
    info.extend_from_slice(aad);
    let pk_len_u32 = u32::try_from(recipient_pk.len()).map_err(|_overflow| {
        crate::prelude::error::LatticeArcError::InvalidInput(
            "recipient PK exceeds 4 GiB".to_string(),
        )
    })?;
    info.extend_from_slice(&pk_len_u32.to_be_bytes());
    info.extend_from_slice(recipient_pk);
    let ct_len_u32 = u32::try_from(kem_ciphertext.len()).map_err(|_overflow| {
        crate::prelude::error::LatticeArcError::InvalidInput(
            "KEM ciphertext exceeds 4 GiB".to_string(),
        )
    })?;
    info.extend_from_slice(&ct_len_u32.to_be_bytes());
    info.extend_from_slice(kem_ciphertext);
    Ok(info)
}

#[cfg(test)]
mod hkdf_kem_label_tests {
    use super::*;

    /// Locks the NUL-freeness invariant the `0x00` separator depends
    /// on. Adding a new `HkdfKemLabel` variant whose byte string
    /// contains `0x00` would break the separator's disambiguation
    /// guarantee — this test catches that at CI time. See L2 audit
    /// fix in [`hkdf_kem_info_with_pk`].
    #[test]
    fn all_label_variants_are_nul_free() {
        for label in [HkdfKemLabel::PqKemAead, HkdfKemLabel::PqOnlyEncryption] {
            let bytes = label.as_bytes();
            assert!(
                !bytes.contains(&0u8),
                "HkdfKemLabel::{:?} maps to a byte string containing 0x00 \
                 ({:?}) — this breaks the NUL separator in hkdf_kem_info_with_pk",
                label,
                bytes,
            );
        }
    }
}

#[cfg(test)]
mod sig_scheme_label_tests {
    use super::*;

    const ALL_LABELS: &[SigSchemeLabel] = &[
        SigSchemeLabel::MlDsa44,
        SigSchemeLabel::MlDsa65,
        SigSchemeLabel::MlDsa87,
        SigSchemeLabel::SlhDsaShake128s,
        SigSchemeLabel::SlhDsaShake192s,
        SigSchemeLabel::SlhDsaShake256s,
        SigSchemeLabel::FnDsa512,
        SigSchemeLabel::FnDsa1024,
        SigSchemeLabel::HybridMlDsa44Ed25519,
        SigSchemeLabel::HybridMlDsa65Ed25519,
        SigSchemeLabel::HybridMlDsa87Ed25519,
        SigSchemeLabel::Ed25519,
    ];

    /// Mirrors `all_label_variants_are_nul_free` for sig contexts. ML-DSA and
    /// SLH-DSA pass the context to the underlying primitive (FIPS 204 §5.2,
    /// FIPS 205 §10.2). FN-DSA and Ed25519 use prefix-padding: the wire form
    /// is `context || 0x00 || message`, so a context containing 0x00 would
    /// make the separator ambiguous and let an attacker craft two distinct
    /// (context, message) pairs that produce identical signed bytes.
    #[test]
    fn all_sig_context_variants_are_nul_free() {
        for &label in ALL_LABELS {
            let bytes = label.as_bytes();
            assert!(
                !bytes.contains(&0u8),
                "SigSchemeLabel::{label:?} maps to {bytes:?} which contains 0x00; \
                 the prefix-padding separator below would collide"
            );
        }
    }

    /// All scheme contexts must be pairwise distinct. A collision would mean
    /// two scheme identifiers share a transcript-binding, defeating H1's
    /// fix — `(ml-dsa-65 sk, msg)` would produce the same signed bytes as
    /// `(hybrid-ml-dsa-65-ed25519 ML-DSA leg, msg)` and the downgrade attack
    /// would still succeed.
    #[test]
    fn all_sig_contexts_pairwise_distinct() {
        for (i, &a) in ALL_LABELS.iter().enumerate() {
            let Some(rest) = ALL_LABELS.get(i.saturating_add(1)..) else {
                continue;
            };
            for &b in rest {
                assert_ne!(
                    a.as_bytes(),
                    b.as_bytes(),
                    "SigSchemeLabel::{a:?} and ::{b:?} share a context"
                );
            }
        }
    }

    /// Wire-format strings the codebase emits at sign-side must round-trip
    /// through `from_scheme_str`. If `sign_with_key` ever produces a scheme
    /// string that the M5 allowlist rejects, signing and verification would
    /// silently disagree.
    #[test]
    fn canonical_scheme_strings_round_trip() {
        let pairs: &[(&str, SigSchemeLabel)] = &[
            ("ml-dsa-44", SigSchemeLabel::MlDsa44),
            ("ml-dsa-65", SigSchemeLabel::MlDsa65),
            ("ml-dsa-87", SigSchemeLabel::MlDsa87),
            ("pq-ml-dsa-44", SigSchemeLabel::MlDsa44),
            ("pq-ml-dsa-65", SigSchemeLabel::MlDsa65),
            ("pq-ml-dsa-87", SigSchemeLabel::MlDsa87),
            ("slh-dsa-shake-128s", SigSchemeLabel::SlhDsaShake128s),
            ("slh-dsa-shake-192s", SigSchemeLabel::SlhDsaShake192s),
            ("slh-dsa-shake-256s", SigSchemeLabel::SlhDsaShake256s),
            ("fn-dsa-512", SigSchemeLabel::FnDsa512),
            ("fn-dsa", SigSchemeLabel::FnDsa512),
            ("fn-dsa-1024", SigSchemeLabel::FnDsa1024),
            ("hybrid-ml-dsa-44-ed25519", SigSchemeLabel::HybridMlDsa44Ed25519),
            ("ml-dsa-44-hybrid-ed25519", SigSchemeLabel::HybridMlDsa44Ed25519),
            ("hybrid-ml-dsa-65-ed25519", SigSchemeLabel::HybridMlDsa65Ed25519),
            ("ml-dsa-65-hybrid-ed25519", SigSchemeLabel::HybridMlDsa65Ed25519),
            ("hybrid-ml-dsa-87-ed25519", SigSchemeLabel::HybridMlDsa87Ed25519),
            ("ml-dsa-87-hybrid-ed25519", SigSchemeLabel::HybridMlDsa87Ed25519),
            ("ed25519", SigSchemeLabel::Ed25519),
        ];
        for &(s, want) in pairs {
            assert_eq!(
                SigSchemeLabel::from_scheme_str(s),
                Some(want),
                "scheme string {s:?} did not map to {want:?}"
            );
        }
    }

    #[test]
    fn unknown_scheme_strings_rejected() {
        for s in [
            "",
            "ml-dsa-99",
            "rsa-2048",
            "hybrid-ml-dsa-65",               // missing classical
            "ml-dsa-65-hybrid",               // missing classical
            "hybrid-ml-dsa-65-ed25519-extra", // suffix tampering
            "Ml-Dsa-65",                      // case-sensitive
        ] {
            assert_eq!(
                SigSchemeLabel::from_scheme_str(s),
                None,
                "scheme string {s:?} must be rejected by the M5 allowlist"
            );
        }
    }
}

// Formal verification with Kani
#[cfg(kani)]
#[expect(
    clippy::indexing_slicing,
    reason = "indexing into a slice whose length is known at this site"
)]
mod kani_proofs {
    use super::*;

    /// Proves all 8 HKDF domain constants are pairwise distinct (C(8,2)=28 pairs).
    /// Security: collision would cause key reuse across protocols (NIST SP 800-108).
    #[kani::proof]
    fn domain_constants_pairwise_distinct() {
        let constants: &[&[u8]] = &[
            CASCADE_OUTER,
            CASCADE_INNER,
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
