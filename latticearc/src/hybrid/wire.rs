//! # Compact binary wire format (v1)
//!
//! A fixed-layout, versioned binary encoding for the hybrid types that
//! applications store or transmit: hybrid KEM public keys, hybrid KEM
//! encapsulations, hybrid ciphertexts, hybrid signature public keys and
//! hybrid signatures. Intended for fixed-size records on disk or untrusted
//! storage where JSON and CBOR are unwanted. The normative specification,
//! including the compatibility policy, is `docs/WIRE_FORMAT.md`.
//!
//! ## Layout
//!
//! ```text
//! magic "LA" (2) | version = 1 (1) | type tag (1) | algorithm id (1) | body
//! ```
//!
//! Every body field has a length fixed by the algorithm id, so there are no
//! length prefixes except for the variable AES-256-GCM ciphertext inside a
//! [`HybridCiphertext`] (one `u32` big-endian prefix, capped at
//! [`MAX_SYMMETRIC_CIPHERTEXT_LEN`]). Trailing bytes are rejected, so each
//! value has exactly one encoding.
//!
//! | Tag | Type | Algorithm id |
//! |---|---|---|
//! | `0x01` | [`HybridKemPublicKey`] | ML-KEM level (1, 3, 5) |
//! | `0x02` | [`EncapsulatedKey`] | ML-KEM level (1, 3, 5) |
//! | `0x03` | [`HybridCiphertext`] | ML-KEM level (1, 3, 5) |
//! | `0x04` | [`HybridSigPublicKey`] | ML-DSA parameter set (2, 3, 5) |
//! | `0x05` | [`HybridSignature`] | ML-DSA parameter set (2, 3, 5) |
//! | `0x06` | reserved for `WrappedKey` | — |
//!
//! Algorithm ids are the discriminants of [`MlKemSecurityLevel`] and
//! [`MlDsaParameterSet`] (the NIST security category).
//!
//! ## Decoding guarantees
//!
//! - Total: every input yields `Ok` or a [`WireError`]; no panics.
//! - The input length is checked against the type's hard maximum
//!   ([`WireEncode::MAX_WIRE_LEN`]) before anything is parsed or allocated.
//! - Allocation is bounded by the input actually supplied: a length prefix
//!   is only honoured when that many bytes are present.
//! - Structural only: component bytes are not validated cryptographically
//!   (point/modulus checks happen at first use, as with
//!   [`HybridKemPublicKey::from_bytes`]).
//!
//! ## Error detail
//!
//! [`WireError`] variants distinguish structural failures (truncation,
//! version, type tag, trailing bytes). Every check reads only the public,
//! attacker-supplied bytes and runs before any key material is touched, so
//! the distinction reveals nothing the attacker did not already choose.
//! Decryption and verification of a decoded value keep their opaque errors.
//!
//! ## Relationship to `HybridKemPublicKey::to_bytes`
//!
//! `HybridKemPublicKey::to_bytes` predates this module and carries its own
//! version byte, a 1/2/3 level tag and `u32` length prefixes. It is left
//! unchanged for existing stored keys. This format uses the shared header so
//! all hybrid types share one envelope and one version rule, and drops the
//! length prefixes because the algorithm id fixes every length.
//!
//! ## Example
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use latticearc::hybrid::kem_hybrid::generate_keypair;
//! use latticearc::{HybridKemPublicKey, WireEncode};
//!
//! let (pk, _sk) = generate_keypair()?;
//! let record = pk.to_wire()?;
//! assert_eq!(record.len(), 5 + 1184 + 32);
//! let restored = HybridKemPublicKey::from_wire(&record)?;
//! assert_eq!(restored.ml_kem_pk(), pk.ml_kem_pk());
//! # Ok(())
//! # }
//! ```

use thiserror::Error;

use crate::hybrid::encrypt_hybrid::HybridCiphertext;
use crate::hybrid::kem_hybrid::{EncapsulatedKey, HybridKemPublicKey};
use crate::hybrid::sig_hybrid::{HybridSigPublicKey, HybridSignature};
use crate::primitives::aead::{NONCE_LEN, TAG_LEN};
use crate::primitives::kem::MlKemSecurityLevel;
use crate::primitives::kem::ecdh::X25519_KEY_SIZE;
use crate::primitives::sig::ml_dsa::MlDsaParameterSet;

/// Magic bytes at the start of every wire value: ASCII `"LA"`.
pub const WIRE_MAGIC: [u8; 2] = *b"LA";

/// The only wire-format version this build encodes and decodes.
pub const WIRE_VERSION: u8 = 1;

/// Header length: magic (2) + version (1) + type tag (1) + algorithm id (1).
pub const WIRE_HEADER_LEN: usize = 5;

/// Type tag reserved for the `WrappedKey` encoding added in 0.13.
///
/// Decoders in this module reject it with [`WireError::WrongType`]. The
/// `WrappedKey` body carries its own leading version byte; the shared
/// header's version rules still apply to the envelope.
pub const WRAPPED_KEY_TYPE_TAG: u8 = 0x06;

/// Hard cap on the AES-256-GCM ciphertext inside an encoded
/// [`HybridCiphertext`] (100 MiB, the default one-shot decryption limit in
/// `primitives::resource_limits`).
pub const MAX_SYMMETRIC_CIPHERTEXT_LEN: usize = 100 * 1024 * 1024;

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;
const SYMMETRIC_LEN_PREFIX: usize = 4;

/// Errors from encoding or decoding the wire format.
///
/// Decoding errors describe structural problems with public input only;
/// see the module documentation for why they are distinguishable.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum WireError {
    /// The input is longer than the maximum for the requested type, or a
    /// length prefix exceeds its cap. Checked before any allocation.
    #[error("wire input length {len} exceeds the maximum of {max} bytes")]
    TooLarge {
        /// Observed length (whole input, or the prefixed field length).
        len: usize,
        /// Applicable maximum.
        max: usize,
    },
    /// The input ends before the last field.
    #[error("wire input is truncated")]
    Truncated,
    /// The input does not start with [`WIRE_MAGIC`].
    #[error("wire input does not start with the LatticeArc magic bytes")]
    BadMagic,
    /// The version byte is not [`WIRE_VERSION`].
    #[error("unsupported wire-format version {0}")]
    UnsupportedVersion(u8),
    /// The type tag does not match the type being decoded.
    #[error("wire type tag {found:#04x} does not match expected {expected:#04x}")]
    WrongType {
        /// Tag of the type being decoded.
        expected: u8,
        /// Tag found in the input.
        found: u8,
    },
    /// The algorithm id is not defined for this type.
    #[error("unknown algorithm id {0} for this wire type")]
    UnknownAlgorithm(u8),
    /// Bytes remain after the last field.
    #[error("wire input has trailing bytes")]
    TrailingBytes,
    /// A component of the value being encoded has a length no algorithm id
    /// describes (for example a hand-built key of the wrong size).
    #[error("cannot encode: invalid {0} length")]
    InvalidComponent(&'static str),
}

mod sealed {
    /// Restricts [`super::WireEncode`] to types defined in this crate.
    pub trait Sealed {}
}

/// Encode to and decode from the LatticeArc binary wire format.
///
/// Sealed: implemented only for [`HybridKemPublicKey`], [`EncapsulatedKey`],
/// [`HybridCiphertext`], [`HybridSigPublicKey`] and [`HybridSignature`].
pub trait WireEncode: sealed::Sealed + Sized {
    /// Type tag written after the version byte.
    const TYPE_TAG: u8;
    /// Largest valid encoding of this type, in bytes. Longer input is
    /// rejected with [`WireError::TooLarge`] before parsing.
    const MAX_WIRE_LEN: usize;

    /// Encode `self`.
    ///
    /// # Errors
    ///
    /// [`WireError::InvalidComponent`] if a component length does not match
    /// any algorithm id (only possible for values assembled by hand), or
    /// [`WireError::TooLarge`] if a variable field exceeds its cap.
    fn to_wire(&self) -> Result<Vec<u8>, WireError>;

    /// Decode a value previously produced by [`Self::to_wire`].
    ///
    /// # Errors
    ///
    /// A [`WireError`] describing the first structural problem found.
    fn from_wire(bytes: &[u8]) -> Result<Self, WireError>;
}

// ----------------------------------------------------------------------------
// Algorithm ids
// ----------------------------------------------------------------------------

const fn kem_level_id(level: MlKemSecurityLevel) -> u8 {
    match level {
        MlKemSecurityLevel::MlKem512 => 1,
        MlKemSecurityLevel::MlKem768 => 3,
        MlKemSecurityLevel::MlKem1024 => 5,
    }
}

fn kem_level_from_id(id: u8) -> Result<MlKemSecurityLevel, WireError> {
    match id {
        1 => Ok(MlKemSecurityLevel::MlKem512),
        3 => Ok(MlKemSecurityLevel::MlKem768),
        5 => Ok(MlKemSecurityLevel::MlKem1024),
        other => Err(WireError::UnknownAlgorithm(other)),
    }
}

/// ML-KEM ciphertext sizes (768 / 1088 / 1568) are pairwise distinct.
fn kem_level_from_ciphertext_len(len: usize) -> Result<MlKemSecurityLevel, WireError> {
    [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
        .into_iter()
        .find(|level| level.ciphertext_size() == len)
        .ok_or(WireError::InvalidComponent("ML-KEM ciphertext"))
}

const fn dsa_set_id(set: MlDsaParameterSet) -> u8 {
    match set {
        MlDsaParameterSet::MlDsa44 => 2,
        MlDsaParameterSet::MlDsa65 => 3,
        MlDsaParameterSet::MlDsa87 => 5,
    }
}

fn dsa_set_from_id(id: u8) -> Result<MlDsaParameterSet, WireError> {
    match id {
        2 => Ok(MlDsaParameterSet::MlDsa44),
        3 => Ok(MlDsaParameterSet::MlDsa65),
        5 => Ok(MlDsaParameterSet::MlDsa87),
        other => Err(WireError::UnknownAlgorithm(other)),
    }
}

/// ML-DSA signature sizes (2420 / 3309 / 4627) are pairwise distinct.
fn dsa_set_from_signature_len(len: usize) -> Result<MlDsaParameterSet, WireError> {
    [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
        .into_iter()
        .find(|set| set.signature_size() == len)
        .ok_or(WireError::InvalidComponent("ML-DSA signature"))
}

// ----------------------------------------------------------------------------
// Encoding / decoding helpers
// ----------------------------------------------------------------------------

/// Start an encoding: header plus capacity for `body_len` bytes.
fn begin(type_tag: u8, alg_id: u8, body_len: usize) -> Result<Vec<u8>, WireError> {
    let total = WIRE_HEADER_LEN
        .checked_add(body_len)
        .ok_or(WireError::TooLarge { len: usize::MAX, max: usize::MAX })?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&WIRE_MAGIC);
    out.push(WIRE_VERSION);
    out.push(type_tag);
    out.push(alg_id);
    Ok(out)
}

/// Check the size cap and header; return the algorithm id and body.
fn parse_header(bytes: &[u8], type_tag: u8, max_len: usize) -> Result<(u8, &[u8]), WireError> {
    if bytes.len() > max_len {
        return Err(WireError::TooLarge { len: bytes.len(), max: max_len });
    }
    let (header, body) = bytes.split_at_checked(WIRE_HEADER_LEN).ok_or(WireError::Truncated)?;
    let [m0, m1, version, found, alg_id]: [u8; WIRE_HEADER_LEN] =
        header.try_into().map_err(|_e| WireError::Truncated)?;
    if [m0, m1] != WIRE_MAGIC {
        return Err(WireError::BadMagic);
    }
    if version != WIRE_VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    if found != type_tag {
        return Err(WireError::WrongType { expected: type_tag, found });
    }
    Ok((alg_id, body))
}

/// Forward-only reader over a body slice.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let (head, tail) = self.rest.split_at_checked(len).ok_or(WireError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn take_u32_be(&mut self) -> Result<u32, WireError> {
        let raw: [u8; SYMMETRIC_LEN_PREFIX] =
            self.take(SYMMETRIC_LEN_PREFIX)?.try_into().map_err(|_e| WireError::Truncated)?;
        Ok(u32::from_be_bytes(raw))
    }

    fn finish(self) -> Result<(), WireError> {
        if self.rest.is_empty() { Ok(()) } else { Err(WireError::TrailingBytes) }
    }
}

fn require_len(field: &[u8], expected: usize, name: &'static str) -> Result<(), WireError> {
    if field.len() == expected { Ok(()) } else { Err(WireError::InvalidComponent(name)) }
}

/// Sum of field lengths; overflow is impossible for the fixed sizes used here
/// and is reported as `TooLarge` rather than wrapping.
fn sum_lens(lens: &[usize]) -> Result<usize, WireError> {
    lens.iter().try_fold(0usize, |acc, &len| {
        acc.checked_add(len).ok_or(WireError::TooLarge { len: usize::MAX, max: usize::MAX })
    })
}

// ----------------------------------------------------------------------------
// HybridKemPublicKey (0x01)
// ----------------------------------------------------------------------------

impl sealed::Sealed for HybridKemPublicKey {}

impl WireEncode for HybridKemPublicKey {
    const TYPE_TAG: u8 = 0x01;
    const MAX_WIRE_LEN: usize =
        WIRE_HEADER_LEN + MlKemSecurityLevel::MlKem1024.public_key_size() + X25519_KEY_SIZE;

    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let level = self.security_level();
        require_len(self.ml_kem_pk(), level.public_key_size(), "ML-KEM public key")?;
        require_len(self.ecdh_pk(), X25519_KEY_SIZE, "X25519 public key")?;
        let body_len = sum_lens(&[self.ml_kem_pk().len(), self.ecdh_pk().len()])?;
        let mut out = begin(Self::TYPE_TAG, kem_level_id(level), body_len)?;
        out.extend_from_slice(self.ml_kem_pk());
        out.extend_from_slice(self.ecdh_pk());
        Ok(out)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let (alg_id, body) = parse_header(bytes, Self::TYPE_TAG, Self::MAX_WIRE_LEN)?;
        let level = kem_level_from_id(alg_id)?;
        let mut reader = Reader::new(body);
        let ml_kem_pk = reader.take(level.public_key_size())?;
        let ecdh_pk = reader.take(X25519_KEY_SIZE)?;
        reader.finish()?;
        Ok(Self::new(ml_kem_pk.to_vec(), ecdh_pk.to_vec(), level))
    }
}

// ----------------------------------------------------------------------------
// EncapsulatedKey (0x02)
// ----------------------------------------------------------------------------

impl sealed::Sealed for EncapsulatedKey {}

/// Encodes only the public encapsulation (ML-KEM ciphertext and ephemeral
/// X25519 public key). The shared secret is never written; decoding yields
/// a value built with [`EncapsulatedKey::for_decapsulate`].
impl WireEncode for EncapsulatedKey {
    const TYPE_TAG: u8 = 0x02;
    const MAX_WIRE_LEN: usize =
        WIRE_HEADER_LEN + MlKemSecurityLevel::MlKem1024.ciphertext_size() + X25519_KEY_SIZE;

    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let level = kem_level_from_ciphertext_len(self.ml_kem_ct().len())?;
        require_len(self.ecdh_pk(), X25519_KEY_SIZE, "X25519 ephemeral public key")?;
        let body_len = sum_lens(&[self.ml_kem_ct().len(), self.ecdh_pk().len()])?;
        let mut out = begin(Self::TYPE_TAG, kem_level_id(level), body_len)?;
        out.extend_from_slice(self.ml_kem_ct());
        out.extend_from_slice(self.ecdh_pk());
        Ok(out)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let (alg_id, body) = parse_header(bytes, Self::TYPE_TAG, Self::MAX_WIRE_LEN)?;
        let level = kem_level_from_id(alg_id)?;
        let mut reader = Reader::new(body);
        let ml_kem_ct = reader.take(level.ciphertext_size())?;
        let ecdh_pk = reader.take(X25519_KEY_SIZE)?;
        reader.finish()?;
        Ok(Self::for_decapsulate(ml_kem_ct.to_vec(), ecdh_pk.to_vec()))
    }
}

// ----------------------------------------------------------------------------
// HybridCiphertext (0x03)
// ----------------------------------------------------------------------------

impl sealed::Sealed for HybridCiphertext {}

impl WireEncode for HybridCiphertext {
    const TYPE_TAG: u8 = 0x03;
    const MAX_WIRE_LEN: usize = WIRE_HEADER_LEN
        + MlKemSecurityLevel::MlKem1024.ciphertext_size()
        + X25519_KEY_SIZE
        + NONCE_LEN
        + TAG_LEN
        + SYMMETRIC_LEN_PREFIX
        + MAX_SYMMETRIC_CIPHERTEXT_LEN;

    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let level = kem_level_from_ciphertext_len(self.kem_ciphertext().len())?;
        require_len(self.ecdh_ephemeral_pk(), X25519_KEY_SIZE, "X25519 ephemeral public key")?;
        require_len(self.nonce(), NONCE_LEN, "AES-GCM nonce")?;
        require_len(self.tag(), TAG_LEN, "AES-GCM tag")?;
        let sym_len = self.symmetric_ciphertext().len();
        if sym_len > MAX_SYMMETRIC_CIPHERTEXT_LEN {
            return Err(WireError::TooLarge { len: sym_len, max: MAX_SYMMETRIC_CIPHERTEXT_LEN });
        }
        let prefix = u32::try_from(sym_len).map_err(|_e| WireError::TooLarge {
            len: sym_len,
            max: MAX_SYMMETRIC_CIPHERTEXT_LEN,
        })?;
        let body_len = sum_lens(&[
            self.kem_ciphertext().len(),
            X25519_KEY_SIZE,
            NONCE_LEN,
            TAG_LEN,
            SYMMETRIC_LEN_PREFIX,
            sym_len,
        ])?;
        let mut out = begin(Self::TYPE_TAG, kem_level_id(level), body_len)?;
        out.extend_from_slice(self.kem_ciphertext());
        out.extend_from_slice(self.ecdh_ephemeral_pk());
        out.extend_from_slice(self.nonce());
        out.extend_from_slice(self.tag());
        out.extend_from_slice(&prefix.to_be_bytes());
        out.extend_from_slice(self.symmetric_ciphertext());
        Ok(out)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let (alg_id, body) = parse_header(bytes, Self::TYPE_TAG, Self::MAX_WIRE_LEN)?;
        let level = kem_level_from_id(alg_id)?;
        let mut reader = Reader::new(body);
        let kem_ct = reader.take(level.ciphertext_size())?;
        let ecdh_pk = reader.take(X25519_KEY_SIZE)?;
        let nonce = reader.take(NONCE_LEN)?;
        let tag = reader.take(TAG_LEN)?;
        let sym_len = usize::try_from(reader.take_u32_be()?).map_err(|_e| WireError::TooLarge {
            len: usize::MAX,
            max: MAX_SYMMETRIC_CIPHERTEXT_LEN,
        })?;
        if sym_len > MAX_SYMMETRIC_CIPHERTEXT_LEN {
            return Err(WireError::TooLarge { len: sym_len, max: MAX_SYMMETRIC_CIPHERTEXT_LEN });
        }
        // `take` fails before any copy if fewer than `sym_len` bytes remain,
        // so the allocation below is bounded by the supplied input.
        let symmetric = reader.take(sym_len)?;
        reader.finish()?;
        Ok(Self::new(
            kem_ct.to_vec(),
            ecdh_pk.to_vec(),
            symmetric.to_vec(),
            nonce.to_vec(),
            tag.to_vec(),
        ))
    }
}

// ----------------------------------------------------------------------------
// HybridSigPublicKey (0x04)
// ----------------------------------------------------------------------------

impl sealed::Sealed for HybridSigPublicKey {}

impl WireEncode for HybridSigPublicKey {
    const TYPE_TAG: u8 = 0x04;
    const MAX_WIRE_LEN: usize =
        WIRE_HEADER_LEN + MlDsaParameterSet::MlDsa87.public_key_size() + ED25519_PUBLIC_KEY_LEN;

    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let set = self.parameter_set();
        require_len(self.ml_dsa_pk(), set.public_key_size(), "ML-DSA public key")?;
        require_len(self.ed25519_pk(), ED25519_PUBLIC_KEY_LEN, "Ed25519 public key")?;
        let body_len = sum_lens(&[self.ml_dsa_pk().len(), self.ed25519_pk().len()])?;
        let mut out = begin(Self::TYPE_TAG, dsa_set_id(set), body_len)?;
        out.extend_from_slice(self.ml_dsa_pk());
        out.extend_from_slice(self.ed25519_pk());
        Ok(out)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let (alg_id, body) = parse_header(bytes, Self::TYPE_TAG, Self::MAX_WIRE_LEN)?;
        let set = dsa_set_from_id(alg_id)?;
        let mut reader = Reader::new(body);
        let ml_dsa_pk = reader.take(set.public_key_size())?;
        let ed25519_pk = reader.take(ED25519_PUBLIC_KEY_LEN)?;
        reader.finish()?;
        // Lengths were fixed by `set` above, so `new`'s length validation
        // cannot fail; map defensively instead of unwrapping.
        Self::new(set, ml_dsa_pk.to_vec(), ed25519_pk.to_vec())
            .map_err(|_e| WireError::InvalidComponent("ML-DSA or Ed25519 public key"))
    }
}

// ----------------------------------------------------------------------------
// HybridSignature (0x05)
// ----------------------------------------------------------------------------

impl sealed::Sealed for HybridSignature {}

/// `HybridSignature` does not store its parameter set; the encoder derives
/// the algorithm id from the ML-DSA signature length.
impl WireEncode for HybridSignature {
    const TYPE_TAG: u8 = 0x05;
    const MAX_WIRE_LEN: usize =
        WIRE_HEADER_LEN + MlDsaParameterSet::MlDsa87.signature_size() + ED25519_SIGNATURE_LEN;

    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let set = dsa_set_from_signature_len(self.ml_dsa_sig().len())?;
        require_len(self.ed25519_sig(), ED25519_SIGNATURE_LEN, "Ed25519 signature")?;
        let body_len = sum_lens(&[self.ml_dsa_sig().len(), self.ed25519_sig().len()])?;
        let mut out = begin(Self::TYPE_TAG, dsa_set_id(set), body_len)?;
        out.extend_from_slice(self.ml_dsa_sig());
        out.extend_from_slice(self.ed25519_sig());
        Ok(out)
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, WireError> {
        let (alg_id, body) = parse_header(bytes, Self::TYPE_TAG, Self::MAX_WIRE_LEN)?;
        let set = dsa_set_from_id(alg_id)?;
        let mut reader = Reader::new(body);
        let ml_dsa_sig = reader.take(set.signature_size())?;
        let ed25519_sig = reader.take(ED25519_SIGNATURE_LEN)?;
        reader.finish()?;
        Ok(Self::new(ml_dsa_sig.to_vec(), ed25519_sig.to_vec()))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test scaffolding: lints suppressed for this module"
)]
mod tests {
    use super::*;
    use crate::hybrid::{decrypt_hybrid, encrypt_hybrid, kem_hybrid, sig_hybrid};
    use proptest::prelude::*;
    use subtle::ConstantTimeEq;

    const KEM_LEVELS: [MlKemSecurityLevel; 3] =
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024];
    const DSA_SETS: [MlDsaParameterSet; 3] =
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87];

    /// Deterministic filler: `b = b * 29 + 7 (mod 256)`, emitting each `b`.
    fn filled(len: usize, seed: u8) -> Vec<u8> {
        let mut b = seed;
        (0..len)
            .map(|_| {
                b = b.wrapping_mul(29).wrapping_add(7);
                b
            })
            .collect()
    }

    fn kem_pk(level: MlKemSecurityLevel) -> HybridKemPublicKey {
        HybridKemPublicKey::new(filled(level.public_key_size(), 1), filled(32, 2), level)
    }

    fn encapsulation(level: MlKemSecurityLevel) -> EncapsulatedKey {
        EncapsulatedKey::for_decapsulate(filled(level.ciphertext_size(), 3), filled(32, 4))
    }

    fn ciphertext(level: MlKemSecurityLevel, sym_len: usize) -> HybridCiphertext {
        HybridCiphertext::new(
            filled(level.ciphertext_size(), 5),
            filled(32, 6),
            filled(sym_len, 7),
            filled(NONCE_LEN, 8),
            filled(TAG_LEN, 9),
        )
    }

    fn sig_pk(set: MlDsaParameterSet) -> HybridSigPublicKey {
        HybridSigPublicKey::new(set, filled(set.public_key_size(), 10), filled(32, 11)).unwrap()
    }

    fn signature(set: MlDsaParameterSet) -> HybridSignature {
        HybridSignature::new(filled(set.signature_size(), 12), filled(64, 13))
    }

    fn valid_alg_ids<T: WireEncode>() -> &'static [u8] {
        if T::TYPE_TAG == HybridSigPublicKey::TYPE_TAG || T::TYPE_TAG == HybridSignature::TYPE_TAG {
            &[2, 3, 5]
        } else {
            &[1, 3, 5]
        }
    }

    /// Every structural mutation of a valid encoding must be rejected with
    /// the matching error.
    fn assert_rejections<T: WireEncode>(enc: &[u8]) {
        assert!(T::from_wire(enc).is_ok());

        for cut in 0..enc.len() {
            assert!(
                matches!(T::from_wire(&enc[..cut]), Err(WireError::Truncated)),
                "prefix of {cut}/{} bytes must be Truncated",
                enc.len()
            );
        }

        let mut extended = enc.to_vec();
        extended.push(0);
        let result = T::from_wire(&extended);
        if enc.len() == T::MAX_WIRE_LEN {
            assert!(matches!(result, Err(WireError::TooLarge { .. })));
        } else {
            assert!(matches!(result, Err(WireError::TrailingBytes)));
        }

        for magic_index in 0..2 {
            let mut bad = enc.to_vec();
            bad[magic_index] ^= 0x20;
            assert!(matches!(T::from_wire(&bad), Err(WireError::BadMagic)));
        }

        for version in [0u8, 2, 0x7F, 0xFF] {
            let mut bad = enc.to_vec();
            bad[2] = version;
            assert!(matches!(
                T::from_wire(&bad),
                Err(WireError::UnsupportedVersion(v)) if v == version
            ));
        }

        for tag in 0..=u8::MAX {
            if tag == T::TYPE_TAG {
                continue;
            }
            let mut bad = enc.to_vec();
            bad[3] = tag;
            assert!(matches!(
                T::from_wire(&bad),
                Err(WireError::WrongType { expected, found })
                    if expected == T::TYPE_TAG && found == tag
            ));
        }

        for alg in 0..=u8::MAX {
            if valid_alg_ids::<T>().contains(&alg) {
                continue;
            }
            let mut bad = enc.to_vec();
            bad[4] = alg;
            assert!(matches!(T::from_wire(&bad), Err(WireError::UnknownAlgorithm(a)) if a == alg));
        }
    }

    fn assert_header(enc: &[u8], tag: u8, alg: u8) {
        assert_eq!(&enc[..WIRE_HEADER_LEN], &[b'L', b'A', WIRE_VERSION, tag, alg]);
    }

    // ---------------- roundtrips (patterned components) ----------------

    #[test]
    fn wire_kem_public_key_roundtrip_all_levels() {
        for level in KEM_LEVELS {
            let pk = kem_pk(level);
            let enc = pk.to_wire().unwrap();
            assert_eq!(enc.len(), WIRE_HEADER_LEN + level.public_key_size() + 32);
            assert_header(&enc, 0x01, kem_level_id(level));
            let dec = HybridKemPublicKey::from_wire(&enc).unwrap();
            assert_eq!(dec.security_level(), level);
            assert_eq!(dec.ml_kem_pk(), pk.ml_kem_pk());
            assert_eq!(dec.ecdh_pk(), pk.ecdh_pk());
            assert_rejections::<HybridKemPublicKey>(&enc);
        }
    }

    #[test]
    fn wire_encapsulated_key_roundtrip_all_levels() {
        for level in KEM_LEVELS {
            let ek = encapsulation(level);
            let enc = ek.to_wire().unwrap();
            assert_eq!(enc.len(), WIRE_HEADER_LEN + level.ciphertext_size() + 32);
            assert_header(&enc, 0x02, kem_level_id(level));
            let dec = EncapsulatedKey::from_wire(&enc).unwrap();
            assert_eq!(dec.ml_kem_ct(), ek.ml_kem_ct());
            assert_eq!(dec.ecdh_pk(), ek.ecdh_pk());
            // The shared secret is never encoded.
            assert_eq!(dec.expose_secret(), &[0u8; 64]);
            assert_rejections::<EncapsulatedKey>(&enc);
        }
    }

    #[test]
    fn wire_hybrid_ciphertext_roundtrip_all_levels() {
        for level in KEM_LEVELS {
            for sym_len in [0usize, 1, 37, 4096] {
                let ct = ciphertext(level, sym_len);
                let enc = ct.to_wire().unwrap();
                assert_eq!(
                    enc.len(),
                    WIRE_HEADER_LEN + level.ciphertext_size() + 32 + 12 + 16 + 4 + sym_len
                );
                assert_header(&enc, 0x03, kem_level_id(level));
                let dec = HybridCiphertext::from_wire(&enc).unwrap();
                assert_eq!(dec.kem_ciphertext(), ct.kem_ciphertext());
                assert_eq!(dec.ecdh_ephemeral_pk(), ct.ecdh_ephemeral_pk());
                assert_eq!(dec.symmetric_ciphertext(), ct.symmetric_ciphertext());
                assert_eq!(dec.nonce(), ct.nonce());
                assert_eq!(dec.tag(), ct.tag());
                if sym_len <= 37 {
                    assert_rejections::<HybridCiphertext>(&enc);
                }
            }
        }
    }

    #[test]
    fn wire_sig_public_key_roundtrip_all_parameter_sets() {
        for set in DSA_SETS {
            let pk = sig_pk(set);
            let enc = pk.to_wire().unwrap();
            assert_eq!(enc.len(), WIRE_HEADER_LEN + set.public_key_size() + 32);
            assert_header(&enc, 0x04, dsa_set_id(set));
            let dec = HybridSigPublicKey::from_wire(&enc).unwrap();
            assert_eq!(dec.parameter_set(), set);
            assert_eq!(dec.ml_dsa_pk(), pk.ml_dsa_pk());
            assert_eq!(dec.ed25519_pk(), pk.ed25519_pk());
            assert_rejections::<HybridSigPublicKey>(&enc);
        }
    }

    #[test]
    fn wire_signature_roundtrip_all_parameter_sets() {
        for set in DSA_SETS {
            let sig = signature(set);
            let enc = sig.to_wire().unwrap();
            assert_eq!(enc.len(), WIRE_HEADER_LEN + set.signature_size() + 64);
            assert_header(&enc, 0x05, dsa_set_id(set));
            let dec = HybridSignature::from_wire(&enc).unwrap();
            assert_eq!(dec.ml_dsa_sig(), sig.ml_dsa_sig());
            assert_eq!(dec.ed25519_sig(), sig.ed25519_sig());
            assert_rejections::<HybridSignature>(&enc);
        }
    }

    // ---------------- roundtrips with real key material ----------------

    #[test]
    fn wire_real_hybrid_encryption_survives_encoding_all_levels() {
        for level in KEM_LEVELS {
            let (pk, sk) = kem_hybrid::generate_keypair_with_level(level).unwrap();
            let pk2 = HybridKemPublicKey::from_wire(&pk.to_wire().unwrap()).unwrap();

            let ek = kem_hybrid::encapsulate(&pk2).unwrap();
            let ek2 = EncapsulatedKey::from_wire(&ek.to_wire().unwrap()).unwrap();
            let ss = kem_hybrid::decapsulate(&sk, &ek2).unwrap();
            assert!(bool::from(ss.expose_secret().ct_eq(ek.expose_secret())));

            let ct = encrypt_hybrid(&pk2, b"vault record", None).unwrap();
            let ct2 = HybridCiphertext::from_wire(&ct.to_wire().unwrap()).unwrap();
            let pt = decrypt_hybrid(&sk, &ct2, None).unwrap();
            assert_eq!(pt.as_slice(), b"vault record");
        }
    }

    #[test]
    fn wire_real_hybrid_signature_survives_encoding_all_parameter_sets() {
        for set in DSA_SETS {
            let (pk, sk) = sig_hybrid::generate_keypair_with_parameter_set(set).unwrap();
            let sig = sig_hybrid::sign(&sk, b"vault manifest").unwrap();
            let pk2 = HybridSigPublicKey::from_wire(&pk.to_wire().unwrap()).unwrap();
            let sig2 = HybridSignature::from_wire(&sig.to_wire().unwrap()).unwrap();
            assert!(sig_hybrid::verify(&pk2, b"vault manifest", &sig2).unwrap());
        }
    }

    // ---------------- size caps and encoder validation ----------------

    #[test]
    fn wire_oversized_input_rejected_before_parsing() {
        fn check<T: WireEncode>() {
            // All-zero input: magic is wrong, so only the size check can
            // produce `TooLarge` — proving it runs first.
            let input = vec![0u8; T::MAX_WIRE_LEN + 1];
            assert!(matches!(
                T::from_wire(&input),
                Err(WireError::TooLarge { len, max }) if len == T::MAX_WIRE_LEN + 1
                    && max == T::MAX_WIRE_LEN
            ));
        }
        check::<HybridKemPublicKey>();
        check::<EncapsulatedKey>();
        check::<HybridCiphertext>();
        check::<HybridSigPublicKey>();
        check::<HybridSignature>();
    }

    #[test]
    fn wire_max_wire_len_constants_match_layouts() {
        assert_eq!(HybridKemPublicKey::MAX_WIRE_LEN, 5 + 1568 + 32);
        assert_eq!(EncapsulatedKey::MAX_WIRE_LEN, 5 + 1568 + 32);
        assert_eq!(HybridCiphertext::MAX_WIRE_LEN, 5 + 1568 + 32 + 12 + 16 + 4 + (100 << 20));
        assert_eq!(HybridSigPublicKey::MAX_WIRE_LEN, 5 + 2592 + 32);
        assert_eq!(HybridSignature::MAX_WIRE_LEN, 5 + 4627 + 64);
    }

    #[test]
    fn wire_symmetric_length_prefix_over_cap_rejected_without_allocation() {
        let mut enc = ciphertext(MlKemSecurityLevel::MlKem768, 0).to_wire().unwrap();
        let prefix_at = enc.len() - 4;
        enc[prefix_at..].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            HybridCiphertext::from_wire(&enc),
            Err(WireError::TooLarge { len, max })
                if len == u32::MAX as usize && max == MAX_SYMMETRIC_CIPHERTEXT_LEN
        ));
        // A prefix under the cap but larger than the supplied bytes is
        // truncation, not an allocation of the claimed size.
        enc[prefix_at..].copy_from_slice(&1_000_000u32.to_be_bytes());
        assert!(matches!(HybridCiphertext::from_wire(&enc), Err(WireError::Truncated)));
    }

    #[test]
    fn wire_symmetric_ciphertext_at_cap_roundtrips_and_over_cap_rejected() {
        let ct = ciphertext(MlKemSecurityLevel::MlKem1024, MAX_SYMMETRIC_CIPHERTEXT_LEN);
        let enc = ct.to_wire().unwrap();
        assert_eq!(enc.len(), HybridCiphertext::MAX_WIRE_LEN);
        assert!(HybridCiphertext::from_wire(&enc).is_ok());

        let too_big = HybridCiphertext::new(
            filled(1088, 1),
            filled(32, 1),
            vec![0u8; MAX_SYMMETRIC_CIPHERTEXT_LEN + 1],
            filled(12, 1),
            filled(16, 1),
        );
        assert!(matches!(too_big.to_wire(), Err(WireError::TooLarge { .. })));
    }

    #[test]
    fn wire_encoder_rejects_malformed_components() {
        let level = MlKemSecurityLevel::MlKem768;
        let bad_pk = HybridKemPublicKey::new(filled(100, 1), filled(32, 1), level);
        assert!(matches!(bad_pk.to_wire(), Err(WireError::InvalidComponent(_))));
        let bad_ecdh = HybridKemPublicKey::new(filled(1184, 1), filled(31, 1), level);
        assert!(matches!(bad_ecdh.to_wire(), Err(WireError::InvalidComponent(_))));

        let bad_ek = EncapsulatedKey::for_decapsulate(filled(1000, 1), filled(32, 1));
        assert!(matches!(bad_ek.to_wire(), Err(WireError::InvalidComponent(_))));

        let good = ciphertext(level, 8);
        let parts = |kem: usize, eph: usize, nonce: usize, tag: usize| {
            HybridCiphertext::new(
                filled(kem, 1),
                filled(eph, 1),
                good.symmetric_ciphertext().to_vec(),
                filled(nonce, 1),
                filled(tag, 1),
            )
        };
        for bad in [parts(1087, 32, 12, 16), parts(1088, 0, 12, 16), parts(1088, 32, 11, 16)] {
            assert!(matches!(bad.to_wire(), Err(WireError::InvalidComponent(_))));
        }
        assert!(matches!(parts(1088, 32, 12, 15).to_wire(), Err(WireError::InvalidComponent(_))));

        let bad_sig = HybridSignature::new(filled(3308, 1), filled(64, 1));
        assert!(matches!(bad_sig.to_wire(), Err(WireError::InvalidComponent(_))));
        let bad_ed = HybridSignature::new(filled(3309, 1), filled(63, 1));
        assert!(matches!(bad_ed.to_wire(), Err(WireError::InvalidComponent(_))));
    }

    #[test]
    fn wire_reserved_wrapped_key_tag_is_rejected() {
        let mut enc = kem_pk(MlKemSecurityLevel::MlKem768).to_wire().unwrap();
        enc[3] = WRAPPED_KEY_TYPE_TAG;
        assert!(matches!(
            HybridKemPublicKey::from_wire(&enc),
            Err(WireError::WrongType { found: WRAPPED_KEY_TYPE_TAG, .. })
        ));
    }

    #[test]
    fn wire_cross_type_decoding_is_rejected() {
        let kem = kem_pk(MlKemSecurityLevel::MlKem1024).to_wire().unwrap();
        // ML-KEM-1024 public key and ciphertext have the same length (1568),
        // so only the type tag separates them.
        assert!(matches!(
            EncapsulatedKey::from_wire(&kem),
            Err(WireError::WrongType { expected: 0x02, found: 0x01 })
        ));
        // ML-DSA-44 signature encoding (2489 B) fits under the signature
        // public-key cap (2629 B), so the type tag is what rejects it.
        let sig = signature(MlDsaParameterSet::MlDsa44).to_wire().unwrap();
        assert!(matches!(
            HybridSigPublicKey::from_wire(&sig),
            Err(WireError::WrongType { expected: 0x04, found: 0x05 })
        ));
    }

    // ---------------- property tests ----------------

    fn kem_level_strategy() -> impl Strategy<Value = MlKemSecurityLevel> {
        prop::sample::select(KEM_LEVELS.to_vec())
    }

    fn dsa_set_strategy() -> impl Strategy<Value = MlDsaParameterSet> {
        prop::sample::select(DSA_SETS.to_vec())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn wire_prop_kem_types_roundtrip(
            level in kem_level_strategy(),
            seed in any::<u8>(),
            ecdh in prop::array::uniform32(any::<u8>()),
            nonce in prop::array::uniform12(any::<u8>()),
            tag in prop::array::uniform16(any::<u8>()),
            sym in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            let pk = HybridKemPublicKey::new(
                filled(level.public_key_size(), seed), ecdh.to_vec(), level);
            let pk2 = HybridKemPublicKey::from_wire(&pk.to_wire().unwrap()).unwrap();
            prop_assert_eq!(pk2.ml_kem_pk(), pk.ml_kem_pk());
            prop_assert_eq!(pk2.ecdh_pk(), pk.ecdh_pk());
            prop_assert_eq!(pk2.security_level(), level);

            let ek = EncapsulatedKey::for_decapsulate(
                filled(level.ciphertext_size(), seed), ecdh.to_vec());
            let ek2 = EncapsulatedKey::from_wire(&ek.to_wire().unwrap()).unwrap();
            prop_assert_eq!(ek2.ml_kem_ct(), ek.ml_kem_ct());
            prop_assert_eq!(ek2.ecdh_pk(), ek.ecdh_pk());

            let ct = HybridCiphertext::new(
                filled(level.ciphertext_size(), seed),
                ecdh.to_vec(),
                sym.clone(),
                nonce.to_vec(),
                tag.to_vec(),
            );
            let enc = ct.to_wire().unwrap();
            let ct2 = HybridCiphertext::from_wire(&enc).unwrap();
            prop_assert_eq!(ct2.symmetric_ciphertext(), sym.as_slice());
            prop_assert_eq!(ct2.nonce(), nonce.as_slice());
            prop_assert_eq!(ct2.tag(), tag.as_slice());
            prop_assert_eq!(ct2.to_wire().unwrap(), enc);
        }

        #[test]
        fn wire_prop_sig_types_roundtrip(
            set in dsa_set_strategy(),
            seed in any::<u8>(),
            ed_pk in prop::array::uniform32(any::<u8>()),
            ed_sig in prop::collection::vec(any::<u8>(), 64..=64),
        ) {
            let pk = HybridSigPublicKey::new(
                set, filled(set.public_key_size(), seed), ed_pk.to_vec()).unwrap();
            let pk2 = HybridSigPublicKey::from_wire(&pk.to_wire().unwrap()).unwrap();
            prop_assert_eq!(pk2.parameter_set(), set);
            prop_assert_eq!(pk2.ml_dsa_pk(), pk.ml_dsa_pk());
            prop_assert_eq!(pk2.ed25519_pk(), pk.ed25519_pk());

            let sig = HybridSignature::new(filled(set.signature_size(), seed), ed_sig.clone());
            let sig2 = HybridSignature::from_wire(&sig.to_wire().unwrap()).unwrap();
            prop_assert_eq!(sig2.ml_dsa_sig(), sig.ml_dsa_sig());
            prop_assert_eq!(sig2.ed25519_sig(), ed_sig.as_slice());
        }

        #[test]
        fn wire_prop_arbitrary_input_never_panics(
            data in prop::collection::vec(any::<u8>(), 0..6000),
        ) {
            // Totality: any input decodes or errors; a successful decode
            // re-encodes to the identical bytes (one encoding per value).
            if let Ok(v) = HybridKemPublicKey::from_wire(&data) {
                prop_assert_eq!(v.to_wire().unwrap(), data.clone());
            }
            if let Ok(v) = EncapsulatedKey::from_wire(&data) {
                prop_assert_eq!(v.to_wire().unwrap(), data.clone());
            }
            if let Ok(v) = HybridCiphertext::from_wire(&data) {
                prop_assert_eq!(v.to_wire().unwrap(), data.clone());
            }
            if let Ok(v) = HybridSigPublicKey::from_wire(&data) {
                prop_assert_eq!(v.to_wire().unwrap(), data.clone());
            }
            if let Ok(v) = HybridSignature::from_wire(&data) {
                prop_assert_eq!(v.to_wire().unwrap(), data);
            }
        }
    }
}
