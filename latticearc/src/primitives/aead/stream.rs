#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Streaming AEAD: AES-256-GCM-HKDF segments (Tink-derived core) under a
//! versioned, key- and context-committing LatticeArc header.
//!
//! # Threat model
//!
//! The adversary controls every byte the decryptor reads: the header and any
//! segment, in any order, from any stream. The guarantees are:
//!
//! - **Wrong key or wrong context fails before any plaintext is released.**
//!   The format-2 header carries a commitment tag over the key *and* the
//!   caller's associated data (CMT-4) that [`StreamDecryptor::new`] verifies
//!   before a segment cipher is even derived, so a stream cannot be opened
//!   under two different keys, nor under two different contexts by someone
//!   who holds the key, and a wrong key or context never reaches AES-GCM.
//!   Legacy format-1 headers commit to the key only (CMT-1); they are read
//!   only under [`FormatPolicy::AllowV1`] (see [Format versions](#format-versions)).
//! - **Truncation, reordering, splicing and tampering are detected.** Every
//!   segment is sealed under a nonce that encodes its index and a
//!   last-segment flag, and under per-segment associated data that binds the
//!   SHA-256 hash of the full header and the same index/flag. A segment from
//!   another stream (different key, salt or nonce prefix), a segment moved to
//!   a different index, a non-final segment presented as final, or a single
//!   flipped bit anywhere all fail authentication.
//! - **The 32-bit segment counter never wraps.** Advancing past `u32::MAX`
//!   returns [`AeadError::SegmentCounterExhausted`]; the Kani harness in this
//!   module proves the increment is checked for every input.
//! - **Errors are opaque on the decrypt path.** Header parse failures,
//!   commitment mismatch and AES-GCM tag failure all surface as the same
//!   [`AeadError::DecryptionFailed`] string, so a remote caller cannot tell
//!   which check rejected the input (design pattern 6). The one exception is
//!   [`AeadError::LegacyFormatRejected`], which reports only the public
//!   version byte of a well-formed format-1 header that the caller's
//!   [`FormatPolicy`] does not accept.
//!
//! Out of scope: nonce-misuse resistance (a stream key must not be reused
//! with the same salt and nonce prefix, which the random header material
//! makes a 2^-312 event per `new`), and hiding the plaintext length (segment
//! boundaries are visible by construction).
//!
//! # Construction
//!
//! The segment layer is Google Tink's `AES-GCM-HKDF-STREAMING`, specified at
//! <https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming>
//! and implemented in
//! <https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/subtle/AesGcmHkdfStreaming.java>:
//!
//! ```text
//! tink_header  = header_length (1 byte, = 40) || salt (32 bytes) || nonce_prefix (7 bytes)
//! segment_key  = HKDF-SHA256(ikm = stream key, salt = salt, info = associated data, L = 32)
//! nonce_i      = nonce_prefix (7) || i as u32 big-endian (4) || last_flag (1: 0x00 / 0x01)
//! C_i          = AES-256-GCM(segment_key, nonce_i, aad_i, M_i) || tag (16)
//! ```
//!
//! `|C_i| == segment_size` for every non-final segment, so each plaintext
//! segment carries `segment_size - 16` bytes, and the first segment is
//! shorter by the 40-byte Tink header so that `tink_header || C_0` also fills
//! exactly one `segment_size` block. Tink validates this core: the
//! `tink_java_sha256_vector` test reproduces the HKDF-SHA256 known-answer
//! vector from
//! <https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/streamingaead/internal/testing/AesGcmHkdfStreamingTestUtil.java>
//! (`createTestVector2`) byte for byte.
//!
//! Files produced here are **not** Tink-interoperable, because two LatticeArc
//! layers sit on top of that core:
//!
//! ```text
//! header = version (1, = 0x02) || flags (1, = 0x00) || segment_size (u32 BE)
//!       || tink_header (40) || commitment (32)                      = 78 bytes
//! commitment = HMAC-SHA256(stream key,
//!                          STREAM_AEAD_COMMITMENT_V2 || header[..46] || SHA-256(aad))
//! aad_i      = SHA-256(header) (32) || i as u32 BE (4) || last_flag (1)
//! ```
//!
//! - The **commitment** follows the "UtC" shape of Bellare and Hoang,
//!   *Efficient Schemes for Committing Authenticated Encryption*
//!   (EUROCRYPT 2022), extended to the associated data by their "CTX"
//!   transform (and Chan and Rogaway, *On Committing Authenticated
//!   Encryption*, ESORICS 2022): a PRF of the key over the public header
//!   material and a hash of the caller's associated data is stored alongside
//!   the ciphertext and checked before decryption. That turns a
//!   non-committing AEAD (AES-GCM; see Albertini et al., *How to Abuse and
//!   Fix Authenticated Encryption with Key Commitment*, USENIX Security 2022)
//!   into one that commits to the key and the context (CMT-4). The HMAC
//!   message has a fixed length (label, 46-byte prefix, 32-byte hash), so it
//!   encodes `(header prefix, aad)` injectively, and HMAC-SHA256 with a
//!   32-byte key is collision resistant in `(key, message)`: two different
//!   `(key, aad)` pairs that verify the same header would yield a SHA-256
//!   collision.
//! - The **per-segment associated data** follows the STREAM construction of
//!   Hoang, Reyhanitabar, Rogaway and Vizár, *Online Authenticated-Encryption
//!   and its Nonce-Reuse Misuse-Resistance* (CCS 2015): each segment is bound
//!   to the stream it belongs to and to its position in it, in addition to
//!   Tink's nonce-level binding.
//!
//! # Format versions
//!
//! | Version | Commitment input | Commits to | Written by |
//! |---|---|---|---|
//! | `0x02` | `STREAM_AEAD_COMMITMENT_V2 \|\| header[..46] \|\| SHA-256(aad)` | key and aad (CMT-4) | every encoder since 0.16.0 |
//! | `0x01` | `STREAM_AEAD_COMMITMENT \|\| header[..46]` | key only (CMT-1) | 0.13.0 – 0.15.x |
//!
//! Everything else (layout, Tink core, per-segment AAD) is identical. In
//! format 1 the associated data reaches only the segment-key HKDF, so a key
//! holder can build one segment that authenticates under two segment keys
//! derived from two different contexts. [`StreamDecryptor::new`] accepts
//! format 2 only; [`StreamDecryptor::new_with_policy`] with
//! [`FormatPolicy::AllowV1`] also opens format 1 so existing data can be
//! read and re-encrypted, and [`StreamDecryptor::format_version`] reports
//! which one was opened.
//!
//! # Random access
//!
//! Segment `i` for `i >= 1` holds plaintext bytes
//! `first + (i - 1) * pss ..` where `first` is
//! [`StreamDecryptor::first_plaintext_segment_size`] and `pss` is
//! [`StreamDecryptor::plaintext_segment_size`]; the matching ciphertext
//! segment is at byte offset `i * segment_size` of the segment stream (the
//! 78-byte header is stored separately by the caller). Callers decrypt any
//! segment independently with [`StreamDecryptor::open_segment`], passing
//! `is_last` for the final one.

use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{
    AeadCipher, AeadError, FormatPolicy, Nonce, TAG_LEN, is_all_zero_key,
};
use crate::primitives::hash::sha2::sha256;
use crate::primitives::kdf::hkdf::hkdf;
use crate::primitives::mac::hmac::hmac_sha256;
use crate::primitives::rand::secure_rng;
use crate::primitives::resource_limits::validate_aad_size;
use crate::types::domains::{STREAM_AEAD_COMMITMENT, STREAM_AEAD_COMMITMENT_V2};
use rand::Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Version byte at offset 0 of every stream header produced by this module
/// (format 2: key- and context-committing).
pub const STREAM_FORMAT_VERSION: u8 = 2;

/// Version byte of the legacy format-1 header (key-committing only). Read
/// under [`FormatPolicy::AllowV1`]; never written.
pub const STREAM_FORMAT_VERSION_V1: u8 = 1;

/// Length of the stream key in bytes (AES-256-GCM-HKDF).
pub const STREAM_KEY_LEN: usize = 32;

/// Length of the Tink nonce prefix (random per stream).
pub const NONCE_PREFIX_LEN: usize = 7;

/// Smallest accepted ciphertext segment size.
///
/// Must exceed `TINK_HEADER_LEN + TAG_LEN` (56) so the first segment can hold
/// at least one plaintext byte; 64 leaves 8.
pub const MIN_SEGMENT_SIZE: u32 = 64;

/// Largest accepted ciphertext segment size (16 MiB).
pub const MAX_SEGMENT_SIZE: u32 = 16 * 1024 * 1024;

/// Length of the Tink-layout header: `header_length || salt || nonce_prefix`.
pub const TINK_HEADER_LEN: usize = 1 + STREAM_KEY_LEN + NONCE_PREFIX_LEN;

/// Length of the HMAC-SHA256 commitment tag.
pub const COMMITMENT_LEN: usize = 32;

/// Length of the full LatticeArc stream header returned by
/// [`StreamEncryptor::header`] and consumed by [`StreamDecryptor::new`].
pub const HEADER_LEN: usize = 1 + 1 + 4 + TINK_HEADER_LEN + COMMITMENT_LEN;

/// Flags byte. No flag is defined for versions 1 and 2; decryptors reject any
/// other value so the byte is available to a future version.
const FLAGS_V1: u8 = 0;

/// Bytes of the header covered by the commitment (everything before it).
const COMMITTED_PREFIX_LEN: usize = HEADER_LEN - COMMITMENT_LEN;

/// Byte offsets of the header fields.
const OFFSET_FLAGS: usize = 1;
const OFFSET_SEGMENT_SIZE: usize = 2;
const OFFSET_TINK_HEADER: usize = 6;
const OFFSET_SALT: usize = OFFSET_TINK_HEADER + 1;
const OFFSET_NONCE_PREFIX: usize = OFFSET_SALT + STREAM_KEY_LEN;
const OFFSET_COMMITMENT: usize = COMMITTED_PREFIX_LEN;

/// Length of the per-segment associated data: `sha256(header) || index || last`.
const SEGMENT_AAD_LEN: usize = 32 + 4 + 1;

/// Single opaque string for every adversary-reachable decrypt failure.
const DECRYPTION_FAILED: &str = "decryption failed";

/// Single opaque string for every encrypt-side internal failure.
const ENCRYPTION_FAILED: &str = "encryption failed";

// ============================================================================
// Tink AES-GCM-HKDF-STREAMING core
// ============================================================================

/// Derives the Tink segment cipher: `HKDF-SHA256(ikm = key, salt, info = aad)`.
///
/// Generic over the AEAD so the AES-128 Tink known-answer vector can exercise
/// exactly the production derivation path. Returns `None` on any failure; the
/// callers map that to their path's opaque error.
fn derive_segment_cipher<C: AeadCipher>(ikm: &[u8], salt: &[u8], aad: &[u8]) -> Option<C> {
    // RFC 5869 treats absent and empty `info` identically; the crate wrapper
    // only distinguishes them for salt, so pass empty aad as `None`.
    let info = (!aad.is_empty()).then_some(aad);
    let okm = hkdf(ikm, Some(salt), info, C::KEY_LEN).ok()?;
    C::new(okm.expose_secret()).ok()
}

/// Tink segment nonce: `nonce_prefix (7) || index (u32 BE) || last_flag (1)`.
fn segment_nonce(prefix: [u8; NONCE_PREFIX_LEN], index: u32, last: bool) -> Nonce {
    let i = index.to_be_bytes();
    [
        prefix[0],
        prefix[1],
        prefix[2],
        prefix[3],
        prefix[4],
        prefix[5],
        prefix[6],
        i[0],
        i[1],
        i[2],
        i[3],
        u8::from(last),
    ]
}

/// Seals one Tink segment and returns `ciphertext || tag`.
fn seal_tink_segment<C: AeadCipher>(
    cipher: &C,
    prefix: [u8; NONCE_PREFIX_LEN],
    index: u32,
    last: bool,
    aad: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let nonce = segment_nonce(prefix, index, last);
    let (mut segment, tag) = cipher.encrypt(&nonce, plaintext, aad)?;
    segment.extend_from_slice(&tag);
    Ok(segment)
}

/// Opens one Tink segment given as `ciphertext || tag`.
fn open_tink_segment<C: AeadCipher>(
    cipher: &C,
    prefix: [u8; NONCE_PREFIX_LEN],
    index: u32,
    last: bool,
    aad: Option<&[u8]>,
    segment: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let opaque = || AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string());
    let split = segment.len().checked_sub(TAG_LEN).ok_or_else(opaque)?;
    let (ciphertext, tag_bytes) = segment.split_at_checked(split).ok_or_else(opaque)?;
    let tag: [u8; TAG_LEN] = tag_bytes.try_into().map_err(|_e| opaque())?;
    let nonce = segment_nonce(prefix, index, last);
    cipher.decrypt(&nonce, ciphertext, &tag, aad).map_err(|_e| opaque())
}

// ============================================================================
// LatticeArc header / commitment / per-segment AAD
// ============================================================================

/// Checked successor of a segment index. Never wraps: `u32::MAX` has no
/// successor and yields [`AeadError::SegmentCounterExhausted`].
fn next_segment_index(current: u32) -> Result<u32, AeadError> {
    current.checked_add(1).ok_or(AeadError::SegmentCounterExhausted)
}

/// Returns `Ok(())` iff `segment_size` lies in the accepted range.
fn validate_segment_size(segment_size: u32) -> Result<(), AeadError> {
    if (MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&segment_size) {
        Ok(())
    } else {
        Err(AeadError::InvalidSegmentSize)
    }
}

/// Plaintext capacity of segment `index` for a given ciphertext segment size:
/// `segment_size - 16`, minus the 40-byte Tink header for segment 0.
/// `None` only when the arithmetic would underflow (never for a validated
/// segment size; see the Kani harness).
fn plaintext_capacity(segment_size: u32, index: u32) -> Option<usize> {
    let size = usize::try_from(segment_size).ok()?;
    let ciphertext_capacity = if index == 0 { size.checked_sub(TINK_HEADER_LEN)? } else { size };
    ciphertext_capacity.checked_sub(TAG_LEN)
}

/// Commitment tag for header format `version`.
///
/// - Format 2: `HMAC(key, STREAM_AEAD_COMMITMENT_V2 || prefix || SHA-256(aad))`
///   commits to the key and the associated data (CMT-4).
/// - Format 1: `HMAC(key, STREAM_AEAD_COMMITMENT || prefix)` commits to the
///   key only (CMT-1); `aad` is ignored.
///
/// `None` for any other version or on HMAC/hash failure.
fn commitment(
    key: &[u8; STREAM_KEY_LEN],
    version: u8,
    committed_prefix: &[u8],
    aad: &[u8],
) -> Option<[u8; COMMITMENT_LEN]> {
    let mut message = Vec::with_capacity(
        STREAM_AEAD_COMMITMENT_V2.len().saturating_add(committed_prefix.len()).saturating_add(32),
    );
    match version {
        STREAM_FORMAT_VERSION => {
            let aad_hash = sha256(aad).ok()?;
            message.extend_from_slice(STREAM_AEAD_COMMITMENT_V2);
            message.extend_from_slice(committed_prefix);
            message.extend_from_slice(&aad_hash);
        }
        STREAM_FORMAT_VERSION_V1 => {
            message.extend_from_slice(STREAM_AEAD_COMMITMENT);
            message.extend_from_slice(committed_prefix);
        }
        _ => return None,
    }
    hmac_sha256(key, &message).ok()
}

/// Per-segment associated data: `sha256(header) || index (u32 BE) || last`.
fn segment_aad(header_hash: &[u8; 32], index: u32, last: bool) -> [u8; SEGMENT_AAD_LEN] {
    let mut aad = [0u8; SEGMENT_AAD_LEN];
    let i = index.to_be_bytes();
    for (dst, src) in aad.iter_mut().zip(header_hash.iter().chain(i.iter())) {
        *dst = *src;
    }
    aad[SEGMENT_AAD_LEN - 1] = u8::from(last);
    aad
}

/// Validates the caller context and the stream key shared by both directions.
fn validate_key_and_aad(
    key: &[u8; STREAM_KEY_LEN],
    aad: &[u8],
    size_error: impl Fn() -> AeadError,
) -> Result<(), AeadError> {
    if aad.is_empty() {
        return Err(AeadError::EmptyContext);
    }
    validate_aad_size(aad.len()).map_err(|_e| size_error())?;
    if is_all_zero_key(key) {
        return Err(AeadError::WeakKey);
    }
    Ok(())
}

// ============================================================================
// StreamEncryptor
// ============================================================================

/// Sequential streaming encryptor.
///
/// Seal every full plaintext segment with [`seal_segment`](Self::seal_segment)
/// and the final (possibly shorter, possibly empty) one with
/// [`finish`](Self::finish). Store [`header`](Self::header) alongside the
/// segments; the decryptor needs it before it can open anything.
///
/// The derived segment key is zeroized on drop (it lives in an
/// [`AesGcm256`], which is `ZeroizeOnDrop`).
pub struct StreamEncryptor {
    cipher: AesGcm256,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    header: [u8; HEADER_LEN],
    header_hash: [u8; 32],
    segment_size: u32,
    first_plaintext_segment_size: usize,
    plaintext_segment_size: usize,
    next_index: u32,
}

impl std::fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamEncryptor")
            .field("cipher", &"[REDACTED]")
            .field("segment_size", &self.segment_size)
            .field("next_index", &self.next_index)
            .finish_non_exhaustive()
    }
}

impl StreamEncryptor {
    /// Starts a new format-2 stream under `key`, bound to the caller's
    /// non-empty `aad` (a purpose string such as `app/v1/file`), with
    /// ciphertext segments of exactly `segment_size` bytes. Salt and nonce
    /// prefix are drawn from the OS CSPRNG. The header commits to both `key`
    /// and `aad`.
    ///
    /// # Errors
    /// - [`AeadError::InvalidSegmentSize`] unless
    ///   `MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE`.
    /// - [`AeadError::EmptyContext`] if `aad` is empty.
    /// - [`AeadError::WeakKey`] if `key` is all zero.
    /// - [`AeadError::EncryptionFailed`] if `aad` exceeds the configured AAD
    ///   resource limit or key derivation fails.
    pub fn new(
        key: &[u8; STREAM_KEY_LEN],
        aad: &[u8],
        segment_size: u32,
    ) -> Result<Self, AeadError> {
        let mut salt = Zeroizing::new([0u8; STREAM_KEY_LEN]);
        secure_rng().fill_bytes(&mut *salt);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        secure_rng().fill_bytes(&mut nonce_prefix);
        Self::build(STREAM_FORMAT_VERSION, key, aad, segment_size, &salt, nonce_prefix)
    }

    /// Deterministic constructor for the pinned-output tests; production code
    /// must go through [`Self::new`], which draws fresh header material and
    /// always writes the current format. `version` may be the legacy format
    /// 1 here only so its known-answer bytes stay pinned.
    #[cfg(test)]
    pub(crate) fn new_with_material(
        version: u8,
        key: &[u8; STREAM_KEY_LEN],
        aad: &[u8],
        segment_size: u32,
        salt: &[u8; STREAM_KEY_LEN],
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
    ) -> Result<Self, AeadError> {
        Self::build(version, key, aad, segment_size, salt, nonce_prefix)
    }

    fn build(
        version: u8,
        key: &[u8; STREAM_KEY_LEN],
        aad: &[u8],
        segment_size: u32,
        salt: &[u8; STREAM_KEY_LEN],
        nonce_prefix: [u8; NONCE_PREFIX_LEN],
    ) -> Result<Self, AeadError> {
        let opaque = || AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string());
        validate_segment_size(segment_size)?;
        validate_key_and_aad(key, aad, opaque)?;
        let first_plaintext_segment_size =
            plaintext_capacity(segment_size, 0).ok_or_else(opaque)?;
        let plaintext_segment_size = plaintext_capacity(segment_size, 1).ok_or_else(opaque)?;

        let tink_header_len = u8::try_from(TINK_HEADER_LEN).map_err(|_e| opaque())?;
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.push(version);
        header.push(FLAGS_V1);
        header.extend_from_slice(&segment_size.to_be_bytes());
        header.push(tink_header_len);
        header.extend_from_slice(salt.as_slice());
        header.extend_from_slice(&nonce_prefix);
        let tag = commitment(key, version, &header, aad).ok_or_else(opaque)?;
        header.extend_from_slice(&tag);
        let header: [u8; HEADER_LEN] = header.try_into().map_err(|_e| opaque())?;
        let header_hash = sha256(&header).map_err(|_e| opaque())?;

        let cipher =
            derive_segment_cipher::<AesGcm256>(key, salt.as_slice(), aad).ok_or_else(opaque)?;
        Ok(Self {
            cipher,
            nonce_prefix,
            header,
            header_hash,
            segment_size,
            first_plaintext_segment_size,
            plaintext_segment_size,
            next_index: 0,
        })
    }

    /// The 78-byte stream header: `version || flags || segment_size ||
    /// tink_header || commitment`. Store it with the ciphertext.
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// Ciphertext segment size this stream was created with.
    #[must_use]
    pub const fn segment_size(&self) -> u32 {
        self.segment_size
    }

    /// Plaintext bytes carried by every segment after the first
    /// (`segment_size - 16`).
    #[must_use]
    pub const fn plaintext_segment_size(&self) -> usize {
        self.plaintext_segment_size
    }

    /// Plaintext bytes carried by segment 0 (`segment_size - 16 - 40`).
    #[must_use]
    pub const fn first_plaintext_segment_size(&self) -> usize {
        self.first_plaintext_segment_size
    }

    /// Index the next sealed segment will receive.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Test hook to reach the top of the counter without sealing 2^32 segments.
    #[cfg(test)]
    pub(crate) const fn set_next_index(&mut self, index: u32) {
        self.next_index = index;
    }

    fn plaintext_capacity_at(&self, index: u32) -> usize {
        if index == 0 { self.first_plaintext_segment_size } else { self.plaintext_segment_size }
    }

    /// Seals one non-final segment. `plaintext` must be exactly
    /// [`first_plaintext_segment_size`](Self::first_plaintext_segment_size)
    /// bytes for the first call and
    /// [`plaintext_segment_size`](Self::plaintext_segment_size) bytes after
    /// that; the returned ciphertext is `plaintext.len() + 16` bytes.
    ///
    /// # Errors
    /// - [`AeadError::InvalidSegmentLength`] if `plaintext` is not exactly
    ///   the segment's capacity.
    /// - [`AeadError::SegmentCounterExhausted`] if this segment would have
    ///   index `u32::MAX`, which no further segment could follow.
    /// - [`AeadError::EncryptionFailed`] if AES-GCM fails.
    #[must_use = "the sealed segment must be stored"]
    pub fn seal_segment(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let index = self.next_index;
        if plaintext.len() != self.plaintext_capacity_at(index) {
            return Err(AeadError::InvalidSegmentLength);
        }
        let next = next_segment_index(index)?;
        let aad = segment_aad(&self.header_hash, index, false);
        let segment = seal_tink_segment(
            &self.cipher,
            self.nonce_prefix,
            index,
            false,
            Some(&aad),
            plaintext,
        )?;
        self.next_index = next;
        Ok(segment)
    }

    /// Seals the final segment (flagged as last) and consumes the encryptor.
    /// `last_plaintext` may be empty and must not exceed the current
    /// segment's capacity.
    ///
    /// # Errors
    /// - [`AeadError::InvalidSegmentLength`] if `last_plaintext` is longer
    ///   than the segment's capacity.
    /// - [`AeadError::EncryptionFailed`] if AES-GCM fails.
    #[must_use = "the sealed final segment must be stored"]
    pub fn finish(self, last_plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        let index = self.next_index;
        if last_plaintext.len() > self.plaintext_capacity_at(index) {
            return Err(AeadError::InvalidSegmentLength);
        }
        let aad = segment_aad(&self.header_hash, index, true);
        seal_tink_segment(&self.cipher, self.nonce_prefix, index, true, Some(&aad), last_plaintext)
    }
}

// ============================================================================
// StreamDecryptor
// ============================================================================

/// Streaming decryptor with random access.
///
/// [`new`](Self::new) parses the header and verifies the commitment; it
/// fails under a wrong key or (format 2) a wrong `aad` before any segment can
/// be opened. After that,
/// [`open_segment`](Self::open_segment) decrypts any segment by index and
/// [`open_next`](Self::open_next) walks the stream sequentially.
pub struct StreamDecryptor {
    cipher: AesGcm256,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    format_version: u8,
    header_hash: [u8; 32],
    segment_size: u32,
    first_plaintext_segment_size: usize,
    plaintext_segment_size: usize,
    next_index: u32,
    finished: bool,
}

impl std::fmt::Debug for StreamDecryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDecryptor")
            .field("cipher", &"[REDACTED]")
            .field("format_version", &self.format_version)
            .field("segment_size", &self.segment_size)
            .field("next_index", &self.next_index)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl StreamDecryptor {
    /// Parses a format-2 `header`, verifies its commitment under `key` and
    /// `aad`, and derives the segment cipher bound to `aad`. Equivalent to
    /// [`new_with_policy`](Self::new_with_policy) with
    /// [`FormatPolicy::RequireV2`]: a legacy format-1 header is refused.
    ///
    /// # Errors
    /// As [`new_with_policy`](Self::new_with_policy); a well-formed format-1
    /// header yields [`AeadError::LegacyFormatRejected`].
    pub fn new(key: &[u8; STREAM_KEY_LEN], aad: &[u8], header: &[u8]) -> Result<Self, AeadError> {
        Self::new_with_policy(key, aad, header, FormatPolicy::RequireV2)
    }

    /// Parses `header`, checks its format version against `policy`, verifies
    /// the commitment under `key` (and, for format 2, `aad`) and derives the
    /// segment cipher bound to `aad`.
    ///
    /// Under format 2 a wrong `aad` fails here, at the constant-time
    /// commitment check, before any key derivation or AES-GCM work. Under
    /// format 1 (only with [`FormatPolicy::AllowV1`]) a wrong `aad` still
    /// fails, but only when a segment is opened, and the stream is not
    /// context-committing.
    ///
    /// # Errors
    /// - [`AeadError::EmptyContext`] if `aad` is empty.
    /// - [`AeadError::WeakKey`] if `key` is all zero.
    /// - [`AeadError::LegacyFormatRejected`] if `header` is a well-formed
    ///   format-1 header and `policy` does not accept format 1.
    /// - [`AeadError::DecryptionFailed`] for every other failure: wrong
    ///   header length, unknown version or flags, segment size out of range,
    ///   commitment mismatch (wrong key, wrong `aad` or tampered header),
    ///   oversize `aad` or key-derivation failure. These are deliberately
    ///   indistinguishable.
    pub fn new_with_policy(
        key: &[u8; STREAM_KEY_LEN],
        aad: &[u8],
        header: &[u8],
        policy: FormatPolicy,
    ) -> Result<Self, AeadError> {
        let opaque = || AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string());
        validate_key_and_aad(key, aad, opaque)?;
        let header: &[u8; HEADER_LEN] = header.try_into().map_err(|_e| opaque())?;

        let version = header[0];
        if (version != STREAM_FORMAT_VERSION && version != STREAM_FORMAT_VERSION_V1)
            || header[OFFSET_FLAGS] != FLAGS_V1
        {
            return Err(opaque());
        }
        let segment_size_bytes: [u8; 4] = header
            .get(OFFSET_SEGMENT_SIZE..OFFSET_TINK_HEADER)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(opaque)?;
        let segment_size = u32::from_be_bytes(segment_size_bytes);
        validate_segment_size(segment_size).map_err(|_e| opaque())?;
        if usize::from(header[OFFSET_TINK_HEADER]) != TINK_HEADER_LEN {
            return Err(opaque());
        }
        // Only the public version byte decides this, after the structural
        // checks, so it reveals nothing beyond what the caller supplied.
        if !policy.accepts(version) {
            return Err(AeadError::LegacyFormatRejected);
        }
        let salt: &[u8] = header.get(OFFSET_SALT..OFFSET_NONCE_PREFIX).ok_or_else(opaque)?;
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = header
            .get(OFFSET_NONCE_PREFIX..OFFSET_COMMITMENT)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(opaque)?;

        let committed_prefix = header.get(..COMMITTED_PREFIX_LEN).ok_or_else(opaque)?;
        let stored = header.get(OFFSET_COMMITMENT..).ok_or_else(opaque)?;
        let expected = commitment(key, version, committed_prefix, aad).ok_or_else(opaque)?;
        if !bool::from(expected.as_slice().ct_eq(stored)) {
            return Err(opaque());
        }

        let header_hash = sha256(header).map_err(|_e| opaque())?;
        let first_plaintext_segment_size =
            plaintext_capacity(segment_size, 0).ok_or_else(opaque)?;
        let plaintext_segment_size = plaintext_capacity(segment_size, 1).ok_or_else(opaque)?;
        let cipher = derive_segment_cipher::<AesGcm256>(key, salt, aad).ok_or_else(opaque)?;
        Ok(Self {
            cipher,
            nonce_prefix,
            format_version: version,
            header_hash,
            segment_size,
            first_plaintext_segment_size,
            plaintext_segment_size,
            next_index: 0,
            finished: false,
        })
    }

    /// Format version of the opened header: [`STREAM_FORMAT_VERSION`] (2) or,
    /// only under [`FormatPolicy::AllowV1`], [`STREAM_FORMAT_VERSION_V1`] (1).
    /// A caller that opened format 1 should re-encrypt the data.
    #[must_use]
    pub const fn format_version(&self) -> u8 {
        self.format_version
    }

    /// Ciphertext segment size recorded in the header.
    #[must_use]
    pub const fn segment_size(&self) -> u32 {
        self.segment_size
    }

    /// Plaintext bytes carried by every segment after the first.
    #[must_use]
    pub const fn plaintext_segment_size(&self) -> usize {
        self.plaintext_segment_size
    }

    /// Plaintext bytes carried by segment 0.
    #[must_use]
    pub const fn first_plaintext_segment_size(&self) -> usize {
        self.first_plaintext_segment_size
    }

    /// Index [`open_next`](Self::open_next) will decrypt on its next call.
    #[must_use]
    pub const fn next_index(&self) -> u32 {
        self.next_index
    }

    /// `true` once [`open_next`](Self::open_next) has accepted the final segment.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Test hook to reach the top of the counter without opening 2^32 segments.
    #[cfg(test)]
    pub(crate) const fn set_next_index(&mut self, index: u32) {
        self.next_index = index;
    }

    fn plaintext_capacity_at(&self, index: u32) -> usize {
        if index == 0 { self.first_plaintext_segment_size } else { self.plaintext_segment_size }
    }

    /// Decrypts the segment at `index`. `segment` is `ciphertext || tag`
    /// exactly as returned by the encryptor, and `is_last` must be `true`
    /// for the segment produced by [`StreamEncryptor::finish`].
    ///
    /// Random access is safe: each call verifies the segment against this
    /// stream's header hash, the index and the last flag.
    ///
    /// # Errors
    /// [`AeadError::DecryptionFailed`] if the segment has an impossible length
    /// for its position, belongs to another stream or index, has the wrong
    /// last flag, or fails AES-GCM authentication. These are deliberately
    /// indistinguishable.
    pub fn open_segment(
        &self,
        index: u32,
        segment: &[u8],
        is_last: bool,
    ) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        let opaque = || AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string());
        let max_len = self.plaintext_capacity_at(index).checked_add(TAG_LEN).ok_or_else(opaque)?;
        let length_ok = if is_last {
            segment.len() >= TAG_LEN && segment.len() <= max_len
        } else {
            segment.len() == max_len
        };
        if !length_ok {
            return Err(opaque());
        }
        let aad = segment_aad(&self.header_hash, index, is_last);
        open_tink_segment(&self.cipher, self.nonce_prefix, index, is_last, Some(&aad), segment)
    }

    /// Decrypts the next segment in sequence. The internal counter advances
    /// only on success; after the final segment (`is_last == true`) is
    /// accepted, further calls fail.
    ///
    /// # Errors
    /// - [`AeadError::StreamExhausted`] after the final segment was accepted.
    /// - [`AeadError::SegmentCounterExhausted`] if a non-final segment at
    ///   index `u32::MAX` was accepted and the counter cannot advance.
    /// - [`AeadError::DecryptionFailed`] as for
    ///   [`open_segment`](Self::open_segment).
    pub fn open_next(
        &mut self,
        segment: &[u8],
        is_last: bool,
    ) -> Result<Zeroizing<Vec<u8>>, AeadError> {
        if self.finished {
            return Err(AeadError::StreamExhausted);
        }
        let index = self.next_index;
        let plaintext = self.open_segment(index, segment, is_last)?;
        if is_last {
            self.finished = true;
        } else {
            self.next_index = next_segment_index(index)?;
        }
        Ok(plaintext)
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves the segment counter can never wrap: for every `u32`, the
    /// successor is computed with checked arithmetic, is `Err` exactly at
    /// `u32::MAX`, and is `current + 1` everywhere else.
    #[kani::proof]
    fn next_segment_index_never_wraps() {
        let current: u32 = kani::any();
        let next = next_segment_index(current);
        if current == u32::MAX {
            kani::assert(
                matches!(next, Err(AeadError::SegmentCounterExhausted)),
                "u32::MAX must have no successor",
            );
        } else {
            kani::assert(
                matches!(next, Ok(n) if n == current + 1),
                "successor must be current + 1 below u32::MAX",
            );
        }
    }

    /// Proves segment capacity arithmetic cannot underflow for any accepted
    /// segment size and any index: both the first and every later segment
    /// have a defined, non-zero plaintext capacity.
    #[kani::proof]
    fn plaintext_capacity_defined_for_valid_sizes() {
        let segment_size: u32 = kani::any();
        kani::assume(validate_segment_size(segment_size).is_ok());
        let index: u32 = kani::any();
        let capacity = plaintext_capacity(segment_size, index);
        kani::assert(
            matches!(capacity, Some(c) if c > 0),
            "every valid segment size yields a positive plaintext capacity",
        );
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::indexing_slicing, reason = "Tests index into buffers of known length")]
#[expect(clippy::arithmetic_side_effects, reason = "Tests use plain arithmetic on known sizes")]
mod tests {
    use super::*;
    use crate::primitives::aead::aes_gcm::AesGcm128;

    const KEY: [u8; 32] = [
        0x4c, 0x61, 0x74, 0x74, 0x69, 0x63, 0x65, 0x41, 0x72, 0x63, 0x2d, 0x73, 0x74, 0x72, 0x65,
        0x61, 0x6d, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x30, 0x30, 0x30,
        0x30, 0x31,
    ];
    const AAD: &[u8] = b"vault/v1/file";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Splits `plaintext` into Tink segments and seals them; returns
    /// `(header, segments)`.
    fn seal_all(enc: StreamEncryptor, plaintext: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
        let header = enc.header().to_vec();
        let mut enc = enc;
        let mut segments = Vec::new();
        let mut rest = plaintext;
        loop {
            let cap = if enc.next_index() == 0 {
                enc.first_plaintext_segment_size()
            } else {
                enc.plaintext_segment_size()
            };
            if rest.len() <= cap {
                segments.push(enc.finish(rest).unwrap());
                return (header, segments);
            }
            let (head, tail) = rest.split_at(cap);
            segments.push(enc.seal_segment(head).unwrap());
            rest = tail;
        }
    }

    fn open_all(dec: &mut StreamDecryptor, segments: &[Vec<u8>]) -> Result<Vec<u8>, AeadError> {
        let mut out = Vec::new();
        let last = segments.len() - 1;
        for (i, seg) in segments.iter().enumerate() {
            out.extend_from_slice(&dec.open_next(seg, i == last)?);
        }
        Ok(out)
    }

    /// Tink known-answer vector `createTestVector2` from
    /// <https://github.com/tink-crypto/tink-java/blob/main/src/main/java/com/google/crypto/tink/streamingaead/internal/testing/AesGcmHkdfStreamingTestUtil.java>:
    /// key size 16, HKDF-SHA256, derived AES-GCM key size 16, ciphertext
    /// segment size 64, empty plaintext, empty associated data. The expected
    /// ciphertext is `header_length (0x18) || salt (16) || nonce_prefix (7)
    /// || C_0` where `C_0` is the AES-128-GCM tag of the empty final segment.
    #[test]
    fn tink_java_sha256_vector() {
        let ikm = unhex("6eb56cdc726dfbe5d57f2fcdc6e9345b");
        let ciphertext = unhex(
            "18be78bce0cab6fd38a9041eea8ab0ffc4cf17e3c00b661d3927f5f79069f41a210fedc40b25648c",
        );
        assert_eq!(ciphertext.len(), 1 + 16 + 7 + 16);
        assert_eq!(ciphertext[0], 0x18, "Tink header length for a 16-byte key is 24");
        let salt = &ciphertext[1..17];
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = ciphertext[17..24].try_into().unwrap();
        let segment_0 = &ciphertext[24..];

        let cipher = derive_segment_cipher::<AesGcm128>(&ikm, salt, &[]).unwrap();
        let sealed = seal_tink_segment(&cipher, nonce_prefix, 0, true, None, &[]).unwrap();
        assert_eq!(hex(&sealed), hex(segment_0), "AES-GCM-HKDF core must reproduce Tink's bytes");

        let opened = open_tink_segment(&cipher, nonce_prefix, 0, true, None, segment_0).unwrap();
        assert!(opened.is_empty());
        assert!(
            open_tink_segment(&cipher, nonce_prefix, 0, false, None, segment_0).is_err(),
            "the Tink last-segment flag must be part of the nonce"
        );
        assert!(
            open_tink_segment(&cipher, nonce_prefix, 1, true, None, segment_0).is_err(),
            "the Tink segment counter must be part of the nonce"
        );
    }

    /// Pins the legacy format-1 AES-256 output for a fixed key, salt and
    /// nonce prefix. These bytes are unchanged since 0.13.0; format-1 decode
    /// must keep accepting them under [`FormatPolicy::AllowV1`].
    #[test]
    fn pinned_aes256_output_bytes() {
        let salt: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let prefix: [u8; NONCE_PREFIX_LEN] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
        let mut enc = StreamEncryptor::new_with_material(
            STREAM_FORMAT_VERSION_V1,
            &KEY,
            AAD,
            64,
            &salt,
            prefix,
        )
        .unwrap();
        let header = enc.header().to_vec();
        let seg0 = enc.seal_segment(&[0x11u8; 8]).unwrap();
        let seg1 = enc.finish(b"final").unwrap();

        assert_eq!(
            hex(&header),
            concat!(
                "0100",
                "00000040",
                "28",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "a0a1a2a3a4a5a6",
                "bb8df52093b77bbc644b8def8409f4803449e9075139ad25f1dd35737b3cf0e6",
            )
        );
        assert_eq!(hex(&seg0), "dbdda4765e7e4c118f921e8a02f7739b6d026f8c5a024b01");
        assert_eq!(hex(&seg1), "25bdbf2236555c1ca4dc1ba1fe416a17519a10b5d8");

        let mut dec =
            StreamDecryptor::new_with_policy(&KEY, AAD, &header, FormatPolicy::AllowV1).unwrap();
        assert_eq!(dec.format_version(), STREAM_FORMAT_VERSION_V1);
        assert_eq!(dec.open_next(&seg0, false).unwrap().as_slice(), &[0x11u8; 8]);
        assert_eq!(dec.open_next(&seg1, true).unwrap().as_slice(), b"final");
        assert!(matches!(
            StreamDecryptor::new(&KEY, AAD, &header),
            Err(AeadError::LegacyFormatRejected)
        ));
    }

    /// Pins the format-2 (CMT-4) AES-256 output for the same fixed key, salt
    /// and nonce prefix, so any drift in the v2 commitment input, header
    /// layout, per-segment AAD or nonce construction is caught.
    #[test]
    fn pinned_aes256_output_bytes_v2() {
        let salt: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let prefix: [u8; NONCE_PREFIX_LEN] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6];
        let mut enc =
            StreamEncryptor::new_with_material(STREAM_FORMAT_VERSION, &KEY, AAD, 64, &salt, prefix)
                .unwrap();
        let header = enc.header().to_vec();
        let seg0 = enc.seal_segment(&[0x11u8; 8]).unwrap();
        let seg1 = enc.finish(b"final").unwrap();

        assert_eq!(
            hex(&header),
            concat!(
                "0200",
                "00000040",
                "28",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "a0a1a2a3a4a5a6",
                "bd2173d22265991580f0be34cb2eaf5eac45ad2c756e3a4132998126b9047432",
            )
        );
        assert_eq!(hex(&seg0), "dbdda4765e7e4c11a2cb1a599a6527dc5ecd139035a1c98a");
        assert_eq!(hex(&seg1), "25bdbf2236780518774489f5b972a56b4df5b33753");

        let mut dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        assert_eq!(dec.format_version(), STREAM_FORMAT_VERSION);
        assert_eq!(dec.open_next(&seg0, false).unwrap().as_slice(), &[0x11u8; 8]);
        assert_eq!(dec.open_next(&seg1, true).unwrap().as_slice(), b"final");
    }

    /// The format-2 commitment depends on the associated data; the format-1
    /// commitment does not (that is the CMT-1 gap format 2 closes).
    #[test]
    fn commitment_covers_aad_only_in_v2() {
        let prefix = [0x5au8; COMMITTED_PREFIX_LEN];
        let a = commitment(&KEY, STREAM_FORMAT_VERSION, &prefix, b"ctx-a").unwrap();
        let b = commitment(&KEY, STREAM_FORMAT_VERSION, &prefix, b"ctx-b").unwrap();
        assert_ne!(a, b);
        let a1 = commitment(&KEY, STREAM_FORMAT_VERSION_V1, &prefix, b"ctx-a").unwrap();
        let b1 = commitment(&KEY, STREAM_FORMAT_VERSION_V1, &prefix, b"ctx-b").unwrap();
        assert_eq!(a1, b1);
        assert_ne!(a, a1);
        assert!(commitment(&KEY, 0, &prefix, b"ctx-a").is_none());
        assert!(commitment(&KEY, 3, &prefix, b"ctx-a").is_none());
    }

    /// Format policy: v2 always opens; v1 opens only under `AllowV1` and is
    /// otherwise refused with the distinct `LegacyFormatRejected`.
    #[test]
    fn format_policy_matrix() {
        let salt = [7u8; 32];
        let prefix = [9u8; NONCE_PREFIX_LEN];
        let v1 = StreamEncryptor::new_with_material(
            STREAM_FORMAT_VERSION_V1,
            &KEY,
            AAD,
            64,
            &salt,
            prefix,
        )
        .unwrap();
        let (h1, s1) = seal_all(v1, b"legacy payload");
        let v2 = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let (h2, s2) = seal_all(v2, b"current payload");

        for policy in [FormatPolicy::RequireV2, FormatPolicy::AllowV1] {
            let mut dec = StreamDecryptor::new_with_policy(&KEY, AAD, &h2, policy).unwrap();
            assert_eq!(dec.format_version(), 2);
            assert_eq!(open_all(&mut dec, &s2).unwrap(), b"current payload");
        }
        assert!(matches!(
            StreamDecryptor::new_with_policy(&KEY, AAD, &h1, FormatPolicy::RequireV2),
            Err(AeadError::LegacyFormatRejected)
        ));
        assert!(matches!(
            StreamDecryptor::new(&KEY, AAD, &h1),
            Err(AeadError::LegacyFormatRejected)
        ));
        let mut dec =
            StreamDecryptor::new_with_policy(&KEY, AAD, &h1, FormatPolicy::AllowV1).unwrap();
        assert_eq!(dec.format_version(), 1);
        assert_eq!(open_all(&mut dec, &s1).unwrap(), b"legacy payload");
        assert_eq!(FormatPolicy::default(), FormatPolicy::RequireV2);
    }

    /// Relabelling a header's version byte (1 <-> 2) breaks its commitment,
    /// so a format-1 header cannot be passed off as format 2 or vice versa.
    #[test]
    fn version_byte_swap_fails() {
        let salt = [3u8; 32];
        let prefix = [4u8; NONCE_PREFIX_LEN];
        for (from, to) in [(STREAM_FORMAT_VERSION_V1, 2u8), (STREAM_FORMAT_VERSION, 1u8)] {
            let enc =
                StreamEncryptor::new_with_material(from, &KEY, AAD, 64, &salt, prefix).unwrap();
            let mut header = enc.header().to_vec();
            header[0] = to;
            assert!(matches!(
                StreamDecryptor::new_with_policy(&KEY, AAD, &header, FormatPolicy::AllowV1),
                Err(AeadError::DecryptionFailed(_))
            ));
        }
    }

    /// A v1 header under `RequireV2` reports `LegacyFormatRejected` only once
    /// the header is structurally valid; malformed v1-looking input stays
    /// opaque.
    #[test]
    fn legacy_rejection_only_for_well_formed_v1() {
        let mut junk = [0u8; HEADER_LEN];
        junk[0] = STREAM_FORMAT_VERSION_V1;
        // segment size 0 is out of range
        assert!(matches!(
            StreamDecryptor::new(&KEY, AAD, &junk),
            Err(AeadError::DecryptionFailed(_))
        ));
        assert!(matches!(
            StreamDecryptor::new(&KEY, AAD, &junk[..HEADER_LEN - 1]),
            Err(AeadError::DecryptionFailed(_))
        ));
    }

    #[test]
    fn header_layout_matches_spec() {
        let enc = StreamEncryptor::new(&KEY, AAD, 1024).unwrap();
        let h = enc.header();
        assert_eq!(h.len(), HEADER_LEN);
        assert_eq!(HEADER_LEN, 78);
        assert_eq!(h[0], STREAM_FORMAT_VERSION);
        assert_eq!(h[1], 0);
        assert_eq!(u32::from_be_bytes(h[2..6].try_into().unwrap()), 1024);
        assert_eq!(h[6], 40);
        assert_eq!(enc.segment_size(), 1024);
        assert_eq!(enc.plaintext_segment_size(), 1024 - 16);
        assert_eq!(enc.first_plaintext_segment_size(), 1024 - 16 - 40);
        assert_eq!(enc.next_index(), 0);
    }

    #[test]
    fn roundtrip_sequential_and_random_access() {
        for (segment_size, total) in [(64u32, 0usize), (64, 8), (64, 9), (64, 200), (256, 1000)] {
            let plaintext: Vec<u8> = (0..total).map(|i| u8::try_from(i % 251).unwrap()).collect();
            let enc = StreamEncryptor::new(&KEY, AAD, segment_size).unwrap();
            let (header, segments) = seal_all(enc, &plaintext);
            for (i, s) in segments.iter().enumerate() {
                let expected = if i == 0 {
                    usize::try_from(segment_size).unwrap() - TINK_HEADER_LEN
                } else {
                    usize::try_from(segment_size).unwrap()
                };
                if i + 1 < segments.len() {
                    assert_eq!(s.len(), expected, "non-final segments fill the segment size");
                } else {
                    assert!(s.len() <= expected);
                }
            }

            let mut dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
            assert_eq!(open_all(&mut dec, &segments).unwrap(), plaintext);
            assert!(dec.is_finished());

            // Random access in reverse order on a fresh decryptor.
            let dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
            let mut recovered = vec![Vec::new(); segments.len()];
            for (i, s) in segments.iter().enumerate().rev() {
                let idx = u32::try_from(i).unwrap();
                recovered[i] = dec.open_segment(idx, s, i + 1 == segments.len()).unwrap().to_vec();
            }
            assert_eq!(recovered.concat(), plaintext);
        }
    }

    #[test]
    fn invalid_segment_size_fails() {
        for size in [0u32, 63, MAX_SEGMENT_SIZE + 1, u32::MAX] {
            assert!(matches!(
                StreamEncryptor::new(&KEY, AAD, size),
                Err(AeadError::InvalidSegmentSize)
            ));
        }
        assert!(StreamEncryptor::new(&KEY, AAD, MIN_SEGMENT_SIZE).is_ok());
        assert!(StreamEncryptor::new(&KEY, AAD, MAX_SEGMENT_SIZE).is_ok());
    }

    #[test]
    fn empty_context_fails() {
        assert!(matches!(StreamEncryptor::new(&KEY, b"", 64), Err(AeadError::EmptyContext)));
        let header = StreamEncryptor::new(&KEY, AAD, 64).unwrap().header().to_vec();
        assert!(matches!(StreamDecryptor::new(&KEY, b"", &header), Err(AeadError::EmptyContext)));
    }

    #[test]
    fn weak_key_fails() {
        let zero = [0u8; 32];
        assert!(matches!(StreamEncryptor::new(&zero, AAD, 64), Err(AeadError::WeakKey)));
        let header = StreamEncryptor::new(&KEY, AAD, 64).unwrap().header().to_vec();
        assert!(matches!(StreamDecryptor::new(&zero, AAD, &header), Err(AeadError::WeakKey)));
    }

    #[test]
    fn invalid_segment_length_fails() {
        let mut enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        assert!(matches!(enc.seal_segment(&[0u8; 7]), Err(AeadError::InvalidSegmentLength)));
        assert!(matches!(enc.seal_segment(&[0u8; 9]), Err(AeadError::InvalidSegmentLength)));
        assert_eq!(enc.next_index(), 0, "a rejected segment must not advance the counter");
        enc.seal_segment(&[0u8; 8]).unwrap();
        assert!(matches!(enc.seal_segment(&[0u8; 47]), Err(AeadError::InvalidSegmentLength)));
        assert!(matches!(enc.finish(&[0u8; 49]), Err(AeadError::InvalidSegmentLength)));
    }

    #[test]
    fn segment_counter_exhausted_fails_and_never_wraps() {
        let mut enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        enc.set_next_index(u32::MAX);
        assert!(matches!(enc.seal_segment(&[0u8; 48]), Err(AeadError::SegmentCounterExhausted)));
        assert_eq!(enc.next_index(), u32::MAX, "counter must not move on failure");
        // The final segment may still carry index u32::MAX.
        let header = enc.header().to_vec();
        let last = enc.finish(b"tail").unwrap();
        let dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        assert_eq!(dec.open_segment(u32::MAX, &last, true).unwrap().as_slice(), b"tail");

        // Sequential decryptor: accepting a non-final segment at u32::MAX
        // cannot advance.
        let mut enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        enc.set_next_index(u32::MAX - 1);
        let header = enc.header().to_vec();
        let seg = enc.seal_segment(&[7u8; 48]).unwrap();
        let mut dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        dec.set_next_index(u32::MAX - 1);
        dec.open_next(&seg, false).unwrap();
        assert_eq!(dec.next_index(), u32::MAX);
        assert!(matches!(next_segment_index(u32::MAX), Err(AeadError::SegmentCounterExhausted)));
    }

    #[test]
    fn stream_exhausted_fails_after_final_segment() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let (header, segments) = seal_all(enc, &[1u8; 100]);
        let mut dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        open_all(&mut dec, &segments).unwrap();
        assert!(matches!(dec.open_next(&segments[1], true), Err(AeadError::StreamExhausted)));
    }

    #[test]
    fn wrong_key_fails_before_any_segment() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let header = enc.header().to_vec();
        let mut wrong = KEY;
        wrong[31] ^= 1;
        let err = StreamDecryptor::new(&wrong, AAD, &header).unwrap_err();
        assert!(matches!(err, AeadError::DecryptionFailed(_)));
    }

    #[test]
    fn wrong_aad_fails() {
        // Format 2: rejected at the header (CMT-4), see
        // `v2_wrong_context_rejected_at_header`.
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let header = enc.header().to_vec();
        assert!(StreamDecryptor::new(&KEY, b"app/v1/other", &header).is_err());

        // Legacy format 1: the header verifies under any aad (CMT-1 only),
        // but the segment, keyed by HKDF over the aad, still fails.
        let v1 = StreamEncryptor::new_with_material(
            STREAM_FORMAT_VERSION_V1,
            &KEY,
            AAD,
            64,
            &[1u8; 32],
            [2u8; NONCE_PREFIX_LEN],
        )
        .unwrap();
        let (header, segments) = seal_all(v1, b"payload");
        let dec =
            StreamDecryptor::new_with_policy(&KEY, b"app/v1/other", &header, FormatPolicy::AllowV1)
                .unwrap();
        assert!(dec.open_segment(0, &segments[0], true).is_err());
    }

    /// CMT-4 (red-first for format v2): a header must not verify under a
    /// different caller context, so a wrong context fails in `new` before
    /// any segment key is derived or any AES-GCM work is done.
    #[test]
    fn v2_wrong_context_rejected_at_header() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let header = enc.header().to_vec();
        assert!(matches!(
            StreamDecryptor::new(&KEY, b"vault/v1/other", &header),
            Err(AeadError::DecryptionFailed(_))
        ));
    }

    #[test]
    fn header_bit_flip_anywhere_fails() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let header = enc.header().to_vec();
        for i in 0..header.len() {
            let mut bad = header.clone();
            bad[i] ^= 0x01;
            assert!(
                matches!(
                    StreamDecryptor::new(&KEY, AAD, &bad),
                    Err(AeadError::DecryptionFailed(_))
                ),
                "flipping header byte {i} must fail"
            );
        }
        assert!(StreamDecryptor::new(&KEY, AAD, &header[..77]).is_err());
        let mut long = header;
        long.push(0);
        assert!(StreamDecryptor::new(&KEY, AAD, &long).is_err());
    }

    #[test]
    fn segment_bit_flip_anywhere_fails() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let (header, segments) = seal_all(enc, &[0xabu8; 60]);
        let dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        for (i, seg) in segments.iter().enumerate() {
            let idx = u32::try_from(i).unwrap();
            let last = i + 1 == segments.len();
            for pos in 0..seg.len() {
                let mut bad = seg.clone();
                bad[pos] ^= 0x80;
                assert!(dec.open_segment(idx, &bad, last).is_err(), "segment {i} byte {pos}");
            }
        }
    }

    #[test]
    fn truncation_reordering_and_splicing_fail() {
        truncation_reordering_and_splicing_fail_for(STREAM_FORMAT_VERSION);
        truncation_reordering_and_splicing_fail_for(STREAM_FORMAT_VERSION_V1);
    }

    fn truncation_reordering_and_splicing_fail_for(version: u8) {
        let plaintext = vec![0x5au8; 8 + 48 + 48 + 10];
        let enc = StreamEncryptor::new_with_material(
            version,
            &KEY,
            AAD,
            64,
            &[0x31u8; 32],
            [0x32u8; NONCE_PREFIX_LEN],
        )
        .unwrap();
        let (header, segments) = seal_all(enc, &plaintext);
        assert_eq!(segments.len(), 4);
        let policy = FormatPolicy::AllowV1;
        let dec = StreamDecryptor::new_with_policy(&KEY, AAD, &header, policy).unwrap();

        // Truncation: presenting a non-final segment as the end of the stream.
        assert!(dec.open_segment(2, &segments[2], true).is_err());
        let mut seq = StreamDecryptor::new_with_policy(&KEY, AAD, &header, policy).unwrap();
        seq.open_next(&segments[0], false).unwrap();
        seq.open_next(&segments[1], false).unwrap();
        assert!(seq.open_next(&segments[2], true).is_err());
        // Dropping the final segment and claiming segment 3 is a middle one.
        assert!(dec.open_segment(3, &segments[3], false).is_err());

        // Reordering: segment 2 at index 1 and vice versa.
        assert!(dec.open_segment(1, &segments[2], false).is_err());
        assert!(dec.open_segment(2, &segments[1], false).is_err());

        // Splicing: a segment from a stream under the same key (different
        // salt / nonce prefix) and from a stream under a different key.
        let enc_b = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let (_, segments_b) = seal_all(enc_b, &plaintext);
        assert!(dec.open_segment(1, &segments_b[1], false).is_err());
        let mut other_key = KEY;
        other_key[0] ^= 0xff;
        let enc_c = StreamEncryptor::new(&other_key, AAD, 64).unwrap();
        let (_, segments_c) = seal_all(enc_c, &plaintext);
        assert!(dec.open_segment(1, &segments_c[1], false).is_err());

        // Wrong-length ciphertexts are rejected before authentication.
        assert!(dec.open_segment(1, &segments[1][..63], false).is_err());
        assert!(dec.open_segment(0, &segments[1], false).is_err());
        assert!(dec.open_segment(3, &[0u8; 15], true).is_err());
        let mut long = segments[3].clone();
        long.extend_from_slice(&[0u8; 64]);
        assert!(dec.open_segment(3, &long, true).is_err());
    }

    #[test]
    fn decrypt_errors_are_opaque() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let (header, segments) = seal_all(enc, b"x");
        let mut wrong = KEY;
        wrong[5] ^= 1;
        let wrong_key = format!("{}", StreamDecryptor::new(&wrong, AAD, &header).unwrap_err());
        let mut bad_header = header.clone();
        bad_header[0] ^= 1;
        let bad_version = format!("{}", StreamDecryptor::new(&KEY, AAD, &bad_header).unwrap_err());
        let dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        let mut bad_seg = segments[0].clone();
        bad_seg[0] ^= 1;
        let bad_tag = format!("{}", dec.open_segment(0, &bad_seg, true).unwrap_err());
        let bad_len = format!("{}", dec.open_segment(0, &segments[0][..3], true).unwrap_err());
        assert_eq!(wrong_key, bad_version);
        assert_eq!(wrong_key, bad_tag);
        assert_eq!(wrong_key, bad_len);
    }

    #[test]
    fn debug_is_redacted() {
        let enc = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let header = enc.header().to_vec();
        let dec = StreamDecryptor::new(&KEY, AAD, &header).unwrap();
        let e = format!("{enc:?}");
        let d = format!("{dec:?}");
        assert!(e.contains("[REDACTED]") && !e.contains(&hex(&KEY)));
        assert!(d.contains("[REDACTED]") && !d.contains(&hex(&KEY)));
    }

    #[test]
    fn fresh_header_material_per_stream() {
        let a = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        let b = StreamEncryptor::new(&KEY, AAD, 64).unwrap();
        assert_ne!(
            a.header()[OFFSET_SALT..OFFSET_NONCE_PREFIX],
            b.header()[OFFSET_SALT..OFFSET_NONCE_PREFIX]
        );
        assert_ne!(
            a.header()[OFFSET_NONCE_PREFIX..OFFSET_COMMITMENT],
            b.header()[OFFSET_NONCE_PREFIX..OFFSET_COMMITMENT]
        );
    }

    #[test]
    fn plaintext_capacity_arithmetic() {
        assert_eq!(plaintext_capacity(64, 0), Some(8));
        assert_eq!(plaintext_capacity(64, 1), Some(48));
        assert_eq!(plaintext_capacity(MAX_SEGMENT_SIZE, 7), Some(16 * 1024 * 1024 - 16));
        assert_eq!(plaintext_capacity(40, 0), None);
        assert_eq!(plaintext_capacity(15, 1), None);
        assert!(matches!(next_segment_index(0), Ok(1)));
        assert!(matches!(next_segment_index(u32::MAX - 1), Ok(u32::MAX)));
    }
}
