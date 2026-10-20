#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Committing key wrap: AES-256-GCM plus an HMAC-SHA256 key-commitment tag,
//! with optional padding to a fixed total size.
//!
//! # Threat model
//!
//! The adversary holds any number of wrapped keys and controls every byte
//! handed to [`unwrap_key`]. The guarantees are:
//!
//! - **A wrong KEK always fails.** AES-GCM alone is not key-committing (a
//!   ciphertext can be crafted to decrypt validly under two keys; Albertini
//!   et al., *How to Abuse and Fix Authenticated Encryption with Key
//!   Commitment*, USENIX Security 2022). Every wrapped key therefore carries
//!   `HMAC-SHA256(kek, KEY_WRAP_COMMITMENT || version || nonce)`, the "UtC"
//!   shape of Bellare and Hoang, *Efficient Schemes for Committing
//!   Authenticated Encryption* (EUROCRYPT 2022): a PRF of the key over the
//!   public header, verified in constant time before the payload is
//!   accepted. HMAC-SHA256 with a 32-byte key is collision resistant in the
//!   key, so no two KEKs verify the same record.
//! - **Context is binding.** The caller's non-empty context (for example
//!   `vault/v1/root/epoch-3/locator-xyz`) is authenticated as AES-GCM
//!   associated data together with the version byte and the payload length,
//!   so a record wrapped for one purpose cannot be unwrapped for another.
//! - **Fixed size, random-looking output.** For a given key length every
//!   output has the same length; [`wrap_key_padded`] pads *under* the AEAD
//!   so any record can be made exactly `total_len` bytes with the true key
//!   length hidden inside the ciphertext. Apart from the leading version
//!   byte, every output byte is a CSPRNG nonce, a PRF output or AES-GCM
//!   ciphertext, so records hide among other opaque files
//!   (`output_bytes_look_random` is a smoke test of this, not a proof).
//! - **Errors are opaque where the adversary can reach them.** Commitment
//!   mismatch, tag failure, bad inner length and non-zero padding all
//!   surface as the same [`AeadError::DecryptionFailed`] string, and the
//!   AES-GCM decryption is always attempted so the two checks cannot be
//!   told apart by timing either. Structural checks on public bytes
//!   (version byte, impossible length) report
//!   [`AeadError::MalformedEncoding`].
//!
//! Out of scope: hiding the *existence* of a wrapped record of a given size
//! (callers choose `total_len` to match their cover traffic) and protecting
//! the KEK itself.
//!
//! # Wire format (version 1)
//!
//! ```text
//! WrappedKey = version (1, = 0x01)
//!           || nonce (12, CSPRNG)
//!           || commitment (32) = HMAC-SHA256(kek, KEY_WRAP_COMMITMENT || version || nonce)
//!           || AES-256-GCM(kek, nonce, aad, payload) || tag (16)
//! payload   = key_len (1) || key (16 | 32 | 64) || zero padding
//! aad       = version (1) || payload_len (u32 BE) || context
//! ```
//!
//! Total length is `62 + key_len + padding`; [`wrap_key`] uses no padding and
//! [`wrap_key_padded`] chooses the padding so the total equals `total_len`.

use crate::primitives::aead::aes_gcm::AesGcm256;
use crate::primitives::aead::{AeadCipher, AeadError, NONCE_LEN, Nonce, TAG_LEN};
use crate::primitives::ct::is_all_zero_bytes;
use crate::primitives::mac::hmac::hmac_sha256;
use crate::primitives::resource_limits::validate_aad_size;
use crate::types::domains::KEY_WRAP_COMMITMENT;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

/// Version byte at offset 0 of every wrapped key produced by this module.
pub const KEY_WRAP_VERSION: u8 = 1;

/// Length of the KEK in bytes (AES-256-GCM).
pub const KEK_LEN: usize = 32;

/// Length of the HMAC-SHA256 key-commitment tag.
pub const COMMITMENT_LEN: usize = 32;

/// Length of the inner key-length prefix inside the encrypted payload.
const KEY_LEN_PREFIX: usize = 1;

/// Bytes every wrapped key carries in addition to the key itself and any
/// padding: `version || nonce || commitment || key_len || tag`.
pub const KEY_WRAP_OVERHEAD: usize = 1 + NONCE_LEN + COMMITMENT_LEN + KEY_LEN_PREFIX + TAG_LEN;

/// Shortest valid encoding: a 16-byte key with no padding.
pub const MIN_WRAPPED_LEN: usize = KEY_WRAP_OVERHEAD + 16;

/// Longest accepted encoding (1 MiB). Padded root records are meant to
/// resemble ordinary files, not bulk data; the cap bounds the AES-GCM work an
/// attacker can trigger through [`WrappedKey::from_bytes`] + [`unwrap_key`].
pub const MAX_WRAPPED_LEN: usize = 1024 * 1024;

/// Key lengths accepted by [`wrap_key`].
pub const SUPPORTED_KEY_LENS: [usize; 3] = [16, 32, 64];

/// Byte offsets of the public fields.
const OFFSET_NONCE: usize = 1;
const OFFSET_COMMITMENT: usize = OFFSET_NONCE + NONCE_LEN;
const OFFSET_CIPHERTEXT: usize = OFFSET_COMMITMENT + COMMITMENT_LEN;

/// Single opaque string for every adversary-reachable unwrap failure.
const DECRYPTION_FAILED: &str = "decryption failed";

/// Single opaque string for every internal wrap-side failure.
const ENCRYPTION_FAILED: &str = "encryption failed";

/// A wrapped key: the public encoding described in the module docs.
///
/// Holds ciphertext only, so it may be cloned and logged freely; `Debug`
/// prints the length, not the bytes, to keep logs compact.
#[derive(Clone)]
pub struct WrappedKey {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKey").field("len", &self.bytes.len()).finish()
    }
}

impl WrappedKey {
    /// Parses an encoding produced by [`WrappedKey::to_bytes`].
    ///
    /// Only the public structure is checked here: the version byte must be
    /// [`KEY_WRAP_VERSION`] and the length must lie in
    /// `MIN_WRAPPED_LEN..=MAX_WRAPPED_LEN`. Everything key-dependent is
    /// verified by [`unwrap_key`].
    ///
    /// # Errors
    /// [`AeadError::MalformedEncoding`] if the version byte or length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AeadError> {
        if !(MIN_WRAPPED_LEN..=MAX_WRAPPED_LEN).contains(&bytes.len()) {
            return Err(AeadError::MalformedEncoding);
        }
        match bytes.first() {
            Some(&KEY_WRAP_VERSION) => Ok(Self { bytes: bytes.to_vec() }),
            _ => Err(AeadError::MalformedEncoding),
        }
    }

    /// The encoding, `version || nonce || commitment || ciphertext || tag`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Borrows the encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the encoding in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always `false`: a valid encoding is at least [`MIN_WRAPPED_LEN`] bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// `HMAC-SHA256(kek, KEY_WRAP_COMMITMENT || version || nonce)`.
fn commitment(kek: &[u8; KEK_LEN], nonce: &Nonce) -> Option<[u8; COMMITMENT_LEN]> {
    let mut message = Vec::with_capacity(KEY_WRAP_COMMITMENT.len().saturating_add(1 + NONCE_LEN));
    message.extend_from_slice(KEY_WRAP_COMMITMENT);
    message.push(KEY_WRAP_VERSION);
    message.extend_from_slice(nonce);
    hmac_sha256(kek, &message).ok()
}

/// `version || payload_len (u32 BE) || context`.
fn associated_data(payload_len: usize, context: &[u8]) -> Option<Vec<u8>> {
    let len = u32::try_from(payload_len).ok()?;
    let mut aad = Vec::with_capacity(context.len().saturating_add(5));
    aad.push(KEY_WRAP_VERSION);
    aad.extend_from_slice(&len.to_be_bytes());
    aad.extend_from_slice(context);
    Some(aad)
}

fn validate_context(context: &[u8], size_error: impl Fn() -> AeadError) -> Result<(), AeadError> {
    if context.is_empty() {
        return Err(AeadError::EmptyContext);
    }
    validate_aad_size(context.len()).map_err(|_e| size_error())
}

/// Wraps `key` (16, 32 or 64 bytes) under `kek`, bound to the non-empty
/// `context`. The output is `KEY_WRAP_OVERHEAD + key.len()` bytes.
///
/// # Errors
/// - [`AeadError::InvalidKeyLength`] unless `key.len()` is 16, 32 or 64.
/// - [`AeadError::EmptyContext`] if `context` is empty.
/// - [`AeadError::WeakKey`] if `kek` is all zero.
/// - [`AeadError::EncryptionFailed`] if `context` exceeds the AAD resource
///   limit or AES-GCM / HMAC fail.
pub fn wrap_key(kek: &[u8; KEK_LEN], key: &[u8], context: &[u8]) -> Result<WrappedKey, AeadError> {
    let total_len = KEY_WRAP_OVERHEAD
        .checked_add(key.len())
        .ok_or_else(|| AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string()))?;
    wrap_key_padded(kek, key, context, total_len)
}

/// Like [`wrap_key`], but pads the plaintext under the AEAD so the encoding
/// is exactly `total_len` bytes. The real key length travels inside the
/// ciphertext; [`unwrap_key`] strips the padding after authentication.
///
/// # Errors
/// - [`AeadError::InvalidPaddedLength`] if `total_len` is below
///   `KEY_WRAP_OVERHEAD + key.len()` or above [`MAX_WRAPPED_LEN`].
/// - Everything [`wrap_key`] can return.
pub fn wrap_key_padded(
    kek: &[u8; KEK_LEN],
    key: &[u8],
    context: &[u8],
    total_len: usize,
) -> Result<WrappedKey, AeadError> {
    let nonce = AesGcm256::generate_nonce();
    wrap_key_with_nonce(kek, key, context, total_len, &nonce)
}

/// Deterministic core shared by every wrap entry point. Public callers never
/// choose the nonce; it is exposed to tests only, to pin the output bytes.
fn wrap_key_with_nonce(
    kek: &[u8; KEK_LEN],
    key: &[u8],
    context: &[u8],
    total_len: usize,
    nonce: &Nonce,
) -> Result<WrappedKey, AeadError> {
    let opaque = || AeadError::EncryptionFailed(ENCRYPTION_FAILED.to_string());
    if !SUPPORTED_KEY_LENS.contains(&key.len()) {
        return Err(AeadError::InvalidKeyLength);
    }
    validate_context(context, opaque)?;
    let min_len = KEY_WRAP_OVERHEAD.checked_add(key.len()).ok_or_else(opaque)?;
    if total_len < min_len || total_len > MAX_WRAPPED_LEN {
        return Err(AeadError::InvalidPaddedLength);
    }
    let padding = total_len.checked_sub(min_len).ok_or_else(opaque)?;
    let key_len = u8::try_from(key.len()).map_err(|_e| opaque())?;

    // Constructing the cipher first surfaces WeakKey / InvalidKeyLength on
    // the KEK before any payload is assembled.
    let cipher = AesGcm256::new(kek)?;

    let payload_len = KEY_LEN_PREFIX
        .checked_add(key.len())
        .and_then(|n| n.checked_add(padding))
        .ok_or_else(opaque)?;
    let mut payload: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(payload_len));
    payload.push(key_len);
    payload.extend_from_slice(key);
    payload.resize(payload_len, 0);

    let tag_commit = commitment(kek, nonce).ok_or_else(opaque)?;
    let aad = associated_data(payload_len, context).ok_or_else(opaque)?;
    let (ciphertext, tag) = cipher.encrypt(nonce, &payload, Some(&aad))?;

    let mut bytes = Vec::with_capacity(total_len);
    bytes.push(KEY_WRAP_VERSION);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&tag_commit);
    bytes.extend_from_slice(&ciphertext);
    bytes.extend_from_slice(&tag);
    if bytes.len() != total_len {
        return Err(opaque());
    }
    Ok(WrappedKey { bytes })
}

/// Unwraps `wrapped` under `kek` and `context`, returning the original key
/// with any padding removed.
///
/// # Errors
/// - [`AeadError::EmptyContext`] if `context` is empty.
/// - [`AeadError::WeakKey`] if `kek` is all zero.
/// - [`AeadError::DecryptionFailed`] for every key-dependent failure: wrong
///   KEK, wrong context, any modified byte, an impossible inner key length or
///   non-zero padding. These are deliberately indistinguishable.
pub fn unwrap_key(
    kek: &[u8; KEK_LEN],
    wrapped: &WrappedKey,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    let opaque = || AeadError::DecryptionFailed(DECRYPTION_FAILED.to_string());
    validate_context(context, opaque)?;
    let cipher = AesGcm256::new(kek)?;

    let bytes = wrapped.as_bytes();
    let nonce: Nonce = bytes
        .get(OFFSET_NONCE..OFFSET_COMMITMENT)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(opaque)?;
    let stored_commitment = bytes.get(OFFSET_COMMITMENT..OFFSET_CIPHERTEXT).ok_or_else(opaque)?;
    let sealed = bytes.get(OFFSET_CIPHERTEXT..).ok_or_else(opaque)?;
    let split = sealed.len().checked_sub(TAG_LEN).ok_or_else(opaque)?;
    let (ciphertext, tag_bytes) = sealed.split_at_checked(split).ok_or_else(opaque)?;
    let tag: [u8; TAG_LEN] = tag_bytes.try_into().map_err(|_e| opaque())?;

    // Verify the commitment and run the AEAD unconditionally, then combine,
    // so a commitment mismatch and a tag failure take the same path.
    let commitment_ok: Choice = match commitment(kek, &nonce) {
        Some(expected) => expected.as_slice().ct_eq(stored_commitment),
        None => Choice::from(0u8),
    };
    let aad = associated_data(ciphertext.len(), context).ok_or_else(opaque)?;
    let payload = cipher.decrypt(&nonce, ciphertext, &tag, Some(&aad));
    let (payload, aead_ok) = match payload {
        Ok(p) => (p, Choice::from(1u8)),
        Err(_e) => (Zeroizing::new(Vec::new()), Choice::from(0u8)),
    };
    if !bool::from(commitment_ok & aead_ok) {
        return Err(opaque());
    }

    let (&key_len, rest) = payload.split_first().ok_or_else(opaque)?;
    let key_len = usize::from(key_len);
    if !SUPPORTED_KEY_LENS.contains(&key_len) {
        return Err(opaque());
    }
    let (key, padding) = rest.split_at_checked(key_len).ok_or_else(opaque)?;
    // `is_all_zero_bytes` is fail-closed on an empty slice; no padding is valid.
    if !padding.is_empty() && !is_all_zero_bytes(padding) {
        return Err(opaque());
    }
    Ok(Zeroizing::new(key.to_vec()))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::indexing_slicing, reason = "Tests index into buffers of known length")]
#[expect(clippy::arithmetic_side_effects, reason = "Tests use plain arithmetic on known sizes")]
mod tests {
    use super::*;

    const KEK: [u8; 32] = [
        0x6b, 0x65, 0x6b, 0x2d, 0x6c, 0x61, 0x74, 0x74, 0x69, 0x63, 0x65, 0x61, 0x72, 0x63, 0x2d,
        0x74, 0x65, 0x73, 0x74, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x31,
    ];
    const CONTEXT: &[u8] = b"vault/v1/root/epoch-1/locator-a";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sample_key(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i * 7 % 256).unwrap()).collect()
    }

    #[test]
    fn roundtrip_all_supported_lengths() {
        for len in SUPPORTED_KEY_LENS {
            let key = sample_key(len);
            let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
            assert_eq!(wrapped.len(), KEY_WRAP_OVERHEAD + len);
            assert_eq!(wrapped.as_bytes()[0], KEY_WRAP_VERSION);
            let parsed = WrappedKey::from_bytes(&wrapped.to_bytes()).unwrap();
            assert_eq!(unwrap_key(&KEK, &parsed, CONTEXT).unwrap().as_slice(), key.as_slice());
        }
    }

    #[test]
    fn padded_outputs_are_exactly_total_len() {
        for len in SUPPORTED_KEY_LENS {
            let key = sample_key(len);
            let min = KEY_WRAP_OVERHEAD + len;
            for total in [min, min + 1, min + 7, 256, 1024, 4096] {
                let wrapped = wrap_key_padded(&KEK, &key, CONTEXT, total).unwrap();
                assert_eq!(wrapped.len(), total, "key {len} total {total}");
                assert_eq!(unwrap_key(&KEK, &wrapped, CONTEXT).unwrap().as_slice(), key.as_slice());
            }
        }
    }

    #[test]
    fn padded_length_errors() {
        let key = sample_key(32);
        let min = KEY_WRAP_OVERHEAD + 32;
        assert!(matches!(
            wrap_key_padded(&KEK, &key, CONTEXT, min - 1),
            Err(AeadError::InvalidPaddedLength)
        ));
        assert!(matches!(
            wrap_key_padded(&KEK, &key, CONTEXT, 0),
            Err(AeadError::InvalidPaddedLength)
        ));
        assert!(matches!(
            wrap_key_padded(&KEK, &key, CONTEXT, MAX_WRAPPED_LEN + 1),
            Err(AeadError::InvalidPaddedLength)
        ));
        assert!(wrap_key_padded(&KEK, &key, CONTEXT, MAX_WRAPPED_LEN).is_ok());
    }

    #[test]
    fn invalid_key_length_fails() {
        for len in [0usize, 15, 17, 24, 31, 33, 48, 63, 65, 128] {
            assert!(
                matches!(
                    wrap_key(&KEK, &sample_key(len), CONTEXT),
                    Err(AeadError::InvalidKeyLength)
                ),
                "key length {len}"
            );
        }
    }

    #[test]
    fn empty_context_fails() {
        let key = sample_key(32);
        assert!(matches!(wrap_key(&KEK, &key, b""), Err(AeadError::EmptyContext)));
        let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
        assert!(matches!(unwrap_key(&KEK, &wrapped, b""), Err(AeadError::EmptyContext)));
    }

    #[test]
    fn weak_kek_fails() {
        let key = sample_key(32);
        assert!(matches!(wrap_key(&[0u8; 32], &key, CONTEXT), Err(AeadError::WeakKey)));
        let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
        assert!(matches!(unwrap_key(&[0u8; 32], &wrapped, CONTEXT), Err(AeadError::WeakKey)));
    }

    #[test]
    fn malformed_encoding_fails() {
        let wrapped = wrap_key(&KEK, &sample_key(16), CONTEXT).unwrap();
        let bytes = wrapped.to_bytes();
        assert_eq!(bytes.len(), MIN_WRAPPED_LEN);
        assert!(matches!(WrappedKey::from_bytes(&[]), Err(AeadError::MalformedEncoding)));
        assert!(matches!(
            WrappedKey::from_bytes(&bytes[..MIN_WRAPPED_LEN - 1]),
            Err(AeadError::MalformedEncoding)
        ));
        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert!(matches!(
            WrappedKey::from_bytes(&wrong_version),
            Err(AeadError::MalformedEncoding)
        ));
        let too_long = vec![KEY_WRAP_VERSION; MAX_WRAPPED_LEN + 1];
        assert!(matches!(WrappedKey::from_bytes(&too_long), Err(AeadError::MalformedEncoding)));
        // A structurally valid but unauthenticated blob parses and then
        // fails at unwrap, never at parse.
        let junk = vec![KEY_WRAP_VERSION; MIN_WRAPPED_LEN];
        let parsed = WrappedKey::from_bytes(&junk).unwrap();
        assert!(matches!(unwrap_key(&KEK, &parsed, CONTEXT), Err(AeadError::DecryptionFailed(_))));
        assert!(!parsed.is_empty());
    }

    #[test]
    fn wrong_kek_always_fails() {
        let key = sample_key(32);
        let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
        for bit in 0..256usize {
            let mut kek = KEK;
            kek[bit / 8] ^= 1 << (bit % 8);
            assert!(
                matches!(unwrap_key(&kek, &wrapped, CONTEXT), Err(AeadError::DecryptionFailed(_))),
                "kek bit {bit}"
            );
        }
    }

    #[test]
    fn wrong_context_fails() {
        let key = sample_key(32);
        let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
        for ctx in [&b"vault/v1/root/epoch-2/locator-a"[..], b"vault/v1/file", b"x"] {
            assert!(matches!(unwrap_key(&KEK, &wrapped, ctx), Err(AeadError::DecryptionFailed(_))));
        }
    }

    #[test]
    fn bit_flip_anywhere_fails() {
        for len in SUPPORTED_KEY_LENS {
            let key = sample_key(len);
            let wrapped =
                wrap_key_padded(&KEK, &key, CONTEXT, KEY_WRAP_OVERHEAD + len + 5).unwrap();
            let bytes = wrapped.to_bytes();
            for pos in 1..bytes.len() {
                for bit in 0..8u8 {
                    let mut bad = bytes.clone();
                    bad[pos] ^= 1 << bit;
                    let parsed = WrappedKey::from_bytes(&bad).unwrap();
                    assert!(
                        matches!(
                            unwrap_key(&KEK, &parsed, CONTEXT),
                            Err(AeadError::DecryptionFailed(_))
                        ),
                        "key {len} byte {pos} bit {bit}"
                    );
                }
            }
        }
    }

    #[test]
    fn unwrap_errors_are_opaque() {
        let key = sample_key(16);
        let wrapped = wrap_key(&KEK, &key, CONTEXT).unwrap();
        let bytes = wrapped.to_bytes();
        let mut other_kek = KEK;
        other_kek[0] ^= 1;
        let wrong_kek = format!("{}", unwrap_key(&other_kek, &wrapped, CONTEXT).unwrap_err());
        let mut bad_commit = bytes.clone();
        bad_commit[OFFSET_COMMITMENT] ^= 1;
        let bad_commit = format!(
            "{}",
            unwrap_key(&KEK, &WrappedKey::from_bytes(&bad_commit).unwrap(), CONTEXT).unwrap_err()
        );
        let mut bad_tag = bytes.clone();
        bad_tag[bytes.len() - 1] ^= 1;
        let bad_tag = format!(
            "{}",
            unwrap_key(&KEK, &WrappedKey::from_bytes(&bad_tag).unwrap(), CONTEXT).unwrap_err()
        );
        let wrong_ctx = format!("{}", unwrap_key(&KEK, &wrapped, b"other").unwrap_err());
        assert_eq!(wrong_kek, bad_commit);
        assert_eq!(wrong_kek, bad_tag);
        assert_eq!(wrong_kek, wrong_ctx);
    }

    #[test]
    fn fresh_nonce_per_wrap() {
        let key = sample_key(32);
        let a = wrap_key(&KEK, &key, CONTEXT).unwrap();
        let b = wrap_key(&KEK, &key, CONTEXT).unwrap();
        assert_ne!(
            a.as_bytes()[OFFSET_NONCE..OFFSET_COMMITMENT],
            b.as_bytes()[OFFSET_NONCE..OFFSET_COMMITMENT]
        );
        assert_ne!(a.as_bytes()[OFFSET_CIPHERTEXT..], b.as_bytes()[OFFSET_CIPHERTEXT..]);
    }

    /// Smoke test, not a proof: across 1000 wraps of the same key under the
    /// same KEK and context, no byte position after the version byte is
    /// constant and every byte value occurs with roughly uniform frequency.
    #[test]
    fn output_bytes_look_random() {
        const SAMPLES: usize = 1000;
        let key = sample_key(32);
        let total = KEY_WRAP_OVERHEAD + 32;
        let outputs: Vec<Vec<u8>> =
            (0..SAMPLES).map(|_| wrap_key(&KEK, &key, CONTEXT).unwrap().to_bytes()).collect();

        for pos in 1..total {
            let first = outputs[0][pos];
            assert!(
                outputs.iter().any(|o| o[pos] != first),
                "byte position {pos} is constant across {SAMPLES} outputs"
            );
        }

        let mut histogram = [0usize; 256];
        for o in &outputs {
            for &b in &o[1..] {
                histogram[usize::from(b)] += 1;
            }
        }
        let n = SAMPLES * (total - 1);
        let expected = n / 256;
        for (value, &count) in histogram.iter().enumerate() {
            assert!(
                count > expected / 2 && count < expected * 3 / 2,
                "byte value {value:#04x} occurs {count} times, expected about {expected}"
            );
        }
    }

    /// Pins this module's output for a fixed KEK, key, context and nonce so
    /// any drift in the commitment, AAD or payload layout is caught.
    #[test]
    fn pinned_output_bytes() {
        let nonce: Nonce = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b];
        let key = sample_key(16);
        let wrapped =
            wrap_key_with_nonce(&KEK, &key, CONTEXT, KEY_WRAP_OVERHEAD + 16 + 4, &nonce).unwrap();
        assert_eq!(
            hex(wrapped.as_bytes()),
            concat!(
                "01",
                "101112131415161718191a1b",
                "bed2627fea9623063f851490043a881ebe485661df3ad9871a02f53901d60461",
                "05ab72831248119c2ae1784865d1856d1fb95c9f595d6add6342181646c1b428d8abcd7dbd",
            )
        );
        assert_eq!(unwrap_key(&KEK, &wrapped, CONTEXT).unwrap().as_slice(), key.as_slice());
    }

    #[test]
    fn debug_prints_length_only() {
        let wrapped = wrap_key(&KEK, &sample_key(16), CONTEXT).unwrap();
        assert_eq!(format!("{wrapped:?}"), format!("WrappedKey {{ len: {} }}", MIN_WRAPPED_LEN));
    }
}
