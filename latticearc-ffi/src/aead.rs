//! Committing key wrap and streaming AEAD.

use std::sync::{Arc, Mutex, PoisonError};

use latticearc::primitives::aead::key_wrap::{
    WrappedKey, unwrap_key_with_policy as core_unwrap_key_with_policy, wrap_key as core_wrap_key,
    wrap_key_padded as core_wrap_key_padded,
};
use latticearc::{
    FormatPolicy, StreamDecryptor as CoreStreamDecryptor, StreamEncryptor as CoreStreamEncryptor,
};

use crate::error::LatticeArcError;
use crate::secrets::{SecretBytes, take_zeroizing};

fn usize_to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// Key wrap
// ---------------------------------------------------------------------------

/// Wraps a 16-, 32- or 64-byte `key` under a 32-byte `kek` with AES-256-GCM
/// plus an HMAC-SHA256 commitment to the KEK and the context (format 2).
/// `context` is required, non-empty, committed and bound as associated data;
/// the same context must be given to [`unwrap_key`].
///
/// # Errors
///
/// `InvalidInput` for a KEK that is not 32 bytes or a key of unsupported
/// length; `InvalidContext` for an empty context.
#[uniffi::export]
pub fn wrap_key(
    kek: &SecretBytes,
    key: &SecretBytes,
    context: Vec<u8>,
) -> Result<Vec<u8>, LatticeArcError> {
    let kek = kek.key32("key-encryption key")?;
    Ok(core_wrap_key(&kek, key.expose(), &context)?.to_bytes())
}

/// Like [`wrap_key`] but pads under the AEAD so the output is exactly
/// `total_len` bytes, whatever the wrapped key's length.
///
/// # Errors
///
/// As [`wrap_key`], plus `InvalidInput` when `total_len` is too small for
/// the key or above the 1 MiB cap.
#[uniffi::export]
pub fn wrap_key_padded(
    kek: &SecretBytes,
    key: &SecretBytes,
    context: Vec<u8>,
    total_len: u32,
) -> Result<Vec<u8>, LatticeArcError> {
    let kek = kek.key32("key-encryption key")?;
    Ok(core_wrap_key_padded(&kek, key.expose(), &context, total_len as usize)?.to_bytes())
}

/// Recovers a key wrapped by [`wrap_key`] or [`wrap_key_padded`] (format 2
/// only).
///
/// # Errors
///
/// `AuthenticationFailed` for a wrong KEK, wrong context or tampered bytes;
/// `InvalidInput` for a KEK that is not 32 bytes, an encoding that is not
/// even the right shape, or a legacy format-1 record (read those with
/// [`unwrap_key_allowing_v1`] and re-wrap them).
#[uniffi::export]
pub fn unwrap_key(
    kek: &SecretBytes,
    wrapped: Vec<u8>,
    context: Vec<u8>,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    unwrap_with_policy(kek, &wrapped, &context, FormatPolicy::RequireV2)
}

/// Like [`unwrap_key`], but also accepts a legacy format-1 record written by
/// LatticeArc 0.13–0.15, whose commitment covers the KEK but not the
/// context. Use only to migrate old records: unwrap, then re-wrap with
/// [`wrap_key`].
///
/// # Errors
///
/// As [`unwrap_key`], except that a format-1 record is accepted.
#[uniffi::export]
pub fn unwrap_key_allowing_v1(
    kek: &SecretBytes,
    wrapped: Vec<u8>,
    context: Vec<u8>,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    unwrap_with_policy(kek, &wrapped, &context, FormatPolicy::AllowV1)
}

fn unwrap_with_policy(
    kek: &SecretBytes,
    wrapped: &[u8],
    context: &[u8],
    policy: FormatPolicy,
) -> Result<Arc<SecretBytes>, LatticeArcError> {
    let kek = kek.key32("key-encryption key")?;
    let wrapped = WrappedKey::from_bytes(wrapped)?;
    let key = core_unwrap_key_with_policy(&kek, &wrapped, context, policy)?;
    Ok(SecretBytes::from_vec(take_zeroizing(key)))
}

// ---------------------------------------------------------------------------
// Streaming AEAD
// ---------------------------------------------------------------------------

/// Encrypts a stream as AES-256-GCM segments under a committing header.
///
/// Call `seal_segment` once per full plaintext segment and `finish` with the
/// (possibly empty, possibly short) tail. Every segment except the first
/// holds `plaintext_segment_size` bytes; the first holds
/// `first_plaintext_segment_size`.
#[derive(uniffi::Object)]
pub struct StreamEncryptor {
    inner: Mutex<Option<CoreStreamEncryptor>>,
    header: Vec<u8>,
    segment_size: u32,
    plaintext_segment_size: u32,
    first_plaintext_segment_size: u32,
}

#[uniffi::export]
impl StreamEncryptor {
    /// Starts a stream under a 32-byte `key` with the required, non-empty
    /// `aad` bound to every segment and ciphertext segments of
    /// `segment_size` bytes (64 bytes to 16 MiB).
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a key that is not 32 bytes or a segment size out of
    /// range; `InvalidContext` for an empty `aad`.
    #[uniffi::constructor]
    pub fn new(
        key: &SecretBytes,
        aad: Vec<u8>,
        segment_size: u32,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let key = key.key32("stream key")?;
        let enc = CoreStreamEncryptor::new(&key, &aad, segment_size)?;
        Ok(Arc::new(Self {
            header: enc.header().to_vec(),
            segment_size: enc.segment_size(),
            plaintext_segment_size: usize_to_u32(enc.plaintext_segment_size()),
            first_plaintext_segment_size: usize_to_u32(enc.first_plaintext_segment_size()),
            inner: Mutex::new(Some(enc)),
        }))
    }

    /// The stream header; store it with the ciphertext.
    #[must_use]
    pub fn header(&self) -> Vec<u8> {
        self.header.clone()
    }

    /// Ciphertext segment size in bytes.
    #[must_use]
    pub fn segment_size(&self) -> u32 {
        self.segment_size
    }

    /// Plaintext bytes carried by every segment after the first.
    #[must_use]
    pub fn plaintext_segment_size(&self) -> u32 {
        self.plaintext_segment_size
    }

    /// Plaintext bytes carried by the first segment.
    #[must_use]
    pub fn first_plaintext_segment_size(&self) -> u32 {
        self.first_plaintext_segment_size
    }

    /// Index of the next segment `seal_segment` will produce.
    ///
    /// # Errors
    ///
    /// `StreamExhausted` after `finish`.
    pub fn next_index(&self) -> Result<u32, LatticeArcError> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref().map(CoreStreamEncryptor::next_index).ok_or(LatticeArcError::StreamExhausted)
    }

    /// Seals one full segment of plaintext and returns the ciphertext
    /// segment.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when `plaintext` is not exactly the segment's
    /// capacity; `StreamExhausted` after `finish` or when the segment
    /// counter would wrap.
    pub fn seal_segment(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, LatticeArcError> {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let enc = guard.as_mut().ok_or(LatticeArcError::StreamExhausted)?;
        Ok(enc.seal_segment(&plaintext)?)
    }

    /// Seals the final segment (any length up to the segment's capacity,
    /// including empty) and closes the stream.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when the tail is longer than a segment;
    /// `StreamExhausted` when the stream was already finished.
    pub fn finish(&self, last_plaintext: Vec<u8>) -> Result<Vec<u8>, LatticeArcError> {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let live = guard.as_ref().ok_or(LatticeArcError::StreamExhausted)?;
        // Check the only input error before consuming the encryptor, so a
        // caller can fix the tail and retry instead of losing the stream.
        let capacity = if live.next_index() == 0 {
            live.first_plaintext_segment_size()
        } else {
            live.plaintext_segment_size()
        };
        if last_plaintext.len() > capacity {
            return Err(LatticeArcError::invalid_input(format!(
                "last segment holds at most {capacity} bytes, got {}",
                last_plaintext.len()
            )));
        }
        let enc = guard.take().ok_or(LatticeArcError::StreamExhausted)?;
        Ok(enc.finish(&last_plaintext)?)
    }
}

/// Decrypts segments produced by [`StreamEncryptor`], in order or by index.
///
/// A wrong key or a wrong `aad` fails in the constructor, before any segment
/// is touched, thanks to the key- and context-commitment in the format-2
/// header. (A legacy format-1 header opened with
/// [`StreamDecryptor::new_allowing_v1`] commits to the key only; there a
/// wrong `aad` fails on the first segment opened.)
#[derive(uniffi::Object)]
pub struct StreamDecryptor {
    inner: Mutex<CoreStreamDecryptor>,
    segment_size: u32,
    plaintext_segment_size: u32,
    first_plaintext_segment_size: u32,
}

#[uniffi::export]
impl StreamDecryptor {
    /// Opens a format-2 stream from its `header`.
    ///
    /// # Errors
    ///
    /// `AuthenticationFailed` for a wrong key, wrong `aad` or tampered
    /// header; `InvalidInput` for a key that is not 32 bytes or a legacy
    /// format-1 header (open those with [`Self::new_allowing_v1`] and
    /// re-encrypt); `InvalidContext` for an empty `aad`.
    #[uniffi::constructor]
    pub fn new(
        key: &SecretBytes,
        aad: Vec<u8>,
        header: Vec<u8>,
    ) -> Result<Arc<Self>, LatticeArcError> {
        Self::open_with_policy(key, &aad, &header, FormatPolicy::RequireV2)
    }

    /// Like [`Self::new`], but also opens a legacy format-1 header written by
    /// LatticeArc 0.13–0.15, which commits to the key but not to `aad`. Use
    /// only to migrate old streams: decrypt, then re-encrypt with
    /// [`StreamEncryptor`].
    ///
    /// # Errors
    ///
    /// As [`Self::new`], except that a format-1 header is accepted.
    #[uniffi::constructor]
    pub fn new_allowing_v1(
        key: &SecretBytes,
        aad: Vec<u8>,
        header: Vec<u8>,
    ) -> Result<Arc<Self>, LatticeArcError> {
        Self::open_with_policy(key, &aad, &header, FormatPolicy::AllowV1)
    }

    /// Format version of the opened header: 2, or 1 for a legacy header
    /// opened with [`Self::new_allowing_v1`].
    #[must_use]
    pub fn format_version(&self) -> u8 {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).format_version()
    }

    /// Ciphertext segment size in bytes.
    #[must_use]
    pub fn segment_size(&self) -> u32 {
        self.segment_size
    }

    /// Plaintext bytes carried by every segment after the first.
    #[must_use]
    pub fn plaintext_segment_size(&self) -> u32 {
        self.plaintext_segment_size
    }

    /// Plaintext bytes carried by the first segment.
    #[must_use]
    pub fn first_plaintext_segment_size(&self) -> u32 {
        self.first_plaintext_segment_size
    }

    /// Index `open_next` will read next.
    #[must_use]
    pub fn next_index(&self) -> u32 {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).next_index()
    }

    /// `true` once `open_next` has consumed the last segment.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).is_finished()
    }

    /// Opens the segment at `index` (random access). `is_last` must say
    /// whether this is the stream's final segment.
    ///
    /// # Errors
    ///
    /// `AuthenticationFailed` for a tampered, reordered or misdescribed
    /// segment.
    pub fn open_segment(
        &self,
        index: u32,
        segment: Vec<u8>,
        is_last: bool,
    ) -> Result<Vec<u8>, LatticeArcError> {
        let guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(take_zeroizing(guard.open_segment(index, &segment, is_last)?))
    }

    /// Opens the next segment in order.
    ///
    /// # Errors
    ///
    /// `AuthenticationFailed` for a tampered or misdescribed segment;
    /// `StreamExhausted` after the last segment.
    pub fn open_next(&self, segment: Vec<u8>, is_last: bool) -> Result<Vec<u8>, LatticeArcError> {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(take_zeroizing(guard.open_next(&segment, is_last)?))
    }
}

impl StreamDecryptor {
    fn open_with_policy(
        key: &SecretBytes,
        aad: &[u8],
        header: &[u8],
        policy: FormatPolicy,
    ) -> Result<Arc<Self>, LatticeArcError> {
        let key = key.key32("stream key")?;
        let dec = CoreStreamDecryptor::new_with_policy(&key, aad, header, policy)?;
        Ok(Arc::new(Self {
            segment_size: dec.segment_size(),
            plaintext_segment_size: usize_to_u32(dec.plaintext_segment_size()),
            first_plaintext_segment_size: usize_to_u32(dec.first_plaintext_segment_size()),
            inner: Mutex::new(dec),
        }))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
#[expect(clippy::indexing_slicing, reason = "Tests index into buffers of known length")]
#[expect(clippy::arithmetic_side_effects, reason = "Tests use plain arithmetic on known sizes")]
mod tests {
    use super::*;

    fn kek() -> Arc<SecretBytes> {
        SecretBytes::import(vec![0x11; 32])
    }

    #[test]
    fn wrap_unwrap_roundtrip_all_key_sizes() {
        for len in [16usize, 32, 64] {
            let key = SecretBytes::import(vec![0x22; len]);
            let wrapped = wrap_key(&kek(), &key, b"app/v1/key".to_vec()).unwrap();
            let back = unwrap_key(&kek(), wrapped, b"app/v1/key".to_vec()).unwrap();
            assert_eq!(back.export_bytes(), vec![0x22; len]);
        }
    }

    #[test]
    fn wrap_rejects_bad_kek_and_empty_context() {
        let key = SecretBytes::import(vec![0x22; 32]);
        let short_kek = SecretBytes::import(vec![0; 16]);
        assert!(matches!(
            wrap_key(&short_kek, &key, b"ctx".to_vec()),
            Err(LatticeArcError::InvalidInput { .. })
        ));
        assert!(matches!(
            wrap_key(&kek(), &key, vec![]),
            Err(LatticeArcError::InvalidContext { .. })
        ));
    }

    #[test]
    fn unwrap_wrong_kek_or_context_is_opaque() {
        let key = SecretBytes::import(vec![0x22; 32]);
        let wrapped = wrap_key(&kek(), &key, b"ctx".to_vec()).unwrap();
        let other = SecretBytes::import(vec![0x33; 32]);
        assert_eq!(
            unwrap_key(&other, wrapped.clone(), b"ctx".to_vec()).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        assert_eq!(
            unwrap_key(&kek(), wrapped.clone(), b"other".to_vec()).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        let mut tampered = wrapped;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            unwrap_key(&kek(), tampered, b"ctx".to_vec()).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
    }

    #[test]
    fn wrap_padded_has_fixed_length() {
        let key = SecretBytes::import(vec![0x22; 32]);
        let wrapped = wrap_key_padded(&kek(), &key, b"root".to_vec(), 512).unwrap();
        assert_eq!(wrapped.len(), 512);
        let back = unwrap_key(&kek(), wrapped, b"root".to_vec()).unwrap();
        assert_eq!(back.export_bytes(), vec![0x22; 32]);
    }

    #[test]
    fn stream_roundtrip_sequential_and_random_access() {
        let key = SecretBytes::import(vec![0x44; 32]);
        let enc = StreamEncryptor::new(&key, b"file".to_vec(), 256).unwrap();
        let first = vec![1u8; enc.first_plaintext_segment_size() as usize];
        let middle = vec![2u8; enc.plaintext_segment_size() as usize];
        let tail = vec![3u8; 10];
        assert_eq!(enc.next_index().unwrap(), 0);
        let s0 = enc.seal_segment(first.clone()).unwrap();
        let s1 = enc.seal_segment(middle.clone()).unwrap();
        assert_eq!(enc.next_index().unwrap(), 2);
        let s2 = enc.finish(tail.clone()).unwrap();
        assert_eq!(enc.seal_segment(vec![]).unwrap_err(), LatticeArcError::StreamExhausted);
        assert_eq!(enc.next_index().unwrap_err(), LatticeArcError::StreamExhausted);

        let dec = StreamDecryptor::new(&key, b"file".to_vec(), enc.header()).unwrap();
        assert_eq!(dec.segment_size(), 256);
        assert_eq!(dec.open_segment(1, s1.clone(), false).unwrap(), middle);
        assert_eq!(dec.open_next(s0, false).unwrap(), first);
        assert_eq!(dec.open_next(s1.clone(), false).unwrap(), middle);
        assert!(!dec.is_finished());
        assert_eq!(dec.open_next(s2.clone(), true).unwrap(), tail);
        assert!(dec.is_finished());
        assert_eq!(dec.open_next(s2, true).unwrap_err(), LatticeArcError::StreamExhausted);

        // Misdescribed, reordered or tampered segments fail opaquely.
        assert_eq!(
            dec.open_segment(1, s1.clone(), true).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        assert_eq!(
            dec.open_segment(0, s1.clone(), false).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
        let mut bad = s1;
        bad[5] ^= 0x80;
        assert_eq!(
            dec.open_segment(1, bad, false).unwrap_err(),
            LatticeArcError::AuthenticationFailed
        );
    }

    #[test]
    fn stream_wrong_key_or_wrong_aad_fails_at_open() {
        let key = SecretBytes::import(vec![0x44; 32]);
        let enc = StreamEncryptor::new(&key, b"aad".to_vec(), 128).unwrap();
        let header = enc.header();
        let only = enc.finish(b"payload".to_vec()).unwrap();
        let other = SecretBytes::import(vec![0x55; 32]);
        assert_eq!(
            StreamDecryptor::new(&other, b"aad".to_vec(), header.clone()).err().unwrap(),
            LatticeArcError::AuthenticationFailed
        );
        assert_eq!(
            StreamDecryptor::new(&key, b"other".to_vec(), header.clone()).err().unwrap(),
            LatticeArcError::AuthenticationFailed
        );
        let dec = StreamDecryptor::new(&key, b"aad".to_vec(), header).unwrap();
        assert_eq!(dec.format_version(), 2);
        assert_eq!(dec.open_segment(0, only, true).unwrap(), b"payload".to_vec());
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Legacy format-1 records (pinned bytes from the core known-answer
    /// tests) are refused by the default entry points and opened by the
    /// `_allowing_v1` ones.
    #[test]
    fn legacy_v1_records_need_the_allowing_v1_entry_points() {
        let kek = SecretBytes::import(b"kek-latticearc-test-000000000001".to_vec());
        let ctx = b"vault/v1/root/epoch-1/locator-a".to_vec();
        let wrapped = unhex(concat!(
            "01",
            "101112131415161718191a1b",
            "bed2627fea9623063f851490043a881ebe485661df3ad9871a02f53901d60461",
            "05ab72831248119c2ae1784865d1856d1fb95c9f595d6add6342181646c1b428d8abcd7dbd",
        ));
        assert!(matches!(
            unwrap_key(&kek, wrapped.clone(), ctx.clone()),
            Err(LatticeArcError::InvalidInput { .. })
        ));
        let key: Vec<u8> = (0..16usize).map(|i| u8::try_from(i * 7 % 256).unwrap()).collect();
        assert_eq!(unwrap_key_allowing_v1(&kek, wrapped, ctx).unwrap().export_bytes(), key);

        let stream_key = SecretBytes::import(b"LatticeArc-stream-test-key-00001".to_vec());
        let header = unhex(concat!(
            "0100",
            "00000040",
            "28",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "a0a1a2a3a4a5a6",
            "bb8df52093b77bbc644b8def8409f4803449e9075139ad25f1dd35737b3cf0e6",
        ));
        let aad = b"vault/v1/file".to_vec();
        assert!(matches!(
            StreamDecryptor::new(&stream_key, aad.clone(), header.clone()).err().unwrap(),
            LatticeArcError::InvalidInput { .. }
        ));
        let dec = StreamDecryptor::new_allowing_v1(&stream_key, aad, header).unwrap();
        assert_eq!(dec.format_version(), 1);
        let seg0 = unhex("dbdda4765e7e4c118f921e8a02f7739b6d026f8c5a024b01");
        let seg1 = unhex("25bdbf2236555c1ca4dc1ba1fe416a17519a10b5d8");
        assert_eq!(dec.open_next(seg0, false).unwrap(), vec![0x11u8; 8]);
        assert_eq!(dec.open_next(seg1, true).unwrap(), b"final".to_vec());
    }

    #[test]
    fn stream_rejects_bad_segment_size_lengths_and_empty_aad() {
        let key = SecretBytes::import(vec![0x44; 32]);
        assert!(matches!(
            StreamEncryptor::new(&key, b"aad".to_vec(), 16).err().unwrap(),
            LatticeArcError::InvalidInput { .. }
        ));
        assert!(matches!(
            StreamEncryptor::new(&key, vec![], 128).err().unwrap(),
            LatticeArcError::InvalidContext { .. }
        ));
        let enc = StreamEncryptor::new(&key, b"aad".to_vec(), 128).unwrap();
        assert!(matches!(
            StreamDecryptor::new(&key, vec![], enc.header()).err().unwrap(),
            LatticeArcError::InvalidContext { .. }
        ));
        assert!(matches!(
            enc.seal_segment(vec![0u8; 3]).unwrap_err(),
            LatticeArcError::InvalidInput { .. }
        ));
        // An over-long tail is rejected without consuming the stream.
        let too_long = vec![0u8; enc.first_plaintext_segment_size() as usize + 1];
        assert!(matches!(enc.finish(too_long).unwrap_err(), LatticeArcError::InvalidInput { .. }));
        assert_eq!(enc.next_index().unwrap(), 0);
        assert!(enc.finish(vec![1, 2, 3]).is_ok());
        assert_eq!(enc.finish(vec![]).unwrap_err(), LatticeArcError::StreamExhausted);
    }
}
