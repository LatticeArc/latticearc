//! Property-based tests for the streaming AEAD (`primitives::aead::stream`).
//!
//! Roundtrip over random segment counts and sizes, then the failure
//! properties: truncation, reordering, splicing from another stream (same key
//! or different key), bit flips in the header or any segment, and wrong AAD.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use latticearc::primitives::aead::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};
use proptest::prelude::*;

/// Non-zero 32-byte key.
fn key_strategy() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
        .prop_filter("all-zero keys are rejected by design", |k| k.iter().any(|&b| b != 0))
}

/// Non-empty AAD up to 64 bytes.
fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

/// Segment sizes small enough to produce several segments from a short
/// plaintext.
fn segment_size_strategy() -> impl Strategy<Value = u32> {
    64u32..=512
}

/// Seals `plaintext` under a fresh stream; returns `(header, segments)`.
fn seal_all(
    key: &[u8; 32],
    aad: &[u8],
    segment_size: u32,
    plaintext: &[u8],
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut enc = StreamEncryptor::new(key, aad, segment_size).unwrap();
    let header = enc.header().to_vec();
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

fn open_all(
    dec: &mut StreamDecryptor,
    segments: &[Vec<u8>],
) -> Result<Vec<u8>, latticearc::primitives::aead::AeadError> {
    let mut out = Vec::new();
    let last = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        out.extend_from_slice(&dec.open_next(seg, i == last)?);
    }
    Ok(out)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Sequential and random-access decryption recover the plaintext for
    /// random segment sizes and plaintext lengths (0 to ~5 segments).
    #[test]
    fn roundtrip(
        key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 0..2500),
    ) {
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        prop_assert_eq!(header.len(), HEADER_LEN);
        for (i, seg) in segments.iter().enumerate() {
            let full = usize::try_from(segment_size).unwrap() - if i == 0 { 40 } else { 0 };
            if i + 1 < segments.len() {
                prop_assert_eq!(seg.len(), full);
            } else {
                prop_assert!(seg.len() <= full);
            }
        }

        let mut dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        prop_assert_eq!(&open_all(&mut dec, &segments).unwrap(), &plaintext);
        prop_assert!(dec.is_finished());

        let dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        let mut recovered = Vec::new();
        for (i, seg) in segments.iter().enumerate() {
            let idx = u32::try_from(i).unwrap();
            let pt = dec.open_segment(idx, seg, i + 1 == segments.len()).unwrap();
            recovered.extend_from_slice(&pt);
        }
        prop_assert_eq!(recovered, plaintext);
    }

    /// Dropping the final segment is detected: the new last segment does not
    /// carry the last flag, and claiming it does fails.
    #[test]
    fn truncation_fails(
        key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 600..2500),
    ) {
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        prop_assert!(segments.len() >= 2);
        let truncated = &segments[..segments.len() - 1];
        let mut dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        prop_assert!(open_all(&mut dec, truncated).is_err());
        prop_assert!(!dec.is_finished());
        let dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        let last_idx = u32::try_from(truncated.len() - 1).unwrap();
        prop_assert!(dec.open_segment(last_idx, &truncated[truncated.len() - 1], true).is_err());
    }

    /// Swapping any two distinct segments fails.
    #[test]
    fn reordering_fails(
        key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 600..2500),
        a in any::<usize>(),
        b in any::<usize>(),
    ) {
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        prop_assert!(segments.len() >= 2);
        let a = a % segments.len();
        let b = b % segments.len();
        prop_assume!(a != b);
        let mut swapped = segments.clone();
        swapped.swap(a, b);
        let mut dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        prop_assert!(open_all(&mut dec, &swapped).is_err());
        let dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        let last = segments.len() - 1;
        prop_assert!(dec.open_segment(u32::try_from(a).unwrap(), &segments[b], a == last).is_err());
    }

    /// A segment from another stream at the same index fails, whether that
    /// stream used the same key (fresh salt / nonce prefix) or another key.
    #[test]
    fn splicing_fails(
        key in key_strategy(),
        other_key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 0..2500),
        which in any::<usize>(),
    ) {
        prop_assume!(key != other_key);
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        let (_, same_key) = seal_all(&key, &aad, segment_size, &plaintext);
        let (_, other) = seal_all(&other_key, &aad, segment_size, &plaintext);
        let i = which % segments.len();
        let idx = u32::try_from(i).unwrap();
        let is_last = i + 1 == segments.len();
        let dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        prop_assert!(dec.open_segment(idx, &segments[i], is_last).is_ok());
        prop_assert!(dec.open_segment(idx, &same_key[i], is_last).is_err());
        prop_assert!(dec.open_segment(idx, &other[i], is_last).is_err());
    }

    /// Flipping any bit of the header fails at construction; flipping any
    /// bit of any segment fails at open.
    #[test]
    fn bit_flip_fails(
        key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 0..2500),
        header_bit in 0usize..(HEADER_LEN * 8),
        seg_pick in any::<usize>(),
        seg_bit in any::<usize>(),
    ) {
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        let mut bad_header = header.clone();
        bad_header[header_bit / 8] ^= 1 << (header_bit % 8);
        prop_assert!(StreamDecryptor::new(&key, &aad, &bad_header).is_err());

        let i = seg_pick % segments.len();
        let seg = &segments[i];
        let bit = seg_bit % (seg.len() * 8);
        let mut bad = seg.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        let dec = StreamDecryptor::new(&key, &aad, &header).unwrap();
        let idx = u32::try_from(i).unwrap();
        prop_assert!(dec.open_segment(idx, &bad, i + 1 == segments.len()).is_err());
    }

    /// A different AAD derives a different segment key: every segment fails.
    #[test]
    fn wrong_aad_fails(
        key in key_strategy(),
        aad in aad_strategy(),
        other_aad in aad_strategy(),
        segment_size in segment_size_strategy(),
        plaintext in prop::collection::vec(any::<u8>(), 0..1200),
    ) {
        prop_assume!(aad != other_aad);
        let (header, segments) = seal_all(&key, &aad, segment_size, &plaintext);
        let mut dec = StreamDecryptor::new(&key, &other_aad, &header).unwrap();
        prop_assert!(open_all(&mut dec, &segments).is_err());
        for (i, seg) in segments.iter().enumerate() {
            let idx = u32::try_from(i).unwrap();
            prop_assert!(dec.open_segment(idx, seg, i + 1 == segments.len()).is_err());
        }
    }

    /// A wrong key is rejected by the commitment before any segment is read.
    #[test]
    fn wrong_key_fails_at_header(
        key in key_strategy(),
        other_key in key_strategy(),
        aad in aad_strategy(),
        segment_size in segment_size_strategy(),
    ) {
        prop_assume!(key != other_key);
        let enc = StreamEncryptor::new(&key, &aad, segment_size).unwrap();
        prop_assert!(StreamDecryptor::new(&other_key, &aad, enc.header()).is_err());
    }
}
