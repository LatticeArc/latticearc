#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the segmented AEAD (`primitives::aead::segmented`).
//!
//! The object length comes from a fuzz-chosen `u32` capped at
//! `3 * PAYLOAD_LEN + 1` (up to four records, biased toward record
//! boundaries) and the plaintext is expanded from a fuzz-chosen seed, so
//! multi-record objects are reachable within libFuzzer's default input size.
//! Exercises four surfaces with attacker-controlled bytes:
//! 1. `SegmentedDecryptor::open_next` on arbitrary record bytes (raw, and
//!    resized to exactly `RECORD_LEN` at a fuzz-chosen stream position) must
//!    never panic, and a rejected record must retire the decryptor.
//! 2. A genuine encrypt/decrypt roundtrip with fuzz-chosen labels, binding,
//!    length and plaintext must recover the plaintext and finish cleanly.
//! 3. Any fuzz-chosen sequence of the object's records (permutation,
//!    duplication, truncation, extension) opens only if it is exactly the
//!    original order.
//! 4. A record spliced in from another object (other length or other
//!    generation), a bit flip, a cut or trailing byte, a mid-stream
//!    truncation, a truncated prefix presented as a shorter object, or a
//!    changed secret, length or generation must be rejected.

use latticearc::primitives::aead::segmented::{
    PAYLOAD_LEN, RECORD_LEN, SegmentedContext, SegmentedDecryptor, SegmentedEncryptor,
    SegmentedLabels, derive_object_id,
};
use libfuzzer_sys::fuzz_target;

/// secret (32) || label length (1) || binding length (1) || length (4) ||
/// seed (8) || flip (4) || position (1) || order length (1) || order (8).
const HEADER_LEN: usize = 60;

/// Longest fuzzed plaintext: three full records and one byte of a fourth.
const MAX_FUZZ_LEN: u64 = 3 * PAYLOAD_LEN as u64 + 1;

/// Maps the fuzz-chosen `raw` to a plaintext length in `0..=MAX_FUZZ_LEN`.
/// With the top bit set the length lands within two bytes of a record
/// boundary; otherwise it is spread over the whole range.
fn object_len(raw: u32) -> u64 {
    if raw & 0x8000_0000 != 0 {
        let boundary = u64::from(raw & 0x3) * PAYLOAD_LEN as u64;
        let delta = u64::from((raw >> 2) % 5);
        (boundary + delta).saturating_sub(2).min(MAX_FUZZ_LEN)
    } else {
        u64::from(raw) % (MAX_FUZZ_LEN + 1)
    }
}

/// `len` bytes of SplitMix64 output from `seed`, with `prefix` copied over
/// the start so the fuzzer still controls leading bytes directly.
fn expand(seed: u64, prefix: &[u8], len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(len);
    let n = prefix.len().min(len);
    out[..n].copy_from_slice(&prefix[..n]);
    out
}

/// Seals `plaintext` as the complete object `context`.
fn seal(secret: &[u8; 32], context: &SegmentedContext, plaintext: &[u8]) -> Vec<Vec<u8>> {
    let mut enc = SegmentedEncryptor::new(secret, context.clone()).unwrap();
    let mut records = Vec::new();
    let mut remaining = plaintext;
    for index in 0..context.record_count() {
        let (head, tail) = remaining.split_at(context.payload_len(index).unwrap());
        let record = enc.seal_next(head).expect("genuine chunk must seal");
        assert_eq!(record.len(), RECORD_LEN);
        records.push(record);
        remaining = tail;
    }
    assert!(remaining.is_empty());
    enc.finish().expect("every record was sealed");
    records
}

/// Opens `records` in order; `true` only if every record and `finish` pass.
fn opens(secret: &[u8; 32], context: &SegmentedContext, records: &[Vec<u8>]) -> bool {
    let Ok(mut dec) = SegmentedDecryptor::new(secret, context.clone()) else {
        return false;
    };
    records.iter().all(|r| dec.open_next(r).is_ok()) && dec.finish().is_ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN {
        return;
    }
    let (header, tail) = data.split_at(HEADER_LEN);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&header[..32]);
    if secret.iter().all(|&b| b == 0) {
        secret[0] = 1;
    }
    let label_len = usize::from(header[32] % 32).min(tail.len());
    let binding_len = usize::from(header[33] % 80).min(tail.len() - label_len);
    let length = object_len(u32::from_be_bytes(header[34..38].try_into().unwrap()));
    let seed = u64::from_be_bytes(header[38..46].try_into().unwrap());
    let flip = u32::from_be_bytes(header[46..50].try_into().unwrap());
    let position = usize::from(header[50]);
    let order_len = usize::from(header[51] % 9);
    let order_bytes = &header[52..52 + order_len];
    let (label, tail) = tail.split_at(label_len);
    let (binding, rest) = tail.split_at(binding_len);

    let key_label = [b"fuzz/key/".as_slice(), label].concat();
    let aad_label = [b"fuzz/aad/".as_slice(), label].concat();
    let labels = SegmentedLabels { record_key: &key_label, record_aad: &aad_label };
    let object_id = derive_object_id(b"fuzz/object/", binding).expect("non-empty prefix");
    let Ok(context) = SegmentedContext::with_random_generation(labels, binding, object_id, length)
    else {
        panic!("valid parameters must construct a context");
    };
    let plaintext = expand(seed, rest, usize::try_from(length).unwrap());

    // Surface 2: genuine roundtrip.
    let records = seal(&secret, &context, &plaintext);
    let n = records.len();
    assert_eq!(n as u64, context.record_count());
    let mut dec = SegmentedDecryptor::new(&secret, context.clone()).unwrap();
    let mut recovered = Vec::new();
    for record in &records {
        recovered.extend_from_slice(&dec.open_next(record).expect("genuine record"));
    }
    dec.finish().expect("genuine object must finish");
    assert_eq!(recovered, plaintext, "roundtrip must recover the plaintext");

    // Surface 1: arbitrary record bytes, first and at a fuzz-chosen position.
    let mut dec = SegmentedDecryptor::new(&secret, context.clone()).unwrap();
    if dec.open_next(rest).is_err() {
        assert!(dec.open_next(rest).is_err(), "a rejected record must retire the decryptor");
    }
    let at = position % n;
    let mut sized = rest.to_vec();
    sized.resize(RECORD_LEN, 0);
    let mut dec = SegmentedDecryptor::new(&secret, context.clone()).unwrap();
    for record in &records[..at] {
        dec.open_next(record).expect("genuine prefix");
    }
    if dec.open_next(&sized).is_err() {
        assert!(
            dec.open_next(&records[at]).is_err(),
            "a rejected record must retire the decryptor"
        );
    }

    // Surface 3: any reordering, duplication, truncation or extension.
    let order: Vec<usize> = order_bytes.iter().map(|&b| usize::from(b) % n).collect();
    let in_order = order.len() == n && order.iter().enumerate().all(|(i, &j)| i == j);
    let sequence: Vec<Vec<u8>> = order.iter().map(|&i| records[i].clone()).collect();
    assert_eq!(opens(&secret, &context, &sequence), in_order, "order {order:?} of {n}");

    // Surface 4: splicing from another object.
    let other_len = if length == 0 { 1 } else { length - 1 };
    let other_length_ctx =
        SegmentedContext::new(labels, binding, object_id, context.generation(), other_len).unwrap();
    let mut other_generation = context.generation();
    other_generation[usize::from(header[50]) % 32] ^= 0x01;
    let other_generation_ctx =
        SegmentedContext::new(labels, binding, object_id, other_generation, length).unwrap();
    for (other_ctx, what) in
        [(&other_length_ctx, "other length"), (&other_generation_ctx, "other generation")]
    {
        let other_plaintext =
            expand(seed ^ 1, rest, usize::try_from(other_ctx.plaintext_len()).unwrap());
        let other_records = seal(&secret, other_ctx, &other_plaintext);
        let mut spliced = records.clone();
        spliced[at] = other_records[at.min(other_records.len() - 1)].clone();
        assert!(!opens(&secret, &context, &spliced), "record from {what} must fail");
        let mut extended = records.clone();
        extended.push(other_records[other_records.len() - 1].clone());
        assert!(!opens(&secret, &context, &extended), "appended record from {what} must fail");
    }

    // Surface 4: tampering, cuts and truncation.
    let flip_at = flip as usize % (n * RECORD_LEN);
    let mut flipped = records.clone();
    flipped[flip_at / RECORD_LEN][flip_at % RECORD_LEN] ^= 1 << (flip >> 29);
    assert!(!opens(&secret, &context, &flipped), "bit flip must fail");
    let mut short = records.clone();
    short[at].pop();
    assert!(!opens(&secret, &context, &short), "missing byte must fail");
    let mut long = records.clone();
    long[at].push(0);
    assert!(!opens(&secret, &context, &long), "trailing byte must fail");
    assert!(!opens(&secret, &context, &records[..at]), "mid-stream truncation must fail");
    assert!(!opens(&secret, &context, &records[..n - 1]), "missing final record must fail");
    if n > 1 {
        // The first n-1 records presented as a complete shorter object: their
        // final flags and the bound length both differ.
        let shorter_len = (n as u64 - 1) * PAYLOAD_LEN as u64;
        let shorter =
            SegmentedContext::new(labels, binding, object_id, context.generation(), shorter_len)
                .unwrap();
        assert!(!opens(&secret, &shorter, &records[..n - 1]), "truncated object must fail");
    }
    let mut wrong_secret = secret;
    wrong_secret[31] ^= 0x01;
    assert!(!opens(&wrong_secret, &context, &records), "wrong secret must fail");
    let longer =
        SegmentedContext::new(labels, binding, object_id, context.generation(), length + 1)
            .unwrap();
    assert!(!opens(&secret, &longer, &records), "length is bound");
    assert!(!opens(&secret, &other_generation_ctx, &records), "generation is bound");
});
