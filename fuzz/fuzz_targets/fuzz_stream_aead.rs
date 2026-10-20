#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the streaming AEAD (`primitives::aead::stream`).
//!
//! Exercises three surfaces with attacker-controlled bytes:
//! 1. `StreamDecryptor::new` on arbitrary header bytes under a fuzz-chosen key
//!    and AAD must never panic and must reject anything but a genuine header.
//! 2. `open_segment` / `open_next` on arbitrary segment bytes must never
//!    panic and must reject anything but the genuine segment at its index.
//! 3. A genuine encrypt/decrypt roundtrip with fuzz-chosen segment size, AAD
//!    and plaintext must recover the plaintext.

use latticearc::primitives::aead::stream::{
    HEADER_LEN, MAX_SEGMENT_SIZE, MIN_SEGMENT_SIZE, StreamDecryptor, StreamEncryptor,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // key (32) || segment-size selector (2) || aad length (1) || rest
    if data.len() < 36 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    if key.iter().all(|&b| b == 0) {
        key[0] = 1;
    }
    // Keep segments small so a fuzz iteration stays cheap: 64..=4096.
    let selector = u32::from(u16::from_be_bytes([data[32], data[33]]));
    let segment_size = MIN_SEGMENT_SIZE + (selector % (4096 - MIN_SEGMENT_SIZE + 1));
    assert!(segment_size <= MAX_SEGMENT_SIZE);
    let aad_len = usize::from(data[34]).min(data.len() - 35);
    let aad = &data[35..35 + aad_len];
    let rest = &data[35 + aad_len..];

    // Surface 1: arbitrary header bytes.
    let _ = StreamDecryptor::new(&key, aad, rest);
    let _ = StreamDecryptor::new(&key, aad, &rest[..rest.len().min(HEADER_LEN)]);

    if aad.is_empty() {
        assert!(StreamEncryptor::new(&key, aad, segment_size).is_err());
        return;
    }
    let Ok(mut enc) = StreamEncryptor::new(&key, aad, segment_size) else {
        panic!("valid parameters must construct an encryptor");
    };
    let header = enc.header().to_vec();
    assert_eq!(header.len(), HEADER_LEN);

    // Surface 3: roundtrip over `rest`, split into Tink segments.
    let mut segments = Vec::new();
    let mut remaining = rest;
    loop {
        let cap = if enc.next_index() == 0 {
            enc.first_plaintext_segment_size()
        } else {
            enc.plaintext_segment_size()
        };
        if remaining.len() <= cap {
            segments.push(enc.finish(remaining).unwrap());
            break;
        }
        let (head, tail) = remaining.split_at(cap);
        segments.push(enc.seal_segment(head).unwrap());
        remaining = tail;
    }

    let mut dec = StreamDecryptor::new(&key, aad, &header).expect("genuine header must parse");
    let mut recovered = Vec::new();
    let last = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        recovered.extend_from_slice(&dec.open_next(seg, i == last).expect("genuine segment"));
    }
    assert_eq!(recovered.as_slice(), rest, "roundtrip must recover the plaintext");
    assert!(dec.open_next(&segments[last], true).is_err(), "stream must be exhausted");

    // Surface 2: arbitrary segment bytes, wrong index, wrong last flag.
    let dec = StreamDecryptor::new(&key, aad, &header).unwrap();
    let _ = dec.open_segment(0, rest, false);
    let _ = dec.open_segment(0, rest, true);
    let _ = dec.open_segment(u32::MAX, rest, true);
    for (i, seg) in segments.iter().enumerate() {
        let idx = u32::try_from(i).unwrap();
        let is_last = i == last;
        assert!(dec.open_segment(idx, seg, !is_last).is_err(), "last flag must be bound");
        assert!(dec.open_segment(idx.wrapping_add(1), seg, is_last).is_err(), "index bound");
        if !seg.is_empty() {
            let mut bad = seg.clone();
            bad[seg.len() / 2] ^= 0x01;
            assert!(dec.open_segment(idx, &bad, is_last).is_err(), "bit flip must fail");
        }
    }

    // Wrong key and tampered header must fail at construction.
    let mut wrong_key = key;
    wrong_key[31] ^= 0x01;
    assert!(StreamDecryptor::new(&wrong_key, aad, &header).is_err());
    let mut bad_header = header.clone();
    bad_header[HEADER_LEN - 1] ^= 0x01;
    assert!(StreamDecryptor::new(&key, aad, &bad_header).is_err());
});
