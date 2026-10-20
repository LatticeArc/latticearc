#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the committing key wrap (`primitives::aead::key_wrap`).
//!
//! Exercises `WrappedKey::from_bytes` and `unwrap_key` on arbitrary bytes
//! (never panic, never accept a non-genuine record), plus a genuine
//! wrap/unwrap roundtrip for every supported key length with fuzz-chosen KEK,
//! context and padded total length.

use latticearc::primitives::aead::key_wrap::{
    KEY_WRAP_OVERHEAD, MAX_WRAPPED_LEN, WrappedKey, unwrap_key, wrap_key, wrap_key_padded,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // kek (32) || context length (1) || padding selector (2) || rest
    if data.len() < 35 {
        return;
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&data[..32]);
    if kek.iter().all(|&b| b == 0) {
        kek[0] = 1;
    }
    let ctx_len = usize::from(data[32]).min(data.len() - 35);
    let context = &data[35..35 + ctx_len];
    let rest = &data[35 + ctx_len..];
    let extra_padding = usize::from(u16::from_be_bytes([data[33], data[34]]));

    // Arbitrary bytes through the parser and unwrap.
    if let Ok(parsed) = WrappedKey::from_bytes(rest) {
        assert_eq!(parsed.to_bytes(), rest);
        if !context.is_empty() {
            assert!(
                unwrap_key(&kek, &parsed, context).is_err(),
                "arbitrary bytes must never unwrap"
            );
        }
    }

    if context.is_empty() {
        assert!(wrap_key(&kek, &[7u8; 32], context).is_err());
        return;
    }

    for key_len in [16usize, 32, 64] {
        let key: Vec<u8> = rest.iter().cycle().take(key_len).copied().collect();
        if key.len() != key_len {
            // `rest` is empty; use a fixed key instead.
            continue;
        }
        let wrapped = wrap_key(&kek, &key, context).expect("valid parameters must wrap");
        assert_eq!(wrapped.len(), KEY_WRAP_OVERHEAD + key_len);
        let bytes = wrapped.to_bytes();
        let parsed = WrappedKey::from_bytes(&bytes).expect("genuine encoding must parse");
        let unwrapped = unwrap_key(&kek, &parsed, context).expect("genuine record must unwrap");
        assert_eq!(unwrapped.as_slice(), key.as_slice());

        let total = (KEY_WRAP_OVERHEAD + key_len + extra_padding).min(MAX_WRAPPED_LEN);
        let padded = wrap_key_padded(&kek, &key, context, total).expect("padded wrap");
        assert_eq!(padded.len(), total);
        assert_eq!(unwrap_key(&kek, &padded, context).unwrap().as_slice(), key.as_slice());
        assert!(wrap_key_padded(&kek, &key, context, KEY_WRAP_OVERHEAD + key_len - 1).is_err());

        // Wrong KEK, wrong context and a flipped byte must all fail.
        let mut wrong_kek = kek;
        wrong_kek[0] ^= 0x80;
        assert!(unwrap_key(&wrong_kek, &parsed, context).is_err());
        let mut other_ctx = context.to_vec();
        other_ctx.push(0);
        assert!(unwrap_key(&kek, &parsed, &other_ctx).is_err());
        let mut bad = bytes.clone();
        bad[1 + (extra_padding % (bytes.len() - 1))] ^= 0x01;
        let bad = WrappedKey::from_bytes(&bad).unwrap();
        assert!(unwrap_key(&kek, &bad, context).is_err());
    }
});
