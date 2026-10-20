//! Property-based tests for the committing key wrap (`primitives::aead::key_wrap`).
//!
//! Roundtrip for every supported key length with random KEK, context and
//! padded total length; wrong KEK, wrong context and bit flips fail; padded
//! outputs are exactly the requested size.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use latticearc::primitives::aead::key_wrap::{
    KEY_WRAP_OVERHEAD, WrappedKey, unwrap_key, wrap_key, wrap_key_padded,
};
use proptest::prelude::*;

fn kek_strategy() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
        .prop_filter("all-zero KEKs are rejected by design", |k| k.iter().any(|&b| b != 0))
}

fn key_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 16),
        prop::collection::vec(any::<u8>(), 32),
        prop::collection::vec(any::<u8>(), 64),
    ]
}

fn context_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..96)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip(kek in kek_strategy(), key in key_strategy(), context in context_strategy()) {
        let wrapped = wrap_key(&kek, &key, &context).unwrap();
        prop_assert_eq!(wrapped.len(), KEY_WRAP_OVERHEAD + key.len());
        let bytes = wrapped.to_bytes();
        prop_assert_eq!(bytes[0], 1);
        let parsed = WrappedKey::from_bytes(&bytes).unwrap();
        prop_assert_eq!(parsed.to_bytes(), bytes);
        let unwrapped = unwrap_key(&kek, &parsed, &context).unwrap();
        prop_assert_eq!(unwrapped.as_slice(), key.as_slice());
    }

    #[test]
    fn padded_roundtrip_is_exact_size(
        kek in kek_strategy(),
        key in key_strategy(),
        context in context_strategy(),
        extra in 0usize..2048,
    ) {
        let total = KEY_WRAP_OVERHEAD + key.len() + extra;
        let wrapped = wrap_key_padded(&kek, &key, &context, total).unwrap();
        prop_assert_eq!(wrapped.len(), total);
        let unwrapped = unwrap_key(&kek, &wrapped, &context).unwrap();
        prop_assert_eq!(unwrapped.as_slice(), key.as_slice());
        prop_assert!(wrap_key_padded(&kek, &key, &context, total - extra - 1).is_err());
    }

    #[test]
    fn wrong_kek_fails(
        kek in kek_strategy(),
        other in kek_strategy(),
        key in key_strategy(),
        context in context_strategy(),
    ) {
        prop_assume!(kek != other);
        let wrapped = wrap_key(&kek, &key, &context).unwrap();
        prop_assert!(unwrap_key(&other, &wrapped, &context).is_err());
    }

    #[test]
    fn wrong_context_fails(
        kek in kek_strategy(),
        key in key_strategy(),
        context in context_strategy(),
        other in context_strategy(),
    ) {
        prop_assume!(context != other);
        let wrapped = wrap_key(&kek, &key, &context).unwrap();
        prop_assert!(unwrap_key(&kek, &wrapped, &other).is_err());
    }

    #[test]
    fn bit_flip_fails(
        kek in kek_strategy(),
        key in key_strategy(),
        context in context_strategy(),
        extra in 0usize..64,
        bit in any::<usize>(),
    ) {
        let total = KEY_WRAP_OVERHEAD + key.len() + extra;
        let bytes = wrap_key_padded(&kek, &key, &context, total).unwrap().to_bytes();
        // Skip the version byte: flipping it is a parse error, tested elsewhere.
        let bit = 8 + bit % ((bytes.len() - 1) * 8);
        let mut bad = bytes;
        bad[bit / 8] ^= 1 << (bit % 8);
        let parsed = WrappedKey::from_bytes(&bad).unwrap();
        prop_assert!(unwrap_key(&kek, &parsed, &context).is_err());
    }

    /// Two wraps of the same inputs never share a nonce or ciphertext.
    #[test]
    fn fresh_nonce_per_wrap(
        kek in kek_strategy(),
        key in key_strategy(),
        context in context_strategy(),
    ) {
        let a = wrap_key(&kek, &key, &context).unwrap().to_bytes();
        let b = wrap_key(&kek, &key, &context).unwrap().to_bytes();
        prop_assert_ne!(&a[1..13], &b[1..13]);
        prop_assert_ne!(&a[45..], &b[45..]);
    }
}
