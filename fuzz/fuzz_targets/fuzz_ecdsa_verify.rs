#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the ECDSA P-256 / P-384 verify-only primitives
//!
//! Feeds arbitrary public keys, signatures and messages to all eight
//! verifiers in `primitives::ec::{p256, p384}`. Checks that nothing panics,
//! that each message verifier agrees with its prehash twin given the digest of
//! the same message, and that a key of the wrong length is always an error.
//! A valid on-curve P-256 key is also derived from the input through
//! hash-to-curve so the signature-parsing paths run past key validation.

use latticearc::primitives::ec::hash_to_curve::p256_xmd_sha256_sswu_ro;
use latticearc::primitives::ec::{p256, p384};
use latticearc::primitives::hash::sha2::{sha256, sha384};
use libfuzzer_sys::fuzz_target;

fn same_verdict(
    a: &latticearc::prelude::error::Result<bool>,
    b: &latticearc::prelude::error::Result<bool>,
) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

fuzz_target!(|data: &[u8]| {
    // Layout: [selector, sig_len, ...sig, ...rest]; `rest` is both the raw
    // key candidate (prefix) and the message.
    let Some((&[selector, sig_len], body)) = data.split_first_chunk::<2>() else {
        return;
    };
    let sig_len = usize::from(sig_len).min(body.len());
    let (sig, rest) = body.split_at(sig_len);

    let Ok(d256) = sha256(rest) else { return };
    let Ok(d384) = sha384(rest) else { return };

    // Raw key candidates straight from the input.
    let raw256 = &rest[..rest.len().min(p256::P256_PUBLIC_KEY_LEN)];
    let raw384 = &rest[..rest.len().min(p384::P384_PUBLIC_KEY_LEN)];

    // A valid P-256 key derived from the input, so verification reaches the
    // signature parser.
    let valid256 = p256_xmd_sha256_sswu_ro(rest, b"fuzz-ecdsa-verify-key").ok();

    let mut keys256: Vec<&[u8]> = vec![raw256];
    if let Some(k) = valid256.as_ref() {
        keys256.push(k.as_slice());
    }

    for key in keys256 {
        let der = p256::verify_ecdsa_p256_sha256(key, rest, sig);
        let der_pre = p256::verify_ecdsa_p256_sha256_prehash(key, &d256, sig);
        let fixed = p256::verify_ecdsa_p256_sha256_fixed(key, rest, sig);
        let fixed_pre = p256::verify_ecdsa_p256_sha256_prehash_fixed(key, &d256, sig);
        assert!(same_verdict(&der, &der_pre), "P-256 DER message/prehash disagree");
        assert!(same_verdict(&fixed, &fixed_pre), "P-256 fixed message/prehash disagree");
        if key.len() != p256::P256_PUBLIC_KEY_LEN {
            assert!(der.is_err() && fixed.is_err(), "P-256 wrong-length key accepted");
        }
        if sig.len() != p256::P256_FIXED_SIGNATURE_LEN {
            assert!(fixed.is_err(), "P-256 wrong-length fixed signature not an error");
        }
    }

    let der = p384::verify_ecdsa_p384_sha384(raw384, rest, sig);
    let der_pre = p384::verify_ecdsa_p384_sha384_prehash(raw384, &d384, sig);
    let fixed = p384::verify_ecdsa_p384_sha384_fixed(raw384, rest, sig);
    let fixed_pre = p384::verify_ecdsa_p384_sha384_prehash_fixed(raw384, &d384, sig);
    assert!(same_verdict(&der, &der_pre), "P-384 DER message/prehash disagree");
    assert!(same_verdict(&fixed, &fixed_pre), "P-384 fixed message/prehash disagree");
    if raw384.len() != p384::P384_PUBLIC_KEY_LEN {
        assert!(der.is_err() && fixed.is_err(), "P-384 wrong-length key accepted");
    }

    // Selector-driven: a signature of the exact fixed width over a valid key.
    if selector & 1 == 1 {
        if let Some(k) = valid256.as_ref() {
            let mut fixed_sig = [0u8; p256::P256_FIXED_SIGNATURE_LEN];
            for (dst, src) in fixed_sig.iter_mut().zip(sig.iter().cycle()) {
                *dst = *src;
            }
            let r = p256::verify_ecdsa_p256_sha256_fixed(k, rest, &fixed_sig);
            assert!(r.is_ok(), "fixed-width signature over a valid key must not error");
        }
    }
});
