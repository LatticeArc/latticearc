//! Known-answer tests for the committing streaming AEAD and key wrap, through
//! the public API only.
//!
//! Each vector is a fixed record produced by the crate's pinned-output unit
//! tests (`stream::tests::pinned_aes256_output_bytes{,_v2}` and
//! `key_wrap::tests::pinned_output_bytes{,_v2}`). The format-2 commitment
//! tags were cross-checked with an independent HMAC-SHA256 / SHA-256
//! implementation (Python `hmac`/`hashlib`):
//!
//! ```text
//! stream v2: HMAC(key, "LatticeArc-v2-StreamAead-Commitment" || header[..46] || SHA-256(aad))
//! wrap   v2: HMAC(kek, "LatticeArc-v2-KeyWrap-Commitment" || 0x02 || nonce || SHA-256(context))
//! ```
//!
//! Format 1 (0.13.0 – 0.15.x) must keep decoding byte for byte under
//! `FormatPolicy::AllowV1` and be refused by default; format 2 must decode
//! under both policies and reject a wrong context.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use latticearc::primitives::aead::key_wrap::{
    KEY_WRAP_VERSION, KEY_WRAP_VERSION_V1, WrappedKey, unwrap_key, unwrap_key_with_policy,
};
use latticearc::primitives::aead::stream::{
    STREAM_FORMAT_VERSION, STREAM_FORMAT_VERSION_V1, StreamDecryptor,
};
use latticearc::primitives::aead::{AeadError, FormatPolicy};

const STREAM_KEY: &[u8; 32] = b"LatticeArc-stream-test-key-00001";
const STREAM_AAD: &[u8] = b"vault/v1/file";
const KEK: &[u8; 32] = b"kek-latticearc-test-000000000001";
const WRAP_CONTEXT: &[u8] = b"vault/v1/root/epoch-1/locator-a";

struct StreamVector {
    version: u8,
    header: &'static str,
    seg0: &'static str,
    seg1: &'static str,
}

const STREAM_V1: StreamVector = StreamVector {
    version: 1,
    header: concat!(
        "0100",
        "00000040",
        "28",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6",
        "bb8df52093b77bbc644b8def8409f4803449e9075139ad25f1dd35737b3cf0e6",
    ),
    seg0: "dbdda4765e7e4c118f921e8a02f7739b6d026f8c5a024b01",
    seg1: "25bdbf2236555c1ca4dc1ba1fe416a17519a10b5d8",
};

const STREAM_V2: StreamVector = StreamVector {
    version: 2,
    header: concat!(
        "0200",
        "00000040",
        "28",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6",
        "bd2173d22265991580f0be34cb2eaf5eac45ad2c756e3a4132998126b9047432",
    ),
    seg0: "dbdda4765e7e4c11a2cb1a599a6527dc5ecd139035a1c98a",
    seg1: "25bdbf2236780518774489f5b972a56b4df5b33753",
};

const WRAP_V1: &str = concat!(
    "01",
    "101112131415161718191a1b",
    "bed2627fea9623063f851490043a881ebe485661df3ad9871a02f53901d60461",
    "05ab72831248119c2ae1784865d1856d1fb95c9f595d6add6342181646c1b428d8abcd7dbd",
);

const WRAP_V2: &str = concat!(
    "02",
    "101112131415161718191a1b",
    "bb79fb8f6d65172f9e0b18e8f61a352abb29c3209359abdfb48e4b7c82c136a1",
    "05ab72831248119c2ae1784865d1856d1fb95c9f59da0e8dc0b22f62dd3c9942e986edd53d",
);

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn wrapped_plain_key() -> Vec<u8> {
    (0..16usize).map(|i| u8::try_from(i * 7 % 256).unwrap()).collect()
}

fn open_stream(v: &StreamVector, aad: &[u8], policy: FormatPolicy) -> Result<Vec<u8>, AeadError> {
    let mut dec = StreamDecryptor::new_with_policy(STREAM_KEY, aad, &unhex(v.header), policy)?;
    if dec.format_version() != v.version {
        return Err(AeadError::DecryptionFailed("unexpected format version".to_string()));
    }
    let mut out = dec.open_next(&unhex(v.seg0), false)?.to_vec();
    out.extend_from_slice(&dec.open_next(&unhex(v.seg1), true)?);
    Ok(out)
}

fn expected_stream_plaintext() -> Vec<u8> {
    let mut p = vec![0x11u8; 8];
    p.extend_from_slice(b"final");
    p
}

#[test]
fn stream_v2_kat_opens_under_both_policies() {
    assert_eq!(STREAM_FORMAT_VERSION, 2);
    for policy in [FormatPolicy::RequireV2, FormatPolicy::AllowV1] {
        assert_eq!(
            open_stream(&STREAM_V2, STREAM_AAD, policy).unwrap(),
            expected_stream_plaintext()
        );
    }
}

#[test]
fn stream_v2_kat_rejects_wrong_context_at_header() {
    for policy in [FormatPolicy::RequireV2, FormatPolicy::AllowV1] {
        assert!(matches!(
            StreamDecryptor::new_with_policy(
                STREAM_KEY,
                b"vault/v1/other",
                &unhex(STREAM_V2.header),
                policy
            ),
            Err(AeadError::DecryptionFailed(_))
        ));
    }
}

#[test]
fn stream_v1_kat_is_legacy_only() {
    assert_eq!(STREAM_FORMAT_VERSION_V1, 1);
    assert!(matches!(
        StreamDecryptor::new(STREAM_KEY, STREAM_AAD, &unhex(STREAM_V1.header)),
        Err(AeadError::LegacyFormatRejected)
    ));
    assert_eq!(
        open_stream(&STREAM_V1, STREAM_AAD, FormatPolicy::AllowV1).unwrap(),
        expected_stream_plaintext()
    );
    // Format 1 is key-committing only: a wrong context passes the header
    // check and fails at the first segment.
    assert!(open_stream(&STREAM_V1, b"vault/v1/other", FormatPolicy::AllowV1).is_err());
}

#[test]
fn stream_kat_truncation_and_reorder_rejected_in_both_formats() {
    for v in [&STREAM_V1, &STREAM_V2] {
        let dec = StreamDecryptor::new_with_policy(
            STREAM_KEY,
            STREAM_AAD,
            &unhex(v.header),
            FormatPolicy::AllowV1,
        )
        .unwrap();
        // Truncation: the non-final segment presented as the last one.
        assert!(dec.open_segment(0, &unhex(v.seg0), true).is_err());
        // Dropping the final flag.
        assert!(dec.open_segment(1, &unhex(v.seg1), false).is_err());
        // Reordering.
        assert!(dec.open_segment(0, &unhex(v.seg1), true).is_err());
        assert!(dec.open_segment(1, &unhex(v.seg0), false).is_err());
    }
    // Splicing across formats: same key, salt and nonce prefix, so only the
    // header hash in the per-segment AAD differs.
    let dec = StreamDecryptor::new(STREAM_KEY, STREAM_AAD, &unhex(STREAM_V2.header)).unwrap();
    assert!(dec.open_segment(0, &unhex(STREAM_V1.seg0), false).is_err());
    assert!(dec.open_segment(1, &unhex(STREAM_V1.seg1), true).is_err());
}

#[test]
fn wrap_v2_kat_unwraps_under_both_policies() {
    assert_eq!(KEY_WRAP_VERSION, 2);
    let w = WrappedKey::from_bytes(&unhex(WRAP_V2)).unwrap();
    assert_eq!(w.version(), 2);
    assert_eq!(unwrap_key(KEK, &w, WRAP_CONTEXT).unwrap().as_slice(), wrapped_plain_key());
    assert_eq!(
        unwrap_key_with_policy(KEK, &w, WRAP_CONTEXT, FormatPolicy::AllowV1).unwrap().as_slice(),
        wrapped_plain_key()
    );
    assert!(matches!(
        unwrap_key(KEK, &w, b"vault/v1/root/epoch-2/locator-a"),
        Err(AeadError::DecryptionFailed(_))
    ));
}

#[test]
fn wrap_v1_kat_is_legacy_only() {
    assert_eq!(KEY_WRAP_VERSION_V1, 1);
    let w = WrappedKey::from_bytes(&unhex(WRAP_V1)).unwrap();
    assert_eq!(w.version(), 1);
    assert!(matches!(unwrap_key(KEK, &w, WRAP_CONTEXT), Err(AeadError::LegacyFormatRejected)));
    assert_eq!(
        unwrap_key_with_policy(KEK, &w, WRAP_CONTEXT, FormatPolicy::AllowV1).unwrap().as_slice(),
        wrapped_plain_key()
    );
    assert!(matches!(
        unwrap_key_with_policy(KEK, &w, b"other", FormatPolicy::AllowV1),
        Err(AeadError::DecryptionFailed(_))
    ));
}
