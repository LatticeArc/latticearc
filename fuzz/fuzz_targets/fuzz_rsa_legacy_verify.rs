#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for the legacy RSA PKCS#1 v1.5 / SHA-1 verifier
//!
//! Treats the input as a public key DER, a signature and a message, and calls
//! `verify_rsa_pkcs1_sha1` with the key declared as PKCS#1 and as
//! SubjectPublicKeyInfo. Checks that nothing panics, that a key wrapped into
//! an `rsaEncryption` SubjectPublicKeyInfo by the harness gets the same
//! verdict as the bare PKCS#1 key, and that the PKCS#1 bytes are never
//! accepted under the SPKI label (or the reverse).

use latticearc::primitives::sig::rsa_legacy::{RsaPublicKeyEncoding, verify_rsa_pkcs1_sha1};
use libfuzzer_sys::fuzz_target;

fn der_len(len: usize) -> Option<Vec<u8>> {
    match len {
        0..=0x7f => Some(vec![u8::try_from(len).ok()?]),
        0x80..=0xff => Some(vec![0x81, u8::try_from(len).ok()?]),
        0x100..=0xffff => {
            Some(vec![0x82, u8::try_from(len >> 8).ok()?, u8::try_from(len & 0xff).ok()?])
        }
        _ => None,
    }
}

fn tlv(tag: u8, content: &[u8]) -> Option<Vec<u8>> {
    let mut v = vec![tag];
    v.extend(der_len(content.len())?);
    v.extend_from_slice(content);
    Some(v)
}

/// Wrap PKCS#1 bytes in an `rsaEncryption` SubjectPublicKeyInfo.
fn spki(pkcs1: &[u8]) -> Option<Vec<u8>> {
    let mut bits = vec![0u8];
    bits.extend_from_slice(pkcs1);
    let mut body = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    body.extend(tlv(0x03, &bits)?);
    tlv(0x30, &body)
}

fuzz_target!(|data: &[u8]| {
    // Layout: [key_len_hi, key_len_lo, sig_len_hi, sig_len_lo, ...key, ...sig, ...msg]
    let Some((&[kh, kl, sh, sl], body)) = data.split_first_chunk::<4>() else {
        return;
    };
    let key_len = (usize::from(kh) << 8 | usize::from(kl)).min(body.len());
    let (key, body) = body.split_at(key_len);
    let sig_len = (usize::from(sh) << 8 | usize::from(sl)).min(body.len());
    let (sig, msg) = body.split_at(sig_len);

    let as_pkcs1 = verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::Pkcs1Der(key), msg, sig);
    let as_spki = verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(key), msg, sig);

    // One byte string cannot be well-formed under both labels.
    assert!(as_pkcs1.is_err() || as_spki.is_err(), "key accepted as both PKCS#1 and SPKI");

    if let Some(wrapped) = spki(key) {
        let wrapped_result =
            verify_rsa_pkcs1_sha1(RsaPublicKeyEncoding::SpkiDer(&wrapped), msg, sig);
        // The size cap applies to the outer DER, so only compare when the
        // wrapped key is within it too.
        if wrapped.len()
            <= latticearc::primitives::sig::rsa_legacy::RSA_LEGACY_MAX_PUBLIC_KEY_DER_LEN
        {
            assert_eq!(as_pkcs1, wrapped_result, "SPKI-wrapped key verdict differs from PKCS#1");
        }
    }
});
