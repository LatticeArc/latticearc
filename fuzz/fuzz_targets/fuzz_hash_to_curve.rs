#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for RFC 9380 hash-to-curve on P-256
//!
//! Splits the input into a domain separation tag and a message and calls
//! `p256_xmd_sha256_sswu_ro`. Checks that nothing panics, that the DST length
//! rule (1 to 255 bytes) is the only reason to fail for short messages, that
//! the output is an uncompressed SEC1 point accepted as a P-256 ECDSA public
//! key, and that the map is deterministic.

use latticearc::primitives::ec::hash_to_curve::{H2C_MAX_DST_LEN, p256_xmd_sha256_sswu_ro};
use latticearc::primitives::ec::p256::verify_ecdsa_p256_sha256_fixed;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [dst_len_hi, dst_len_lo, ...dst, ...msg]
    let Some((&[hi, lo], body)) = data.split_first_chunk::<2>() else {
        return;
    };
    let dst_len = (usize::from(hi) << 8 | usize::from(lo)).min(body.len());
    let (dst, msg) = body.split_at(dst_len);

    let result = p256_xmd_sha256_sswu_ro(msg, dst);
    let dst_ok = !dst.is_empty() && dst.len() <= H2C_MAX_DST_LEN;
    match &result {
        Ok(point) => {
            assert!(dst_ok, "out-of-range DST accepted");
            assert_eq!(point[0], 0x04, "output is not uncompressed SEC1");
            // The point must be a valid public key: an all-zero fixed-width
            // signature is then Ok(false), never a key error.
            let verdict = verify_ecdsa_p256_sha256_fixed(point, b"", &[0u8; 64]);
            assert_eq!(verdict.ok(), Some(false), "output rejected as a P-256 public key");
            assert_eq!(p256_xmd_sha256_sswu_ro(msg, dst).ok(), Some(*point), "not deterministic");
        }
        Err(_) => {
            // libFuzzer inputs are far below the 64 KiB message limit, so the
            // DST is the only possible cause.
            assert!(!dst_ok, "valid input rejected");
        }
    }
});
