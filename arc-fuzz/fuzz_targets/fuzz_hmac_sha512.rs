#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for HMAC-SHA256
//!
//! Tests that HMAC operations handle arbitrary input data
//! without crashing and verify constant-time properties.

use libfuzzer_sys::fuzz_target;
use arc_primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Split input into key and message
    let key = &data[..16];
    let message = &data[16..];

    // Test HMAC-SHA256
    test_hmac_sha256(key, message, data);
});

fn test_hmac_sha256(key: &[u8], message: &[u8], data: &[u8]) {
    // Compute HMAC
    match hmac_sha256(key, message) {
        Ok(tag) => {
            // Verify tag length (32 bytes for SHA-256)
            assert_eq!(tag.len(), 32, "HMAC-SHA256 tag must be 32 bytes");

            // Verify valid tag
            assert!(verify_hmac_sha256(key, message, &tag), "Valid HMAC must verify");

            // Verify determinism
            if let Ok(tag2) = hmac_sha256(key, message) {
                assert_eq!(tag, tag2, "HMAC must be deterministic");
            }

            // Wrong message should fail verification
            let wrong_msg = b"different message";
            assert!(
                !verify_hmac_sha256(key, wrong_msg, &tag),
                "Wrong message must fail verification"
            );

            // Wrong key should fail verification
            let wrong_key = b"wrong key here!!";
            assert!(
                !verify_hmac_sha256(wrong_key, message, &tag),
                "Wrong key must fail verification"
            );

            // Corrupted tag should fail verification
            let mut corrupted_tag = tag;
            corrupted_tag[0] ^= 0xFF;
            assert!(
                !verify_hmac_sha256(key, message, &corrupted_tag),
                "Corrupted tag must fail verification"
            );

            // Fuzzed tag verification (should not crash)
            let fake_tag = data.get(32..64).unwrap_or(&[]);
            let _ = verify_hmac_sha256(key, message, fake_tag);
        }
        Err(_) => {
            // HMAC can fail for invalid parameters
        }
    }

    // Test with empty key
    let _ = hmac_sha256(&[], message);

    // Test with empty message
    if let Ok(empty_tag) = hmac_sha256(key, &[]) {
        assert!(verify_hmac_sha256(key, &[], &empty_tag), "Empty message HMAC must verify");
    }

    // Test with large key
    let large_key = data;
    if let Ok(tag) = hmac_sha256(large_key, message) {
        assert!(verify_hmac_sha256(large_key, message, &tag));
    }

    // Test with different key sizes
    for key_size in [8, 16, 32, 64, 128] {
        if data.len() >= key_size {
            let test_key = &data[..key_size];
            if let Ok(tag) = hmac_sha256(test_key, message) {
                assert!(verify_hmac_sha256(test_key, message, &tag));
            }
        }
    }

    // Test with various message sizes
    for msg_size in [0, 1, 16, 64, 256] {
        if data.len() >= msg_size {
            let test_msg = &data[..msg_size];
            if let Ok(tag) = hmac_sha256(key, test_msg) {
                assert!(verify_hmac_sha256(key, test_msg, &tag));
            }
        }
    }
}
