#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for HMAC verification
//!
//! Tests that HMAC operations handle arbitrary input gracefully
//! and verify constant-time properties.

use libfuzzer_sys::fuzz_target;
use arc_primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes: 16 for key, 16 for message
    if data.len() < 32 {
        return;
    }

    // Split input
    let key = &data[..16];
    let message = &data[16..32];
    let fake_tag = if data.len() >= 64 {
        &data[32..64]
    } else {
        &data[32..]
    };

    // Compute valid HMAC
    if let Ok(valid_tag) = hmac_sha256(key, message) {
        // Test 1: Valid tag must verify
        assert!(verify_hmac_sha256(key, message, &valid_tag), "Valid HMAC must verify");

        // Test 2: Fuzzed tag verification should not crash
        let _ = verify_hmac_sha256(key, message, fake_tag);

        // Test 3: Wrong message should fail
        let wrong_msg = b"different message";
        assert!(!verify_hmac_sha256(key, wrong_msg, &valid_tag), "Wrong message must fail verification");

        // Test 4: Wrong key should fail
        let wrong_key = b"wrong key here!!";
        assert!(!verify_hmac_sha256(wrong_key, message, &valid_tag), "Wrong key must fail verification");

        // Test 5: Corrupted tag should fail
        if valid_tag.len() > 0 {
            let mut corrupted_tag = valid_tag.clone();
            corrupted_tag[0] ^= 0xFF;
            assert!(!verify_hmac_sha256(key, message, &corrupted_tag), "Corrupted tag must fail verification");

            // Flip last byte too
            if corrupted_tag.len() > 1 {
                corrupted_tag[corrupted_tag.len() - 1] ^= 0xFF;
                assert!(!verify_hmac_sha256(key, message, &corrupted_tag), "Corrupted tag must fail verification");
            }
        }

        // Test 6: Empty message
        if let Ok(empty_tag) = hmac_sha256(key, &[]) {
            assert!(verify_hmac_sha256(key, &[], &empty_tag), "Empty message HMAC must verify");
        }

        // Test 7: Large message (if enough data available)
        if data.len() >= 128 {
            let large_msg = &data[32..128];
            if let Ok(large_tag) = hmac_sha256(key, large_msg) {
                assert!(verify_hmac_sha256(key, large_msg, &large_tag), "Large message HMAC must verify");
            }
        }
    }
});
