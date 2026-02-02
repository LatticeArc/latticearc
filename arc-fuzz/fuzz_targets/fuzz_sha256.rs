#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for SHA-256 hashing
//!
//! Tests that SHA-256 operations handle arbitrary input data
//! without crashing and produce consistent outputs.

use libfuzzer_sys::fuzz_target;
use arc_primitives::hash::{sha256, sha384, sha512, sha3_256, sha3_384, sha3_512};

fuzz_target!(|data: &[u8]| {
    // Test SHA-256
    test_sha256(data);

    // Test SHA-384
    test_sha384(data);

    // Test SHA-512
    test_sha512(data);

    // Test SHA3-256
    test_sha3_256(data);

    // Test SHA3-384
    test_sha3_384(data);

    // Test SHA3-512
    test_sha3_512(data);
});

fn test_sha256(data: &[u8]) {
    if let Ok(hash1) = sha256(data) {
        // Verify hash length (32 bytes)
        assert_eq!(hash1.len(), 32, "SHA-256 hash must be 32 bytes");

        // Verify determinism
        if let Ok(hash2) = sha256(data) {
            assert_eq!(hash1, hash2, "SHA-256 must be deterministic");
        }

        // Different input should produce different output (with high probability)
        if !data.is_empty() {
            let mut modified = data.to_vec();
            modified[0] ^= 0xFF;
            if let Ok(hash_modified) = sha256(&modified) {
                assert_ne!(hash1, hash_modified, "Different input should produce different hash");
            }
        }
    }

    // Empty input should have specific hash
    if let Ok(empty_hash) = sha256(&[]) {
        assert_eq!(empty_hash.len(), 32);
    }

    // Large input handling
    if data.len() >= 10000 {
        if let Ok(large_hash) = sha256(data) {
            assert_eq!(large_hash.len(), 32);
        }
    }
}

fn test_sha384(data: &[u8]) {
    if let Ok(hash1) = sha384(data) {
        // Verify hash length (48 bytes)
        assert_eq!(hash1.len(), 48, "SHA-384 hash must be 48 bytes");

        // Verify determinism
        if let Ok(hash2) = sha384(data) {
            assert_eq!(hash1, hash2, "SHA-384 must be deterministic");
        }

        // Different input should produce different output
        if !data.is_empty() {
            let mut modified = data.to_vec();
            modified[0] ^= 0xFF;
            if let Ok(hash_modified) = sha384(&modified) {
                assert_ne!(hash1, hash_modified);
            }
        }
    }
}

fn test_sha512(data: &[u8]) {
    if let Ok(hash1) = sha512(data) {
        // Verify hash length (64 bytes)
        assert_eq!(hash1.len(), 64, "SHA-512 hash must be 64 bytes");

        // Verify determinism
        if let Ok(hash2) = sha512(data) {
            assert_eq!(hash1, hash2, "SHA-512 must be deterministic");
        }

        // Different input should produce different output
        if !data.is_empty() {
            let mut modified = data.to_vec();
            modified[0] ^= 0xFF;
            if let Ok(hash_modified) = sha512(&modified) {
                assert_ne!(hash1, hash_modified);
            }
        }
    }
}

fn test_sha3_256(data: &[u8]) {
    // SHA3 functions return arrays directly, not Result
    let hash1 = sha3_256(data);

    // Verify hash length (32 bytes)
    assert_eq!(hash1.len(), 32, "SHA3-256 hash must be 32 bytes");

    // Verify determinism
    let hash2 = sha3_256(data);
    assert_eq!(hash1, hash2, "SHA3-256 must be deterministic");

    // SHA-2 and SHA-3 should produce different hashes for same input
    if let Ok(sha2_hash) = sha256(data) {
        assert_ne!(hash1.as_slice(), sha2_hash.as_slice(), "SHA-2 and SHA-3 should differ");
    }
}

fn test_sha3_384(data: &[u8]) {
    // SHA3 functions return arrays directly, not Result
    let hash1 = sha3_384(data);

    // Verify hash length (48 bytes)
    assert_eq!(hash1.len(), 48, "SHA3-384 hash must be 48 bytes");

    // Verify determinism
    let hash2 = sha3_384(data);
    assert_eq!(hash1, hash2, "SHA3-384 must be deterministic");
}

fn test_sha3_512(data: &[u8]) {
    // SHA3 functions return arrays directly, not Result
    let hash1 = sha3_512(data);

    // Verify hash length (64 bytes)
    assert_eq!(hash1.len(), 64, "SHA3-512 hash must be 64 bytes");

    // Verify determinism
    let hash2 = sha3_512(data);
    assert_eq!(hash1, hash2, "SHA3-512 must be deterministic");
}
