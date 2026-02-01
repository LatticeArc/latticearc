#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SHA-3 Hash Functions
//!
//! This module provides SHA-3 implementations (SHA3-256, SHA3-384, SHA3-512).

use sha3::{Digest, Sha3_256, Sha3_384, Sha3_512};

/// SHA3-256 hash function
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-384 hash function
#[must_use]
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha3_384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-512 hash function
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256() {
        let result = sha3_256(b"hello");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha3_384() {
        let result = sha3_384(b"hello");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha3_512() {
        let result = sha3_512(b"hello");
        assert_eq!(result.len(), 64);
    }

    // NIST test vectors - Empty input
    #[test]
    fn test_sha3_256_empty() {
        let result = sha3_256(b"");
        let expected = [
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
            0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
            0x80, 0xf8, 0x43, 0x4a,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha3_384_empty() {
        let result = sha3_384(b"");
        let expected = [
            0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c,
            0x24, 0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb,
            0xee, 0x98, 0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b,
            0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha3_512_empty() {
        let result = sha3_512(b"");
        let expected = [
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a,
            0x75, 0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1,
            0x47, 0x5c, 0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3,
            0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
            0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
        ];
        assert_eq!(result, expected);
    }

    // Single byte tests
    #[test]
    fn test_sha3_256_single_byte() {
        let result = sha3_256(b"a");
        let expected = [
            0x80, 0x08, 0x4b, 0xf2, 0xfb, 0xa0, 0x24, 0x75, 0x72, 0x6f, 0xeb, 0x2c, 0xab, 0x2d,
            0x82, 0x15, 0xea, 0xb1, 0x4b, 0xc6, 0xbd, 0xd8, 0xbf, 0xb2, 0xc8, 0x15, 0x12, 0x57,
            0x03, 0x2e, 0xcd, 0x8b,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha3_512_single_byte() {
        let result = sha3_512(b"a");
        assert_eq!(result.len(), 64);
        // Verify determinism
        assert_eq!(sha3_512(b"a"), result);
        // Verify it's different from empty
        assert_ne!(result, sha3_512(b""));
    }

    // NIST test vector: "abc"
    #[test]
    fn test_sha3_256_abc() {
        let result = sha3_256(b"abc");
        let expected = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3,
            0x90, 0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45,
            0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha3_384_abc() {
        let result = sha3_384(b"abc");
        let expected = [
            0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6,
            0xad, 0x8d, 0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0,
            0xe4, 0x9b, 0xe4, 0xb2, 0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1,
            0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha3_512_abc() {
        let result = sha3_512(b"abc");
        let expected = [
            0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b,
            0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02,
            0x40, 0xd2, 0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e,
            0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
            0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
        ];
        assert_eq!(result, expected);
    }

    // Multi-block message tests
    #[test]
    fn test_sha3_256_long_message() {
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let result = sha3_256(input);
        assert_eq!(result.len(), 32);
        // Verify determinism
        assert_eq!(sha3_256(input), result);
    }

    #[test]
    fn test_sha3_512_long_message() {
        let input = vec![b'a'; 200]; // Long message
        let result = sha3_512(&input);
        assert_eq!(result.len(), 64);
        // Verify determinism
        assert_eq!(sha3_512(&input), result);
    }

    // Large input test (1MB)
    #[test]
    fn test_sha3_256_large_input() {
        let input = vec![0x42; 1024 * 1024]; // 1MB
        let result = sha3_256(&input);
        assert_eq!(result.len(), 32);
        // Verify determinism
        assert_eq!(sha3_256(&input), result);
    }

    // Test all three functions with same input
    #[test]
    fn test_all_sha3_functions() {
        let input = b"The quick brown fox jumps over the lazy dog";

        let sha3_256_result = sha3_256(input);
        assert_eq!(sha3_256_result.len(), 32);

        let sha3_384_result = sha3_384(input);
        assert_eq!(sha3_384_result.len(), 48);

        let sha3_512_result = sha3_512(input);
        assert_eq!(sha3_512_result.len(), 64);

        // All should be deterministic
        assert_eq!(sha3_256(input), sha3_256_result);
        assert_eq!(sha3_384(input), sha3_384_result);
        assert_eq!(sha3_512(input), sha3_512_result);
    }

    // Test different outputs between SHA-3 variants
    #[test]
    fn test_sha3_variants_produce_different_hashes() {
        let input = b"test data";
        let h256 = sha3_256(input);
        let h384 = sha3_384(input);
        let h512 = sha3_512(input);

        // First 32 bytes of each should be different (SHA-3 property)
        assert_ne!(&h256[..], &h384[..32]);
        assert_ne!(&h256[..], &h512[..32]);
    }
}
