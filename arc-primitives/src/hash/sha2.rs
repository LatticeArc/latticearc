#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SHA-2 Hash Functions
//!
//! This module provides SHA-2 implementations (SHA-256, SHA-384, SHA-512).

use crate::error::Error;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::instrument;

/// Maximum input size for hash functions (1 GB)
/// This prevents DoS attacks via excessive memory usage
const MAX_HASH_INPUT_SIZE: usize = 1_000_000_000;

/// SHA-256 hash function with input size validation
///
/// # Errors
/// Returns `Error::ResourceExceeded` if input exceeds 1 GB
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Error::ResourceExceeded(format!(
            "Hash input too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_HASH_INPUT_SIZE
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// SHA-384 hash function with input size validation
///
/// # Errors
/// Returns `Error::ResourceExceeded` if input exceeds 1 GB
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha384(data: &[u8]) -> Result<[u8; 48], Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Error::ResourceExceeded(format!(
            "Hash input too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_HASH_INPUT_SIZE
        )));
    }

    let mut hasher = Sha384::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// SHA-512 hash function with input size validation
///
/// # Errors
/// Returns `Error::ResourceExceeded` if input exceeds 1 GB
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha512(data: &[u8]) -> Result<[u8; 64], Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Error::ResourceExceeded(format!(
            "Hash input too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_HASH_INPUT_SIZE
        )));
    }

    let mut hasher = Sha512::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = sha256(b"hello").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha384() {
        let result = sha384(b"hello").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let result = sha512(b"hello").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha256_size_limit() {
        // Create a large input that exceeds the limit
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha256(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ResourceExceeded(_))));
    }

    #[test]
    fn test_sha384_size_limit() {
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha384(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ResourceExceeded(_))));
    }

    #[test]
    fn test_sha512_size_limit() {
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha512(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ResourceExceeded(_))));
    }

    // Empty input tests
    #[test]
    fn test_sha256_empty() {
        let result = sha256(b"").unwrap();
        // NIST test vector for empty input
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha384_empty() {
        let result = sha384(b"").unwrap();
        // NIST test vector for empty input
        let expected = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_empty() {
        let result = sha512(b"").unwrap();
        // NIST test vector for empty input
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(result, expected);
    }

    // Single byte tests
    #[test]
    fn test_sha256_single_byte() {
        let result = sha256(b"a").unwrap();
        let expected = [
            0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23,
            0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85,
            0xaf, 0xee, 0x48, 0xbb,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_single_byte() {
        let result = sha512(b"a").unwrap();
        let expected = [
            0x1f, 0x40, 0xfc, 0x92, 0xda, 0x24, 0x16, 0x94, 0x75, 0x09, 0x79, 0xee, 0x6c, 0xf5,
            0x82, 0xf2, 0xd5, 0xd7, 0xd2, 0x8e, 0x18, 0x33, 0x5d, 0xe0, 0x5a, 0xbc, 0x54, 0xd0,
            0x56, 0x0e, 0x0f, 0x53, 0x02, 0x86, 0x0c, 0x65, 0x2b, 0xf0, 0x8d, 0x56, 0x02, 0x52,
            0xaa, 0x5e, 0x74, 0x21, 0x05, 0x46, 0xf3, 0x69, 0xfb, 0xbb, 0xce, 0x8c, 0x12, 0xcf,
            0xc7, 0x95, 0x7b, 0x26, 0x52, 0xfe, 0x9a, 0x75,
        ];
        assert_eq!(result, expected);
    }

    // Multi-block message tests (> 64 bytes for SHA-256/384, > 128 bytes for SHA-512)
    #[test]
    fn test_sha256_multi_block() {
        // 100 bytes - requires 2 blocks
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
        let result = sha256(input).unwrap();
        assert_eq!(result.len(), 32);
        // Verify it's deterministic
        let result2 = sha256(input).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_sha512_multi_block() {
        // 150 bytes - requires 2 blocks for SHA-512
        let input = vec![b'a'; 150];
        let result = sha512(&input).unwrap();
        assert_eq!(result.len(), 64);
        // Verify determinism
        let result2 = sha512(&input).unwrap();
        assert_eq!(result, result2);
    }

    // NIST test vector: "abc"
    #[test]
    fn test_sha256_abc() {
        let result = sha256(b"abc").unwrap();
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha384_abc() {
        let result = sha384(b"abc").unwrap();
        let expected = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
            0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
            0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
            0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_abc() {
        let result = sha512(b"abc").unwrap();
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(result, expected);
    }

    // Large input test (1MB)
    #[test]
    fn test_sha256_large_input() {
        let input = vec![0x42; 1024 * 1024]; // 1MB
        let result = sha256(&input).unwrap();
        assert_eq!(result.len(), 32);
        // Verify determinism
        let result2 = sha256(&input).unwrap();
        assert_eq!(result, result2);
    }

    // Test all three functions with same input
    #[test]
    fn test_all_sha2_functions() {
        let input = b"The quick brown fox jumps over the lazy dog";

        let sha256_result = sha256(input).unwrap();
        assert_eq!(sha256_result.len(), 32);

        let sha384_result = sha384(input).unwrap();
        assert_eq!(sha384_result.len(), 48);

        let sha512_result = sha512(input).unwrap();
        assert_eq!(sha512_result.len(), 64);

        // All should be deterministic
        assert_eq!(sha256(input).unwrap(), sha256_result);
        assert_eq!(sha384(input).unwrap(), sha384_result);
        assert_eq!(sha512(input).unwrap(), sha512_result);
    }
}
