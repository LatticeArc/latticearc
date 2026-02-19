//! Common utilities for NIST KAT tests
//!
//! Provides shared test infrastructure including:
//! - Hex encoding/decoding utilities
//! - Constant-time comparison

#![allow(dead_code)] // Some utilities may be used by future tests

use sha2::{Digest, Sha256};

/// Decode a hex string to bytes
///
/// # Errors
/// Returns an error if the input is not valid hex
pub fn decode_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_str).map_err(|e| format!("Invalid hex: {e}"))
}

/// Encode bytes to a hex string
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Compare two byte slices in constant time
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Hash data using SHA-256 for test verification
#[must_use]
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = encode_hex(&original);
        let decoded = decode_hex(&hex).expect("decode should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test data";
        let hash1 = sha256_hash(data);
        let hash2 = sha256_hash(data);
        assert_eq!(hash1, hash2);
    }
}
