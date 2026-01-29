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
}
