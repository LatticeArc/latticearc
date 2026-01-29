#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SHA-2 Hash Functions
//!
//! This module provides SHA-2 implementations (SHA-256, SHA-384, SHA-512).

use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::instrument;

/// SHA-256 hash function
#[must_use]
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-384 hash function
#[must_use]
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-512 hash function
#[must_use]
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let result = sha256(b"hello");
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha384() {
        let result = sha384(b"hello");
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512() {
        let result = sha512(b"hello");
        assert_eq!(result.len(), 64);
    }
}
