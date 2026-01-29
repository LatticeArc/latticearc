#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Cryptographically Secure Random Number Generator
//!
//! This module provides CSPRNG using OsRng.

use rand::{RngCore, rngs::OsRng};

/// Generate random bytes
#[must_use]
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate random u32
#[must_use]
pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

/// Generate random u64
#[must_use]
pub fn random_u64() -> u64 {
    OsRng.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(32);
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_u32() {
        let val = random_u32();
        assert!(val < u32::MAX);
    }

    #[test]
    fn test_random_u64() {
        let val = random_u64();
        assert!(val < u64::MAX);
    }
}
