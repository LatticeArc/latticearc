#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! BLAKE2b Hash Function
//!
//! This module provides BLAKE2b-256 (RFC 7693) hashing.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// BLAKE2b-256 hash function (RFC 7693).
///
/// Produces a 32-byte (256-bit) digest. Infallible — always succeeds for any input.
///
/// # Example
///
/// ```
/// use latticearc::primitives::hash::blake2b_256;
///
/// let digest = blake2b_256(b"hello");
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // RFC 7693 Appendix A — BLAKE2b-256("abc")
    #[test]
    fn test_blake2b_256_abc_kat() {
        let result = blake2b_256(b"abc");
        let expected = [
            0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72, 0x31, 0x71, 0xef, 0x3f, 0xee, 0x98,
            0x57, 0x9b, 0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42, 0x72, 0x62, 0xc8, 0xc0,
            0x68, 0xd5, 0x23, 0x19,
        ];
        assert_eq!(result, expected);
    }

    // Empty input
    #[test]
    fn test_blake2b_256_empty() {
        let result = blake2b_256(b"");
        assert_eq!(result.len(), 32);
        // BLAKE2b-256("") is a well-known constant — verify determinism
        assert_eq!(blake2b_256(b""), result);
    }

    // Large input (1 MB)
    #[test]
    fn test_blake2b_256_large_input() {
        let input = vec![0x42; 1024 * 1024];
        let result = blake2b_256(&input);
        assert_eq!(result.len(), 32);
        // Determinism
        assert_eq!(blake2b_256(&input), result);
    }

    // Different inputs produce different outputs
    #[test]
    fn test_blake2b_256_different_inputs() {
        let h1 = blake2b_256(b"hello");
        let h2 = blake2b_256(b"world");
        assert_ne!(h1, h2);
    }

    // Distinct from SHA3-256 for same input
    #[test]
    fn test_blake2b_256_not_sha3() {
        let blake = blake2b_256(b"test");
        let sha3 = crate::primitives::hash::sha3_256(b"test");
        assert_ne!(blake, sha3);
    }
}
