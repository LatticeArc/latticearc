#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SHA-2 Hash Functions
//!
//! This module provides SHA-2 implementations (SHA-256, SHA-384, SHA-512).

use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;
use tracing::instrument;

/// Maximum input size for hash functions (1 GB)
/// This prevents DoS attacks via excessive memory usage
const MAX_HASH_INPUT_SIZE: usize = 1_000_000_000;

/// Errors from the SHA-2 hash functions.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Sha2Error {
    /// Input length exceeds the 1 GB DoS bound. The length is caller-known,
    /// non-secret diagnostic detail.
    #[error("Resource limit exceeded: {0}")]
    ResourceExceeded(String),
}

/// SHA-256 hash function with input size validation
///
/// # Errors
/// Returns `Error::ResourceExceeded` if input exceeds 1 GB
#[instrument(level = "debug", skip(data), fields(data_len = data.len()))]
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Sha2Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Sha2Error::ResourceExceeded(format!(
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
pub fn sha384(data: &[u8]) -> Result<[u8; 48], Sha2Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Sha2Error::ResourceExceeded(format!(
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
pub fn sha512(data: &[u8]) -> Result<[u8; 64], Sha2Error> {
    if data.len() > MAX_HASH_INPUT_SIZE {
        return Err(Sha2Error::ResourceExceeded(format!(
            "Hash input too large: {} bytes (max {} bytes)",
            data.len(),
            MAX_HASH_INPUT_SIZE
        )));
    }

    let mut hasher = Sha512::new();
    hasher.update(data);
    Ok(hasher.finalize().into())
}

/// Incremental SHA-256 hasher.
///
/// Feed data with [`update`](Self::update) in any chunking and obtain the digest
/// with [`finalize`](Self::finalize), which consumes the hasher. The total input
/// is bounded by the same 1 GB limit as [`sha256`].
#[derive(Clone)]
pub struct Sha256Hasher {
    inner: Sha256,
    total_len: usize,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    /// Creates a hasher with an empty input.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Sha256::new(), total_len: 0 }
    }

    /// Absorbs `data` into the running hash.
    ///
    /// # Errors
    /// Returns `Sha2Error::ResourceExceeded` if the total input fed so far
    /// would exceed 1 GB; the hasher is left unchanged in that case.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha2Error> {
        let new_len = self
            .total_len
            .checked_add(data.len())
            .filter(|len| *len <= MAX_HASH_INPUT_SIZE)
            .ok_or_else(|| {
                Sha2Error::ResourceExceeded(format!(
                    "Hash input too large: more than {} bytes",
                    MAX_HASH_INPUT_SIZE
                ))
            })?;
        self.inner.update(data);
        self.total_len = new_len;
        Ok(())
    }

    /// Consumes the hasher and returns the 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

/// Incremental SHA-512 hasher.
///
/// Feed data with [`update`](Self::update) in any chunking and obtain the digest
/// with [`finalize`](Self::finalize), which consumes the hasher. The total input
/// is bounded by the same 1 GB limit as [`sha512`].
#[derive(Clone)]
pub struct Sha512Hasher {
    inner: Sha512,
    total_len: usize,
}

impl Default for Sha512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512Hasher {
    /// Creates a hasher with an empty input.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Sha512::new(), total_len: 0 }
    }

    /// Absorbs `data` into the running hash.
    ///
    /// # Errors
    /// Returns `Sha2Error::ResourceExceeded` if the total input fed so far
    /// would exceed 1 GB; the hasher is left unchanged in that case.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Sha2Error> {
        let new_len = self
            .total_len
            .checked_add(data.len())
            .filter(|len| *len <= MAX_HASH_INPUT_SIZE)
            .ok_or_else(|| {
                Sha2Error::ResourceExceeded(format!(
                    "Hash input too large: more than {} bytes",
                    MAX_HASH_INPUT_SIZE
                ))
            })?;
        self.inner.update(data);
        self.total_len = new_len;
        Ok(())
    }

    /// Consumes the hasher and returns the 64-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 64] {
        self.inner.finalize().into()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_returns_32_byte_digest_succeeds() {
        let result = sha256(b"hello").unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_sha384_returns_48_byte_digest_succeeds() {
        let result = sha384(b"hello").unwrap();
        assert_eq!(result.len(), 48);
    }

    #[test]
    fn test_sha512_returns_64_byte_digest_succeeds() {
        let result = sha512(b"hello").unwrap();
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_sha256_size_limit_returns_error_when_exceeded_fails() {
        // Create a large input that exceeds the limit
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha256(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Sha2Error::ResourceExceeded(_))));
    }

    #[test]
    fn test_sha384_size_limit_returns_error_when_exceeded_fails() {
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha384(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Sha2Error::ResourceExceeded(_))));
    }

    #[test]
    fn test_sha512_size_limit_returns_error_when_exceeded_fails() {
        let large_input = vec![0u8; MAX_HASH_INPUT_SIZE + 1];
        let result = sha512(&large_input);
        assert!(result.is_err());
        assert!(matches!(result, Err(Sha2Error::ResourceExceeded(_))));
    }

    // Empty input tests
    #[test]
    fn test_sha256_empty_matches_nist_vector_matches_expected() {
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
    fn test_sha384_empty_matches_nist_vector_matches_expected() {
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
    fn test_sha512_empty_matches_nist_vector_matches_expected() {
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
    fn test_sha256_single_byte_matches_known_vector_matches_expected() {
        let result = sha256(b"a").unwrap();
        let expected = [
            0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23,
            0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85,
            0xaf, 0xee, 0x48, 0xbb,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_single_byte_matches_known_vector_matches_expected() {
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
    fn test_sha256_multi_block_is_deterministic() {
        // 100 bytes - requires 2 blocks
        let input = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`";
        let result = sha256(input).unwrap();
        assert_eq!(result.len(), 32);
        // Verify it's deterministic
        let result2 = sha256(input).unwrap();
        assert_eq!(result, result2);
    }

    #[test]
    fn test_sha512_multi_block_is_deterministic() {
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
    fn test_sha256_abc_matches_nist_vector_matches_expected() {
        let result = sha256(b"abc").unwrap();
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha384_abc_matches_nist_vector_matches_expected() {
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
    fn test_sha512_abc_matches_nist_vector_matches_expected() {
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
    fn test_sha256_large_input_is_deterministic() {
        let input = vec![0x42; 1024 * 1024]; // 1MB
        let result = sha256(&input).unwrap();
        assert_eq!(result.len(), 32);
        // Verify determinism
        let result2 = sha256(&input).unwrap();
        assert_eq!(result, result2);
    }

    // Test all three functions with same input
    #[test]
    fn test_all_sha2_functions_return_correct_digest_sizes_has_correct_size() {
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

    /// Hex-encode a digest for comparison against published vectors.
    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// FIPS 180-2 Appendix B.2 (SHA-256, 448-bit two-block message).
    const SHA256_TWO_BLOCK_MSG: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const SHA256_TWO_BLOCK_HEX: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    /// FIPS 180-2 Appendix C.2 (SHA-512, 896-bit two-block message).
    const SHA512_TWO_BLOCK_MSG: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const SHA512_TWO_BLOCK_HEX: &str = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

    fn sha256_chunked(msg: &[u8], chunk: usize) -> [u8; 32] {
        let mut h = Sha256Hasher::new();
        for c in msg.chunks(chunk) {
            h.update(c).unwrap();
        }
        h.finalize()
    }

    fn sha512_chunked(msg: &[u8], chunk: usize) -> [u8; 64] {
        let mut h = Sha512Hasher::new();
        for c in msg.chunks(chunk) {
            h.update(c).unwrap();
        }
        h.finalize()
    }

    #[test]
    fn test_sha256_hasher_empty_matches_nist_vector_matches_expected() {
        let expected = sha256(b"").unwrap();
        assert_eq!(Sha256Hasher::new().finalize(), expected);
        assert_eq!(
            to_hex(&expected),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hasher_abc_chunked_matches_nist_vector_matches_expected() {
        let expected = sha256(b"abc").unwrap();
        for chunk in [1, 64, 3] {
            assert_eq!(sha256_chunked(b"abc", chunk), expected, "chunk {chunk}");
        }
        assert_eq!(
            to_hex(&expected),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_hasher_two_block_chunked_matches_nist_vector_matches_expected() {
        for chunk in [1, 64, SHA256_TWO_BLOCK_MSG.len()] {
            let got = sha256_chunked(SHA256_TWO_BLOCK_MSG, chunk);
            assert_eq!(to_hex(&got), SHA256_TWO_BLOCK_HEX, "chunk {chunk}");
        }
    }

    #[test]
    fn test_sha256_hasher_large_input_chunked_matches_one_shot_matches_expected() {
        let input = vec![0x42u8; 1024 * 1024];
        let expected = sha256(&input).unwrap();
        for chunk in [1000, 64, input.len()] {
            assert_eq!(sha256_chunked(&input, chunk), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn test_sha512_hasher_empty_matches_nist_vector_matches_expected() {
        let expected = sha512(b"").unwrap();
        assert_eq!(Sha512Hasher::new().finalize(), expected);
        assert_eq!(
            to_hex(&expected),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_sha512_hasher_abc_chunked_matches_nist_vector_matches_expected() {
        let expected = sha512(b"abc").unwrap();
        for chunk in [1, 64, 3] {
            assert_eq!(sha512_chunked(b"abc", chunk), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn test_sha512_hasher_two_block_chunked_matches_nist_vector_matches_expected() {
        for chunk in [1, 64, SHA512_TWO_BLOCK_MSG.len()] {
            let got = sha512_chunked(SHA512_TWO_BLOCK_MSG, chunk);
            assert_eq!(to_hex(&got), SHA512_TWO_BLOCK_HEX, "chunk {chunk}");
        }
    }

    #[test]
    fn test_sha512_hasher_large_input_chunked_matches_one_shot_matches_expected() {
        let input = vec![0x42u8; 1024 * 1024];
        let expected = sha512(&input).unwrap();
        for chunk in [1000, 64, input.len()] {
            assert_eq!(sha512_chunked(&input, chunk), expected, "chunk {chunk}");
        }
    }

    #[test]
    fn test_sha256_hasher_total_size_limit_returns_error_when_exceeded_fails() {
        let mut h = Sha256Hasher::new();
        h.total_len = MAX_HASH_INPUT_SIZE;
        h.update(&[]).unwrap();
        assert!(matches!(h.update(b"x"), Err(Sha2Error::ResourceExceeded(_))));
    }

    #[test]
    fn test_sha512_hasher_total_size_limit_returns_error_when_exceeded_fails() {
        let mut h = Sha512Hasher::new();
        h.total_len = MAX_HASH_INPUT_SIZE;
        h.update(&[]).unwrap();
        assert!(matches!(h.update(b"x"), Err(Sha2Error::ResourceExceeded(_))));
    }
}
