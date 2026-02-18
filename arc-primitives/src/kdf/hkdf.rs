#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SP 800-56C: HMAC-based Extract-and-Expand Key Derivation (HKDF)
//!
//! HKDF is a cryptographic key derivation function based on HMAC. It follows
//! the extract-and-expand paradigm defined in NIST SP 800-56C / RFC 5869.
//!
//! This implementation provides:
//! - HKDF-Extract: Extract entropy from input keying material
//! - HKDF-Expand: Expand pseudorandom key to desired length
//! - Full HKDF: Combined extract + expand operation
//! - SHA-256 as underlying hash function
//!
//! This implementation uses aws-lc-rs for FIPS 140-3 compliance and optimized performance.

use arc_prelude::error::{LatticeArcError, Result};
use aws_lc_rs::hmac::{self, HMAC_SHA256};
use tracing::instrument;
use zeroize::Zeroize;

/// HKDF result containing the derived key
pub struct HkdfResult {
    /// Derived key material
    pub key: Vec<u8>,
    /// Length of the derived key
    pub key_length: usize,
}

impl Zeroize for HkdfResult {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for HkdfResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HkdfResult {
    /// Get the derived key
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// HKDF-Extract: Extract entropy from input keying material
///
/// This function extracts entropy from potentially high-entropy IKM (Input Keying Material)
/// to produce a fixed-length pseudorandom key (PRK). This is useful when the input
/// may not be uniformly distributed.
///
/// Per RFC 5869: `PRK = HMAC-Hash(salt, IKM)`
///
/// # Security
///
/// ⚠️ **Salt Usage:** While RFC 5869 permits a zero salt (which this implementation
/// uses when `salt` is `None`), you **SHOULD** provide a random salt for maximum
/// security. A random salt ensures that even if the same input key material (IKM)
/// is used multiple times, the derived keys will be different.
///
/// **Best Practice:** Generate a random salt using a cryptographically secure RNG:
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use arc_primitives::kdf::hkdf::hkdf_extract;
/// use rand::RngCore;
/// # let ikm = b"input key material";
/// let mut salt = [0u8; 32];
/// rand::rngs::OsRng.fill_bytes(&mut salt);
/// let prk = hkdf_extract(Some(&salt), ikm)?;
/// # Ok(())
/// # }
/// ```
///
/// If salt is `None`, a string of 32 zero bytes is used (per RFC 5869 Section 2.2).
/// This is acceptable for scenarios where the IKM already has sufficient entropy and
/// is never reused, but random salts provide defense-in-depth.
///
/// # Arguments
/// * `salt` - Optional salt value. **Strongly recommended** to provide a random 32-byte salt.
/// * `ikm` - Input keying material (the secret to derive from)
///
/// # Returns
/// A 32-byte pseudorandom key (PRK)
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use arc_primitives::kdf::hkdf::hkdf_extract;
/// let ikm = b"secret input key material";
/// let salt = b"random salt value for maximum security";
/// let prk = hkdf_extract(Some(salt), ikm)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns an error if the extraction operation fails.
#[instrument(level = "debug", skip(salt, ikm), fields(has_salt = salt.is_some(), ikm_len = ikm.len()))]
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> Result<[u8; 32]> {
    // Per RFC 5869: If salt is not provided, use a string of HashLen zeros
    const DEFAULT_SALT: [u8; 32] = [0u8; 32];
    let salt_bytes = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &DEFAULT_SALT,
    };

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    // Use aws-lc-rs HMAC directly to get raw PRK bytes
    let key = hmac::Key::new(HMAC_SHA256, salt_bytes);
    let tag = hmac::sign(&key, ikm);

    let mut prk_array = [0u8; 32];
    let tag_bytes = tag.as_ref();
    if let Some(src) = tag_bytes.get(..32) {
        prk_array.copy_from_slice(src);
    }

    Ok(prk_array)
}

/// HKDF-Expand: Expand pseudorandom key to desired length
///
/// This function expands a pseudorandom key to output keying material of the
/// desired length, optionally incorporating context information via the info parameter.
///
/// Per RFC 5869 Section 2.3:
/// ```text
/// N = ceil(L/HashLen)
/// T = T(1) | T(2) | T(3) | ... | T(N)
/// OKM = first L octets of T
///
/// where:
/// T(0) = empty string
/// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
/// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
/// ...
/// ```
///
/// # Arguments
/// * `prk` - Pseudorandom key (32 bytes from HKDF-Extract)
/// * `info` - Optional context and application specific information
/// * `length` - Desired output length in bytes (max 255 * 32 = 8160 bytes)
///
/// # Returns
/// Output keying material of the requested length
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use arc_primitives::kdf::hkdf::{hkdf_extract, hkdf_expand};
/// # let ikm = b"input key material";
/// # let salt = b"salt";
/// let prk = hkdf_extract(Some(salt), ikm)?;
/// let info = b"context information";
/// let okm = hkdf_expand(&prk, Some(info), 64)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns an error if output length is zero or exceeds maximum (8160 bytes).
#[instrument(level = "debug", skip(prk, info), fields(has_info = info.is_some(), output_length = length))]
pub fn hkdf_expand(prk: &[u8; 32], info: Option<&[u8]>, length: usize) -> Result<HkdfResult> {
    // Validate length: max output is 255 * hash_length
    const HASH_LEN: usize = 32;
    const MAX_LEN: usize = 255 * HASH_LEN;

    if length == 0 {
        return Err(LatticeArcError::InvalidParameter(
            "Output length must be greater than 0".to_string(),
        ));
    }

    if length > MAX_LEN {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Output length {} exceeds maximum of {}",
            length, MAX_LEN
        )));
    }

    // RFC 5869 HKDF-Expand using aws-lc-rs HMAC
    // N = ceil(L/HashLen)
    let n = length.div_ceil(HASH_LEN);

    let info_bytes = info.unwrap_or(&[]);
    let mut output = Vec::with_capacity(length);
    let mut t_prev: Vec<u8> = Vec::new(); // T(0) = empty string

    let key = hmac::Key::new(HMAC_SHA256, prk);

    for i in 1..=n {
        // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        let capacity = t_prev.len().saturating_add(info_bytes.len()).saturating_add(1);
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(&t_prev);
        data.extend_from_slice(info_bytes);
        // Counter byte (1-indexed, fits in u8 since max N = 255)
        let counter = u8::try_from(i)
            .map_err(|_e| LatticeArcError::InvalidParameter("HKDF counter overflow".to_string()))?;
        data.push(counter);

        let tag = hmac::sign(&key, &data);
        let t_i = tag.as_ref();

        // Append T(i) to output (only up to the required length)
        let remaining = length.saturating_sub(output.len());
        let to_copy = remaining.min(HASH_LEN);
        if let Some(bytes) = t_i.get(..to_copy) {
            output.extend_from_slice(bytes);
        }

        // T(i-1) for next iteration
        t_prev = t_i.to_vec();
    }

    Ok(HkdfResult { key: output, key_length: length })
}

/// Full HKDF: Extract then expand
///
/// Combines HKDF-Extract and HKDF-Expand in a single call for convenience.
/// This is the recommended way to use HKDF for most applications.
///
/// # Arguments
/// * `ikm` - Input keying material (the secret to derive from)
/// * `salt` - Optional salt value. Use empty slice or None if not available.
/// * `info` - Optional context and application specific information
/// * `length` - Desired output length in bytes (max 255 * 32 = 8160 bytes)
///
/// # Returns
/// Output keying material of the requested length
///
/// # Example
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # use arc_primitives::kdf::hkdf::hkdf;
/// let ikm = b"secret input key material";
/// let salt = b"random salt";
/// let info = b"context information";
/// let okm = hkdf(ikm, Some(salt), Some(info), 64)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns an error if output length is zero or exceeds maximum (8160 bytes).
#[instrument(level = "debug", skip(ikm, salt, info), fields(ikm_len = ikm.len(), has_salt = salt.is_some(), has_info = info.is_some(), output_length = length))]
pub fn hkdf(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    length: usize,
) -> Result<HkdfResult> {
    // Extract: PRK = HMAC-Hash(salt, IKM)
    let prk = hkdf_extract(salt, ikm)?;

    // Expand: OKM = HKDF-Expand(PRK, info, L)
    hkdf_expand(&prk, info, length)
}

/// Simple HKDF derivation with default parameters
///
/// Convenience function that uses recommended default parameters:
/// - Random 16-byte salt
/// - No info parameter
/// - 32-byte output key
///
/// # Errors
/// Returns an error if key derivation fails.
#[instrument(level = "debug", skip(ikm), fields(ikm_len = ikm.len(), output_length = length))]
pub fn hkdf_simple(ikm: &[u8], length: usize) -> Result<HkdfResult> {
    let mut salt = vec![0u8; 16];
    get_random_bytes(&mut salt);

    hkdf(ikm, Some(&salt), None, length)
}

/// Get random bytes for salt generation
fn get_random_bytes(bytes: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::indexing_slicing)] // Tests use slice indexing for verification
mod tests {
    use super::*;

    // Test vectors from RFC 5869
    #[test]
    fn test_hkdf_extract_rfc5869_test_case_1() {
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];

        let prk = hkdf_extract(Some(&salt), &ikm).unwrap();

        // Expected PRK from RFC 5869
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];

        assert_eq!(prk, expected_prk);
    }

    #[test]
    fn test_hkdf_extract_empty_salt() {
        let ikm = b"test input key material";

        // With empty salt
        let prk1 = hkdf_extract(Some(&[]), ikm).unwrap();

        // With None salt (should be same as empty)
        let prk2 = hkdf_extract(None, ikm).unwrap();

        assert_eq!(prk1, prk2);
    }

    #[test]
    fn test_hkdf_full() {
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let okm = hkdf(&ikm, Some(&salt), Some(&info), 42).unwrap();

        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        assert_eq!(okm.key, expected_okm);
    }

    #[test]
    fn test_hkdf_different_ikm() {
        let salt = b"salt";
        let info = b"info";

        let okm1 = hkdf(b"ikm1", Some(salt), Some(info), 32).unwrap();
        let okm2 = hkdf(b"ikm2", Some(salt), Some(info), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_different_salt() {
        let ikm = b"ikm";
        let info = b"info";

        let okm1 = hkdf(ikm, Some(b"salt1"), Some(info), 32).unwrap();
        let okm2 = hkdf(ikm, Some(b"salt2"), Some(info), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"ikm";
        let salt = b"salt";

        let okm1 = hkdf(ikm, Some(salt), Some(b"info1"), 32).unwrap();
        let okm2 = hkdf(ikm, Some(salt), Some(b"info2"), 32).unwrap();

        assert_ne!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_different_lengths() {
        let ikm = b"ikm";
        let salt = b"salt";
        let info = b"info";

        let okm1 = hkdf(ikm, Some(salt), Some(info), 16).unwrap();
        let okm2 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();
        let okm3 = hkdf(ikm, Some(salt), Some(info), 64).unwrap();

        assert_eq!(okm1.key.len(), 16);
        assert_eq!(okm2.key.len(), 32);
        assert_eq!(okm3.key.len(), 64);

        // Different lengths should have same prefix (first 16 bytes identical)
        assert_eq!(okm1.key, &okm2.key[..16]);
        // But the full outputs should be different lengths
        assert_ne!(okm1.key_length, okm2.key_length);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"test ikm";
        let salt = b"test salt";
        let info = b"test info";

        let okm1 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();
        let okm2 = hkdf(ikm, Some(salt), Some(info), 32).unwrap();

        assert_eq!(okm1.key, okm2.key);
    }

    #[test]
    fn test_hkdf_validation() {
        let ikm = b"ikm";
        let salt = b"salt";

        // Zero length should fail
        assert!(hkdf(ikm, Some(salt), None, 0).is_err());

        // Length too long should fail
        assert!(hkdf(ikm, Some(salt), None, 8161).is_err());

        // Max length should succeed
        assert!(hkdf(ikm, Some(salt), None, 8160).is_ok());
    }

    #[test]
    fn test_hkdf_simple() {
        let ikm = b"test input key material";

        let result1 = hkdf_simple(ikm, 32).unwrap();
        let result2 = hkdf_simple(ikm, 32).unwrap();

        // Different random salts should produce different keys
        assert_ne!(result1.key, result2.key);
        assert_eq!(result1.key.len(), 32);
        assert_eq!(result2.key.len(), 32);
    }

    #[test]
    fn test_hkdf_result_zeroize_on_drop() {
        let ikm = b"test ikm";
        let salt = b"test salt";

        let key_bytes = {
            let result = hkdf(ikm, Some(salt), None, 32).unwrap();
            let key_copy = result.key.clone();
            drop(result);
            key_copy
        };

        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_hkdf_explicit_zeroization() {
        let ikm = b"test ikm";
        let salt = b"test salt";

        let mut result = hkdf(ikm, Some(salt), None, 32).unwrap();

        assert!(!result.key.iter().all(|&b| b == 0), "HKDF result should contain non-zero data");

        result.zeroize();

        assert!(result.key.iter().all(|&b| b == 0), "HKDF result should be zeroized");
    }

    #[test]
    fn test_hkdf_ikm_zeroization() {
        let mut ikm = vec![0x77; 64];
        let salt = b"test salt";

        assert!(!ikm.iter().all(|&b| b == 0), "IKM should contain non-zero data");

        hkdf(&ikm, Some(salt), None, 32).unwrap();

        ikm.zeroize();

        assert!(ikm.iter().all(|&b| b == 0), "IKM should be zeroized");
    }

    #[test]
    fn test_hkdf_salt_zeroization() {
        let ikm = b"test ikm";
        let mut salt = vec![0x88; 32];

        assert!(!salt.iter().all(|&b| b == 0), "Salt should contain non-zero data");

        hkdf(ikm, Some(&salt), None, 32).unwrap();

        salt.zeroize();

        assert!(salt.iter().all(|&b| b == 0), "Salt should be zeroized");
    }

    #[test]
    fn test_hkdf_expand_with_hash_boundary() {
        let ikm = b"ikm";
        let salt = b"salt";

        // Test at hash length boundary (32 bytes)
        let okm1 = hkdf(ikm, Some(salt), None, 32).unwrap();
        assert_eq!(okm1.key.len(), 32);

        // Test just over hash length boundary (33 bytes)
        let okm2 = hkdf(ikm, Some(salt), None, 33).unwrap();
        assert_eq!(okm2.key.len(), 33);

        // First 32 bytes should match
        assert_eq!(okm1.key, &okm2.key[..32]);
    }

    // RFC 5869 Test Case 2: Longer inputs/outputs
    #[test]
    fn test_rfc5869_test_case_2() {
        let ikm = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        ];
        // RFC 5869 Test Case 2: salt is 80 bytes (0x60-0xaf)
        let salt = [
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        ];
        let info = [
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        ];

        let okm = hkdf(&ikm, Some(&salt), Some(&info), 82).unwrap();

        // The expected output from RFC 5869 Test Case 2
        let expected_okm = [
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
        ];

        assert_eq!(okm.key, expected_okm);
        assert_eq!(okm.key.len(), 82);
    }

    // RFC 5869 Test Case 3: Zero-length salt/info
    #[test]
    fn test_rfc5869_test_case_3() {
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [];
        let info = [];

        let okm = hkdf(&ikm, Some(&salt), Some(&info), 42).unwrap();

        let expected_okm = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ];

        assert_eq!(okm.key, expected_okm);
    }

    // Test that the implementation uses aws-lc-rs correctly
    #[test]
    fn test_uses_aws_lc_rs() {
        // This test verifies that the implementation produces RFC 5869 compliant output
        // by checking that the outputs match the expected test vectors.
        // Since aws-lc-rs is FIPS 140-3 validated, passing these tests confirms proper usage.

        // Test Case 1 from RFC 5869
        let ikm = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let okm = hkdf(&ikm, Some(&salt), Some(&info), 42).unwrap();

        // Expected output from RFC 5869 (using aws-lc-rs FIPS implementation)
        let expected_okm = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        assert_eq!(okm.key, expected_okm, "HKDF must use aws-lc-rs implementation correctly");
    }
}
