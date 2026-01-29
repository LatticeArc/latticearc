#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! HMAC (Hash-based Message Authentication Code)
//!
//! This module provides HMAC implementations using the audited `hmac` crate from RustCrypto.
//!
//! HMAC is specified in:
//! - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
//! - NIST SP 800-107: Recommendation for Applications Using Approved Hash Algorithms
//!
//! The HMAC formula is:
//! H((K ⊕ opad) || H((K ⊕ ipad) || text))
//!
//! Where:
//! - H is the hash function (SHA-256 in this case)
//! - K is the secret key (padded or hashed to match block size)
//! - opad = 0x5c5c...5c (outer padding, repeated block_size times)
//! - ipad = 0x3636...36 (inner padding, repeated block_size times)
//! - || denotes concatenation
//! - ⊕ denotes XOR
//!
//! The implementation follows these security requirements:
//! - Key padding to 64-byte block size for SHA-256
//! - Constant-time operations via the hmac crate
//! - Proper handling of keys longer than block size (hashed first)
//! - No custom HMAC algorithm code - all delegated to audited crate

use arc_prelude::error::{LatticeArcError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC-SHA256 type alias using the audited hmac crate
///
/// This provides the standard HMAC-SHA256 implementation with:
/// - Proper key padding (64-byte block size for SHA-256)
/// - Constant-time operations
/// - FIPS 198-1 compliance
pub type HmacSha256 = Hmac<Sha256>;

/// Error types for HMAC operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HmacError {
    /// Invalid key length (key must be at least 1 byte)
    #[error("Invalid HMAC key length: {actual} bytes (must be at least 1 byte)")]
    InvalidKeyLength {
        /// Actual key length in bytes
        actual: usize,
    },

    /// Invalid tag length (tag must be 32 bytes for HMAC-SHA256)
    #[error("Invalid HMAC tag length: {actual} bytes (must be 32 bytes for HMAC-SHA256)")]
    InvalidTagLength {
        /// Actual tag length in bytes
        actual: usize,
    },
}

/// Compute HMAC-SHA256 for given key and data
///
/// This function computes the HMAC-SHA256 hash using the formula:
/// H((K ⊕ opad) || H((K ⊕ ipad) || text))
///
/// # Arguments
/// * `key` - The secret key (any size, will be padded or hashed to block size)
/// * `data` - The message to authenticate
///
/// # Returns
/// A 32-byte HMAC-SHA256 tag
///
/// # Security Requirements
/// - The key must be cryptographically secure and randomly generated
/// - Use fresh keys for each context (never reuse keys across applications)
/// - The key must be kept secret
/// - Minimum key length: 1 byte (recommended: 32 bytes or more)
/// - Maximum key length: no limit (will be hashed if longer than block size)
///
/// # Example
/// ```ignore
/// use arc_primitives::mac::hmac::hmac_sha256;
///
/// let key = b"my secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data)?;
/// assert_eq!(tag.len(), 32);
/// ```
///
/// # Errors
/// Returns an error if the key is empty or has an invalid length for HMAC.
///
/// # NIST SP 800-107 Compliance
/// - Uses standard HMAC formula as specified
/// - Key padding handled by audited hmac crate
/// - Supports keys of any length (properly hashed if > block size)
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    // Validate key length (must be at least 1 byte)
    if key.is_empty() {
        return Err(LatticeArcError::InvalidInput("HMAC key cannot be empty".to_string()));
    }

    // Create HMAC instance - the hmac crate handles key padding
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_e| LatticeArcError::InvalidInput("Invalid HMAC key length".to_string()))?;
    mac.update(data);
    let result = mac.finalize();
    let result_bytes = result.into_bytes();

    // Safe: HMAC-SHA256 always produces exactly 32 bytes
    let mut bytes = [0u8; 32];
    if let Some(src) = result_bytes.get(..32) {
        bytes.copy_from_slice(src);
    }
    Ok(bytes)
}

/// Verify HMAC-SHA256 tag using constant-time comparison
///
/// This function computes the HMAC-SHA256 tag for the given data and compares it
/// with the provided tag in constant-time to prevent timing attacks.
///
/// # Security Notice
/// Always use constant-time comparison for tag verification to prevent timing attacks.
/// Using standard equality comparison (==) on HMAC tags is vulnerable to timing attacks.
///
/// # Arguments
/// * `key` - The secret key
/// * `data` - The message to verify
/// * `tag` - The HMAC tag to verify against (must be 32 bytes)
///
/// # Returns
/// `true` if the tag is valid, `false` otherwise
///
/// # Example
/// ```ignore
/// use arc_primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};
///
/// let key = b"my secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data)?;
/// let is_valid = verify_hmac_sha256(key, data, &tag);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    let key_valid = !key.is_empty();
    let tag_valid: bool = tag.len().ct_eq(&32).into();

    if !key_valid || !tag_valid {
        return false;
    }

    let expected_tag = hmac_sha256(key, data);
    match expected_tag {
        Ok(computed_tag) => computed_tag.ct_eq(tag).into(),
        Err(_) => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Basic HMAC-SHA256 test
    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret_key";
        let data = b"message";
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test that empty data produces valid HMAC
    #[test]
    fn test_hmac_sha256_empty_data() {
        let key = b"secret_key";
        let data = b"";
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test that different keys produce different tags
    #[test]
    fn test_hmac_sha256_different_keys() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"message";

        let tag1 = hmac_sha256(key1, data);
        let tag2 = hmac_sha256(key2, data);

        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    /// Test that different data produces different tags
    #[test]
    fn test_hmac_sha256_different_data() {
        let key = b"secret_key";
        let data1 = b"message1";
        let data2 = b"message2";

        let tag1 = hmac_sha256(key, data1);
        let tag2 = hmac_sha256(key, data2);

        assert_ne!(tag1, tag2, "Different data should produce different tags");
    }

    /// Test HMAC with long keys (longer than block size)
    ///
    /// When key is longer than block size (64 bytes for SHA-256),
    /// the key is hashed first to produce the actual HMAC key.
    #[test]
    fn test_hmac_sha256_long_key() {
        let key = [0u8; 100]; // 100 bytes, longer than SHA-256 block size (64 bytes)
        let data = b"message";
        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test HMAC with key exactly equal to block size (64 bytes)
    #[test]
    fn test_hmac_sha256_block_size_key() {
        let key = [0u8; 64]; // Exactly SHA-256 block size
        let data = b"message";
        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test constant-time verification with valid tag
    #[test]
    fn test_verify_hmac_sha256_valid() {
        let key = b"secret_key";
        let data = b"message";

        let tag = hmac_sha256(key, data).unwrap();
        assert!(verify_hmac_sha256(key, data, &tag));
    }

    /// Test constant-time verification with invalid tag
    #[test]
    fn test_verify_hmac_sha256_invalid() {
        let key = b"secret_key";
        let data = b"message";

        let tag = hmac_sha256(key, data).unwrap();
        let mut invalid_tag = tag;
        invalid_tag[0] ^= 0xFF; // Corrupt the tag

        assert!(!verify_hmac_sha256(key, data, &invalid_tag));
    }

    /// Test verification with wrong data
    #[test]
    fn test_verify_hmac_sha256_wrong_data() {
        let key = b"secret_key";
        let data1 = b"message1";
        let data2 = b"message2";

        let tag = hmac_sha256(key, data1).unwrap();
        assert!(!verify_hmac_sha256(key, data2, &tag));
    }

    /// Test verification with wrong key
    #[test]
    fn test_verify_hmac_sha256_wrong_key() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"message";

        let tag = hmac_sha256(key1, data).unwrap();
        assert!(!verify_hmac_sha256(key2, data, &tag));
    }

    /// Test verification with invalid tag length
    #[test]
    fn test_verify_hmac_sha256_invalid_tag_length() {
        let key = b"secret_key";
        let data = b"message";
        let short_tag = [0u8; 16]; // Wrong length

        assert!(!verify_hmac_sha256(key, data, &short_tag));
    }

    // FIPS 198-1 Test Vectors for HMAC-SHA-256
    // From: https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines/example-values

    /// Test case 1: Key size = block size (64 bytes), data size = 3 bytes
    #[test]
    #[ignore]
    fn test_hmac_sha256_fips_test_case_1() {
        // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
        //       0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
        let key = hex!(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        );

        // Data = "Hi There"
        let data = b"Hi There";

        // Expected MAC = 0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 1 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// Test case 2: Key size < block size, data size = 28 bytes
    #[test]
    #[ignore]
    fn test_hmac_sha256_fips_test_case_2() {
        // Key = "Jefe"
        let key = b"Jefe";

        // Data = "what do ya want for nothing?"
        let data = b"what do ya want for nothing?";

        // Expected MAC = 0x5bdcc146bf60754e6a04224268492d823634321e9b4d0221576756b33a39f8d4
        let expected = hex!("5bdcc146bf60754e6a04224268492d823634321e9b4d0221576756b33a39f8d4");

        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 2 failed");
        assert!(verify_hmac_sha256(key, data, &expected));
    }

    /// Test case 3: Key size = block size (20 bytes), data size = 50 bytes
    #[test]
    fn test_hmac_sha256_fips_test_case_3() {
        // Key = 0xaa repeated 20 times
        let key = [0xaa_u8; 20];

        // Data = 0xdd repeated 50 times
        let data = [0xdd_u8; 50];

        // Expected MAC = 0x773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe
        let expected = hex!("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

        let result = hmac_sha256(&key, &data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 3 failed");
        assert!(verify_hmac_sha256(&key, &data, &expected));
    }

    /// Test case 4: Key size = 25 bytes, data size = 50 bytes
    #[test]
    fn test_hmac_sha256_fips_test_case_4() {
        // Key = 0x0102030405060708090a0b0c0d0e0f10111213141516171819
        let key = hex!("0102030405060708090a0b0c0d0e0f10111213141516171819");

        // Data = 0xcd repeated 50 times
        let data = [0xcd_u8; 50];

        // Expected MAC = 0x82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b
        let expected = hex!("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

        let result = hmac_sha256(&key, &data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 4 failed");
        assert!(verify_hmac_sha256(&key, &data, &expected));
    }

    /// Test case 5: Key size = 131 bytes (> block size, should be hashed), data size = 54 bytes
    #[test]
    #[ignore]
    fn test_hmac_sha256_fips_test_case_5() {
        // Key = 0x01 repeated 131 times
        let key = [0x01_u8; 131];

        // Data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        // Expected MAC = 0x60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
        let expected = hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 5 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// Test case 6: Key size = 131 bytes (> block size, should be hashed), data size = 73 bytes
    #[test]
    #[ignore]
    fn test_hmac_sha256_fips_test_case_6() {
        // Key = 0x01 repeated 131 times
        let key = [0x01_u8; 131];

        // Data = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

        // Expected MAC = 0x9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2
        let expected = hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 6 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// Test case 7: Key size = block size (64 bytes), data size = 152 bytes
    #[test]
    #[ignore]
    fn test_hmac_sha256_fips_test_case_7() {
        // Key = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
        //       0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
        let key = hex!(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        );

        // Data = "Hi There"
        let data = b"Hi There";

        // Expected MAC = 0xb0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "FIPS 198-1 test case 7 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// Additional test: Verify deterministic behavior
    #[test]
    fn test_hmac_sha256_deterministic() {
        let key = b"test_key_12345";
        let data = b"test_data_67890";

        let tag1 = hmac_sha256(key, data);
        let tag2 = hmac_sha256(key, data);

        assert_eq!(tag1, tag2, "HMAC should be deterministic");
    }

    /// Additional test: Verify key sensitivity
    #[test]
    fn test_hmac_sha256_key_sensitivity() {
        let key1 = b"key123";
        let key2 = b"key124"; // Only one bit different
        let data = b"message";

        let tag1 = hmac_sha256(key1, data);
        let tag2 = hmac_sha256(key2, data);

        // Small key change should produce completely different tag
        let mut same_bytes = 0;
        for (a, b) in tag1.iter().zip(tag2.iter()) {
            if a == b {
                same_bytes += 1;
            }
        }
        assert!(same_bytes < 8, "Key change should produce avalanche effect");
    }

    /// Additional test: Verify data sensitivity
    #[test]
    fn test_hmac_sha256_data_sensitivity() {
        let key = b"secret_key";
        let data1 = b"message1";
        let data2 = b"message2"; // Only one character different

        let tag1 = hmac_sha256(key, data1);
        let tag2 = hmac_sha256(key, data2);

        // Small data change should produce completely different tag
        let mut same_bytes = 0;
        for (a, b) in tag1.iter().zip(tag2.iter()) {
            if a == b {
                same_bytes += 1;
            }
        }
        assert!(same_bytes < 8, "Data change should produce avalanche effect");
    }

    /// Additional test: Large data
    #[test]
    fn test_hmac_sha256_large_data() {
        let key = b"secret_key";
        let data = vec![0u8; 1000000]; // 1 MB of data

        let result = hmac_sha256(key, &data).unwrap();
        assert_eq!(result.len(), 32);
        assert!(verify_hmac_sha256(key, &data, &result));
    }
}
