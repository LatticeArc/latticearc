#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! HMAC (Hash-based Message Authentication Code)
//!
//! HMAC-SHA256 backed by FIPS 140-3 validated `aws-lc-rs`.
//!
//! Standards:
//! - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
//! - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
//! - NIST SP 800-107: Recommendation for Applications Using Approved Hash Algorithms
//!
//! The HMAC formula is:
//! `H((K ⊕ opad) || H((K ⊕ ipad) || text))`
//!
//! All HMAC operations in the crate share a single backend (aws-lc-rs). Key
//! padding, constant-time tag verification, and FIPS compliance are handled
//! by the underlying library.

use crate::prelude::error::{LatticeArcError, Result};
use aws_lc_rs::hmac::{self, HMAC_SHA256};

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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::mac::hmac::hmac_sha256;
///
/// let key = b"my secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data)?;
/// assert_eq!(tag.len(), 32);
/// # Ok(())
/// # }
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
    // Validate key length (must be at least 1 byte). aws-lc-rs accepts any
    // nonzero key length and handles padding/hashing per RFC 2104.
    if key.is_empty() {
        return Err(LatticeArcError::InvalidInput("HMAC key cannot be empty".to_string()));
    }

    let hk = hmac::Key::new(HMAC_SHA256, key);
    let tag = hmac::sign(&hk, data);

    // HMAC-SHA256 always produces exactly 32 bytes (RFC 2104).
    // Returning all-zeros on shorter output would be a dangerous silent failure.
    let src = tag.as_ref().get(..32).ok_or_else(|| LatticeArcError::ValidationError {
        message: format!("HMAC-SHA256 output is {} bytes, expected 32", tag.as_ref().len()),
    })?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(src);
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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::mac::hmac::{hmac_sha256, verify_hmac_sha256};
///
/// let key = b"my secret key";
/// let data = b"message to authenticate";
///
/// let tag = hmac_sha256(key, data)?;
/// let is_valid = verify_hmac_sha256(key, data, &tag);
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
#[must_use]
pub fn verify_hmac_sha256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    use subtle::{Choice, ConstantTimeEq};

    // Always compute MAC to prevent timing side-channels.
    let key_valid = Choice::from(u8::from(!key.is_empty()));
    let tag_len_valid = tag.len().ct_eq(&32);

    let mac_matches = match hmac_sha256(key, data) {
        Ok(computed_tag) => computed_tag.ct_eq(tag),
        Err(_) => Choice::from(0u8),
    };

    // Bitwise AND on subtle::Choice: no short-circuit, constant-time combine.
    bool::from(key_valid & tag_len_valid & mac_matches)
}

/// HMAC-SHA256 verifier that caches the `aws-lc-rs` key context.
///
/// Use when verifying many tags under the same key (e.g., session MAC
/// validation, token verification in a loop). The one-shot
/// [`verify_hmac_sha256`] allocates a fresh `hmac::Key` on every call;
/// `HmacSha256Verifier` allocates once at construction and reuses the
/// key context for every `.verify()` call.
///
/// Beyond the ergonomic win, the cached-key path also removes aws-lc-rs
/// FFI allocator churn from the verify hot path — important for the
/// dudect constant-time gate, whose per-sample resolution is otherwise
/// swamped by allocator-state variance.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use latticearc::primitives::mac::hmac::{hmac_sha256, HmacSha256Verifier};
///
/// let key = b"my secret key";
/// let verifier = HmacSha256Verifier::new(key)?;
///
/// let tag = hmac_sha256(key, b"message 1")?;
/// assert!(verifier.verify(b"message 1", &tag));
/// assert!(!verifier.verify(b"message 2", &tag));
/// # Ok(())
/// # }
/// ```
pub struct HmacSha256Verifier {
    key: hmac::Key,
}

impl HmacSha256Verifier {
    /// Construct a verifier bound to `key`.
    ///
    /// # Errors
    /// Returns an error if `key` is empty. aws-lc-rs handles padding/hashing
    /// for keys longer than the block size.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() {
            return Err(LatticeArcError::InvalidInput("HMAC key cannot be empty".to_string()));
        }
        Ok(Self { key: hmac::Key::new(HMAC_SHA256, key) })
    }

    /// Verify `tag` against `HMAC-SHA256(key, data)` in constant time.
    ///
    /// Returns `false` (never errors) on length mismatch or MAC mismatch.
    /// No FFI allocation on the hot path — the key context was bound at
    /// construction.
    #[must_use]
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        use subtle::{Choice, ConstantTimeEq};

        let tag_len_valid = tag.len().ct_eq(&32);

        let computed = hmac::sign(&self.key, data);
        let computed_bytes = computed.as_ref();
        // HMAC-SHA256 output is always 32 bytes by construction; the length
        // check above guards `tag` so both sides feed subtle equal-length slices
        // on the accept path and zero-length subtle on the reject path.
        let mac_matches = match computed_bytes.get(..32) {
            Some(slice) => slice.ct_eq(tag),
            None => Choice::from(0u8),
        };

        bool::from(tag_len_valid & mac_matches)
    }
}

impl std::fmt::Debug for HmacSha256Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacSha256Verifier").field("key", &"[REDACTED]").finish()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Tests use unwrap for simplicity")]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Basic HMAC-SHA256 test
    #[test]
    fn test_hmac_sha256_basic_returns_32_byte_tag_succeeds() {
        let key = b"secret_key";
        let data = b"message";
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test that empty data produces valid HMAC
    #[test]
    fn test_hmac_sha256_empty_data_returns_32_byte_tag_succeeds() {
        let key = b"secret_key";
        let data = b"";
        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test that different keys produce different tags
    #[test]
    fn test_hmac_sha256_different_keys_produce_distinct_tags_are_unique() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"message";

        let tag1 = hmac_sha256(key1, data);
        let tag2 = hmac_sha256(key2, data);

        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    /// Test that different data produces different tags
    #[test]
    fn test_hmac_sha256_different_data_produce_distinct_tags_are_unique() {
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
    fn test_hmac_sha256_long_key_returns_32_byte_tag_succeeds() {
        let key = [0u8; 100]; // 100 bytes, longer than SHA-256 block size (64 bytes)
        let data = b"message";
        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test HMAC with key exactly equal to block size (64 bytes)
    #[test]
    fn test_hmac_sha256_block_size_key_returns_32_byte_tag_has_correct_size() {
        let key = [0u8; 64]; // Exactly SHA-256 block size
        let data = b"message";
        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result.len(), 32);
    }

    /// Test constant-time verification with valid tag
    #[test]
    fn test_verify_hmac_sha256_valid_tag_returns_true_succeeds() {
        let key = b"secret_key";
        let data = b"message";

        let tag = hmac_sha256(key, data).unwrap();
        assert!(verify_hmac_sha256(key, data, &tag));
    }

    /// Test constant-time verification with invalid tag
    #[test]
    fn test_verify_hmac_sha256_invalid_returns_false_fails() {
        let key = b"secret_key";
        let data = b"message";

        let tag = hmac_sha256(key, data).unwrap();
        let mut invalid_tag = tag;
        invalid_tag[0] ^= 0xFF; // Corrupt the tag

        assert!(!verify_hmac_sha256(key, data, &invalid_tag));
    }

    /// Test verification with wrong data
    #[test]
    fn test_verify_hmac_sha256_wrong_data_returns_false_fails() {
        let key = b"secret_key";
        let data1 = b"message1";
        let data2 = b"message2";

        let tag = hmac_sha256(key, data1).unwrap();
        assert!(!verify_hmac_sha256(key, data2, &tag));
    }

    /// Test verification with wrong key
    #[test]
    fn test_verify_hmac_sha256_wrong_key_returns_false_fails() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"message";

        let tag = hmac_sha256(key1, data).unwrap();
        assert!(!verify_hmac_sha256(key2, data, &tag));
    }

    /// Test verification with invalid tag length
    #[test]
    fn test_verify_hmac_sha256_invalid_tag_length_returns_false_fails() {
        let key = b"secret_key";
        let data = b"message";
        let short_tag = [0u8; 16]; // Wrong length

        assert!(!verify_hmac_sha256(key, data, &short_tag));
    }

    // ========================================================================
    // HmacSha256Verifier coverage — mirrors the verify_hmac_sha256 tests
    // above so the cached-key API path has equivalent assurance.
    // ========================================================================

    #[test]
    fn test_verifier_new_empty_key_returns_error() {
        assert!(HmacSha256Verifier::new(&[]).is_err());
    }

    #[test]
    fn test_verifier_valid_tag_returns_true_succeeds() {
        let key = b"secret_key";
        let data = b"message";
        let tag = hmac_sha256(key, data).unwrap();
        let verifier = HmacSha256Verifier::new(key).unwrap();
        assert!(verifier.verify(data, &tag));
    }

    #[test]
    fn test_verifier_tampered_tag_returns_false_fails() {
        let key = b"secret_key";
        let data = b"message";
        let mut tag = hmac_sha256(key, data).unwrap();
        tag[0] ^= 0xFF;
        let verifier = HmacSha256Verifier::new(key).unwrap();
        assert!(!verifier.verify(data, &tag));
    }

    #[test]
    fn test_verifier_wrong_data_returns_false_fails() {
        let key = b"secret_key";
        let tag = hmac_sha256(key, b"original message").unwrap();
        let verifier = HmacSha256Verifier::new(key).unwrap();
        assert!(!verifier.verify(b"different message", &tag));
    }

    #[test]
    fn test_verifier_wrong_tag_length_returns_false_fails() {
        let key = b"secret_key";
        let verifier = HmacSha256Verifier::new(key).unwrap();
        assert!(!verifier.verify(b"message", &[0u8; 16]));
        assert!(!verifier.verify(b"message", &[0u8; 31]));
        assert!(!verifier.verify(b"message", &[0u8; 33]));
        assert!(!verifier.verify(b"message", &[0u8; 64]));
    }

    #[test]
    fn test_verifier_agrees_with_one_shot_verify_on_rfc4231_case1() {
        // RFC 4231 Test Case 1 — sanity: cached-key path and one-shot path
        // must produce identical verdicts on a known-answer test vector.
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let verifier = HmacSha256Verifier::new(&key).unwrap();
        assert_eq!(verify_hmac_sha256(&key, data, &expected), verifier.verify(data, &expected));
        assert!(verifier.verify(data, &expected));
    }

    #[test]
    fn test_verifier_reusable_across_many_calls_succeeds() {
        // The whole point of the cached-key API: construct once, verify
        // many. This test asserts the Verifier stays valid and produces
        // correct verdicts across many calls without needing reconstruction.
        let key = b"long-lived-session-key";
        let verifier = HmacSha256Verifier::new(key).unwrap();
        for i in 0..256u32 {
            let data = i.to_le_bytes();
            let tag = hmac_sha256(key, &data).unwrap();
            assert!(verifier.verify(&data, &tag), "iter {i}: valid tag rejected");
            let mut bad_tag = tag;
            let flip_idx = (i as usize) % 32;
            *bad_tag.get_mut(flip_idx).unwrap() ^= 0x01;
            assert!(!verifier.verify(&data, &bad_tag), "iter {i}: tampered tag accepted");
        }
    }

    #[test]
    fn test_verifier_debug_redacts_key() {
        let verifier = HmacSha256Verifier::new(b"secret").unwrap();
        let dbg = format!("{:?}", verifier);
        assert!(dbg.contains("HmacSha256Verifier"));
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("secret"));
    }

    // FIPS 198-1 Test Vectors for HMAC-SHA-256
    // From: https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines/example-values

    /// RFC 4231 Test Case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_1_matches_expected() {
        let key = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

        let data = b"Hi There";

        let expected = hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "RFC 4231 test case 1 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_2_matches_expected() {
        let key = b"Jefe";

        let data = b"what do ya want for nothing?";

        let expected = hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        let result = hmac_sha256(key, data).unwrap();
        assert_eq!(result, expected, "RFC 4231 test case 2 failed");
        assert!(verify_hmac_sha256(key, data, &expected));
    }

    /// Test case 3: Key size = block size (20 bytes), data size = 50 bytes
    #[test]
    fn test_hmac_sha256_fips_test_case_3_matches_expected() {
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
    fn test_hmac_sha256_fips_test_case_4_matches_expected() {
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

    /// RFC 4231 Test Case 6: Key = 131 bytes of 0xaa, large key (hashed first)
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_6_matches_expected() {
        let key = [0xaa_u8; 131];

        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";

        let expected = hex!("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "RFC 4231 test case 6 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// RFC 4231 Test Case 7: Key = 131 bytes of 0xaa, large key + large data
    #[test]
    fn test_hmac_sha256_rfc4231_test_case_7_matches_expected() {
        let key = [0xaa_u8; 131];

        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

        let expected = hex!("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");

        let result = hmac_sha256(&key, data).unwrap();
        assert_eq!(result, expected, "RFC 4231 test case 7 failed");
        assert!(verify_hmac_sha256(&key, data, &expected));
    }

    /// Additional test: Verify deterministic behavior
    #[test]
    fn test_hmac_sha256_deterministic_returns_same_tag_is_deterministic() {
        let key = b"test_key_12345";
        let data = b"test_data_67890";

        let tag1 = hmac_sha256(key, data);
        let tag2 = hmac_sha256(key, data);

        assert_eq!(tag1, tag2, "HMAC should be deterministic");
    }

    /// Additional test: Verify key sensitivity
    #[test]
    fn test_hmac_sha256_key_sensitivity_produces_avalanche_effect_succeeds() {
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
    fn test_hmac_sha256_data_sensitivity_produces_avalanche_effect_succeeds() {
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
    fn test_hmac_sha256_large_data_succeeds() {
        let key = b"secret_key";
        let data = vec![0u8; 1000000]; // 1 MB of data

        let result = hmac_sha256(key, &data).unwrap();
        assert_eq!(result.len(), 32);
        assert!(verify_hmac_sha256(key, &data, &result));
    }
}
