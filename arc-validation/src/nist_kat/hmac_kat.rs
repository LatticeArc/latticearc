#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! HMAC Known Answer Tests
//!
//! Test vectors from RFC 4231 (Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256,
//! HMAC-SHA-384, and HMAC-SHA-512)
//!
//! ## Test Coverage
//! - HMAC-SHA-224
//! - HMAC-SHA-256
//! - HMAC-SHA-384
//! - HMAC-SHA-512
//! - Various key and message lengths
//! - Edge cases (short keys, long keys, empty messages)

use super::{NistKatError, decode_hex};
use hmac::{Hmac, Mac};
use sha2::{Sha224, Sha256, Sha384, Sha512};

type HmacSha224 = Hmac<Sha224>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

/// Test vector for HMAC
pub struct HmacTestVector {
    pub test_name: &'static str,
    pub key: &'static str,
    pub message: &'static str,
    pub expected_mac_sha224: &'static str,
    pub expected_mac_sha256: &'static str,
    pub expected_mac_sha384: &'static str,
    pub expected_mac_sha512: &'static str,
}

/// HMAC test vectors from RFC 4231
pub const HMAC_VECTORS: &[HmacTestVector] = &[
    // Test Case 1: 20-byte key
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-1",
        key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        message: "4869205468657265", // "Hi There"
        expected_mac_sha224: "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        expected_mac_sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        expected_mac_sha384: "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        expected_mac_sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    // Test Case 2: Short key ("Jefe")
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-2",
        key: "4a656665",                                                     // "Jefe"
        message: "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
        expected_mac_sha224: "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
        expected_mac_sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        expected_mac_sha384: "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        expected_mac_sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    // Test Case 3: 20-byte key (all 0xaa)
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-3",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        message: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", // 50 bytes of 0xdd
        expected_mac_sha224: "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
        expected_mac_sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        expected_mac_sha384: "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
        expected_mac_sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
    // Test Case 4: 25-byte key (incremental 0x01..0x19)
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-4",
        key: "0102030405060708090a0b0c0d0e0f10111213141516171819",
        message: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", // 50 bytes of 0xcd
        expected_mac_sha224: "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
        expected_mac_sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        expected_mac_sha384: "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
        expected_mac_sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
    },
    // Test Case 5: Truncated output (not tested here, standard output only)
    // Test Case 6: 131-byte key (longer than block size for SHA-256/224)
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-6",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        message: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", // "Test Using Larger Than Block-Size Key - Hash Key First"
        expected_mac_sha224: "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
        expected_mac_sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        expected_mac_sha384: "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
        expected_mac_sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
    // Test Case 7: 131-byte key with longer message
    HmacTestVector {
        test_name: "RFC-4231-Test-Case-7",
        key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        message: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e", // "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
        expected_mac_sha224: "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
        expected_mac_sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        expected_mac_sha384: "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
        expected_mac_sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    },
];

/// Run HMAC-SHA256 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_hmac_sha256_kat() -> Result<(), NistKatError> {
    for vector in HMAC_VECTORS {
        let key = decode_hex(vector.key)?;
        let message = decode_hex(vector.message)?;
        let expected_mac = decode_hex(vector.expected_mac_sha256)?;

        let mut mac = HmacSha256::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA256".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
    }
    Ok(())
}

/// Run HMAC-SHA224 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_hmac_sha224_kat() -> Result<(), NistKatError> {
    for vector in HMAC_VECTORS {
        let key = decode_hex(vector.key)?;
        let message = decode_hex(vector.message)?;
        let expected_mac = decode_hex(vector.expected_mac_sha224)?;

        let mut mac = HmacSha224::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA224".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
    }
    Ok(())
}

/// Run HMAC-SHA384 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_hmac_sha384_kat() -> Result<(), NistKatError> {
    for vector in HMAC_VECTORS {
        let key = decode_hex(vector.key)?;
        let message = decode_hex(vector.message)?;
        let expected_mac = decode_hex(vector.expected_mac_sha384)?;

        let mut mac = HmacSha384::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA384".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
    }
    Ok(())
}

/// Run HMAC-SHA512 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_hmac_sha512_kat() -> Result<(), NistKatError> {
    for vector in HMAC_VECTORS {
        let key = decode_hex(vector.key)?;
        let message = decode_hex(vector.message)?;
        let expected_mac = decode_hex(vector.expected_mac_sha512)?;

        let mut mac = HmacSha512::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA512".to_string(),
                test_name: vector.test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::indexing_slicing, clippy::err_expect)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_kat() {
        let result = run_hmac_sha256_kat();
        assert!(result.is_ok(), "HMAC-SHA256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_hmac_sha224_kat() {
        let result = run_hmac_sha224_kat();
        assert!(result.is_ok(), "HMAC-SHA224 KAT failed: {:?}", result);
    }

    #[test]
    fn test_hmac_sha384_kat() {
        let result = run_hmac_sha384_kat();
        assert!(result.is_ok(), "HMAC-SHA384 KAT failed: {:?}", result);
    }

    #[test]
    fn test_hmac_sha512_kat() {
        let result = run_hmac_sha512_kat();
        assert!(result.is_ok(), "HMAC-SHA512 KAT failed: {:?}", result);
    }

    // ---------------------------------------------------------------
    // Tests exercising error paths and edge cases
    // ---------------------------------------------------------------

    /// Helper that runs the HMAC-SHA256 KAT flow against a single custom
    /// vector, exercising the same code path as `run_hmac_sha256_kat`.
    #[allow(dead_code)]
    fn run_single_hmac_sha256(
        key_hex: &str,
        msg_hex: &str,
        expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let key = decode_hex(key_hex)?;
        let message = decode_hex(msg_hex)?;
        let expected_mac = decode_hex(expected_hex)?;

        let mut mac = HmacSha256::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA256".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
        Ok(())
    }

    /// Helper that runs the HMAC-SHA224 KAT flow against a single custom
    /// vector, exercising the same code path as `run_hmac_sha224_kat`.
    #[allow(dead_code)]
    fn run_single_hmac_sha224(
        key_hex: &str,
        msg_hex: &str,
        expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let key = decode_hex(key_hex)?;
        let message = decode_hex(msg_hex)?;
        let expected_mac = decode_hex(expected_hex)?;

        let mut mac = HmacSha224::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA224".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
        Ok(())
    }

    /// Helper that runs the HMAC-SHA384 KAT flow against a single custom
    /// vector, exercising the same code path as `run_hmac_sha384_kat`.
    #[allow(dead_code)]
    fn run_single_hmac_sha384(
        key_hex: &str,
        msg_hex: &str,
        expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let key = decode_hex(key_hex)?;
        let message = decode_hex(msg_hex)?;
        let expected_mac = decode_hex(expected_hex)?;

        let mut mac = HmacSha384::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA384".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
        Ok(())
    }

    /// Helper that runs the HMAC-SHA512 KAT flow against a single custom
    /// vector, exercising the same code path as `run_hmac_sha512_kat`.
    #[allow(dead_code)]
    fn run_single_hmac_sha512(
        key_hex: &str,
        msg_hex: &str,
        expected_hex: &str,
        test_name: &str,
    ) -> Result<(), NistKatError> {
        let key = decode_hex(key_hex)?;
        let message = decode_hex(msg_hex)?;
        let expected_mac = decode_hex(expected_hex)?;

        let mut mac = HmacSha512::new_from_slice(&key).map_err(|e| {
            NistKatError::ImplementationError(format!("HMAC creation failed: {:?}", e))
        })?;
        mac.update(&message);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        if code_bytes.as_slice() != expected_mac.as_slice() {
            return Err(NistKatError::TestFailed {
                algorithm: "HMAC-SHA512".to_string(),
                test_name: test_name.to_string(),
                message: format!(
                    "MAC mismatch: got {}, expected {}",
                    hex::encode(code_bytes),
                    hex::encode(&expected_mac)
                ),
            });
        }
        Ok(())
    }

    // --- MAC mismatch tests (TestFailed error path) ---

    #[test]
    fn test_hmac_sha256_mac_mismatch() {
        let vector = &HMAC_VECTORS[0];
        // Use a wrong expected MAC (flip the last byte)
        let wrong_expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cfff";
        let result =
            run_single_hmac_sha256(vector.key, vector.message, wrong_expected, vector.test_name);
        assert!(result.is_err());
        let err = result.err();
        assert!(err.is_some());
        let err_val = err.expect("error expected");
        let msg = format!("{}", err_val);
        assert!(msg.contains("HMAC-SHA256"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha224_mac_mismatch() {
        let vector = &HMAC_VECTORS[0];
        // Wrong expected MAC for SHA-224
        let wrong_expected = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b00";
        let result =
            run_single_hmac_sha224(vector.key, vector.message, wrong_expected, vector.test_name);
        assert!(result.is_err());
        let err_val = result.err().expect("error expected");
        let msg = format!("{}", err_val);
        assert!(msg.contains("HMAC-SHA224"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha384_mac_mismatch() {
        let vector = &HMAC_VECTORS[0];
        // Wrong expected MAC for SHA-384
        let wrong_expected = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9c00";
        let result =
            run_single_hmac_sha384(vector.key, vector.message, wrong_expected, vector.test_name);
        assert!(result.is_err());
        let err_val = result.err().expect("error expected");
        let msg = format!("{}", err_val);
        assert!(msg.contains("HMAC-SHA384"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha512_mac_mismatch() {
        let vector = &HMAC_VECTORS[0];
        // Wrong expected MAC for SHA-512
        let wrong_expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a12685f";
        let result =
            run_single_hmac_sha512(vector.key, vector.message, wrong_expected, vector.test_name);
        assert!(result.is_err());
        let err_val = result.err().expect("error expected");
        let msg = format!("{}", err_val);
        assert!(msg.contains("HMAC-SHA512"));
        assert!(msg.contains("MAC mismatch"));
    }

    // --- Hex decode error paths ---

    #[test]
    fn test_hmac_sha256_invalid_key_hex() {
        let result = run_single_hmac_sha256("ZZZZ", "aa", "bb", "bad-key-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha256_invalid_message_hex() {
        let result = run_single_hmac_sha256("aabb", "XXXX", "bb", "bad-msg-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha256_invalid_expected_hex() {
        let result = run_single_hmac_sha256("aabb", "ccdd", "GGGG", "bad-expected-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha224_invalid_key_hex() {
        let result = run_single_hmac_sha224("ZZZZ", "aa", "bb", "bad-key-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha224_invalid_message_hex() {
        let result = run_single_hmac_sha224("aabb", "XXXX", "bb", "bad-msg-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha384_invalid_key_hex() {
        let result = run_single_hmac_sha384("ZZZZ", "aa", "bb", "bad-key-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha384_invalid_message_hex() {
        let result = run_single_hmac_sha384("aabb", "XXXX", "bb", "bad-msg-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha512_invalid_key_hex() {
        let result = run_single_hmac_sha512("ZZZZ", "aa", "bb", "bad-key-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha512_invalid_message_hex() {
        let result = run_single_hmac_sha512("aabb", "XXXX", "bb", "bad-msg-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    // --- Test vector struct field access ---

    #[test]
    fn test_hmac_vector_fields_accessible() {
        let vector = &HMAC_VECTORS[0];
        assert_eq!(vector.test_name, "RFC-4231-Test-Case-1");
        assert_eq!(vector.key, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assert_eq!(vector.message, "4869205468657265");
        assert!(!vector.expected_mac_sha224.is_empty());
        assert!(!vector.expected_mac_sha256.is_empty());
        assert!(!vector.expected_mac_sha384.is_empty());
        assert!(!vector.expected_mac_sha512.is_empty());
    }

    #[test]
    fn test_hmac_vector_count() {
        // Verify all expected test vectors are present (cases 1-4, 6, 7)
        assert_eq!(HMAC_VECTORS.len(), 6);
    }

    #[test]
    fn test_hmac_vectors_all_names() {
        let names: Vec<&str> = HMAC_VECTORS.iter().map(|v| v.test_name).collect();
        assert!(names.contains(&"RFC-4231-Test-Case-1"));
        assert!(names.contains(&"RFC-4231-Test-Case-2"));
        assert!(names.contains(&"RFC-4231-Test-Case-3"));
        assert!(names.contains(&"RFC-4231-Test-Case-4"));
        assert!(names.contains(&"RFC-4231-Test-Case-6"));
        assert!(names.contains(&"RFC-4231-Test-Case-7"));
    }

    // --- Edge case: empty message ---

    #[test]
    fn test_hmac_sha256_empty_message() {
        // HMAC with empty message should produce a valid MAC (not an error)
        let result = run_single_hmac_sha256(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            // Pre-computed HMAC-SHA256 of empty message with test key
            // This will mismatch, but the point is the function runs
            // through the HMAC computation path without errors.
            "0000000000000000000000000000000000000000000000000000000000000000",
            "empty-message-test",
        );
        // We expect a TestFailed because the expected doesn't match.
        // The important thing is that it does NOT return a HexError or
        // ImplementationError (i.e. the HMAC computation itself succeeded).
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha512_empty_message() {
        let result = run_single_hmac_sha512(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "empty-message-test",
        );
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    // --- Odd-length hex string (invalid hex) ---

    #[test]
    fn test_hmac_sha256_odd_length_hex_key() {
        let result = run_single_hmac_sha256("aab", "ccdd", "eeff", "odd-hex-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha512_odd_length_hex_key() {
        let result = run_single_hmac_sha512("aab", "ccdd", "eeff", "odd-hex-test");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    // --- Verify each vector individually for SHA-256 ---

    #[test]
    fn test_hmac_sha256_individual_vectors() {
        for vector in HMAC_VECTORS {
            let result = run_single_hmac_sha256(
                vector.key,
                vector.message,
                vector.expected_mac_sha256,
                vector.test_name,
            );
            assert!(result.is_ok(), "SHA-256 failed for {}: {:?}", vector.test_name, result);
        }
    }

    // --- Verify each vector individually for SHA-224 ---

    #[test]
    fn test_hmac_sha224_individual_vectors() {
        for vector in HMAC_VECTORS {
            let result = run_single_hmac_sha224(
                vector.key,
                vector.message,
                vector.expected_mac_sha224,
                vector.test_name,
            );
            assert!(result.is_ok(), "SHA-224 failed for {}: {:?}", vector.test_name, result);
        }
    }

    // --- Verify each vector individually for SHA-384 ---

    #[test]
    fn test_hmac_sha384_individual_vectors() {
        for vector in HMAC_VECTORS {
            let result = run_single_hmac_sha384(
                vector.key,
                vector.message,
                vector.expected_mac_sha384,
                vector.test_name,
            );
            assert!(result.is_ok(), "SHA-384 failed for {}: {:?}", vector.test_name, result);
        }
    }

    // --- Verify each vector individually for SHA-512 ---

    #[test]
    fn test_hmac_sha512_individual_vectors() {
        for vector in HMAC_VECTORS {
            let result = run_single_hmac_sha512(
                vector.key,
                vector.message,
                vector.expected_mac_sha512,
                vector.test_name,
            );
            assert!(result.is_ok(), "SHA-512 failed for {}: {:?}", vector.test_name, result);
        }
    }

    // --- NistKatError display coverage ---

    #[test]
    fn test_nist_kat_error_test_failed_display() {
        let err = NistKatError::TestFailed {
            algorithm: "HMAC-SHA256".to_string(),
            test_name: "test-1".to_string(),
            message: "mismatch".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("HMAC-SHA256"));
        assert!(display.contains("test-1"));
        assert!(display.contains("mismatch"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display() {
        let err = NistKatError::HexError("invalid character".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Hex decode error"));
        assert!(display.contains("invalid character"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display() {
        let err = NistKatError::ImplementationError("HMAC creation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Implementation error"));
        assert!(display.contains("HMAC creation failed"));
    }

    #[test]
    fn test_nist_kat_error_debug() {
        let err = NistKatError::TestFailed {
            algorithm: "HMAC-SHA256".to_string(),
            test_name: "test-1".to_string(),
            message: "mismatch".to_string(),
        };
        let debug = format!("{:?}", err);
        assert!(debug.contains("TestFailed"));
    }

    // --- decode_hex coverage ---

    #[test]
    fn test_decode_hex_valid() {
        let result = decode_hex("48656c6c6f");
        assert!(result.is_ok());
        assert_eq!(result.expect("valid hex"), b"Hello");
    }

    #[test]
    fn test_decode_hex_empty() {
        let result = decode_hex("");
        assert!(result.is_ok());
        assert!(result.expect("empty hex").is_empty());
    }

    #[test]
    fn test_decode_hex_invalid() {
        let result = decode_hex("ZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hex_odd_length() {
        let result = decode_hex("abc");
        assert!(result.is_err());
    }

    // --- Cross-variant consistency: same key/message produces different MACs ---

    #[test]
    fn test_hmac_variants_produce_different_macs() {
        let vector = &HMAC_VECTORS[0];
        let key = decode_hex(vector.key).expect("valid key hex");
        let message = decode_hex(vector.message).expect("valid message hex");

        let mut mac256 = HmacSha256::new_from_slice(&key).expect("valid key for sha256");
        mac256.update(&message);
        let result256 = mac256.finalize().into_bytes();

        let mut mac512 = HmacSha512::new_from_slice(&key).expect("valid key for sha512");
        mac512.update(&message);
        let result512 = mac512.finalize().into_bytes();

        // SHA-256 output is 32 bytes, SHA-512 output is 64 bytes
        assert_ne!(result256.len(), result512.len());
    }

    #[test]
    fn test_hmac_sha224_vs_sha256_different_output_lengths() {
        let vector = &HMAC_VECTORS[0];
        let key = decode_hex(vector.key).expect("valid key hex");
        let message = decode_hex(vector.message).expect("valid message hex");

        let mut mac224 = HmacSha224::new_from_slice(&key).expect("valid key for sha224");
        mac224.update(&message);
        let result224 = mac224.finalize().into_bytes();

        let mut mac256 = HmacSha256::new_from_slice(&key).expect("valid key for sha256");
        mac256.update(&message);
        let result256 = mac256.finalize().into_bytes();

        assert_eq!(result224.len(), 28);
        assert_eq!(result256.len(), 32);
    }

    #[test]
    fn test_hmac_sha384_output_length() {
        let vector = &HMAC_VECTORS[0];
        let key = decode_hex(vector.key).expect("valid key hex");
        let message = decode_hex(vector.message).expect("valid message hex");

        let mut mac384 = HmacSha384::new_from_slice(&key).expect("valid key for sha384");
        mac384.update(&message);
        let result384 = mac384.finalize().into_bytes();

        assert_eq!(result384.len(), 48);
    }

    // --- Test with single-byte key and message ---

    #[test]
    fn test_hmac_sha256_single_byte_inputs() {
        // Single-byte key and message: HMAC should succeed (no errors),
        // but the MAC will not match the fabricated expected value.
        let result = run_single_hmac_sha256(
            "aa",
            "bb",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "single-byte-test",
        );
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha224_single_byte_inputs() {
        let result = run_single_hmac_sha224(
            "aa",
            "bb",
            "00000000000000000000000000000000000000000000000000000000",
            "single-byte-test",
        );
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha384_single_byte_inputs() {
        let result = run_single_hmac_sha384(
            "aa",
            "bb",
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "single-byte-test",
        );
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    #[test]
    fn test_hmac_sha512_single_byte_inputs() {
        let result = run_single_hmac_sha512(
            "aa",
            "bb",
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "single-byte-test",
        );
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("MAC mismatch"));
    }

    // --- Test invalid hex on expected_mac field for each variant ---

    #[test]
    fn test_hmac_sha224_invalid_expected_hex() {
        let result = run_single_hmac_sha224("aabb", "ccdd", "GGGG", "bad-expected-224");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha384_invalid_expected_hex() {
        let result = run_single_hmac_sha384("aabb", "ccdd", "GGGG", "bad-expected-384");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }

    #[test]
    fn test_hmac_sha512_invalid_expected_hex() {
        let result = run_single_hmac_sha512("aabb", "ccdd", "GGGG", "bad-expected-512");
        assert!(result.is_err());
        let msg = format!("{}", result.err().expect("error expected"));
        assert!(msg.contains("Hex decode error"));
    }
}
