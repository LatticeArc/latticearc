#![deny(unsafe_code)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

//! Comprehensive Tests for HMAC Known Answer Tests
//!
//! This module provides extensive test coverage for the HMAC KAT implementation
//! in `arc-validation/src/nist_kat/hmac_kat.rs`.
//!
//! ## Test Categories
//! 1. All HMAC variant functions (HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512)
//! 2. Test vector validation
//! 3. Error handling paths
//! 4. Known answer test verification
//! 5. Edge cases and boundary conditions

use arc_validation::nist_kat::hmac_kat::{
    HMAC_VECTORS, run_hmac_sha224_kat, run_hmac_sha256_kat, run_hmac_sha384_kat,
    run_hmac_sha512_kat,
};
use arc_validation::nist_kat::{NistKatError, decode_hex};
use hmac::{Hmac, Mac};
use sha2::{Sha224, Sha256, Sha384, Sha512};

type HmacSha224 = Hmac<Sha224>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

// =============================================================================
// HMAC-SHA256 Tests
// =============================================================================

mod hmac_sha256_tests {
    use super::*;

    #[test]
    fn test_run_hmac_sha256_kat_passes() {
        let result = run_hmac_sha256_kat();
        assert!(result.is_ok(), "HMAC-SHA256 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_hmac_sha256_all_vectors_individually() {
        for vector in HMAC_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_mac_sha256).unwrap();

            let mut mac =
                HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 can take key of any size");
            mac.update(&message);
            let result = mac.finalize();
            let code_bytes = result.into_bytes();

            assert_eq!(
                code_bytes.as_slice(),
                expected.as_slice(),
                "HMAC-SHA256 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_hmac_sha256_output_length() {
        // HMAC-SHA256 should always produce 32 bytes (256 bits)
        let key = b"test key";
        let message = b"test message";

        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 output should be 32 bytes");
    }

    #[test]
    fn test_hmac_sha256_rfc_4231_test_case_1() {
        // RFC 4231 Test Case 1: 20-byte key "Hi There"
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap(); // "Hi There"
        let expected =
            decode_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha256_rfc_4231_test_case_2() {
        // RFC 4231 Test Case 2: Short key "Jefe" with "what do ya want for nothing?"
        let key = decode_hex("4a656665").unwrap(); // "Jefe"
        let message =
            decode_hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap();
        let expected =
            decode_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha256_incremental_update() {
        // Test that incremental updates work correctly
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap();

        let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
        mac1.update(&message);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
        // Update byte by byte
        for byte in &message {
            mac2.update(&[*byte]);
        }
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(
            result1.as_slice(),
            result2.as_slice(),
            "Incremental update should produce same result"
        );
    }

    #[test]
    fn test_hmac_sha256_empty_message() {
        // Test with empty message
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message: &[u8] = &[];

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        // Output should still be 32 bytes
        assert_eq!(result.into_bytes().len(), 32);
    }

    #[test]
    fn test_hmac_sha256_long_key() {
        // RFC 4231 Test Case 6: 131-byte key (longer than block size)
        let key = decode_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaa",
        )
        .unwrap();
        let message = decode_hex(
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
        )
        .unwrap();
        let expected =
            decode_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54").unwrap();

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }
}

// =============================================================================
// HMAC-SHA224 Tests
// =============================================================================

mod hmac_sha224_tests {
    use super::*;

    #[test]
    fn test_run_hmac_sha224_kat_passes() {
        let result = run_hmac_sha224_kat();
        assert!(result.is_ok(), "HMAC-SHA224 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_hmac_sha224_all_vectors_individually() {
        for vector in HMAC_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_mac_sha224).unwrap();

            let mut mac =
                HmacSha224::new_from_slice(&key).expect("HMAC-SHA224 can take key of any size");
            mac.update(&message);
            let result = mac.finalize();
            let code_bytes = result.into_bytes();

            assert_eq!(
                code_bytes.as_slice(),
                expected.as_slice(),
                "HMAC-SHA224 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_hmac_sha224_output_length() {
        // HMAC-SHA224 should always produce 28 bytes (224 bits)
        let key = b"test key";
        let message = b"test message";

        let mut mac = HmacSha224::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 28, "HMAC-SHA224 output should be 28 bytes");
    }

    #[test]
    fn test_hmac_sha224_rfc_4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap();
        let expected =
            decode_hex("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22").unwrap();

        let mut mac = HmacSha224::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha224_empty_message() {
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message: &[u8] = &[];

        let mut mac = HmacSha224::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        // Output should still be 28 bytes
        assert_eq!(result.into_bytes().len(), 28);
    }
}

// =============================================================================
// HMAC-SHA384 Tests
// =============================================================================

mod hmac_sha384_tests {
    use super::*;

    #[test]
    fn test_run_hmac_sha384_kat_passes() {
        let result = run_hmac_sha384_kat();
        assert!(result.is_ok(), "HMAC-SHA384 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_hmac_sha384_all_vectors_individually() {
        for vector in HMAC_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_mac_sha384).unwrap();

            let mut mac =
                HmacSha384::new_from_slice(&key).expect("HMAC-SHA384 can take key of any size");
            mac.update(&message);
            let result = mac.finalize();
            let code_bytes = result.into_bytes();

            assert_eq!(
                code_bytes.as_slice(),
                expected.as_slice(),
                "HMAC-SHA384 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_hmac_sha384_output_length() {
        // HMAC-SHA384 should always produce 48 bytes (384 bits)
        let key = b"test key";
        let message = b"test message";

        let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 48, "HMAC-SHA384 output should be 48 bytes");
    }

    #[test]
    fn test_hmac_sha384_rfc_4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap();
        let expected = decode_hex(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        )
        .unwrap();

        let mut mac = HmacSha384::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha384_empty_message() {
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message: &[u8] = &[];

        let mut mac = HmacSha384::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        // Output should still be 48 bytes
        assert_eq!(result.into_bytes().len(), 48);
    }
}

// =============================================================================
// HMAC-SHA512 Tests
// =============================================================================

mod hmac_sha512_tests {
    use super::*;

    #[test]
    fn test_run_hmac_sha512_kat_passes() {
        let result = run_hmac_sha512_kat();
        assert!(result.is_ok(), "HMAC-SHA512 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_hmac_sha512_all_vectors_individually() {
        for vector in HMAC_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_mac_sha512).unwrap();

            let mut mac =
                HmacSha512::new_from_slice(&key).expect("HMAC-SHA512 can take key of any size");
            mac.update(&message);
            let result = mac.finalize();
            let code_bytes = result.into_bytes();

            assert_eq!(
                code_bytes.as_slice(),
                expected.as_slice(),
                "HMAC-SHA512 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_hmac_sha512_output_length() {
        // HMAC-SHA512 should always produce 64 bytes (512 bits)
        let key = b"test key";
        let message = b"test message";

        let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 64, "HMAC-SHA512 output should be 64 bytes");
    }

    #[test]
    fn test_hmac_sha512_rfc_4231_test_case_1() {
        // RFC 4231 Test Case 1
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap();
        let expected = decode_hex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        )
        .unwrap();

        let mut mac = HmacSha512::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hmac_sha512_empty_message() {
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message: &[u8] = &[];

        let mut mac = HmacSha512::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        // Output should still be 64 bytes
        assert_eq!(result.into_bytes().len(), 64);
    }

    #[test]
    fn test_hmac_sha512_long_key_and_message() {
        // RFC 4231 Test Case 7: 131-byte key with longer message
        let key = decode_hex(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             aaaaaa",
        )
        .unwrap();
        let message = decode_hex(
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
        )
        .unwrap();
        let expected = decode_hex(
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        )
        .unwrap();

        let mut mac = HmacSha512::new_from_slice(&key).unwrap();
        mac.update(&message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
    }
}

// =============================================================================
// Test Vector Structure Tests
// =============================================================================

mod test_vector_structure_tests {
    use super::*;

    #[test]
    fn test_hmac_vector_count() {
        // RFC 4231 has 6 test vectors (Test Case 5 - truncation is often omitted)
        assert_eq!(
            HMAC_VECTORS.len(),
            6,
            "Expected 6 HMAC test vectors (RFC 4231 Test Cases 1-4, 6-7)"
        );
    }

    #[test]
    fn test_hmac_vector_fields_not_empty() {
        for vector in HMAC_VECTORS {
            assert!(!vector.test_name.is_empty(), "Test name should not be empty");
            assert!(!vector.key.is_empty(), "Key should not be empty");
            assert!(!vector.message.is_empty(), "Message should not be empty");
            assert!(
                !vector.expected_mac_sha224.is_empty(),
                "Expected MAC SHA-224 should not be empty"
            );
            assert!(
                !vector.expected_mac_sha256.is_empty(),
                "Expected MAC SHA-256 should not be empty"
            );
            assert!(
                !vector.expected_mac_sha384.is_empty(),
                "Expected MAC SHA-384 should not be empty"
            );
            assert!(
                !vector.expected_mac_sha512.is_empty(),
                "Expected MAC SHA-512 should not be empty"
            );
        }
    }

    #[test]
    fn test_hmac_vector_names_unique() {
        let names: Vec<&str> = HMAC_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_expected_mac_lengths() {
        for vector in HMAC_VECTORS {
            // SHA-224: 224/4 = 56 hex chars
            assert_eq!(
                vector.expected_mac_sha224.len(),
                56,
                "HMAC-SHA224 for '{}' should be 56 hex chars",
                vector.test_name
            );

            // SHA-256: 256/4 = 64 hex chars
            assert_eq!(
                vector.expected_mac_sha256.len(),
                64,
                "HMAC-SHA256 for '{}' should be 64 hex chars",
                vector.test_name
            );

            // SHA-384: 384/4 = 96 hex chars
            assert_eq!(
                vector.expected_mac_sha384.len(),
                96,
                "HMAC-SHA384 for '{}' should be 96 hex chars",
                vector.test_name
            );

            // SHA-512: 512/4 = 128 hex chars
            assert_eq!(
                vector.expected_mac_sha512.len(),
                128,
                "HMAC-SHA512 for '{}' should be 128 hex chars",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_all_hex_values_valid() {
        for vector in HMAC_VECTORS {
            assert!(
                decode_hex(vector.key).is_ok(),
                "Key for '{}' is invalid hex",
                vector.test_name
            );
            assert!(
                decode_hex(vector.message).is_ok(),
                "Message for '{}' is invalid hex",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_mac_sha224).is_ok(),
                "Expected MAC SHA-224 for '{}' is invalid hex",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_mac_sha256).is_ok(),
                "Expected MAC SHA-256 for '{}' is invalid hex",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_mac_sha384).is_ok(),
                "Expected MAC SHA-384 for '{}' is invalid hex",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_mac_sha512).is_ok(),
                "Expected MAC SHA-512 for '{}' is invalid hex",
                vector.test_name
            );
        }
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_nist_kat_error_test_failed_display() {
        let error = NistKatError::TestFailed {
            algorithm: "HMAC-SHA256".to_string(),
            test_name: "RFC-4231-Test-Case-1".to_string(),
            message: "MAC mismatch: got abc, expected def".to_string(),
        };
        let display_str = format!("{}", error);
        assert!(display_str.contains("HMAC-SHA256"));
        assert!(display_str.contains("RFC-4231-Test-Case-1"));
        assert!(display_str.contains("MAC mismatch"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display() {
        let error = NistKatError::HexError("Invalid character 'g' at position 0".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Hex"));
        assert!(display_str.contains("Invalid character"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display() {
        let error = NistKatError::ImplementationError("HMAC creation failed".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Implementation error"));
        assert!(display_str.contains("HMAC creation failed"));
    }

    #[test]
    fn test_decode_hex_invalid_returns_error() {
        let result = decode_hex("GHIJ");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    #[test]
    fn test_decode_hex_odd_length_returns_error() {
        let result = decode_hex("abc");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error for odd length: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }
}

// =============================================================================
// Cross-Algorithm Consistency Tests
// =============================================================================

mod cross_algorithm_tests {
    use super::*;

    #[test]
    fn test_same_key_message_different_algorithms() {
        // The same key and message should produce different MACs for different algorithms
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message = decode_hex("4869205468657265").unwrap();

        let mut mac224 = HmacSha224::new_from_slice(&key).unwrap();
        mac224.update(&message);
        let result224 = mac224.finalize().into_bytes();

        let mut mac256 = HmacSha256::new_from_slice(&key).unwrap();
        mac256.update(&message);
        let result256 = mac256.finalize().into_bytes();

        let mut mac384 = HmacSha384::new_from_slice(&key).unwrap();
        mac384.update(&message);
        let result384 = mac384.finalize().into_bytes();

        let mut mac512 = HmacSha512::new_from_slice(&key).unwrap();
        mac512.update(&message);
        let result512 = mac512.finalize().into_bytes();

        // All MACs should be different from each other
        assert_ne!(result224.as_slice(), &result256.as_slice()[..28]);
        assert_ne!(result384.as_slice(), &result512.as_slice()[..48]);
        assert_ne!(result256.as_slice(), &result512.as_slice()[..32]);
    }

    #[test]
    fn test_all_hmac_variants_run_successfully() {
        // Run all KAT tests and ensure they all pass
        assert!(run_hmac_sha224_kat().is_ok(), "HMAC-SHA224 KAT failed");
        assert!(run_hmac_sha256_kat().is_ok(), "HMAC-SHA256 KAT failed");
        assert!(run_hmac_sha384_kat().is_ok(), "HMAC-SHA384 KAT failed");
        assert!(run_hmac_sha512_kat().is_ok(), "HMAC-SHA512 KAT failed");
    }
}

// =============================================================================
// Determinism Tests
// =============================================================================

mod determinism_tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_deterministic() {
        // Same input should always produce same output
        let key = decode_hex("deadbeefcafe").unwrap();
        let message = decode_hex("0123456789abcdef").unwrap();

        let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
        mac1.update(&message);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
        mac2.update(&message);
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(result1.as_slice(), result2.as_slice(), "HMAC-SHA256 should be deterministic");
    }

    #[test]
    fn test_hmac_sha512_deterministic() {
        let key = decode_hex("cafebabe").unwrap();
        let message = decode_hex("fedcba9876543210").unwrap();

        let mut mac1 = HmacSha512::new_from_slice(&key).unwrap();
        mac1.update(&message);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha512::new_from_slice(&key).unwrap();
        mac2.update(&message);
        let result2 = mac2.finalize().into_bytes();

        assert_eq!(result1.as_slice(), result2.as_slice(), "HMAC-SHA512 should be deterministic");
    }

    #[test]
    fn test_multiple_kat_runs_consistent() {
        // Running KAT multiple times should always succeed
        for _ in 0..5 {
            assert!(run_hmac_sha224_kat().is_ok());
            assert!(run_hmac_sha256_kat().is_ok());
            assert!(run_hmac_sha384_kat().is_ok());
            assert!(run_hmac_sha512_kat().is_ok());
        }
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_single_byte_key() {
        // Test with minimum size key (1 byte)
        let key = vec![0x42_u8];
        let message = b"test message";

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 should produce 32 bytes");
    }

    #[test]
    fn test_large_key() {
        // Test with a very large key (256 bytes)
        let key = vec![0xaa_u8; 256];
        let message = b"test message";

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 should produce 32 bytes");
    }

    #[test]
    fn test_large_message() {
        // Test with a large message (1 MB)
        let key = b"test key";
        let message = vec![0x61_u8; 1024 * 1024]; // 1 MB of 'a'

        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(&message);
        let result = mac.finalize();
        let result_bytes = result.into_bytes();

        assert_eq!(result_bytes.len(), 32, "HMAC-SHA256 should produce 32 bytes for large input");
        // Verify the MAC is not all zeros (basic sanity check)
        assert!(result_bytes.iter().any(|&b| b != 0), "MAC should not be all zeros");
    }

    #[test]
    fn test_all_zeros_key() {
        let key = vec![0x00_u8; 32];
        let message = b"test message";

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32);
    }

    #[test]
    fn test_all_ones_key() {
        let key = vec![0xFF_u8; 32];
        let message = b"test message";

        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(message);
        let result = mac.finalize();

        assert_eq!(result.into_bytes().len(), 32);
    }

    #[test]
    fn test_block_boundary_key_sizes() {
        // SHA-256 has a block size of 64 bytes
        // Test keys at block boundaries
        for size in [63_usize, 64, 65, 127, 128, 129] {
            let key = vec![0x61_u8; size];
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(
                result.into_bytes().len(),
                32,
                "HMAC-SHA256 should produce 32 bytes for {} byte key",
                size
            );
        }
    }

    #[test]
    fn test_block_boundary_message_sizes() {
        // Test messages at block boundaries
        for size in [63_usize, 64, 65, 127, 128, 129] {
            let key = b"test key";
            let message = vec![0x61_u8; size];

            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(&message);
            let result = mac.finalize();

            assert_eq!(
                result.into_bytes().len(),
                32,
                "HMAC-SHA256 should produce 32 bytes for {} byte message",
                size
            );
        }
    }

    #[test]
    fn test_sha512_block_boundary_key_sizes() {
        // SHA-512 has a block size of 128 bytes
        for size in [127_usize, 128, 129, 255, 256, 257] {
            let key = vec![0x61_u8; size];
            let message = b"test message";

            let mut mac = HmacSha512::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(
                result.into_bytes().len(),
                64,
                "HMAC-SHA512 should produce 64 bytes for {} byte key",
                size
            );
        }
    }
}

// =============================================================================
// Integration Tests with KatRunner
// =============================================================================

mod integration_tests {
    use super::*;
    use arc_validation::nist_kat::{KatRunner, KatSummary};

    #[test]
    fn test_hmac_kat_runner_integration() {
        let mut runner = KatRunner::new();

        runner.run_test("HMAC-SHA224", "HMAC", || run_hmac_sha224_kat());
        runner.run_test("HMAC-SHA256", "HMAC", || run_hmac_sha256_kat());
        runner.run_test("HMAC-SHA384", "HMAC", || run_hmac_sha384_kat());
        runner.run_test("HMAC-SHA512", "HMAC", || run_hmac_sha512_kat());

        let summary: KatSummary = runner.finish();

        assert!(
            summary.all_passed(),
            "All HMAC KAT tests should pass. Failed: {}/{}",
            summary.failed,
            summary.total
        );
        assert_eq!(summary.total, 4, "Should have run 4 HMAC variant tests");
    }

    #[test]
    fn test_comprehensive_hmac_validation() {
        println!("\n========================================");
        println!("Comprehensive HMAC Validation Suite");
        println!("========================================\n");

        let mut total_vectors = 0;

        for vector in HMAC_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let message = decode_hex(vector.message).unwrap();

            // HMAC-SHA224
            let expected_224 = decode_hex(vector.expected_mac_sha224).unwrap();
            let mut mac224 = HmacSha224::new_from_slice(&key).unwrap();
            mac224.update(&message);
            let result224 = mac224.finalize().into_bytes();
            assert_eq!(result224.as_slice(), expected_224.as_slice());
            println!("  [PASS] {} - HMAC-SHA224", vector.test_name);
            total_vectors += 1;

            // HMAC-SHA256
            let expected_256 = decode_hex(vector.expected_mac_sha256).unwrap();
            let mut mac256 = HmacSha256::new_from_slice(&key).unwrap();
            mac256.update(&message);
            let result256 = mac256.finalize().into_bytes();
            assert_eq!(result256.as_slice(), expected_256.as_slice());
            println!("  [PASS] {} - HMAC-SHA256", vector.test_name);
            total_vectors += 1;

            // HMAC-SHA384
            let expected_384 = decode_hex(vector.expected_mac_sha384).unwrap();
            let mut mac384 = HmacSha384::new_from_slice(&key).unwrap();
            mac384.update(&message);
            let result384 = mac384.finalize().into_bytes();
            assert_eq!(result384.as_slice(), expected_384.as_slice());
            println!("  [PASS] {} - HMAC-SHA384", vector.test_name);
            total_vectors += 1;

            // HMAC-SHA512
            let expected_512 = decode_hex(vector.expected_mac_sha512).unwrap();
            let mut mac512 = HmacSha512::new_from_slice(&key).unwrap();
            mac512.update(&message);
            let result512 = mac512.finalize().into_bytes();
            assert_eq!(result512.as_slice(), expected_512.as_slice());
            println!("  [PASS] {} - HMAC-SHA512", vector.test_name);
            total_vectors += 1;
        }

        println!("\n========================================");
        println!("Total Vectors Validated: {} (6 test cases x 4 algorithms)", total_vectors);
        println!("========================================\n");

        assert_eq!(total_vectors, 24, "Should validate 24 vectors (6 x 4)");
    }
}

// =============================================================================
// RFC 4231 Specific Test Cases
// =============================================================================

mod rfc_4231_tests {
    use super::*;

    #[test]
    fn test_rfc_4231_test_case_3_50_bytes_dd() {
        // Test Case 3: 20-byte key (all 0xaa) with 50 bytes of 0xdd
        let key = decode_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let message = decode_hex(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();

        // Test SHA-256
        let expected_256 =
            decode_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").unwrap();
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected_256.as_slice());
    }

    #[test]
    fn test_rfc_4231_test_case_4_incremental_key() {
        // Test Case 4: 25-byte key (incremental 0x01..0x19) with 50 bytes of 0xcd
        let key = decode_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let message = decode_hex(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();

        // Test SHA-256
        let expected_256 =
            decode_hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b").unwrap();
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&message);
        assert_eq!(mac.finalize().into_bytes().as_slice(), expected_256.as_slice());
    }

    #[test]
    fn test_rfc_4231_verifies_different_key_produces_different_mac() {
        // Verify that changing the key produces a different MAC
        let key1 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let key2 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c").unwrap(); // Last byte changed
        let message = decode_hex("4869205468657265").unwrap();

        let mut mac1 = HmacSha256::new_from_slice(&key1).unwrap();
        mac1.update(&message);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha256::new_from_slice(&key2).unwrap();
        mac2.update(&message);
        let result2 = mac2.finalize().into_bytes();

        assert_ne!(
            result1.as_slice(),
            result2.as_slice(),
            "Different keys should produce different MACs"
        );
    }

    #[test]
    fn test_rfc_4231_verifies_different_message_produces_different_mac() {
        // Verify that changing the message produces a different MAC
        let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let message1 = decode_hex("4869205468657265").unwrap(); // "Hi There"
        let message2 = decode_hex("4869205468657265aa").unwrap(); // "Hi There" + extra byte

        let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
        mac1.update(&message1);
        let result1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
        mac2.update(&message2);
        let result2 = mac2.finalize().into_bytes();

        assert_ne!(
            result1.as_slice(),
            result2.as_slice(),
            "Different messages should produce different MACs"
        );
    }
}

// =============================================================================
// HmacTestVector Struct Field Access Tests
// =============================================================================

mod hmac_test_vector_tests {
    use super::*;
    use arc_validation::nist_kat::hmac_kat::HmacTestVector;

    #[test]
    fn test_hmac_test_vector_struct_fields_accessible() {
        // Access each field to ensure they're public
        let vector = &HMAC_VECTORS[0];
        let _test_name: &str = vector.test_name;
        let _key: &str = vector.key;
        let _message: &str = vector.message;
        let _expected_mac_sha224: &str = vector.expected_mac_sha224;
        let _expected_mac_sha256: &str = vector.expected_mac_sha256;
        let _expected_mac_sha384: &str = vector.expected_mac_sha384;
        let _expected_mac_sha512: &str = vector.expected_mac_sha512;
    }

    #[test]
    fn test_hmac_test_vector_can_be_constructed() {
        // Verify the struct can be constructed (ensuring it's public)
        let _vector = HmacTestVector {
            test_name: "Test-Custom",
            key: "0102030405",
            message: "deadbeef",
            expected_mac_sha224: "0".repeat(56).leak(),
            expected_mac_sha256: "0".repeat(64).leak(),
            expected_mac_sha384: "0".repeat(96).leak(),
            expected_mac_sha512: "0".repeat(128).leak(),
        };
    }

    #[test]
    fn test_first_vector_is_rfc_4231_test_case_1() {
        let vector = &HMAC_VECTORS[0];
        assert_eq!(vector.test_name, "RFC-4231-Test-Case-1");
        assert_eq!(vector.key, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        assert_eq!(vector.message, "4869205468657265");
    }

    #[test]
    fn test_second_vector_is_rfc_4231_test_case_2() {
        let vector = &HMAC_VECTORS[1];
        assert_eq!(vector.test_name, "RFC-4231-Test-Case-2");
        assert_eq!(vector.key, "4a656665"); // "Jefe"
    }
}
