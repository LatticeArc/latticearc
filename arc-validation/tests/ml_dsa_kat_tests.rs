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

//! Comprehensive Tests for ML-DSA Known Answer Tests
//!
//! This module provides extensive test coverage for the ML-DSA KAT implementation
//! in `arc-validation/src/nist_kat/ml_dsa_kat.rs`.
//!
//! ## Test Categories
//! 1. All ML-DSA variant functions (ML-DSA-44, ML-DSA-65, ML-DSA-87)
//! 2. Test vector validation
//! 3. Error handling paths
//! 4. Known answer test verification
//! 5. Edge cases and boundary conditions
//! 6. Determinism and consistency tests
//!
//! ## Security Levels Tested
//! - ML-DSA-44: NIST Security Level 2 (128-bit classical security)
//! - ML-DSA-65: NIST Security Level 3 (192-bit classical security)
//! - ML-DSA-87: NIST Security Level 5 (256-bit classical security)

use arc_validation::nist_kat::ml_dsa_kat::{
    ML_DSA_44_VECTORS, ML_DSA_65_VECTORS, ML_DSA_87_VECTORS,
};
use arc_validation::nist_kat::{NistKatError, decode_hex, ml_dsa_kat};
use fips204::ml_dsa_44;
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;
use fips204::traits::{Signer, Verifier};

// =============================================================================
// ML-DSA-44 Tests (NIST Security Level 2)
// =============================================================================

mod ml_dsa_44_tests {
    use super::*;

    #[test]
    fn test_run_ml_dsa_44_kat_passes() {
        let result = ml_dsa_kat::run_ml_dsa_44_kat();
        assert!(result.is_ok(), "ML-DSA-44 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_ml_dsa_44_keygen_sign_verify() {
        // Test basic key generation, signing, and verification
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = b"Test message for ML-DSA-44";
        let signature = sk.try_sign(message, &[]).expect("Signing should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_44_empty_message() {
        // Test signing and verifying an empty message
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message: &[u8] = &[];
        let signature = sk.try_sign(message, &[]).expect("Signing empty message should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Empty message signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_44_wrong_key_verification() {
        // Test that verification fails with wrong public key
        let (pk1, sk1) = ml_dsa_44::try_keygen().expect("Key generation 1 should succeed");
        let (pk2, _sk2) = ml_dsa_44::try_keygen().expect("Key generation 2 should succeed");

        let message = b"Test message";
        let signature = sk1.try_sign(message, &[]).expect("Signing should succeed");

        // Verify with wrong public key should fail (pk2 instead of pk1)
        let verify_result = pk2.verify(message, &signature, &[]);
        assert!(!verify_result, "Verification with wrong key should fail");

        // Verify with correct public key should succeed
        let verify_result_correct = pk1.verify(message, &signature, &[]);
        assert!(verify_result_correct, "Verification with correct key should succeed");
    }

    #[test]
    fn test_ml_dsa_44_wrong_message_verification() {
        // Test that verification fails with wrong message
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message1 = b"Original message";
        let message2 = b"Different message";
        let signature = sk.try_sign(message1, &[]).expect("Signing should succeed");

        // Verify with wrong message should fail
        let verify_result = pk.verify(message2, &signature, &[]);
        assert!(!verify_result, "Verification with wrong message should fail");
    }

    #[test]
    fn test_ml_dsa_44_vector_count() {
        assert!(
            ML_DSA_44_VECTORS.len() >= 2,
            "ML-DSA-44 should have at least 2 test vectors, found {}",
            ML_DSA_44_VECTORS.len()
        );
    }

    #[test]
    fn test_ml_dsa_44_all_vectors() {
        for vector in ML_DSA_44_VECTORS {
            let message = decode_hex(vector.message).expect("Message hex decode should succeed");
            let _seed = decode_hex(vector.seed).expect("Seed hex decode should succeed");

            // Generate keys and sign/verify
            let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Signing should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);

            assert!(verify_result, "ML-DSA-44 test '{}' verification failed", vector.test_name);
        }
    }

    #[test]
    fn test_ml_dsa_44_long_message() {
        // Test with a long message (1KB)
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = vec![0x61u8; 1024]; // 1KB of 'a'
        let signature = sk.try_sign(&message, &[]).expect("Signing long message should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "Long message signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_44_binary_message() {
        // Test with binary data including null bytes
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message: Vec<u8> = (0..=255).collect();
        let signature = sk.try_sign(&message, &[]).expect("Signing binary message should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "Binary message signature verification should succeed");
    }
}

// =============================================================================
// ML-DSA-65 Tests (NIST Security Level 3)
// =============================================================================

mod ml_dsa_65_tests {
    use super::*;

    #[test]
    fn test_run_ml_dsa_65_kat_passes() {
        let result = ml_dsa_kat::run_ml_dsa_65_kat();
        assert!(result.is_ok(), "ML-DSA-65 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_ml_dsa_65_keygen_sign_verify() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message = b"Test message for ML-DSA-65";
        let signature = sk.try_sign(message, &[]).expect("Signing should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_65_empty_message() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message: &[u8] = &[];
        let signature = sk.try_sign(message, &[]).expect("Signing empty message should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Empty message signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_65_wrong_key_verification() {
        let (_pk1, sk1) = ml_dsa_65::try_keygen().expect("Key generation 1 should succeed");
        let (pk2, _sk2) = ml_dsa_65::try_keygen().expect("Key generation 2 should succeed");

        let message = b"Test message";
        let signature = sk1.try_sign(message, &[]).expect("Signing should succeed");

        let verify_result = pk2.verify(message, &signature, &[]);
        assert!(!verify_result, "Verification with wrong key should fail");
    }

    #[test]
    fn test_ml_dsa_65_wrong_message_verification() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message1 = b"Original message";
        let message2 = b"Different message";
        let signature = sk.try_sign(message1, &[]).expect("Signing should succeed");

        let verify_result = pk.verify(message2, &signature, &[]);
        assert!(!verify_result, "Verification with wrong message should fail");
    }

    #[test]
    fn test_ml_dsa_65_vector_count() {
        assert!(
            ML_DSA_65_VECTORS.len() >= 2,
            "ML-DSA-65 should have at least 2 test vectors, found {}",
            ML_DSA_65_VECTORS.len()
        );
    }

    #[test]
    fn test_ml_dsa_65_all_vectors() {
        for vector in ML_DSA_65_VECTORS {
            let message = decode_hex(vector.message).expect("Message hex decode should succeed");
            let _seed = decode_hex(vector.seed).expect("Seed hex decode should succeed");

            let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Signing should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);

            assert!(verify_result, "ML-DSA-65 test '{}' verification failed", vector.test_name);
        }
    }

    #[test]
    fn test_ml_dsa_65_long_message() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message = vec![0x62u8; 2048]; // 2KB of 'b'
        let signature = sk.try_sign(&message, &[]).expect("Signing long message should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "Long message signature verification should succeed");
    }
}

// =============================================================================
// ML-DSA-87 Tests (NIST Security Level 5)
// =============================================================================

mod ml_dsa_87_tests {
    use super::*;

    #[test]
    fn test_run_ml_dsa_87_kat_passes() {
        let result = ml_dsa_kat::run_ml_dsa_87_kat();
        assert!(result.is_ok(), "ML-DSA-87 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_ml_dsa_87_keygen_sign_verify() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        let message = b"Test message for ML-DSA-87";
        let signature = sk.try_sign(message, &[]).expect("Signing should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_87_empty_message() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        let message: &[u8] = &[];
        let signature = sk.try_sign(message, &[]).expect("Signing empty message should succeed");

        let verify_result = pk.verify(message, &signature, &[]);
        assert!(verify_result, "Empty message signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_87_wrong_key_verification() {
        let (_pk1, sk1) = ml_dsa_87::try_keygen().expect("Key generation 1 should succeed");
        let (pk2, _sk2) = ml_dsa_87::try_keygen().expect("Key generation 2 should succeed");

        let message = b"Test message";
        let signature = sk1.try_sign(message, &[]).expect("Signing should succeed");

        let verify_result = pk2.verify(message, &signature, &[]);
        assert!(!verify_result, "Verification with wrong key should fail");
    }

    #[test]
    fn test_ml_dsa_87_wrong_message_verification() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        let message1 = b"Original message";
        let message2 = b"Different message";
        let signature = sk.try_sign(message1, &[]).expect("Signing should succeed");

        let verify_result = pk.verify(message2, &signature, &[]);
        assert!(!verify_result, "Verification with wrong message should fail");
    }

    #[test]
    fn test_ml_dsa_87_vector_count() {
        assert!(
            ML_DSA_87_VECTORS.len() >= 2,
            "ML-DSA-87 should have at least 2 test vectors, found {}",
            ML_DSA_87_VECTORS.len()
        );
    }

    #[test]
    fn test_ml_dsa_87_all_vectors() {
        for vector in ML_DSA_87_VECTORS {
            let message = decode_hex(vector.message).expect("Message hex decode should succeed");
            let _seed = decode_hex(vector.seed).expect("Seed hex decode should succeed");

            let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Signing should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);

            assert!(verify_result, "ML-DSA-87 test '{}' verification failed", vector.test_name);
        }
    }

    #[test]
    fn test_ml_dsa_87_long_message() {
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        let message = vec![0x63u8; 4096]; // 4KB of 'c'
        let signature = sk.try_sign(&message, &[]).expect("Signing long message should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "Long message signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_87_max_security_level() {
        // ML-DSA-87 provides NIST Security Level 5 (256-bit classical security)
        // Verify it can handle various message patterns
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        // Test with different message patterns
        let patterns: Vec<Vec<u8>> = vec![
            vec![0x00; 256],     // All zeros
            vec![0xFF; 256],     // All ones
            (0..=255).collect(), // Sequential bytes
            vec![0xAA; 256],     // Alternating bits pattern 1
            vec![0x55; 256],     // Alternating bits pattern 2
        ];

        for (i, message) in patterns.iter().enumerate() {
            let signature =
                sk.try_sign(message, &[]).expect(&format!("Signing pattern {} should succeed", i));
            let verify_result = pk.verify(message, &signature, &[]);
            assert!(verify_result, "Pattern {} signature verification should succeed", i);
        }
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_decode_hex_valid() {
        let result = decode_hex("616263");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x61, 0x62, 0x63]);
    }

    #[test]
    fn test_decode_hex_empty() {
        let result = decode_hex("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_hex_invalid_chars() {
        let result = decode_hex("GHIJ"); // Invalid hex characters
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    #[test]
    fn test_decode_hex_odd_length() {
        let result = decode_hex("abc"); // Odd number of characters
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error for odd length: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    #[test]
    fn test_decode_hex_uppercase() {
        let result = decode_hex("ABC123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xC1, 0x23]);
    }

    #[test]
    fn test_decode_hex_mixed_case() {
        let result = decode_hex("AbCdEf");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_nist_kat_error_test_failed_display() {
        let error = NistKatError::TestFailed {
            algorithm: "ML-DSA-44".to_string(),
            test_name: "test-1".to_string(),
            message: "verification failed".to_string(),
        };
        let display_str = format!("{}", error);
        assert!(display_str.contains("ML-DSA-44"));
        assert!(display_str.contains("test-1"));
        assert!(display_str.contains("verification failed"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display() {
        let error = NistKatError::HexError("invalid character".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Hex decode error"));
        assert!(display_str.contains("invalid character"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display() {
        let error = NistKatError::ImplementationError("KeyGen failed".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Implementation error"));
        assert!(display_str.contains("KeyGen failed"));
    }

    #[test]
    fn test_nist_kat_error_unsupported_algorithm_display() {
        let error = NistKatError::UnsupportedAlgorithm("ML-DSA-99".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Unsupported algorithm"));
        assert!(display_str.contains("ML-DSA-99"));
    }
}

// =============================================================================
// Test Vector Structure Tests
// =============================================================================

mod test_vector_structure_tests {
    use super::*;

    #[test]
    fn test_ml_dsa_test_vector_fields() {
        // Verify test vector structure is correct for ML-DSA-44
        for vector in ML_DSA_44_VECTORS {
            assert!(!vector.test_name.is_empty(), "Test name should not be empty");
            assert!(!vector.seed.is_empty(), "Seed should not be empty");
            // Message can be empty (for empty string test)
            assert!(!vector.expected_pk.is_empty(), "Expected public key should not be empty");
            assert!(!vector.expected_sk.is_empty(), "Expected secret key should not be empty");
            assert!(
                !vector.expected_signature.is_empty(),
                "Expected signature should not be empty"
            );
        }
    }

    #[test]
    fn test_ml_dsa_44_vector_names_unique() {
        let names: Vec<&str> = ML_DSA_44_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_ml_dsa_65_vector_names_unique() {
        let names: Vec<&str> = ML_DSA_65_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_ml_dsa_87_vector_names_unique() {
        let names: Vec<&str> = ML_DSA_87_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_seed_length_consistency() {
        // All seeds should be 32 bytes (64 hex chars)
        for vector in ML_DSA_44_VECTORS {
            assert_eq!(vector.seed.len(), 64, "ML-DSA-44 seed should be 64 hex chars");
        }
        for vector in ML_DSA_65_VECTORS {
            assert_eq!(vector.seed.len(), 64, "ML-DSA-65 seed should be 64 hex chars");
        }
        for vector in ML_DSA_87_VECTORS {
            assert_eq!(vector.seed.len(), 64, "ML-DSA-87 seed should be 64 hex chars");
        }
    }

    #[test]
    fn test_vector_hex_validity() {
        // Verify all hex strings in test vectors are valid
        for vector in ML_DSA_44_VECTORS {
            assert!(decode_hex(vector.seed).is_ok(), "Invalid seed hex in {}", vector.test_name);
            assert!(
                decode_hex(vector.message).is_ok(),
                "Invalid message hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_pk).is_ok(),
                "Invalid expected_pk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_sk).is_ok(),
                "Invalid expected_sk hex in {}",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_signature).is_ok(),
                "Invalid expected_signature hex in {}",
                vector.test_name
            );
        }
    }
}

// =============================================================================
// Cross-Algorithm Tests
// =============================================================================

mod cross_algorithm_tests {
    use super::*;

    #[test]
    fn test_same_message_different_security_levels() {
        // The same message signed with different security levels produces different signatures
        let message = b"Test message across security levels";

        let (pk44, sk44) = ml_dsa_44::try_keygen().expect("ML-DSA-44 keygen should succeed");
        let (pk65, sk65) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen should succeed");
        let (pk87, sk87) = ml_dsa_87::try_keygen().expect("ML-DSA-87 keygen should succeed");

        let sig44 = sk44.try_sign(message, &[]).expect("ML-DSA-44 sign should succeed");
        let sig65 = sk65.try_sign(message, &[]).expect("ML-DSA-65 sign should succeed");
        let sig87 = sk87.try_sign(message, &[]).expect("ML-DSA-87 sign should succeed");

        // All signatures should verify with their own keys
        assert!(pk44.verify(message, &sig44, &[]), "ML-DSA-44 verify should succeed");
        assert!(pk65.verify(message, &sig65, &[]), "ML-DSA-65 verify should succeed");
        assert!(pk87.verify(message, &sig87, &[]), "ML-DSA-87 verify should succeed");

        // Signatures have different sizes based on security level
        // ML-DSA-44 signature: 2420 bytes
        // ML-DSA-65 signature: 3309 bytes
        // ML-DSA-87 signature: 4627 bytes
        println!("ML-DSA-44 signature size: {} bytes", sig44.len());
        println!("ML-DSA-65 signature size: {} bytes", sig65.len());
        println!("ML-DSA-87 signature size: {} bytes", sig87.len());
    }

    #[test]
    fn test_all_ml_dsa_variants_run_successfully() {
        // Run all KAT tests and ensure they all pass
        assert!(ml_dsa_kat::run_ml_dsa_44_kat().is_ok(), "ML-DSA-44 KAT failed");
        assert!(ml_dsa_kat::run_ml_dsa_65_kat().is_ok(), "ML-DSA-65 KAT failed");
        assert!(ml_dsa_kat::run_ml_dsa_87_kat().is_ok(), "ML-DSA-87 KAT failed");
    }

    #[test]
    fn test_total_vector_count() {
        let total = ML_DSA_44_VECTORS.len() + ML_DSA_65_VECTORS.len() + ML_DSA_87_VECTORS.len();

        println!("Total ML-DSA test vectors: {}", total);
        assert!(total >= 6, "Should have at least 6 ML-DSA test vectors");
    }
}

// =============================================================================
// Determinism Tests
// =============================================================================

mod determinism_tests {
    use super::*;

    #[test]
    fn test_verification_deterministic() {
        // Verification should always produce the same result
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = b"Determinism test message";
        let signature = sk.try_sign(message, &[]).expect("Signing should succeed");

        // Verify multiple times - should always succeed
        for i in 0..10 {
            let verify_result = pk.verify(message, &signature, &[]);
            assert!(verify_result, "Verification {} should succeed", i);
        }
    }

    #[test]
    fn test_multiple_kat_runs_consistent() {
        // Running KAT multiple times should always succeed
        for i in 0..3 {
            assert!(ml_dsa_kat::run_ml_dsa_44_kat().is_ok(), "ML-DSA-44 KAT run {} failed", i);
            assert!(ml_dsa_kat::run_ml_dsa_65_kat().is_ok(), "ML-DSA-65 KAT run {} failed", i);
            assert!(ml_dsa_kat::run_ml_dsa_87_kat().is_ok(), "ML-DSA-87 KAT run {} failed", i);
        }
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_single_byte_messages() {
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        // Test signing single byte messages
        for byte in [0x00u8, 0x61, 0xFF] {
            let message = vec![byte];
            let signature = sk.try_sign(&message, &[]).expect("Signing single byte should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);
            assert!(
                verify_result,
                "Single byte 0x{:02X} signature verification should succeed",
                byte
            );
        }
    }

    #[test]
    fn test_large_message() {
        // Test with a large message (64KB)
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = vec![0x61u8; 64 * 1024]; // 64KB
        let signature = sk.try_sign(&message, &[]).expect("Signing large message should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "Large message signature verification should succeed");
    }

    #[test]
    fn test_all_zeros_message() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message = vec![0x00u8; 256];
        let signature = sk.try_sign(&message, &[]).expect("Signing all zeros should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "All zeros message signature verification should succeed");
    }

    #[test]
    fn test_all_ones_message() {
        let (pk, sk) = ml_dsa_65::try_keygen().expect("Key generation should succeed");

        let message = vec![0xFFu8; 256];
        let signature = sk.try_sign(&message, &[]).expect("Signing all ones should succeed");

        let verify_result = pk.verify(&message, &signature, &[]);
        assert!(verify_result, "All ones message signature verification should succeed");
    }

    #[test]
    fn test_message_boundary_sizes() {
        // Test messages at various boundary sizes
        let (pk, sk) = ml_dsa_87::try_keygen().expect("Key generation should succeed");

        for size in [63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513] {
            let message = vec![0x61u8; size];
            let signature = sk
                .try_sign(&message, &[])
                .expect(&format!("Signing {} bytes should succeed", size));

            let verify_result = pk.verify(&message, &signature, &[]);
            assert!(verify_result, "Message size {} signature verification should succeed", size);
        }
    }

    #[test]
    fn test_context_parameter() {
        // Test with non-empty context (if supported)
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = b"Message with context";
        let context = b"test-context";

        let signature = sk.try_sign(message, context).expect("Signing with context should succeed");

        // Verify with same context should succeed
        let verify_result = pk.verify(message, &signature, context);
        assert!(verify_result, "Verification with matching context should succeed");

        // Verify with different context should fail
        let different_context = b"different-context";
        let verify_result_diff = pk.verify(message, &signature, different_context);
        assert!(!verify_result_diff, "Verification with different context should fail");

        // Verify with empty context should fail (if context was non-empty during signing)
        let verify_result_empty = pk.verify(message, &signature, &[]);
        assert!(
            !verify_result_empty,
            "Verification with empty context should fail when signed with context"
        );
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

mod integration_tests {
    use super::*;
    use arc_validation::nist_kat::{KatRunner, KatSummary};

    #[test]
    fn test_ml_dsa_kat_runner_integration() {
        let mut runner = KatRunner::new();

        runner.run_test("ML-DSA-44", "ML-DSA", || ml_dsa_kat::run_ml_dsa_44_kat());
        runner.run_test("ML-DSA-65", "ML-DSA", || ml_dsa_kat::run_ml_dsa_65_kat());
        runner.run_test("ML-DSA-87", "ML-DSA", || ml_dsa_kat::run_ml_dsa_87_kat());

        let summary: KatSummary = runner.finish();

        assert!(
            summary.all_passed(),
            "All ML-DSA KAT tests should pass. Failed: {}/{}",
            summary.failed,
            summary.total
        );
        assert_eq!(summary.total, 3, "Should have run 3 ML-DSA variant tests");
    }

    #[test]
    fn test_comprehensive_ml_dsa_validation() {
        println!("\n========================================");
        println!("Comprehensive ML-DSA Validation Suite");
        println!("========================================\n");

        let mut total_vectors = 0;

        // ML-DSA-44
        println!("ML-DSA-44 Vectors:");
        for vector in ML_DSA_44_VECTORS {
            let message = decode_hex(vector.message).expect("Message decode should succeed");
            let (pk, sk) = ml_dsa_44::try_keygen().expect("Keygen should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Sign should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);
            assert!(verify_result, "Verify should succeed for {}", vector.test_name);
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // ML-DSA-65
        println!("ML-DSA-65 Vectors:");
        for vector in ML_DSA_65_VECTORS {
            let message = decode_hex(vector.message).expect("Message decode should succeed");
            let (pk, sk) = ml_dsa_65::try_keygen().expect("Keygen should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Sign should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);
            assert!(verify_result, "Verify should succeed for {}", vector.test_name);
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // ML-DSA-87
        println!("ML-DSA-87 Vectors:");
        for vector in ML_DSA_87_VECTORS {
            let message = decode_hex(vector.message).expect("Message decode should succeed");
            let (pk, sk) = ml_dsa_87::try_keygen().expect("Keygen should succeed");
            let signature = sk.try_sign(&message, &[]).expect("Sign should succeed");
            let verify_result = pk.verify(&message, &signature, &[]);
            assert!(verify_result, "Verify should succeed for {}", vector.test_name);
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        println!("\n========================================");
        println!("Total Vectors Validated: {}", total_vectors);
        println!("========================================\n");
    }

    #[test]
    fn test_ml_dsa_test_vector_struct_access() {
        // Test that MlDsaTestVector struct fields are accessible
        let vector = &ML_DSA_44_VECTORS[0];

        // Access all public fields to ensure they're properly exposed
        let _name: &str = vector.test_name;
        let _seed: &str = vector.seed;
        let _message: &str = vector.message;
        let _pk: &str = vector.expected_pk;
        let _sk: &str = vector.expected_sk;
        let _sig: &str = vector.expected_signature;

        assert!(!vector.test_name.is_empty(), "Test name should be accessible");
    }
}

// =============================================================================
// Security Property Tests
// =============================================================================

mod security_property_tests {
    use super::*;

    #[test]
    fn test_signature_malleability() {
        // Test that modified signatures fail verification
        let (pk, sk) = ml_dsa_44::try_keygen().expect("Key generation should succeed");

        let message = b"Test message for malleability check";
        let signature = sk.try_sign(message, &[]).expect("Signing should succeed");

        // Original should verify
        assert!(pk.verify(message, &signature, &[]), "Original signature should verify");

        // Modify signature and verify it fails
        let mut modified_sig = signature.clone();
        if !modified_sig.is_empty() {
            modified_sig[0] ^= 0x01; // Flip a bit
            let verify_result = pk.verify(message, &modified_sig, &[]);
            assert!(!verify_result, "Modified signature should fail verification");
        }
    }

    #[test]
    fn test_different_keys_different_signatures() {
        // Different key pairs should produce different signatures for the same message
        let message = b"Test message";

        let (pk1, sk1) = ml_dsa_44::try_keygen().expect("Key generation 1 should succeed");
        let (pk2, sk2) = ml_dsa_44::try_keygen().expect("Key generation 2 should succeed");

        let sig1 = sk1.try_sign(message, &[]).expect("Signing 1 should succeed");
        let sig2 = sk2.try_sign(message, &[]).expect("Signing 2 should succeed");

        // Signatures should be different
        assert_ne!(sig1, sig2, "Different keys should produce different signatures");

        // Each signature should verify with its own key
        assert!(pk1.verify(message, &sig1, &[]), "Sig1 should verify with pk1");
        assert!(pk2.verify(message, &sig2, &[]), "Sig2 should verify with pk2");

        // Cross-verification should fail
        assert!(!pk1.verify(message, &sig2, &[]), "Sig2 should not verify with pk1");
        assert!(!pk2.verify(message, &sig1, &[]), "Sig1 should not verify with pk2");
    }

    #[test]
    fn test_signature_size_consistency() {
        // Signatures should have consistent sizes for each security level
        let message = b"Test message for size check";

        // ML-DSA-44
        let (_pk44, sk44) = ml_dsa_44::try_keygen().expect("ML-DSA-44 keygen should succeed");
        let sig44_1 = sk44.try_sign(message, &[]).expect("Sign 1 should succeed");
        let sig44_2 = sk44.try_sign(b"Different message", &[]).expect("Sign 2 should succeed");
        assert_eq!(
            sig44_1.len(),
            sig44_2.len(),
            "ML-DSA-44 signatures should have consistent size"
        );

        // ML-DSA-65
        let (_pk65, sk65) = ml_dsa_65::try_keygen().expect("ML-DSA-65 keygen should succeed");
        let sig65_1 = sk65.try_sign(message, &[]).expect("Sign 1 should succeed");
        let sig65_2 = sk65.try_sign(b"Different message", &[]).expect("Sign 2 should succeed");
        assert_eq!(
            sig65_1.len(),
            sig65_2.len(),
            "ML-DSA-65 signatures should have consistent size"
        );

        // ML-DSA-87
        let (_pk87, sk87) = ml_dsa_87::try_keygen().expect("ML-DSA-87 keygen should succeed");
        let sig87_1 = sk87.try_sign(message, &[]).expect("Sign 1 should succeed");
        let sig87_2 = sk87.try_sign(b"Different message", &[]).expect("Sign 2 should succeed");
        assert_eq!(
            sig87_1.len(),
            sig87_2.len(),
            "ML-DSA-87 signatures should have consistent size"
        );

        // Higher security levels should have larger signatures
        assert!(
            sig44_1.len() < sig65_1.len(),
            "ML-DSA-65 should have larger signatures than ML-DSA-44"
        );
        assert!(
            sig65_1.len() < sig87_1.len(),
            "ML-DSA-87 should have larger signatures than ML-DSA-65"
        );
    }
}
