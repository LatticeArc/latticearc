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

//! Comprehensive Tests for SHA-2 Known Answer Tests
//!
//! This module provides extensive test coverage for the SHA-2 KAT implementation
//! in `arc-validation/src/nist_kat/sha2_kat.rs`.
//!
//! ## Test Categories
//! 1. All SHA-2 variant functions (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
//! 2. Test vector validation
//! 3. Error handling paths
//! 4. Known answer test verification

use arc_validation::nist_kat::sha2_kat::{
    SHA224_VECTORS, SHA256_VECTORS, SHA384_VECTORS, SHA512_224_VECTORS, SHA512_256_VECTORS,
    SHA512_VECTORS,
};
use arc_validation::nist_kat::{NistKatError, decode_hex, sha2_kat};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

// =============================================================================
// SHA-256 Tests
// =============================================================================

mod sha256_tests {
    use super::*;

    #[test]
    fn test_run_sha256_kat_passes() {
        let result = sha2_kat::run_sha256_kat();
        assert!(result.is_ok(), "SHA-256 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha256_empty_string() {
        // NIST test vector: SHA-256 of empty string
        let message = decode_hex("").unwrap();
        let expected =
            decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_abc() {
        // NIST test vector: SHA-256 of "abc"
        let message = decode_hex("616263").unwrap(); // "abc"
        let expected =
            decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_vector_count() {
        // Ensure we have expected number of test vectors
        assert!(
            SHA256_VECTORS.len() >= 2,
            "SHA-256 should have at least 2 test vectors, found {}",
            SHA256_VECTORS.len()
        );
    }

    #[test]
    fn test_sha256_all_vectors_individually() {
        for vector in SHA256_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-256 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha256_output_length() {
        // SHA-256 should always produce 32 bytes (256 bits)
        let mut hasher = Sha256::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32, "SHA-256 output should be 32 bytes");
    }

    #[test]
    fn test_sha256_incremental_hashing() {
        // Test that incremental hashing works correctly
        let message = decode_hex("616263").unwrap(); // "abc"
        let expected =
            decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

        let mut hasher = Sha256::new();
        // Update byte by byte
        for byte in &message {
            hasher.update([*byte]);
        }
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha256_long_message() {
        // Test case 4: long message
        let message = decode_hex(
            "61626364656667686263646566676869636465666768696a6465666768696a6b\
             65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f\
             696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f70717273\
             6d6e6f70717273746e6f707172737475",
        )
        .unwrap();
        let expected =
            decode_hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }
}

// =============================================================================
// SHA-224 Tests
// =============================================================================

mod sha224_tests {
    use super::*;

    #[test]
    fn test_run_sha224_kat_passes() {
        let result = sha2_kat::run_sha224_kat();
        assert!(result.is_ok(), "SHA-224 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha224_empty_string() {
        let message = decode_hex("").unwrap();
        let expected =
            decode_hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f").unwrap();

        let mut hasher = Sha224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha224_abc() {
        let message = decode_hex("616263").unwrap();
        let expected =
            decode_hex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7").unwrap();

        let mut hasher = Sha224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha224_vector_count() {
        assert!(SHA224_VECTORS.len() >= 2, "SHA-224 should have at least 2 test vectors");
    }

    #[test]
    fn test_sha224_all_vectors_individually() {
        for vector in SHA224_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-224 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha224_output_length() {
        // SHA-224 should always produce 28 bytes (224 bits)
        let mut hasher = Sha224::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 28, "SHA-224 output should be 28 bytes");
    }
}

// =============================================================================
// SHA-384 Tests
// =============================================================================

mod sha384_tests {
    use super::*;

    #[test]
    fn test_run_sha384_kat_passes() {
        let result = sha2_kat::run_sha384_kat();
        assert!(result.is_ok(), "SHA-384 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha384_empty_string() {
        let message = decode_hex("").unwrap();
        let expected = decode_hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        )
        .unwrap();

        let mut hasher = Sha384::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_abc() {
        let message = decode_hex("616263").unwrap();
        let expected = decode_hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        )
        .unwrap();

        let mut hasher = Sha384::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha384_vector_count() {
        assert!(SHA384_VECTORS.len() >= 2, "SHA-384 should have at least 2 test vectors");
    }

    #[test]
    fn test_sha384_all_vectors_individually() {
        for vector in SHA384_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha384::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-384 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha384_output_length() {
        // SHA-384 should always produce 48 bytes (384 bits)
        let mut hasher = Sha384::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 48, "SHA-384 output should be 48 bytes");
    }
}

// =============================================================================
// SHA-512 Tests
// =============================================================================

mod sha512_tests {
    use super::*;

    #[test]
    fn test_run_sha512_kat_passes() {
        let result = sha2_kat::run_sha512_kat();
        assert!(result.is_ok(), "SHA-512 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha512_empty_string() {
        let message = decode_hex("").unwrap();
        let expected = decode_hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        )
        .unwrap();

        let mut hasher = Sha512::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_abc() {
        let message = decode_hex("616263").unwrap();
        let expected = decode_hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        )
        .unwrap();

        let mut hasher = Sha512::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_vector_count() {
        assert!(SHA512_VECTORS.len() >= 2, "SHA-512 should have at least 2 test vectors");
    }

    #[test]
    fn test_sha512_all_vectors_individually() {
        for vector in SHA512_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha512::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-512 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha512_output_length() {
        // SHA-512 should always produce 64 bytes (512 bits)
        let mut hasher = Sha512::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 64, "SHA-512 output should be 64 bytes");
    }
}

// =============================================================================
// SHA-512/224 Tests
// =============================================================================

mod sha512_224_tests {
    use super::*;

    #[test]
    fn test_run_sha512_224_kat_passes() {
        let result = sha2_kat::run_sha512_224_kat();
        assert!(result.is_ok(), "SHA-512/224 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha512_224_empty_string() {
        let message = decode_hex("").unwrap();
        let expected =
            decode_hex("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4").unwrap();

        let mut hasher = Sha512_224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_224_abc() {
        let message = decode_hex("616263").unwrap();
        let expected =
            decode_hex("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa").unwrap();

        let mut hasher = Sha512_224::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_224_vector_count() {
        assert!(SHA512_224_VECTORS.len() >= 2, "SHA-512/224 should have at least 2 test vectors");
    }

    #[test]
    fn test_sha512_224_all_vectors_individually() {
        for vector in SHA512_224_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha512_224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-512/224 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha512_224_output_length() {
        // SHA-512/224 should always produce 28 bytes (224 bits)
        let mut hasher = Sha512_224::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 28, "SHA-512/224 output should be 28 bytes");
    }
}

// =============================================================================
// SHA-512/256 Tests
// =============================================================================

mod sha512_256_tests {
    use super::*;

    #[test]
    fn test_run_sha512_256_kat_passes() {
        let result = sha2_kat::run_sha512_256_kat();
        assert!(result.is_ok(), "SHA-512/256 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_sha512_256_empty_string() {
        let message = decode_hex("").unwrap();
        let expected =
            decode_hex("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a").unwrap();

        let mut hasher = Sha512_256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_256_abc() {
        let message = decode_hex("616263").unwrap();
        let expected =
            decode_hex("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23").unwrap();

        let mut hasher = Sha512_256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sha512_256_vector_count() {
        assert!(SHA512_256_VECTORS.len() >= 2, "SHA-512/256 should have at least 2 test vectors");
    }

    #[test]
    fn test_sha512_256_all_vectors_individually() {
        for vector in SHA512_256_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();

            let mut hasher = Sha512_256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(
                result.as_slice(),
                expected.as_slice(),
                "SHA-512/256 test '{}' failed",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_sha512_256_output_length() {
        // SHA-512/256 should always produce 32 bytes (256 bits)
        let mut hasher = Sha512_256::new();
        hasher.update(b"test message");
        let result = hasher.finalize();
        assert_eq!(result.len(), 32, "SHA-512/256 output should be 32 bytes");
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
        // Upper case should work
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
    fn test_nist_kat_error_display() {
        let error = NistKatError::TestFailed {
            algorithm: "SHA-256".to_string(),
            test_name: "test-1".to_string(),
            message: "hash mismatch".to_string(),
        };
        let display_str = format!("{}", error);
        assert!(display_str.contains("SHA-256"));
        assert!(display_str.contains("test-1"));
        assert!(display_str.contains("hash mismatch"));
    }

    #[test]
    fn test_hex_error_display() {
        let error = NistKatError::HexError("invalid character".to_string());
        let display_str = format!("{}", error);
        assert!(display_str.contains("Hex decode error"));
        assert!(display_str.contains("invalid character"));
    }
}

// =============================================================================
// Test Vector Structure Tests
// =============================================================================

mod test_vector_structure_tests {
    use super::*;

    #[test]
    fn test_sha2_test_vector_fields() {
        // Verify test vector structure is correct
        for vector in SHA256_VECTORS {
            assert!(!vector.test_name.is_empty(), "Test name should not be empty");
            // Message can be empty (for empty string test)
            assert!(!vector.expected_hash.is_empty(), "Expected hash should not be empty");
        }
    }

    #[test]
    fn test_sha256_vector_names_unique() {
        let names: Vec<&str> = SHA256_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_sha224_vector_names_unique() {
        let names: Vec<&str> = SHA224_VECTORS.iter().map(|v| v.test_name).collect();
        for (i, name) in names.iter().enumerate() {
            for (j, other_name) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(name, other_name, "Duplicate test name found: {}", name);
                }
            }
        }
    }

    #[test]
    fn test_expected_hash_lengths() {
        // SHA-224: 224/4 = 56 hex chars
        for vector in SHA224_VECTORS {
            assert_eq!(vector.expected_hash.len(), 56, "SHA-224 hash should be 56 hex chars");
        }

        // SHA-256: 256/4 = 64 hex chars
        for vector in SHA256_VECTORS {
            assert_eq!(vector.expected_hash.len(), 64, "SHA-256 hash should be 64 hex chars");
        }

        // SHA-384: 384/4 = 96 hex chars
        for vector in SHA384_VECTORS {
            assert_eq!(vector.expected_hash.len(), 96, "SHA-384 hash should be 96 hex chars");
        }

        // SHA-512: 512/4 = 128 hex chars
        for vector in SHA512_VECTORS {
            assert_eq!(vector.expected_hash.len(), 128, "SHA-512 hash should be 128 hex chars");
        }

        // SHA-512/224: 224/4 = 56 hex chars
        for vector in SHA512_224_VECTORS {
            assert_eq!(vector.expected_hash.len(), 56, "SHA-512/224 hash should be 56 hex chars");
        }

        // SHA-512/256: 256/4 = 64 hex chars
        for vector in SHA512_256_VECTORS {
            assert_eq!(vector.expected_hash.len(), 64, "SHA-512/256 hash should be 64 hex chars");
        }
    }
}

// =============================================================================
// Cross-Algorithm Consistency Tests
// =============================================================================

mod cross_algorithm_tests {
    use super::*;

    #[test]
    fn test_same_message_different_algorithms() {
        // The same message should produce different hashes for different algorithms
        let message = decode_hex("616263").unwrap(); // "abc"

        let mut sha224 = Sha224::new();
        sha224.update(&message);
        let hash224 = sha224.finalize();

        let mut sha256 = Sha256::new();
        sha256.update(&message);
        let hash256 = sha256.finalize();

        let mut sha384 = Sha384::new();
        sha384.update(&message);
        let hash384 = sha384.finalize();

        let mut sha512 = Sha512::new();
        sha512.update(&message);
        let hash512 = sha512.finalize();

        let mut sha512_224 = Sha512_224::new();
        sha512_224.update(&message);
        let hash512_224 = sha512_224.finalize();

        let mut sha512_256 = Sha512_256::new();
        sha512_256.update(&message);
        let hash512_256 = sha512_256.finalize();

        // All hashes should be different from each other
        assert_ne!(
            hash224.as_slice(),
            &hash256.as_slice()[..28],
            "SHA-224 and truncated SHA-256 should differ"
        );
        assert_ne!(
            hash384.as_slice(),
            &hash512.as_slice()[..48],
            "SHA-384 and truncated SHA-512 should differ"
        );

        // SHA-512/224 and SHA-224 have the same output length but different values
        assert_ne!(
            hash224.as_slice(),
            hash512_224.as_slice(),
            "SHA-224 and SHA-512/224 should produce different hashes"
        );

        // SHA-512/256 and SHA-256 have the same output length but different values
        assert_ne!(
            hash256.as_slice(),
            hash512_256.as_slice(),
            "SHA-256 and SHA-512/256 should produce different hashes"
        );
    }

    #[test]
    fn test_all_sha2_variants_run_successfully() {
        // Run all KAT tests and ensure they all pass
        assert!(sha2_kat::run_sha224_kat().is_ok(), "SHA-224 KAT failed");
        assert!(sha2_kat::run_sha256_kat().is_ok(), "SHA-256 KAT failed");
        assert!(sha2_kat::run_sha384_kat().is_ok(), "SHA-384 KAT failed");
        assert!(sha2_kat::run_sha512_kat().is_ok(), "SHA-512 KAT failed");
        assert!(sha2_kat::run_sha512_224_kat().is_ok(), "SHA-512/224 KAT failed");
        assert!(sha2_kat::run_sha512_256_kat().is_ok(), "SHA-512/256 KAT failed");
    }

    #[test]
    fn test_total_vector_count() {
        let total = SHA224_VECTORS.len()
            + SHA256_VECTORS.len()
            + SHA384_VECTORS.len()
            + SHA512_VECTORS.len()
            + SHA512_224_VECTORS.len()
            + SHA512_256_VECTORS.len();

        println!("Total SHA-2 test vectors: {}", total);
        assert!(total >= 12, "Should have at least 12 SHA-2 test vectors");
    }
}

// =============================================================================
// Determinism Tests
// =============================================================================

mod determinism_tests {
    use super::*;

    #[test]
    fn test_sha256_deterministic() {
        // Same input should always produce same output
        let message = decode_hex("deadbeef").unwrap();

        let mut hasher1 = Sha256::new();
        hasher1.update(&message);
        let result1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(&message);
        let result2 = hasher2.finalize();

        assert_eq!(result1.as_slice(), result2.as_slice(), "SHA-256 should be deterministic");
    }

    #[test]
    fn test_sha512_deterministic() {
        let message = decode_hex("cafebabe").unwrap();

        let mut hasher1 = Sha512::new();
        hasher1.update(&message);
        let result1 = hasher1.finalize();

        let mut hasher2 = Sha512::new();
        hasher2.update(&message);
        let result2 = hasher2.finalize();

        assert_eq!(result1.as_slice(), result2.as_slice(), "SHA-512 should be deterministic");
    }

    #[test]
    fn test_multiple_kat_runs_consistent() {
        // Running KAT multiple times should always succeed
        for _ in 0..5 {
            assert!(sha2_kat::run_sha256_kat().is_ok());
            assert!(sha2_kat::run_sha512_kat().is_ok());
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
        // Test hashing of single byte messages
        for byte in [0x00_u8, 0x61, 0xFF] {
            let message = vec![byte];

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.len(), 32, "SHA-256 should produce 32 bytes for single byte input");
        }
    }

    #[test]
    fn test_large_message() {
        // Test hashing of a large message (1 MB)
        let message = vec![0x61_u8; 1024 * 1024]; // 1 MB of 'a'

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.len(), 32, "SHA-256 should produce 32 bytes for large input");
        // Verify the hash is not all zeros (basic sanity check)
        assert!(result.iter().any(|&b| b != 0), "Hash should not be all zeros");
    }

    #[test]
    fn test_all_zeros_message() {
        let message = vec![0x00_u8; 64];

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        // Known hash of 64 zero bytes
        assert_eq!(result.len(), 32);
        assert!(result.iter().any(|&b| b != 0), "Hash of zeros should not be all zeros");
    }

    #[test]
    fn test_all_ones_message() {
        let message = vec![0xFF_u8; 64];

        let mut hasher = Sha256::new();
        hasher.update(&message);
        let result = hasher.finalize();

        assert_eq!(result.len(), 32);
        assert!(result.iter().any(|&b| b != 0xFF), "Hash of all 0xFF should not be all 0xFF");
    }

    #[test]
    fn test_block_boundary_messages() {
        // SHA-256 has a block size of 64 bytes
        // Test messages at block boundaries
        for size in [63, 64, 65, 127, 128, 129] {
            let message = vec![0x61_u8; size];

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.len(), 32, "SHA-256 should produce 32 bytes for {} byte input", size);
        }
    }

    #[test]
    fn test_sha512_block_boundary_messages() {
        // SHA-512 has a block size of 128 bytes
        // Test messages at block boundaries
        for size in [127, 128, 129, 255, 256, 257] {
            let message = vec![0x61_u8; size];

            let mut hasher = Sha512::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.len(), 64, "SHA-512 should produce 64 bytes for {} byte input", size);
        }
    }
}

// =============================================================================
// Integration Tests
// =============================================================================

mod integration_tests {
    use super::*;
    use arc_validation::nist_kat::{KatRunner, KatSummary};

    #[test]
    fn test_sha2_kat_runner_integration() {
        let mut runner = KatRunner::new();

        runner.run_test("SHA-224", "SHA-2", || sha2_kat::run_sha224_kat());
        runner.run_test("SHA-256", "SHA-2", || sha2_kat::run_sha256_kat());
        runner.run_test("SHA-384", "SHA-2", || sha2_kat::run_sha384_kat());
        runner.run_test("SHA-512", "SHA-2", || sha2_kat::run_sha512_kat());
        runner.run_test("SHA-512/224", "SHA-2", || sha2_kat::run_sha512_224_kat());
        runner.run_test("SHA-512/256", "SHA-2", || sha2_kat::run_sha512_256_kat());

        let summary: KatSummary = runner.finish();

        assert!(
            summary.all_passed(),
            "All SHA-2 KAT tests should pass. Failed: {}/{}",
            summary.failed,
            summary.total
        );
        assert_eq!(summary.total, 6, "Should have run 6 SHA-2 variant tests");
    }

    #[test]
    fn test_comprehensive_sha2_validation() {
        println!("\n========================================");
        println!("Comprehensive SHA-2 Validation Suite");
        println!("========================================\n");

        let mut total_vectors = 0;

        // SHA-224
        println!("SHA-224 Vectors:");
        for vector in SHA224_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha224::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // SHA-256
        println!("SHA-256 Vectors:");
        for vector in SHA256_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // SHA-384
        println!("SHA-384 Vectors:");
        for vector in SHA384_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha384::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // SHA-512
        println!("SHA-512 Vectors:");
        for vector in SHA512_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha512::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // SHA-512/224
        println!("SHA-512/224 Vectors:");
        for vector in SHA512_224_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha512_224::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        // SHA-512/256
        println!("SHA-512/256 Vectors:");
        for vector in SHA512_256_VECTORS {
            let message = decode_hex(vector.message).unwrap();
            let expected = decode_hex(vector.expected_hash).unwrap();
            let mut hasher = Sha512_256::new();
            hasher.update(&message);
            let result = hasher.finalize();
            assert_eq!(result.as_slice(), expected.as_slice());
            println!("  [PASS] {}", vector.test_name);
            total_vectors += 1;
        }

        println!("\n========================================");
        println!("Total Vectors Validated: {}", total_vectors);
        println!("========================================\n");
    }
}
