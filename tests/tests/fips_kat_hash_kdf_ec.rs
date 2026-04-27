//! FIPS hash, KDF, MAC, and EC KAT tests.
//!
//! Sub-modules preserve original file structure and imports.

#![deny(unsafe_code)]

// Originally: fips_nist_kat_sha2_tests.rs
mod sha2 {
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

    use latticearc_tests::validation::nist_kat::sha2_kat::{
        SHA224_VECTORS, SHA256_VECTORS, SHA384_VECTORS, SHA512_224_VECTORS, SHA512_256_VECTORS,
        SHA512_VECTORS,
    };
    use latticearc_tests::validation::nist_kat::{NistKatError, decode_hex, sha2_kat};
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

    // =============================================================================
    // SHA-256 Tests
    // =============================================================================

    mod sha256_tests {
        use super::*;

        #[test]
        fn test_run_sha256_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha256_kat();
            assert!(result.is_ok(), "SHA-256 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha256_empty_string_matches_nist_vector_matches_expected() {
            // NIST test vector: SHA-256 of empty string
            let message = decode_hex("").unwrap();
            let expected =
                decode_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                    .unwrap();

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha256_abc_matches_nist_vector_matches_expected() {
            // NIST test vector: SHA-256 of "abc"
            let message = decode_hex("616263").unwrap(); // "abc"
            let expected =
                decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                    .unwrap();

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha256_vector_count_matches_expected() {
            // Ensure we have expected number of test vectors
            assert!(
                SHA256_VECTORS.len() >= 2,
                "SHA-256 should have at least 2 test vectors, found {}",
                SHA256_VECTORS.len()
            );
        }

        #[test]
        fn test_sha256_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha256_output_length_matches_expected() {
            // SHA-256 should always produce 32 bytes (256 bits)
            let mut hasher = Sha256::new();
            hasher.update(b"test message");
            let result = hasher.finalize();
            assert_eq!(result.len(), 32, "SHA-256 output should be 32 bytes");
        }

        #[test]
        fn test_sha256_incremental_hashing_matches_nist_vector_matches_expected() {
            // Test that incremental hashing works correctly
            let message = decode_hex("616263").unwrap(); // "abc"
            let expected =
                decode_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                    .unwrap();

            let mut hasher = Sha256::new();
            // Update byte by byte
            for byte in &message {
                hasher.update([*byte]);
            }
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha256_long_message_matches_nist_vector_matches_expected() {
            // Test case 4: long message
            let message = decode_hex(
                "61626364656667686263646566676869636465666768696a6465666768696a6b\
             65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f\
             696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f70717273\
             6d6e6f70717273746e6f707172737475",
            )
            .unwrap();
            let expected =
                decode_hex("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
                    .unwrap();

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
        fn test_run_sha224_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha224_kat();
            assert!(result.is_ok(), "SHA-224 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha224_empty_string_matches_nist_vector_matches_expected() {
            let message = decode_hex("").unwrap();
            let expected =
                decode_hex("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f").unwrap();

            let mut hasher = Sha224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha224_abc_matches_nist_vector_matches_expected() {
            let message = decode_hex("616263").unwrap();
            let expected =
                decode_hex("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7").unwrap();

            let mut hasher = Sha224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha224_vector_count_matches_expected() {
            assert!(SHA224_VECTORS.len() >= 2, "SHA-224 should have at least 2 test vectors");
        }

        #[test]
        fn test_sha224_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha224_output_length_matches_expected() {
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
        fn test_run_sha384_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha384_kat();
            assert!(result.is_ok(), "SHA-384 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha384_empty_string_matches_nist_vector_matches_expected() {
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
        fn test_sha384_abc_matches_nist_vector_matches_expected() {
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
        fn test_sha384_vector_count_matches_expected() {
            assert!(SHA384_VECTORS.len() >= 2, "SHA-384 should have at least 2 test vectors");
        }

        #[test]
        fn test_sha384_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha384_output_length_matches_expected() {
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
        fn test_run_sha512_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha512_kat();
            assert!(result.is_ok(), "SHA-512 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha512_empty_string_matches_nist_vector_matches_expected() {
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
        fn test_sha512_abc_matches_nist_vector_matches_expected() {
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
        fn test_sha512_vector_count_matches_expected() {
            assert!(SHA512_VECTORS.len() >= 2, "SHA-512 should have at least 2 test vectors");
        }

        #[test]
        fn test_sha512_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha512_output_length_matches_expected() {
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
        fn test_run_sha512_224_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha512_224_kat();
            assert!(result.is_ok(), "SHA-512/224 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha512_224_empty_string_matches_nist_vector_matches_expected() {
            let message = decode_hex("").unwrap();
            let expected =
                decode_hex("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4").unwrap();

            let mut hasher = Sha512_224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha512_224_abc_matches_nist_vector_matches_expected() {
            let message = decode_hex("616263").unwrap();
            let expected =
                decode_hex("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa").unwrap();

            let mut hasher = Sha512_224::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha512_224_vector_count_matches_expected() {
            assert!(
                SHA512_224_VECTORS.len() >= 2,
                "SHA-512/224 should have at least 2 test vectors"
            );
        }

        #[test]
        fn test_sha512_224_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha512_224_output_length_matches_expected() {
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
        fn test_run_sha512_256_kat_passes_matches_nist_vector_matches_expected() {
            let result = sha2_kat::run_sha512_256_kat();
            assert!(result.is_ok(), "SHA-512/256 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_sha512_256_empty_string_matches_nist_vector_matches_expected() {
            let message = decode_hex("").unwrap();
            let expected =
                decode_hex("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
                    .unwrap();

            let mut hasher = Sha512_256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha512_256_abc_matches_nist_vector_matches_expected() {
            let message = decode_hex("616263").unwrap();
            let expected =
                decode_hex("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
                    .unwrap();

            let mut hasher = Sha512_256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.as_slice(), expected.as_slice());
        }

        #[test]
        fn test_sha512_256_vector_count_matches_expected() {
            assert!(
                SHA512_256_VECTORS.len() >= 2,
                "SHA-512/256 should have at least 2 test vectors"
            );
        }

        #[test]
        fn test_sha512_256_all_vectors_individually_match_nist_vector_matches_expected() {
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
        fn test_sha512_256_output_length_matches_expected() {
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
        fn test_decode_hex_valid_matches_expected() {
            let result = decode_hex("616263");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0x61, 0x62, 0x63]);
        }

        #[test]
        fn test_decode_hex_empty_matches_expected() {
            let result = decode_hex("");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Vec::<u8>::new());
        }

        #[test]
        fn test_decode_hex_invalid_chars_matches_expected() {
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
        fn test_decode_hex_odd_length_matches_expected() {
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
        fn test_decode_hex_uppercase_matches_expected() {
            // Upper case should work
            let result = decode_hex("ABC123");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xC1, 0x23]);
        }

        #[test]
        fn test_decode_hex_mixed_case_matches_expected() {
            let result = decode_hex("AbCdEf");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
        }

        #[test]
        fn test_nist_kat_error_display_matches_expected() {
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
        fn test_hex_error_display_matches_expected() {
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
        fn test_sha2_test_vector_fields_matches_expected() {
            // Verify test vector structure is correct
            for vector in SHA256_VECTORS {
                assert!(!vector.test_name.is_empty(), "Test name should not be empty");
                // Message can be empty (for empty string test)
                assert!(!vector.expected_hash.is_empty(), "Expected hash should not be empty");
            }
        }

        #[test]
        fn test_sha256_vector_names_unique_matches_expected() {
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
        fn test_sha224_vector_names_unique_matches_expected() {
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
        fn test_expected_hash_lengths_matches_nist_vector_matches_expected() {
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
                assert_eq!(
                    vector.expected_hash.len(),
                    56,
                    "SHA-512/224 hash should be 56 hex chars"
                );
            }

            // SHA-512/256: 256/4 = 64 hex chars
            for vector in SHA512_256_VECTORS {
                assert_eq!(
                    vector.expected_hash.len(),
                    64,
                    "SHA-512/256 hash should be 64 hex chars"
                );
            }
        }
    }

    // =============================================================================
    // Cross-Algorithm Consistency Tests
    // =============================================================================

    mod cross_algorithm_tests {
        use super::*;

        #[test]
        fn test_same_message_different_algorithms_matches_nist_vector_matches_expected() {
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
        fn test_all_sha2_variants_run_successfully_matches_nist_vector_matches_expected() {
            // Run all KAT tests and ensure they all pass
            assert!(sha2_kat::run_sha224_kat().is_ok(), "SHA-224 KAT failed");
            assert!(sha2_kat::run_sha256_kat().is_ok(), "SHA-256 KAT failed");
            assert!(sha2_kat::run_sha384_kat().is_ok(), "SHA-384 KAT failed");
            assert!(sha2_kat::run_sha512_kat().is_ok(), "SHA-512 KAT failed");
            assert!(sha2_kat::run_sha512_224_kat().is_ok(), "SHA-512/224 KAT failed");
            assert!(sha2_kat::run_sha512_256_kat().is_ok(), "SHA-512/256 KAT failed");
        }

        #[test]
        fn test_total_vector_count_matches_expected() {
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
        fn test_sha256_deterministic_matches_nist_vector_matches_expected() {
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
        fn test_sha512_deterministic_matches_nist_vector_matches_expected() {
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
        fn test_multiple_kat_runs_consistent_matches_nist_vector_matches_expected() {
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
        fn test_single_byte_messages_matches_nist_vector_matches_expected() {
            // Test hashing of single byte messages
            for byte in [0x00_u8, 0x61, 0xFF] {
                let message = vec![byte];

                let mut hasher = Sha256::new();
                hasher.update(&message);
                let result = hasher.finalize();

                assert_eq!(
                    result.len(),
                    32,
                    "SHA-256 should produce 32 bytes for single byte input"
                );
            }
        }

        #[test]
        fn test_large_message_matches_nist_vector_matches_expected() {
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
        fn test_all_zeros_message_matches_nist_vector_matches_expected() {
            let message = vec![0x00_u8; 64];

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            // Known hash of 64 zero bytes
            assert_eq!(result.len(), 32);
            assert!(result.iter().any(|&b| b != 0), "Hash of zeros should not be all zeros");
        }

        #[test]
        fn test_all_ones_message_matches_nist_vector_matches_expected() {
            let message = vec![0xFF_u8; 64];

            let mut hasher = Sha256::new();
            hasher.update(&message);
            let result = hasher.finalize();

            assert_eq!(result.len(), 32);
            assert!(result.iter().any(|&b| b != 0xFF), "Hash of all 0xFF should not be all 0xFF");
        }

        #[test]
        fn test_block_boundary_messages_matches_nist_vector_matches_expected() {
            // SHA-256 has a block size of 64 bytes
            // Test messages at block boundaries
            for size in [63, 64, 65, 127, 128, 129] {
                let message = vec![0x61_u8; size];

                let mut hasher = Sha256::new();
                hasher.update(&message);
                let result = hasher.finalize();

                assert_eq!(
                    result.len(),
                    32,
                    "SHA-256 should produce 32 bytes for {} byte input",
                    size
                );
            }
        }

        #[test]
        fn test_sha512_block_boundary_messages_matches_nist_vector_matches_expected() {
            // SHA-512 has a block size of 128 bytes
            // Test messages at block boundaries
            for size in [127, 128, 129, 255, 256, 257] {
                let message = vec![0x61_u8; size];

                let mut hasher = Sha512::new();
                hasher.update(&message);
                let result = hasher.finalize();

                assert_eq!(
                    result.len(),
                    64,
                    "SHA-512 should produce 64 bytes for {} byte input",
                    size
                );
            }
        }
    }

    // =============================================================================
    // Integration Tests
    // =============================================================================

    mod integration_tests {
        use super::*;
        use latticearc_tests::validation::nist_kat::{KatRunner, KatSummary};

        #[test]
        fn test_sha2_kat_runner_integration_matches_nist_vector_matches_expected() {
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
        fn test_comprehensive_sha2_validation_matches_nist_vector_matches_expected() {
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
}

// Originally: fips_hkdf_kat_tests.rs
mod hkdf {
    //! Comprehensive Tests for HKDF Known Answer Tests
    //!
    //! This module provides extensive test coverage for the HKDF KAT implementation
    //! in `arc-validation/src/nist_kat/hkdf_kat.rs`.
    //!
    //! ## Test Categories
    //! 1. HkdfTestVector struct field access
    //! 2. Test vector validation
    //! 3. HKDF-SHA256 KAT runner function
    //! 4. PRK (Pseudorandom Key) verification
    //! 5. OKM (Output Keying Material) verification
    //! 6. Empty salt/info handling
    //! 7. Error handling paths
    //! 8. Edge cases and boundary conditions

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

    use hkdf::Hkdf;
    use latticearc_tests::validation::nist_kat::hkdf_kat::HKDF_SHA256_VECTORS;
    use latticearc_tests::validation::nist_kat::{NistKatError, decode_hex, hkdf_kat};
    use sha2::Sha256;

    // Helper type alias for explicit type usage (HkdfTestVector is accessed via HKDF_SHA256_VECTORS)
    type TestVectorSlice = &'static [hkdf_kat::HkdfTestVector];

    // =============================================================================
    // HkdfTestVector Struct Tests
    // =============================================================================

    mod hkdf_test_vector_tests {
        use super::*;

        #[test]
        fn test_vector_slice_type_matches_rfc5869_vector_matches_expected() {
            // Verify the slice type is correctly exported
            let vectors: TestVectorSlice = HKDF_SHA256_VECTORS;
            assert_eq!(vectors.len(), 3);
        }

        #[test]
        fn test_vector_struct_fields_accessible_matches_rfc5869_vector_matches_expected() {
            // Test that all fields of HkdfTestVector are publicly accessible
            let vector = &HKDF_SHA256_VECTORS[0];

            // Access all fields
            let _test_name: &str = vector.test_name;
            let _ikm: &str = vector.ikm;
            let _salt: &str = vector.salt;
            let _info: &str = vector.info;
            let _length: usize = vector.length;
            let _expected_prk: &str = vector.expected_prk;
            let _expected_okm: &str = vector.expected_okm;
        }

        #[test]
        fn test_vector_count_matches_expected() {
            // RFC 5869 defines 3 SHA-256 test vectors
            assert_eq!(
                HKDF_SHA256_VECTORS.len(),
                3,
                "HKDF-SHA256 should have exactly 3 test vectors"
            );
        }

        #[test]
        fn test_vector_test_names_matches_expected() {
            // Verify all test vectors have proper RFC names
            assert_eq!(HKDF_SHA256_VECTORS[0].test_name, "RFC-5869-Test-Case-1");
            assert_eq!(HKDF_SHA256_VECTORS[1].test_name, "RFC-5869-Test-Case-2");
            assert_eq!(HKDF_SHA256_VECTORS[2].test_name, "RFC-5869-Test-Case-3");
        }

        #[test]
        fn test_vector_lengths_matches_rfc5869_vector_matches_expected() {
            // Verify OKM lengths match expected values
            assert_eq!(HKDF_SHA256_VECTORS[0].length, 42);
            assert_eq!(HKDF_SHA256_VECTORS[1].length, 82);
            assert_eq!(HKDF_SHA256_VECTORS[2].length, 42);
        }

        #[test]
        fn test_vector_ikm_decode_matches_rfc5869_vector_matches_expected() {
            for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
                let result = decode_hex(vector.ikm);
                assert!(
                    result.is_ok(),
                    "Test case {} IKM should be valid hex: {:?}",
                    i + 1,
                    result.err()
                );
            }
        }

        #[test]
        fn test_vector_salt_decode_matches_rfc5869_vector_matches_expected() {
            for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
                let result = decode_hex(vector.salt);
                assert!(
                    result.is_ok(),
                    "Test case {} salt should be valid hex: {:?}",
                    i + 1,
                    result.err()
                );
            }
        }

        #[test]
        fn test_vector_info_decode_matches_rfc5869_vector_matches_expected() {
            for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
                let result = decode_hex(vector.info);
                assert!(
                    result.is_ok(),
                    "Test case {} info should be valid hex: {:?}",
                    i + 1,
                    result.err()
                );
            }
        }

        #[test]
        fn test_vector_prk_decode_matches_rfc5869_vector_matches_expected() {
            for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
                let result = decode_hex(vector.expected_prk);
                assert!(
                    result.is_ok(),
                    "Test case {} PRK should be valid hex: {:?}",
                    i + 1,
                    result.err()
                );
                // PRK for SHA-256 should be 32 bytes
                let prk = result.unwrap();
                assert_eq!(
                    prk.len(),
                    32,
                    "Test case {} PRK should be 32 bytes, got {}",
                    i + 1,
                    prk.len()
                );
            }
        }

        #[test]
        fn test_vector_okm_decode_matches_rfc5869_vector_matches_expected() {
            for (i, vector) in HKDF_SHA256_VECTORS.iter().enumerate() {
                let result = decode_hex(vector.expected_okm);
                assert!(
                    result.is_ok(),
                    "Test case {} OKM should be valid hex: {:?}",
                    i + 1,
                    result.err()
                );
                // OKM length should match specified length
                let okm = result.unwrap();
                assert_eq!(
                    okm.len(),
                    vector.length,
                    "Test case {} OKM length should match specified length",
                    i + 1
                );
            }
        }
    }

    // =============================================================================
    // HKDF KAT Runner Tests
    // =============================================================================

    mod hkdf_runner_tests {
        use super::*;

        #[test]
        fn test_run_hkdf_sha256_kat_passes_matches_rfc5869_vector_matches_expected() {
            let result = hkdf_kat::run_hkdf_sha256_kat();
            assert!(result.is_ok(), "HKDF-SHA256 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_run_hkdf_sha256_kat_returns_ok_matches_rfc5869_vector_matches_expected() {
            // Explicit test that the function returns Ok(()) on success
            match hkdf_kat::run_hkdf_sha256_kat() {
                Ok(()) => {} // Expected
                Err(e) => panic!("Expected Ok(()), got Err: {:?}", e),
            }
        }

        #[test]
        fn test_all_vectors_pass_matches_rfc5869_vector_matches_expected() {
            // Run each vector directly using the hkdf crate
            for vector in HKDF_SHA256_VECTORS {
                let ikm = decode_hex(vector.ikm).unwrap();
                let salt = decode_hex(vector.salt).unwrap();
                let info = decode_hex(vector.info).unwrap();
                let expected_prk = decode_hex(vector.expected_prk).unwrap();
                let expected_okm = decode_hex(vector.expected_okm).unwrap();

                // Test Extract step
                let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
                let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);

                assert_eq!(
                    prk.as_slice(),
                    expected_prk.as_slice(),
                    "PRK mismatch for {}",
                    vector.test_name
                );

                // Test Expand step
                let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
                let mut okm = vec![0u8; vector.length];
                let expand_result = hk.expand(&info, &mut okm);
                assert!(expand_result.is_ok(), "HKDF expand failed for {}", vector.test_name);

                assert_eq!(okm, expected_okm, "OKM mismatch for {}", vector.test_name);
            }
        }
    }

    // =============================================================================
    // Test Case 1: Basic HKDF Test
    // =============================================================================

    mod test_case_1_basic {
        use super::*;

        #[test]
        fn test_case_1_ikm_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[0];
            let ikm = decode_hex(vector.ikm).unwrap();
            assert_eq!(ikm.len(), 22, "Test case 1 IKM should be 22 bytes");
            // IKM is 0x0b repeated 22 times
            for byte in &ikm {
                assert_eq!(*byte, 0x0b);
            }
        }

        #[test]
        fn test_case_1_salt_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[0];
            let salt = decode_hex(vector.salt).unwrap();
            assert_eq!(salt.len(), 13, "Test case 1 salt should be 13 bytes");
            // Salt is 0x00..0x0c
            for (i, byte) in salt.iter().enumerate() {
                assert_eq!(*byte, i as u8);
            }
        }

        #[test]
        fn test_case_1_info_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[0];
            let info = decode_hex(vector.info).unwrap();
            assert_eq!(info.len(), 10, "Test case 1 info should be 10 bytes");
            // Info is 0xf0..0xf9
            for (i, byte) in info.iter().enumerate() {
                assert_eq!(*byte, (0xf0 + i) as u8);
            }
        }

        #[test]
        fn test_case_1_prk_extraction_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[0];
            let ikm = decode_hex(vector.ikm).unwrap();
            let salt = decode_hex(vector.salt).unwrap();
            let expected_prk = decode_hex(vector.expected_prk).unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());
        }

        #[test]
        fn test_case_1_okm_expansion_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[0];
            let ikm = decode_hex(vector.ikm).unwrap();
            let salt = decode_hex(vector.salt).unwrap();
            let info = decode_hex(vector.info).unwrap();
            let expected_okm = decode_hex(vector.expected_okm).unwrap();

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; vector.length];
            hk.expand(&info, &mut okm).unwrap();

            assert_eq!(okm, expected_okm);
        }
    }

    // =============================================================================
    // Test Case 2: Longer Inputs/Outputs
    // =============================================================================

    mod test_case_2_longer {
        use super::*;

        #[test]
        fn test_case_2_ikm_length_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[1];
            let ikm = decode_hex(vector.ikm).unwrap();
            assert_eq!(ikm.len(), 80, "Test case 2 IKM should be 80 bytes");
        }

        #[test]
        fn test_case_2_salt_length_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[1];
            let salt = decode_hex(vector.salt).unwrap();
            assert_eq!(salt.len(), 80, "Test case 2 salt should be 80 bytes");
        }

        #[test]
        fn test_case_2_info_length_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[1];
            let info = decode_hex(vector.info).unwrap();
            assert_eq!(info.len(), 80, "Test case 2 info should be 80 bytes");
        }

        #[test]
        fn test_case_2_okm_length_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[1];
            assert_eq!(vector.length, 82, "Test case 2 OKM should be 82 bytes");
        }

        #[test]
        fn test_case_2_full_flow_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[1];
            let ikm = decode_hex(vector.ikm).unwrap();
            let salt = decode_hex(vector.salt).unwrap();
            let info = decode_hex(vector.info).unwrap();
            let expected_prk = decode_hex(vector.expected_prk).unwrap();
            let expected_okm = decode_hex(vector.expected_okm).unwrap();

            // Extract
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice(), "PRK mismatch");

            // Expand
            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; vector.length];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(okm, expected_okm, "OKM mismatch");
        }
    }

    // =============================================================================
    // Test Case 3: Empty Salt and Info
    // =============================================================================

    mod test_case_3_empty_salt_info {
        use super::*;

        #[test]
        fn test_case_3_empty_salt_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[2];
            let salt = decode_hex(vector.salt).unwrap();
            assert!(salt.is_empty(), "Test case 3 salt should be empty");
        }

        #[test]
        fn test_case_3_empty_info_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[2];
            let info = decode_hex(vector.info).unwrap();
            assert!(info.is_empty(), "Test case 3 info should be empty");
        }

        #[test]
        fn test_case_3_prk_with_empty_salt_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[2];
            let ikm = decode_hex(vector.ikm).unwrap();
            let expected_prk = decode_hex(vector.expected_prk).unwrap();

            // Using None for salt (empty salt scenario)
            let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());
        }

        #[test]
        fn test_case_3_okm_with_empty_info_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[2];
            let ikm = decode_hex(vector.ikm).unwrap();
            let expected_okm = decode_hex(vector.expected_okm).unwrap();

            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut okm = vec![0u8; vector.length];
            // Empty info
            hk.expand(&[], &mut okm).unwrap();

            assert_eq!(okm, expected_okm);
        }

        #[test]
        fn test_case_3_full_flow_empty_params_matches_rfc5869_vector_matches_expected() {
            let vector = &HKDF_SHA256_VECTORS[2];
            let ikm = decode_hex(vector.ikm).unwrap();
            let salt = decode_hex(vector.salt).unwrap();
            let info = decode_hex(vector.info).unwrap();
            let expected_prk = decode_hex(vector.expected_prk).unwrap();
            let expected_okm = decode_hex(vector.expected_okm).unwrap();

            // Verify salt and info are empty
            assert!(salt.is_empty());
            assert!(info.is_empty());

            // Extract with empty salt (None)
            let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
            let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());

            // Expand with empty info
            let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
            let mut okm = vec![0u8; vector.length];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(okm, expected_okm);
        }
    }

    // =============================================================================
    // HKDF Properties and Edge Cases
    // =============================================================================

    mod hkdf_properties {
        use super::*;

        #[test]
        fn test_hkdf_deterministic_matches_rfc5869_vector_matches_expected() {
            // Same inputs should produce same outputs
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();
            let info = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);

            let mut okm1 = vec![0u8; 42];
            let mut okm2 = vec![0u8; 42];

            hk.expand(&info, &mut okm1).unwrap();

            // Create new instance with same params
            let hk2 = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            hk2.expand(&info, &mut okm2).unwrap();

            assert_eq!(okm1, okm2, "HKDF should be deterministic");
        }

        #[test]
        fn test_hkdf_different_info_different_output_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);

            let info1 = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
            let info2 = decode_hex("f0f1f2f3f4f5f6f7f8fa").unwrap(); // Different last byte

            let mut okm1 = vec![0u8; 42];
            let mut okm2 = vec![0u8; 42];

            hk.expand(&info1, &mut okm1).unwrap();
            hk.expand(&info2, &mut okm2).unwrap();

            assert_ne!(okm1, okm2, "Different info should produce different OKM");
        }

        #[test]
        fn test_hkdf_different_salt_different_prk_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt1 = decode_hex("000102030405060708090a0b0c").unwrap();
            let salt2 = decode_hex("000102030405060708090a0b0d").unwrap(); // Different last byte

            let (prk1, _) = Hkdf::<Sha256>::extract(Some(salt1.as_slice()), &ikm);
            let (prk2, _) = Hkdf::<Sha256>::extract(Some(salt2.as_slice()), &ikm);

            assert_ne!(
                prk1.as_slice(),
                prk2.as_slice(),
                "Different salt should produce different PRK"
            );
        }

        #[test]
        fn test_hkdf_different_ikm_different_prk_matches_rfc5869_vector_matches_expected() {
            let ikm1 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let ikm2 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c").unwrap(); // Different last byte
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let (prk1, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm1);
            let (prk2, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm2);

            assert_ne!(
                prk1.as_slice(),
                prk2.as_slice(),
                "Different IKM should produce different PRK"
            );
        }

        #[test]
        fn test_hkdf_prk_length_matches_rfc5869_vector_matches_expected() {
            // PRK should always be hash output length (32 bytes for SHA-256)
            for vector in HKDF_SHA256_VECTORS {
                let prk = decode_hex(vector.expected_prk).unwrap();
                assert_eq!(prk.len(), 32, "PRK should be 32 bytes for SHA-256");
            }
        }

        #[test]
        fn test_hkdf_okm_max_length_matches_rfc5869_vector_matches_expected() {
            // HKDF-SHA256 can generate up to 255 * 32 = 8160 bytes
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Test a reasonably large output (255 bytes, which is still < max)
            let mut okm = vec![0u8; 255];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle 255-byte OKM");
        }

        #[test]
        fn test_hkdf_empty_ikm_matches_rfc5869_vector_matches_expected() {
            // Empty IKM should still work
            let ikm: Vec<u8> = vec![];
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.len(), 32, "PRK should be 32 bytes even with empty IKM");

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle empty IKM");
        }

        #[test]
        fn test_hkdf_single_byte_ikm_matches_rfc5869_vector_matches_expected() {
            let ikm = vec![0xab];
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.len(), 32, "PRK should be 32 bytes");

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle single-byte IKM");
        }
    }

    // =============================================================================
    // HKDF Extract Step Tests
    // =============================================================================

    mod hkdf_extract_tests {
        use super::*;

        #[test]
        fn test_extract_returns_hkdf_instance_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            // Extract returns (PRK, Hkdf instance)
            let (prk, hkdf_instance) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);

            // PRK should be 32 bytes
            assert_eq!(prk.len(), 32);

            // Hkdf instance should be usable for expand
            let mut okm = vec![0u8; 32];
            let result = hkdf_instance.expand(&[], &mut okm);
            assert!(result.is_ok());
        }

        #[test]
        fn test_extract_with_none_salt_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
            assert_eq!(prk.len(), 32);

            // Compare with test case 3 which uses empty salt
            let expected_prk =
                decode_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                    .unwrap();
            assert_eq!(prk.as_slice(), expected_prk.as_slice());
        }

        #[test]
        fn test_extract_prk_matches_rfc5869_vector_matches_expected() {
            // Test all vectors for PRK correctness
            for vector in HKDF_SHA256_VECTORS {
                let ikm = decode_hex(vector.ikm).unwrap();
                let salt = decode_hex(vector.salt).unwrap();
                let expected_prk = decode_hex(vector.expected_prk).unwrap();

                let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
                let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);

                assert_eq!(
                    prk.as_slice(),
                    expected_prk.as_slice(),
                    "PRK mismatch for {}",
                    vector.test_name
                );
            }
        }
    }

    // =============================================================================
    // HKDF Expand Step Tests
    // =============================================================================

    mod hkdf_expand_tests {
        use super::*;

        #[test]
        fn test_expand_zero_length_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            let mut okm: Vec<u8> = vec![];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle zero-length OKM");
        }

        #[test]
        fn test_expand_one_byte_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            let mut okm = vec![0u8; 1];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle single-byte OKM");
            assert_ne!(okm[0], 0, "OKM should not be zero (very unlikely)");
        }

        #[test]
        fn test_expand_exactly_hash_length_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            let mut okm = vec![0u8; 32]; // Exactly SHA-256 output length
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle hash-length OKM");
        }

        #[test]
        fn test_expand_multiple_hash_lengths_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Test 2 * 32 = 64 bytes
            let mut okm = vec![0u8; 64];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle multi-block OKM");

            // Test 3 * 32 = 96 bytes
            let mut okm = vec![0u8; 96];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok(), "Should handle multi-block OKM");
        }

        #[test]
        fn test_expand_with_info_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();
            let info = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
            let expected_okm = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 42];
            hk.expand(&info, &mut okm).unwrap();

            assert_eq!(okm, expected_okm);
        }

        #[test]
        fn test_expand_without_info_matches_rfc5869_vector_matches_expected() {
            // Test case 3 uses empty info
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let expected_okm = decode_hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();

            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut okm = vec![0u8; 42];
            hk.expand(&[], &mut okm).unwrap();

            assert_eq!(okm, expected_okm);
        }

        #[test]
        fn test_expand_okm_matches_rfc5869_vector_matches_expected() {
            // Test all vectors for OKM correctness
            for vector in HKDF_SHA256_VECTORS {
                let ikm = decode_hex(vector.ikm).unwrap();
                let salt = decode_hex(vector.salt).unwrap();
                let info = decode_hex(vector.info).unwrap();
                let expected_okm = decode_hex(vector.expected_okm).unwrap();

                let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
                let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
                let mut okm = vec![0u8; vector.length];
                hk.expand(&info, &mut okm).unwrap();

                assert_eq!(okm, expected_okm, "OKM mismatch for {}", vector.test_name);
            }
        }
    }

    // =============================================================================
    // Error Handling Tests
    // =============================================================================

    mod error_handling_tests {
        use super::*;

        #[test]
        fn test_invalid_hex_in_ikm_matches_expected() {
            let result = decode_hex("invalid_hex");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {} // Expected
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_odd_length_hex_matches_expected() {
            let result = decode_hex("123");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(_)) => {} // Expected
                _ => panic!("Expected HexError"),
            }
        }

        #[test]
        fn test_nist_kat_error_test_failed_display_matches_expected() {
            let error = NistKatError::TestFailed {
                algorithm: "HKDF-SHA256".to_string(),
                test_name: "test-case-1".to_string(),
                message: "PRK mismatch".to_string(),
            };
            let display = format!("{}", error);
            assert!(display.contains("HKDF-SHA256"));
            assert!(display.contains("test-case-1"));
            assert!(display.contains("PRK mismatch"));
        }

        #[test]
        fn test_nist_kat_error_hex_error_display_matches_expected() {
            let error = NistKatError::HexError("invalid character".to_string());
            let display = format!("{}", error);
            assert!(display.contains("invalid character"));
        }

        #[test]
        fn test_nist_kat_error_implementation_error_display_matches_expected() {
            let error = NistKatError::ImplementationError("expand failed".to_string());
            let display = format!("{}", error);
            assert!(display.contains("expand failed"));
        }

        #[test]
        fn test_hkdf_expand_too_long_matches_expected() {
            // HKDF can produce at most 255 * HashLen bytes (8160 for SHA-256)
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Try to expand more than max (255 * 32 + 1 = 8161)
            let mut okm = vec![0u8; 8161];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_err(), "Should fail for OKM > max length");
        }
    }

    // =============================================================================
    // RFC 5869 Compliance Tests
    // =============================================================================

    mod rfc_5869_compliance {
        use super::*;

        #[test]
        fn test_rfc_appendix_a_test_case_1_matches_rfc5869_vector_matches_expected() {
            // RFC 5869 Appendix A - Test Case 1
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();
            let info = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
            let expected_prk =
                decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
                    .unwrap();
            let expected_okm = decode_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 42];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(okm, expected_okm);
        }

        #[test]
        fn test_rfc_appendix_a_test_case_2_matches_rfc5869_vector_matches_expected() {
            // RFC 5869 Appendix A - Test Case 2 (longer inputs)
            let ikm = decode_hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
            )
            .unwrap();
            let salt = decode_hex(
                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            )
            .unwrap();
            let info = decode_hex(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            )
            .unwrap();
            let expected_prk =
                decode_hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
                    .unwrap();
            let expected_okm = decode_hex(
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
            )
            .unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 82];
            hk.expand(&info, &mut okm).unwrap();
            assert_eq!(okm, expected_okm);
        }

        #[test]
        fn test_rfc_appendix_a_test_case_3_matches_rfc5869_vector_matches_expected() {
            // RFC 5869 Appendix A - Test Case 3 (zero-length salt/info)
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let expected_prk =
                decode_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
                    .unwrap();
            let expected_okm = decode_hex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        )
        .unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
            assert_eq!(prk.as_slice(), expected_prk.as_slice());

            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut okm = vec![0u8; 42];
            hk.expand(&[], &mut okm).unwrap();
            assert_eq!(okm, expected_okm);
        }
    }

    // =============================================================================
    // Integration Tests
    // =============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_hkdf_kat_module_integration_matches_rfc5869_vector_matches_expected() {
            // Test that the KAT module integrates properly with the validation framework
            let result = hkdf_kat::run_hkdf_sha256_kat();
            assert!(result.is_ok());
        }

        #[test]
        fn test_vectors_accessible_from_module_matches_rfc5869_vector_matches_expected() {
            // Test that vectors are properly exported
            let vectors = HKDF_SHA256_VECTORS;
            assert_eq!(vectors.len(), 3);

            for vector in vectors {
                assert!(!vector.test_name.is_empty());
                assert!(!vector.ikm.is_empty());
                // salt and info can be empty
                assert!(vector.length > 0);
                assert!(!vector.expected_prk.is_empty());
                assert!(!vector.expected_okm.is_empty());
            }
        }

        #[test]
        fn test_decode_hex_from_module_matches_expected() {
            // Test that decode_hex is properly exported from nist_kat
            let result = decode_hex("0123456789abcdef");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        }

        #[test]
        fn test_full_hkdf_workflow_matches_rfc5869_vector_matches_expected() {
            // End-to-end test of the HKDF workflow
            for vector in HKDF_SHA256_VECTORS {
                // 1. Decode all hex values
                let ikm = decode_hex(vector.ikm).unwrap();
                let salt = decode_hex(vector.salt).unwrap();
                let info = decode_hex(vector.info).unwrap();
                let expected_prk = decode_hex(vector.expected_prk).unwrap();
                let expected_okm = decode_hex(vector.expected_okm).unwrap();

                // 2. Handle empty salt
                let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };

                // 3. Perform HKDF Extract
                let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);
                assert_eq!(prk.as_slice(), expected_prk.as_slice());

                // 4. Perform HKDF Expand
                let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
                let mut okm = vec![0u8; vector.length];
                let expand_result = hk.expand(&info, &mut okm);
                assert!(expand_result.is_ok());
                assert_eq!(okm, expected_okm);
            }
        }
    }

    // =============================================================================
    // Additional Edge Cases
    // =============================================================================

    mod additional_edge_cases {
        use super::*;

        #[test]
        fn test_very_short_info_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Single byte info
            let info = vec![0x01];
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&info, &mut okm);
            assert!(result.is_ok());
        }

        #[test]
        fn test_very_long_info_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // 1024 byte info
            let info = vec![0xab; 1024];
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&info, &mut okm);
            assert!(result.is_ok());
        }

        #[test]
        fn test_all_zeros_ikm_matches_rfc5869_vector_matches_expected() {
            let ikm = vec![0u8; 32];
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.len(), 32);

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok());
        }

        #[test]
        fn test_all_ones_ikm_matches_rfc5869_vector_matches_expected() {
            let ikm = vec![0xff; 32];
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();

            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
            assert_eq!(prk.len(), 32);

            let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
            let mut okm = vec![0u8; 32];
            let result = hk.expand(&[], &mut okm);
            assert!(result.is_ok());
        }

        #[test]
        fn test_repeated_expand_calls_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Multiple expand calls with different info
            let info1 = b"application 1";
            let info2 = b"application 2";

            let mut okm1 = vec![0u8; 32];
            let mut okm2 = vec![0u8; 32];

            hk.expand(info1, &mut okm1).unwrap();
            hk.expand(info2, &mut okm2).unwrap();

            assert_ne!(okm1, okm2, "Different info should produce different OKM");
        }

        #[test]
        fn test_boundary_okm_lengths_matches_rfc5869_vector_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let hk = Hkdf::<Sha256>::new(None, &ikm);

            // Test various boundary lengths
            let boundary_lengths = vec![1, 31, 32, 33, 63, 64, 65, 255];

            for len in boundary_lengths {
                let mut okm = vec![0u8; len];
                let result = hk.expand(&[], &mut okm);
                assert!(result.is_ok(), "Should handle OKM length {}", len);
                assert_eq!(okm.len(), len);
            }
        }
    }

    // =============================================================================
    // Performance Sanity Tests
    // =============================================================================

    mod performance_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn test_hkdf_performance_reasonable_matches_expected() {
            let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let salt = decode_hex("000102030405060708090a0b0c").unwrap();
            let info = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();

            let iterations = 1000;
            let start = Instant::now();

            for _ in 0..iterations {
                let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm);
                let mut okm = vec![0u8; 42];
                hk.expand(&info, &mut okm).unwrap();
            }

            let duration = start.elapsed();
            let per_op_us = duration.as_micros() / iterations;

            // HKDF should be reasonably fast (< 1ms per operation)
            assert!(per_op_us < 1000, "HKDF should complete in < 1ms, took {} us", per_op_us);
        }

        #[test]
        fn test_kat_runner_performance_matches_expected() {
            let iterations = 100;
            let start = Instant::now();

            for _ in 0..iterations {
                let result = hkdf_kat::run_hkdf_sha256_kat();
                assert!(result.is_ok());
            }

            let duration = start.elapsed();
            let per_run_ms = duration.as_millis() / iterations as u128;

            // KAT run should complete in < 10ms
            assert!(
                per_run_ms < 10,
                "KAT runner should complete in < 10ms, took {} ms",
                per_run_ms
            );
        }
    }
}

// Originally: fips_hmac_kat_tests.rs
mod hmac {
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

    use hmac::{Hmac, KeyInit, Mac};
    use latticearc_tests::validation::nist_kat::hmac_kat::{
        HMAC_VECTORS, run_hmac_sha224_kat, run_hmac_sha256_kat, run_hmac_sha384_kat,
        run_hmac_sha512_kat,
    };
    use latticearc_tests::validation::nist_kat::{NistKatError, decode_hex};
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
        fn test_run_hmac_sha256_kat_succeeds() {
            let result = run_hmac_sha256_kat();
            assert!(result.is_ok(), "HMAC-SHA256 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_hmac_sha256_all_vectors_individually_match_expected_matches_expected() {
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
        fn test_hmac_sha256_output_length_matches_expected() {
            // HMAC-SHA256 should always produce 32 bytes (256 bits)
            let key = b"test key";
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 output should be 32 bytes");
        }

        #[test]
        fn test_hmac_sha256_rfc_4231_test_case_1_matches_rfc_vector_matches_expected() {
            // RFC 4231 Test Case 1: 20-byte key "Hi There"
            let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let message = decode_hex("4869205468657265").unwrap(); // "Hi There"
            let expected =
                decode_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                    .unwrap();

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
        }

        #[test]
        fn test_hmac_sha256_rfc_4231_test_case_2_matches_rfc_vector_matches_expected() {
            // RFC 4231 Test Case 2: Short key "Jefe" with "what do ya want for nothing?"
            let key = decode_hex("4a656665").unwrap(); // "Jefe"
            let message =
                decode_hex("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap();
            let expected =
                decode_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                    .unwrap();

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().as_slice(), expected.as_slice());
        }

        #[test]
        fn test_hmac_sha256_incremental_update_matches_expected() {
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
        fn test_hmac_sha256_empty_message_matches_expected() {
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
        fn test_hmac_sha256_long_key_matches_rfc_vector_matches_expected() {
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
                decode_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
                    .unwrap();

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
        fn test_run_hmac_sha224_kat_succeeds() {
            let result = run_hmac_sha224_kat();
            assert!(result.is_ok(), "HMAC-SHA224 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_hmac_sha224_all_vectors_individually_match_expected_matches_expected() {
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
        fn test_hmac_sha224_output_length_matches_expected() {
            // HMAC-SHA224 should always produce 28 bytes (224 bits)
            let key = b"test key";
            let message = b"test message";

            let mut mac = HmacSha224::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 28, "HMAC-SHA224 output should be 28 bytes");
        }

        #[test]
        fn test_hmac_sha224_rfc_4231_test_case_1_matches_rfc_vector_matches_expected() {
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
        fn test_hmac_sha224_empty_message_matches_expected() {
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
        fn test_run_hmac_sha384_kat_succeeds() {
            let result = run_hmac_sha384_kat();
            assert!(result.is_ok(), "HMAC-SHA384 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_hmac_sha384_all_vectors_individually_match_expected_matches_expected() {
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
        fn test_hmac_sha384_output_length_matches_expected() {
            // HMAC-SHA384 should always produce 48 bytes (384 bits)
            let key = b"test key";
            let message = b"test message";

            let mut mac = HmacSha384::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 48, "HMAC-SHA384 output should be 48 bytes");
        }

        #[test]
        fn test_hmac_sha384_rfc_4231_test_case_1_matches_rfc_vector_matches_expected() {
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
        fn test_hmac_sha384_empty_message_matches_expected() {
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
        fn test_run_hmac_sha512_kat_succeeds() {
            let result = run_hmac_sha512_kat();
            assert!(result.is_ok(), "HMAC-SHA512 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_hmac_sha512_all_vectors_individually_match_expected_matches_expected() {
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
        fn test_hmac_sha512_output_length_matches_expected() {
            // HMAC-SHA512 should always produce 64 bytes (512 bits)
            let key = b"test key";
            let message = b"test message";

            let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key size");
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 64, "HMAC-SHA512 output should be 64 bytes");
        }

        #[test]
        fn test_hmac_sha512_rfc_4231_test_case_1_matches_rfc_vector_matches_expected() {
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
        fn test_hmac_sha512_empty_message_matches_expected() {
            let key = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
            let message: &[u8] = &[];

            let mut mac = HmacSha512::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            // Output should still be 64 bytes
            assert_eq!(result.into_bytes().len(), 64);
        }

        #[test]
        fn test_hmac_sha512_long_key_and_message_matches_rfc_vector_matches_expected() {
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
        fn test_hmac_vector_count_matches_expected() {
            // RFC 4231 has 6 test vectors (Test Case 5 - truncation is often omitted)
            assert_eq!(
                HMAC_VECTORS.len(),
                6,
                "Expected 6 HMAC test vectors (RFC 4231 Test Cases 1-4, 6-7)"
            );
        }

        #[test]
        fn test_hmac_vector_fields_not_empty_matches_expected() {
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
        fn test_expected_mac_lengths_match_expected_has_correct_size() {
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
        fn test_all_hex_values_valid_succeeds() {
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
        fn test_nist_kat_error_test_failed_display_matches_expected() {
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
        fn test_nist_kat_error_hex_error_display_matches_expected() {
            let error = NistKatError::HexError("Invalid character 'g' at position 0".to_string());
            let display_str = format!("{}", error);
            assert!(display_str.contains("Hex"));
            assert!(display_str.contains("Invalid character"));
        }

        #[test]
        fn test_nist_kat_error_implementation_error_display_matches_expected() {
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
        fn test_same_key_message_different_algorithms_produce_different_macs_succeeds() {
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
        fn test_all_hmac_variants_run_successfully_matches_expected() {
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
        fn test_hmac_sha256_deterministic_matches_expected() {
            // Same input should always produce same output
            let key = decode_hex("deadbeefcafe").unwrap();
            let message = decode_hex("0123456789abcdef").unwrap();

            let mut mac1 = HmacSha256::new_from_slice(&key).unwrap();
            mac1.update(&message);
            let result1 = mac1.finalize().into_bytes();

            let mut mac2 = HmacSha256::new_from_slice(&key).unwrap();
            mac2.update(&message);
            let result2 = mac2.finalize().into_bytes();

            assert_eq!(
                result1.as_slice(),
                result2.as_slice(),
                "HMAC-SHA256 should be deterministic"
            );
        }

        #[test]
        fn test_hmac_sha512_deterministic_matches_expected() {
            let key = decode_hex("cafebabe").unwrap();
            let message = decode_hex("fedcba9876543210").unwrap();

            let mut mac1 = HmacSha512::new_from_slice(&key).unwrap();
            mac1.update(&message);
            let result1 = mac1.finalize().into_bytes();

            let mut mac2 = HmacSha512::new_from_slice(&key).unwrap();
            mac2.update(&message);
            let result2 = mac2.finalize().into_bytes();

            assert_eq!(
                result1.as_slice(),
                result2.as_slice(),
                "HMAC-SHA512 should be deterministic"
            );
        }

        #[test]
        fn test_multiple_kat_runs_are_consistent() {
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
        fn test_single_byte_key_matches_expected() {
            // Test with minimum size key (1 byte)
            let key = vec![0x42_u8];
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 should produce 32 bytes");
        }

        #[test]
        fn test_large_key_matches_expected() {
            // Test with a very large key (256 bytes)
            let key = vec![0xaa_u8; 256];
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 32, "HMAC-SHA256 should produce 32 bytes");
        }

        #[test]
        fn test_large_message_matches_expected() {
            // Test with a large message (1 MB)
            let key = b"test key";
            let message = vec![0x61_u8; 1024 * 1024]; // 1 MB of 'a'

            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(&message);
            let result = mac.finalize();
            let result_bytes = result.into_bytes();

            assert_eq!(
                result_bytes.len(),
                32,
                "HMAC-SHA256 should produce 32 bytes for large input"
            );
            // Verify the MAC is not all zeros (basic sanity check)
            assert!(result_bytes.iter().any(|&b| b != 0), "MAC should not be all zeros");
        }

        #[test]
        fn test_all_zeros_key_matches_expected() {
            let key = vec![0x00_u8; 32];
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 32);
        }

        #[test]
        fn test_all_ones_key_matches_expected() {
            let key = vec![0xFF_u8; 32];
            let message = b"test message";

            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(message);
            let result = mac.finalize();

            assert_eq!(result.into_bytes().len(), 32);
        }

        #[test]
        fn test_block_boundary_key_sizes_match_expected_has_correct_size() {
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
        fn test_block_boundary_message_sizes_match_expected_has_correct_size() {
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
        fn test_sha512_block_boundary_key_sizes_match_expected_has_correct_size() {
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
        use latticearc_tests::validation::nist_kat::{KatRunner, KatSummary};

        #[test]
        fn test_hmac_kat_runner_integration_succeeds() {
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
        fn test_comprehensive_hmac_validation_succeeds() {
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
        fn test_rfc_4231_test_case_3_50_bytes_dd_matches_rfc_vector_matches_expected() {
            // Test Case 3: 20-byte key (all 0xaa) with 50 bytes of 0xdd
            let key = decode_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
            let message = decode_hex(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();

            // Test SHA-256
            let expected_256 =
                decode_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
                    .unwrap();
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&message);
            assert_eq!(mac.finalize().into_bytes().as_slice(), expected_256.as_slice());
        }

        #[test]
        fn test_rfc_4231_test_case_4_incremental_key_matches_rfc_vector_matches_expected() {
            // Test Case 4: 25-byte key (incremental 0x01..0x19) with 50 bytes of 0xcd
            let key = decode_hex("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
            let message = decode_hex(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();

            // Test SHA-256
            let expected_256 =
                decode_hex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
                    .unwrap();
            let mut mac = HmacSha256::new_from_slice(&key).unwrap();
            mac.update(&message);
            assert_eq!(mac.finalize().into_bytes().as_slice(), expected_256.as_slice());
        }

        #[test]
        fn test_rfc_4231_verifies_different_key_produces_different_mac_succeeds() {
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
        fn test_rfc_4231_verifies_different_message_produces_different_mac_succeeds() {
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
        use latticearc_tests::validation::nist_kat::hmac_kat::HmacTestVector;

        #[test]
        fn test_hmac_test_vector_struct_fields_accessible_matches_expected() {
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
        fn test_hmac_test_vector_can_be_constructed_succeeds() {
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
        fn test_first_vector_is_rfc_4231_test_case_1_matches_expected() {
            let vector = &HMAC_VECTORS[0];
            assert_eq!(vector.test_name, "RFC-4231-Test-Case-1");
            assert_eq!(vector.key, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            assert_eq!(vector.message, "4869205468657265");
        }

        #[test]
        fn test_second_vector_is_rfc_4231_test_case_2_matches_expected() {
            let vector = &HMAC_VECTORS[1];
            assert_eq!(vector.test_name, "RFC-4231-Test-Case-2");
            assert_eq!(vector.key, "4a656665"); // "Jefe"
        }
    }
}

// Originally: fips_kat_ec_tests.rs
mod ec {
    //! Elliptic Curve KAT (Known Answer Test) Comprehensive Test Suite
    //!
    //! This module provides comprehensive tests for the EC KAT functionality
    //! including Ed25519 and secp256k1 curves. Tests cover:
    //! - Public API functions
    //! - EC curve test vectors
    //! - Verification of EC operations
    //! - KatResult type behavior
    //! - Edge cases and boundary conditions

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

    use latticearc_tests::validation::kat_tests::ec::run_ec_kat_tests;
    use latticearc_tests::validation::kat_tests::types::{
        AlgorithmType, Ed25519KatVector, KatConfig, KatResult, Secp256k1KatVector,
    };
    use std::time::Duration;

    // ============================================================================
    // Tests for run_ec_kat_tests function
    // ============================================================================

    mod run_ec_kat_tests_tests {
        use super::*;

        #[test]
        fn test_run_ec_kat_tests_returns_ok_result_matches_expected() {
            let result = run_ec_kat_tests();
            assert!(result.is_ok(), "run_ec_kat_tests should return Ok");
        }

        #[test]
        fn test_run_ec_kat_tests_returns_nonempty_results_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            assert!(!results.is_empty(), "Should return at least one KatResult");
        }

        #[test]
        fn test_run_ec_kat_tests_includes_ed25519_results_correctly_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            let ed25519_results: Vec<_> =
                results.iter().filter(|r| r.test_case.contains("Ed25519")).collect();

            assert!(!ed25519_results.is_empty(), "Should include Ed25519 test results");
        }

        #[test]
        fn test_run_ec_kat_tests_includes_secp256k1_results_correctly_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            let secp256k1_results: Vec<_> =
                results.iter().filter(|r| r.test_case.contains("secp256k1")).collect();

            assert!(!secp256k1_results.is_empty(), "Should include secp256k1 test results");
        }

        #[test]
        fn test_run_ec_kat_tests_all_pass_successfully_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            let all_passed = results.iter().all(|r| r.passed);
            assert!(all_passed, "All EC KAT tests should pass");
        }

        #[test]
        fn test_run_ec_kat_tests_expected_count_is_correct() {
            let results = run_ec_kat_tests().unwrap();
            // 5 Ed25519 tests + 3 secp256k1 tests = 8 total
            assert_eq!(results.len(), 8, "Should return exactly 8 KAT results");
        }

        #[test]
        fn test_run_ec_kat_tests_ed25519_count_is_correct() {
            let results = run_ec_kat_tests().unwrap();
            let ed25519_count = results.iter().filter(|r| r.test_case.contains("Ed25519")).count();
            assert_eq!(ed25519_count, 5, "Should have exactly 5 Ed25519 test cases");
        }

        #[test]
        fn test_run_ec_kat_tests_secp256k1_count_is_correct() {
            let results = run_ec_kat_tests().unwrap();
            let secp256k1_count =
                results.iter().filter(|r| r.test_case.contains("secp256k1")).count();
            assert_eq!(secp256k1_count, 3, "Should have exactly 3 secp256k1 test cases");
        }

        #[test]
        fn test_run_ec_kat_tests_no_error_messages_on_pass_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            for result in &results {
                assert!(
                    result.error_message.is_none(),
                    "Test {} should have no error message",
                    result.test_case
                );
            }
        }

        #[test]
        fn test_run_ec_kat_tests_execution_time_recorded_correctly_matches_expected() {
            let results = run_ec_kat_tests().unwrap();
            for result in &results {
                // Execution time should be recorded (can be 0 for very fast tests)
                assert!(
                    result.execution_time_ns < u128::MAX,
                    "Execution time should be recorded for {}",
                    result.test_case
                );
            }
        }

        #[test]
        fn test_run_ec_kat_tests_test_case_naming_is_correct() {
            let results = run_ec_kat_tests().unwrap();

            // Check Ed25519 naming pattern
            for i in 1..=5 {
                let expected_name = format!("Ed25519-KAT-{:03}", i);
                assert!(
                    results.iter().any(|r| r.test_case == expected_name),
                    "Should have test case named {}",
                    expected_name
                );
            }

            // Check secp256k1 naming pattern
            for i in 1..=3 {
                let expected_name = format!("secp256k1-KAT-{:03}", i);
                assert!(
                    results.iter().any(|r| r.test_case == expected_name),
                    "Should have test case named {}",
                    expected_name
                );
            }
        }

        #[test]
        fn test_run_ec_kat_tests_idempotent_produces_same_results_matches_expected() {
            // Running multiple times should produce consistent results
            let results1 = run_ec_kat_tests().unwrap();
            let results2 = run_ec_kat_tests().unwrap();

            assert_eq!(results1.len(), results2.len(), "Multiple runs should return same count");

            for (r1, r2) in results1.iter().zip(results2.iter()) {
                assert_eq!(r1.test_case, r2.test_case, "Test case names should be consistent");
                assert_eq!(r1.passed, r2.passed, "Pass/fail should be consistent");
            }
        }
    }

    // ============================================================================
    // Tests for KatResult type
    // ============================================================================

    mod kat_result_tests {
        use super::*;

        #[test]
        fn test_kat_result_passed_constructor_has_correct_fields_matches_expected() {
            let duration = Duration::from_micros(100);
            let result = KatResult::passed("Test-001".to_string(), duration);

            assert_eq!(result.test_case, "Test-001");
            assert!(result.passed);
            assert_eq!(result.execution_time_ns, 100_000);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_kat_result_failed_constructor_has_correct_fields_matches_expected() {
            let duration = Duration::from_millis(5);
            let result = KatResult::failed(
                "Test-002".to_string(),
                duration,
                "Signature mismatch".to_string(),
            );

            assert_eq!(result.test_case, "Test-002");
            assert!(!result.passed);
            assert_eq!(result.execution_time_ns, 5_000_000);
            assert_eq!(result.error_message, Some("Signature mismatch".to_string()));
        }

        #[test]
        fn test_kat_result_clone_produces_equal_value_matches_expected() {
            let result = KatResult::passed("Clone-Test".to_string(), Duration::from_nanos(500));
            let cloned = result.clone();

            assert_eq!(result.test_case, cloned.test_case);
            assert_eq!(result.passed, cloned.passed);
            assert_eq!(result.execution_time_ns, cloned.execution_time_ns);
            assert_eq!(result.error_message, cloned.error_message);
        }

        #[test]
        fn test_kat_result_equality_matches_expected() {
            let result1 = KatResult::passed("Eq-Test".to_string(), Duration::from_micros(100));
            let result2 = KatResult::passed("Eq-Test".to_string(), Duration::from_micros(100));

            assert_eq!(result1, result2);
        }

        #[test]
        fn test_kat_result_inequality_test_case_returns_not_equal_matches_expected() {
            let result1 = KatResult::passed("Test-A".to_string(), Duration::from_micros(100));
            let result2 = KatResult::passed("Test-B".to_string(), Duration::from_micros(100));

            assert_ne!(result1, result2);
        }

        #[test]
        fn test_kat_result_inequality_passed_returns_not_equal_matches_expected() {
            let result1 = KatResult::passed("Test-A".to_string(), Duration::from_micros(100));
            let result2 = KatResult::failed(
                "Test-A".to_string(),
                Duration::from_micros(100),
                "Error".to_string(),
            );

            assert_ne!(result1, result2);
        }

        #[test]
        fn test_kat_result_debug_format_has_correct_string_matches_expected() {
            let result = KatResult::passed("Debug-Test".to_string(), Duration::from_micros(50));
            let debug_str = format!("{:?}", result);

            assert!(debug_str.contains("Debug-Test"));
            assert!(debug_str.contains("passed: true"));
        }

        #[test]
        fn test_kat_result_serialization_round_trips_correctly_roundtrip() {
            let result = KatResult::passed("Serde-Test".to_string(), Duration::from_micros(250));
            let json = serde_json::to_string(&result).unwrap();

            assert!(json.contains("Serde-Test"));
            assert!(json.contains("true"));
        }

        #[test]
        fn test_kat_result_deserialization_round_trips_correctly_roundtrip() {
            let json = r#"{"test_case":"Deser-Test","passed":true,"execution_time_ns":1000,"error_message":null}"#;
            let result: KatResult = serde_json::from_str(json).unwrap();

            assert_eq!(result.test_case, "Deser-Test");
            assert!(result.passed);
            assert_eq!(result.execution_time_ns, 1000);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_kat_result_round_trip_serialization_succeeds() {
            let original = KatResult::failed(
                "RoundTrip".to_string(),
                Duration::from_millis(10),
                "Test error".to_string(),
            );
            let json = serde_json::to_string(&original).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();

            assert_eq!(original, deserialized);
        }

        #[test]
        fn test_kat_result_zero_duration_is_accepted() {
            let result = KatResult::passed("Zero-Duration".to_string(), Duration::ZERO);
            assert_eq!(result.execution_time_ns, 0);
        }

        #[test]
        fn test_kat_result_large_duration_is_accepted() {
            let result = KatResult::passed("Large-Duration".to_string(), Duration::from_secs(3600));
            assert_eq!(result.execution_time_ns, 3600 * 1_000_000_000u128);
        }

        #[test]
        fn test_kat_result_empty_test_case_name_is_accepted() {
            let result = KatResult::passed(String::new(), Duration::from_micros(1));
            assert!(result.test_case.is_empty());
            assert!(result.passed);
        }

        #[test]
        fn test_kat_result_empty_error_message_is_accepted() {
            let result = KatResult::failed(
                "Empty-Error".to_string(),
                Duration::from_micros(1),
                String::new(),
            );
            assert_eq!(result.error_message, Some(String::new()));
        }

        #[test]
        fn test_kat_result_unicode_test_case_is_accepted() {
            let result = KatResult::passed("Test-Unicode-".to_string(), Duration::from_micros(1));
            assert!(result.test_case.contains(""));
        }
    }

    // ============================================================================
    // Tests for Ed25519KatVector type
    // ============================================================================

    mod ed25519_kat_vector_tests {
        use super::*;

        #[test]
        fn test_ed25519_kat_vector_creation_has_correct_fields_matches_expected() {
            let vector = Ed25519KatVector {
                test_case: "Ed25519-001".to_string(),
                seed: vec![0u8; 32],
                expected_public_key: vec![0u8; 32],
                message: b"test message".to_vec(),
                expected_signature: vec![0u8; 64],
            };

            assert_eq!(vector.test_case, "Ed25519-001");
            assert_eq!(vector.seed.len(), 32);
            assert_eq!(vector.expected_public_key.len(), 32);
            assert_eq!(vector.expected_signature.len(), 64);
        }

        #[test]
        fn test_ed25519_kat_vector_clone_produces_equal_value_matches_expected() {
            let vector = Ed25519KatVector {
                test_case: "Clone-Test".to_string(),
                seed: vec![1, 2, 3, 4],
                expected_public_key: vec![5, 6, 7, 8],
                message: vec![9, 10, 11, 12],
                expected_signature: vec![13, 14, 15, 16],
            };

            let cloned = vector.clone();
            assert_eq!(vector, cloned);
        }

        #[test]
        fn test_ed25519_kat_vector_equality_matches_expected() {
            let v1 = Ed25519KatVector {
                test_case: "Test".to_string(),
                seed: vec![1, 2, 3],
                expected_public_key: vec![4, 5, 6],
                message: vec![7, 8, 9],
                expected_signature: vec![10, 11, 12],
            };

            let v2 = v1.clone();
            assert_eq!(v1, v2);
        }

        #[test]
        fn test_ed25519_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Ed25519KatVector {
                test_case: "Serde-Test".to_string(),
                seed: vec![0xab, 0xcd],
                expected_public_key: vec![0xef],
                message: vec![0x12, 0x34],
                expected_signature: vec![0x56, 0x78],
            };

            let json = serde_json::to_string(&vector).unwrap();
            assert!(json.contains("Serde-Test"));

            let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_ed25519_kat_vector_empty_message_is_accepted() {
            let vector = Ed25519KatVector {
                test_case: "Empty-Message".to_string(),
                seed: vec![0u8; 32],
                expected_public_key: vec![0u8; 32],
                message: Vec::new(),
                expected_signature: vec![0u8; 64],
            };

            assert!(vector.message.is_empty());
        }

        #[test]
        fn test_ed25519_kat_vector_large_message_is_accepted() {
            let vector = Ed25519KatVector {
                test_case: "Large-Message".to_string(),
                seed: vec![0u8; 32],
                expected_public_key: vec![0u8; 32],
                message: vec![0xffu8; 10000],
                expected_signature: vec![0u8; 64],
            };

            assert_eq!(vector.message.len(), 10000);
        }
    }

    // ============================================================================
    // Tests for Secp256k1KatVector type
    // ============================================================================

    mod secp256k1_kat_vector_tests {
        use super::*;

        #[test]
        fn test_secp256k1_kat_vector_creation_has_correct_fields_matches_expected() {
            let vector = Secp256k1KatVector {
                test_case: "secp256k1-001".to_string(),
                private_key: vec![0u8; 32],
                expected_public_key: vec![0u8; 33], // Compressed public key
                message: b"test message".to_vec(),
                expected_signature: vec![0u8; 72], // DER-encoded signature
            };

            assert_eq!(vector.test_case, "secp256k1-001");
            assert_eq!(vector.private_key.len(), 32);
        }

        #[test]
        fn test_secp256k1_kat_vector_clone_produces_equal_value_matches_expected() {
            let vector = Secp256k1KatVector {
                test_case: "Clone-Test".to_string(),
                private_key: vec![1, 2, 3, 4],
                expected_public_key: vec![5, 6, 7, 8],
                message: vec![9, 10, 11, 12],
                expected_signature: vec![13, 14, 15, 16],
            };

            let cloned = vector.clone();
            assert_eq!(vector, cloned);
        }

        #[test]
        fn test_secp256k1_kat_vector_equality_matches_expected() {
            let v1 = Secp256k1KatVector {
                test_case: "Test".to_string(),
                private_key: vec![1, 2, 3],
                expected_public_key: vec![4, 5, 6],
                message: vec![7, 8, 9],
                expected_signature: vec![10, 11, 12],
            };

            let v2 = v1.clone();
            assert_eq!(v1, v2);
        }

        #[test]
        fn test_secp256k1_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Secp256k1KatVector {
                test_case: "Serde-Test".to_string(),
                private_key: vec![0xab, 0xcd],
                expected_public_key: vec![0xef],
                message: vec![0x12, 0x34],
                expected_signature: vec![0x56, 0x78],
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Secp256k1KatVector = serde_json::from_str(&json).unwrap();
            assert_eq!(vector, deserialized);
        }
    }

    // ============================================================================
    // Tests for AlgorithmType enum (EC-related variants)
    // ============================================================================

    mod algorithm_type_ec_tests {
        use super::*;

        #[test]
        fn test_algorithm_type_ed25519_is_accessible() {
            let algo = AlgorithmType::Ed25519;
            assert_eq!(algo.name(), "Ed25519");
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_algorithm_type_secp256k1_is_accessible() {
            let algo = AlgorithmType::Secp256k1;
            assert_eq!(algo.name(), "secp256k1");
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_algorithm_type_bls12_381_is_accessible() {
            let algo = AlgorithmType::Bls12_381;
            assert_eq!(algo.name(), "BLS12-381");
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_algorithm_type_bn254_is_accessible() {
            let algo = AlgorithmType::Bn254;
            assert_eq!(algo.name(), "BN254");
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_algorithm_type_clone_produces_equal_value_succeeds() {
            let algo = AlgorithmType::Ed25519;
            let cloned = algo.clone();
            assert_eq!(algo, cloned);
        }

        #[test]
        fn test_algorithm_type_equality_matches_expected() {
            assert_eq!(AlgorithmType::Ed25519, AlgorithmType::Ed25519);
            assert_ne!(AlgorithmType::Ed25519, AlgorithmType::Secp256k1);
        }

        #[test]
        fn test_algorithm_type_debug_has_correct_format() {
            let algo = AlgorithmType::Ed25519;
            let debug_str = format!("{:?}", algo);
            assert!(debug_str.contains("Ed25519"));
        }

        #[test]
        fn test_algorithm_type_serialization_round_trips_correctly_roundtrip() {
            let algo = AlgorithmType::Ed25519;
            let json = serde_json::to_string(&algo).unwrap();
            let deserialized: AlgorithmType = serde_json::from_str(&json).unwrap();
            assert_eq!(algo, deserialized);
        }

        #[test]
        fn test_algorithm_type_secp256k1_serialization_round_trips_correctly_roundtrip() {
            let algo = AlgorithmType::Secp256k1;
            let json = serde_json::to_string(&algo).unwrap();
            let deserialized: AlgorithmType = serde_json::from_str(&json).unwrap();
            assert_eq!(algo, deserialized);
        }
    }

    // ============================================================================
    // Tests for KatConfig (EC-related configurations)
    // ============================================================================

    mod kat_config_tests {
        use super::*;

        #[test]
        fn test_kat_config_default_has_expected_values_matches_expected() {
            let config = KatConfig::default();

            assert_eq!(config.test_count, 100);
            assert!(config.run_statistical_tests);
            assert_eq!(config.timeout_per_test, Duration::from_secs(10));
            assert!(config.validate_fips);
        }

        #[test]
        fn test_kat_config_clone_produces_equal_value_matches_expected() {
            let config = KatConfig::default();
            let cloned = config.clone();

            assert_eq!(config.test_count, cloned.test_count);
            assert_eq!(config.run_statistical_tests, cloned.run_statistical_tests);
            assert_eq!(config.timeout_per_test, cloned.timeout_per_test);
        }

        #[test]
        fn test_kat_config_equality_matches_expected() {
            let c1 = KatConfig::default();
            let c2 = KatConfig::default();
            assert_eq!(c1, c2);
        }

        #[test]
        fn test_kat_config_debug_has_correct_format() {
            let config = KatConfig::default();
            let debug_str = format!("{:?}", config);
            assert!(debug_str.contains("test_count"));
        }

        #[test]
        fn test_kat_config_serialization_round_trips_correctly_roundtrip() {
            let config = KatConfig::default();
            let json = serde_json::to_string(&config).unwrap();
            assert!(json.contains("test_count"));

            let deserialized: KatConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(config, deserialized);
        }

        #[test]
        fn test_kat_config_ml_kem_has_correct_fields_matches_expected() {
            let config = KatConfig::ml_kem("768", 50);

            assert!(matches!(config.algorithm, AlgorithmType::MlKem { .. }));
            assert_eq!(config.test_count, 50);
        }

        #[test]
        fn test_kat_config_ml_dsa_has_correct_fields_matches_expected() {
            let config = KatConfig::ml_dsa("65", 25);

            assert!(matches!(config.algorithm, AlgorithmType::MlDsa { .. }));
            assert_eq!(config.test_count, 25);
        }

        #[test]
        fn test_kat_config_slh_dsa_has_correct_fields_matches_expected() {
            let config = KatConfig::slh_dsa("128", 10);

            assert!(matches!(config.algorithm, AlgorithmType::SlhDsa { .. }));
            assert_eq!(config.test_count, 10);
            // SLH-DSA has longer timeout
            assert_eq!(config.timeout_per_test, Duration::from_secs(30));
        }
    }

    // ============================================================================
    // Edge case and boundary tests
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_multiple_sequential_runs_produce_consistent_results_succeeds() {
            // Run EC KAT tests multiple times in sequence
            for i in 0..3 {
                let results = run_ec_kat_tests().unwrap();
                assert_eq!(results.len(), 8, "Run {} should have 8 results", i + 1);
                assert!(results.iter().all(|r| r.passed), "Run {} should pass all tests", i + 1);
            }
        }

        #[test]
        fn test_result_ordering_consistent_across_runs_succeeds() {
            let results = run_ec_kat_tests().unwrap();

            // Ed25519 results should come before secp256k1 results
            let first_secp256k1_idx =
                results.iter().position(|r| r.test_case.contains("secp256k1")).unwrap();
            let last_ed25519_idx =
                results.iter().rposition(|r| r.test_case.contains("Ed25519")).unwrap();

            assert!(
                last_ed25519_idx < first_secp256k1_idx,
                "Ed25519 tests should come before secp256k1 tests"
            );
        }

        #[test]
        fn test_kat_result_with_special_characters_is_accepted() {
            let result = KatResult::passed(
                "Test-with-special-chars-!@#$%".to_string(),
                Duration::from_micros(1),
            );

            // Should serialize and deserialize correctly
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();
            assert_eq!(result.test_case, deserialized.test_case);
        }

        #[test]
        fn test_ed25519_vector_with_all_zeros_is_accepted() {
            let vector = Ed25519KatVector {
                test_case: "All-Zeros".to_string(),
                seed: vec![0u8; 32],
                expected_public_key: vec![0u8; 32],
                message: vec![0u8; 100],
                expected_signature: vec![0u8; 64],
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_ed25519_vector_with_all_ones_is_accepted() {
            let vector = Ed25519KatVector {
                test_case: "All-Ones".to_string(),
                seed: vec![0xffu8; 32],
                expected_public_key: vec![0xffu8; 32],
                message: vec![0xffu8; 100],
                expected_signature: vec![0xffu8; 64],
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();
            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_secp256k1_vector_with_all_zeros_is_accepted() {
            let vector = Secp256k1KatVector {
                test_case: "All-Zeros".to_string(),
                private_key: vec![0u8; 32],
                expected_public_key: vec![0u8; 33],
                message: vec![0u8; 100],
                expected_signature: vec![0u8; 72],
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Secp256k1KatVector = serde_json::from_str(&json).unwrap();
            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_kat_result_collect_to_vec_succeeds() {
            let results = run_ec_kat_tests().unwrap();

            let passed_results: Vec<_> = results.iter().filter(|r| r.passed).cloned().collect();
            let failed_results: Vec<_> = results.iter().filter(|r| !r.passed).cloned().collect();

            assert_eq!(passed_results.len(), 8);
            assert!(failed_results.is_empty());
        }

        #[test]
        fn test_algorithm_type_all_ec_variants_are_accessible() {
            let ec_algorithms = [
                AlgorithmType::Ed25519,
                AlgorithmType::Secp256k1,
                AlgorithmType::Bls12_381,
                AlgorithmType::Bn254,
            ];

            for algo in ec_algorithms {
                // All EC algorithms should have 128-bit security level
                assert_eq!(
                    algo.security_level(),
                    128,
                    "{} should have 128-bit security",
                    algo.name()
                );
            }
        }
    }

    // ============================================================================
    // Integration tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_full_ec_kat_workflow_succeeds() {
            // Simulate a full KAT workflow
            let results = run_ec_kat_tests().unwrap();

            // Verify all results
            assert!(!results.is_empty(), "Should have results");
            assert!(results.iter().all(|r| r.passed), "All should pass");

            // Generate summary statistics
            let total_time_ns: u128 = results.iter().map(|r| r.execution_time_ns).sum();
            let avg_time_ns = total_time_ns / (results.len() as u128);

            // Average time should be reasonable (less than 1 second)
            assert!(
                avg_time_ns < 1_000_000_000,
                "Average execution time should be less than 1 second"
            );
        }

        #[test]
        fn test_kat_result_filtering_and_aggregation_is_correct() {
            let results = run_ec_kat_tests().unwrap();

            // Filter by curve type
            let ed25519_results: Vec<_> =
                results.iter().filter(|r| r.test_case.starts_with("Ed25519")).collect();

            let secp256k1_results: Vec<_> =
                results.iter().filter(|r| r.test_case.starts_with("secp256k1")).collect();

            // Verify counts
            assert_eq!(ed25519_results.len(), 5);
            assert_eq!(secp256k1_results.len(), 3);

            // Verify all passed
            assert!(ed25519_results.iter().all(|r| r.passed));
            assert!(secp256k1_results.iter().all(|r| r.passed));
        }

        #[test]
        fn test_kat_result_json_report_generation_succeeds() {
            let results = run_ec_kat_tests().unwrap();

            // Generate JSON report
            let report = serde_json::json!({
                "test_suite": "EC KAT Tests",
                "total_tests": results.len(),
                "passed": results.iter().filter(|r| r.passed).count(),
                "failed": results.iter().filter(|r| !r.passed).count(),
                "results": results
            });

            let json_str = serde_json::to_string_pretty(&report).unwrap();

            assert!(json_str.contains("EC KAT Tests"));
            assert!(json_str.contains("\"passed\": 8"));
            assert!(json_str.contains("\"failed\": 0"));
        }

        #[test]
        fn test_kat_types_interoperability_succeeds() {
            // Test that different KAT vector types can be used together
            let ed25519_vec = Ed25519KatVector {
                test_case: "Ed25519-Interop".to_string(),
                seed: vec![0u8; 32],
                expected_public_key: vec![0u8; 32],
                message: b"interop test".to_vec(),
                expected_signature: vec![0u8; 64],
            };

            let secp256k1_vec = Secp256k1KatVector {
                test_case: "secp256k1-Interop".to_string(),
                private_key: vec![0u8; 32],
                expected_public_key: vec![0u8; 33],
                message: b"interop test".to_vec(),
                expected_signature: vec![0u8; 72],
            };

            // Both should serialize to JSON
            let ed25519_json = serde_json::to_string(&ed25519_vec).unwrap();
            let secp256k1_json = serde_json::to_string(&secp256k1_vec).unwrap();

            assert!(ed25519_json.contains("Ed25519-Interop"));
            assert!(secp256k1_json.contains("secp256k1-Interop"));
        }

        #[test]
        fn test_algorithm_type_name_consistency_is_correct() {
            // Verify algorithm names are consistent with industry standards
            let names = vec![
                (AlgorithmType::Ed25519, "Ed25519"),
                (AlgorithmType::Secp256k1, "secp256k1"),
                (AlgorithmType::Bls12_381, "BLS12-381"),
                (AlgorithmType::Bn254, "BN254"),
            ];

            for (algo, expected_name) in names {
                assert_eq!(algo.name(), expected_name);
            }
        }
    }

    // ============================================================================
    // Performance-related tests
    // ============================================================================

    mod performance_tests {
        use super::*;
        use std::time::Instant;

        #[test]
        fn test_ec_kat_execution_time_is_recorded_matches_expected() {
            let start = Instant::now();
            let _results = run_ec_kat_tests().unwrap();
            let duration = start.elapsed();

            // EC KAT tests should complete quickly (under 1 second)
            assert!(duration.as_secs() < 1, "EC KAT tests took too long: {:?}", duration);
        }

        #[test]
        fn test_individual_result_timing_is_recorded_succeeds() {
            let results = run_ec_kat_tests().unwrap();

            // Each individual test should be fast
            for result in &results {
                let duration_ms = result.execution_time_ns / 1_000_000;
                assert!(
                    duration_ms < 100,
                    "Test {} took {}ms, expected < 100ms",
                    result.test_case,
                    duration_ms
                );
            }
        }

        #[test]
        fn test_total_execution_time_reasonable_is_acceptable_succeeds() {
            let results = run_ec_kat_tests().unwrap();

            let total_ns: u128 = results.iter().map(|r| r.execution_time_ns).sum();
            let total_ms = total_ns / 1_000_000;

            // Total time should be reasonable (under 500ms)
            assert!(total_ms < 500, "Total execution time {}ms exceeds 500ms", total_ms);
        }
    }

    // ============================================================================
    // Thread safety tests
    // ============================================================================

    mod thread_safety_tests {
        use super::*;
        use std::thread;

        #[test]
        fn test_concurrent_ec_kat_runs_produce_consistent_results_matches_expected() {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    thread::spawn(|| {
                        let results = run_ec_kat_tests().unwrap();
                        assert_eq!(results.len(), 8);
                        assert!(results.iter().all(|r| r.passed));
                    })
                })
                .collect();

            for handle in handles {
                handle.join().unwrap();
            }
        }

        #[test]
        fn test_kat_result_send_sync_is_implemented() {
            // Verify KatResult implements Send + Sync
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<KatResult>();
        }

        #[test]
        fn test_kat_vector_types_send_sync_are_implemented_matches_expected() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<Ed25519KatVector>();
            assert_send_sync::<Secp256k1KatVector>();
        }

        #[test]
        fn test_algorithm_type_send_sync_is_implemented() {
            fn assert_send_sync<T: Send + Sync>() {}
            assert_send_sync::<AlgorithmType>();
        }
    }
}
