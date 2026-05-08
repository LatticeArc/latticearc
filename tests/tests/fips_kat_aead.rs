//! FIPS AEAD KAT tests (AES-GCM, ChaCha20-Poly1305).
//!
//! Each sub-module preserves the structure and imports of its original
//! source file. Tests run as `fips_kat_aead::aes_gcm::*` and
//! `fips_kat_aead::chacha20_poly1305::*`.

#![deny(unsafe_code)]

// Originally: fips_aes_gcm_kat_tests.rs
mod aes_gcm {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::redundant_clone,
        clippy::useless_vec
    )]

    //! Comprehensive Tests for AES-GCM Known Answer Tests
    //!
    //! This module provides extensive test coverage for the AES-GCM KAT implementation
    //! in `arc-validation/src/nist_kat/aes_gcm_kat.rs`.
    //!
    //! ## Test Categories
    //! 1. AES-128-GCM KAT functions
    //! 2. AES-256-GCM KAT functions
    //! 3. Test vector validation
    //! 4. Error handling paths
    //! 5. Edge cases and boundary conditions

    use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    use latticearc_tests::validation::nist_kat::aes_gcm_kat::{
        AES_128_GCM_VECTORS, AES_256_GCM_VECTORS, AesGcmTestVector, run_aes_128_gcm_kat,
        run_aes_256_gcm_kat,
    };
    use latticearc_tests::validation::nist_kat::{NistKatError, decode_hex};

    // =============================================================================
    // AES-128-GCM KAT Tests
    // =============================================================================

    mod aes_128_gcm_tests {
        use super::*;

        #[test]
        fn test_run_aes_128_gcm_kat_all_vectors_pass_matches_expected() {
            let result = run_aes_128_gcm_kat();
            assert!(result.is_ok(), "AES-128-GCM KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_aes_128_gcm_vector_count_is_correct() {
            // Ensure we have expected number of test vectors
            assert!(
                AES_128_GCM_VECTORS.len() >= 3,
                "AES-128-GCM should have at least 3 test vectors, found {}",
                AES_128_GCM_VECTORS.len()
            );
        }

        #[test]
        fn test_aes_128_gcm_vector_names_have_correct_format_succeeds() {
            // Verify all test vectors have proper names
            for (i, vector) in AES_128_GCM_VECTORS.iter().enumerate() {
                assert!(
                    !vector.test_name.is_empty(),
                    "Vector {} should have a non-empty test name",
                    i
                );
                assert!(
                    vector.test_name.contains("AES-128-GCM"),
                    "Vector {} name should contain 'AES-128-GCM', got: {}",
                    i,
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_128_gcm_key_lengths_are_correct() {
            // AES-128 requires 16-byte (32 hex chars) keys
            for vector in AES_128_GCM_VECTORS {
                assert_eq!(
                    vector.key.len(),
                    32,
                    "AES-128-GCM key should be 32 hex chars (16 bytes), got {} for {}",
                    vector.key.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_128_gcm_nonce_lengths_are_correct() {
            // GCM nonces should be 12 bytes (24 hex chars)
            for vector in AES_128_GCM_VECTORS {
                assert_eq!(
                    vector.nonce.len(),
                    24,
                    "GCM nonce should be 24 hex chars (12 bytes), got {} for {}",
                    vector.nonce.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_128_gcm_tag_lengths_are_correct() {
            // GCM tags should be 16 bytes (32 hex chars)
            for vector in AES_128_GCM_VECTORS {
                assert_eq!(
                    vector.expected_tag.len(),
                    32,
                    "GCM tag should be 32 hex chars (16 bytes), got {} for {}",
                    vector.expected_tag.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_128_gcm_empty_plaintext_matches_expected() {
            // Test Case 1: Empty plaintext
            let vector = &AES_128_GCM_VECTORS[0];
            assert!(vector.plaintext.is_empty(), "First test vector should have empty plaintext");
            assert!(
                vector.expected_ciphertext.is_empty(),
                "Empty plaintext should produce empty ciphertext"
            );

            // Manually verify encryption
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = Vec::new();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            // For empty plaintext, output should be just the tag
            assert_eq!(
                in_out.len(),
                16,
                "Empty plaintext encryption should produce 16-byte tag only"
            );
            assert_eq!(in_out, expected_tag, "Tag mismatch for empty plaintext");
        }

        #[test]
        fn test_aes_128_gcm_128bit_plaintext_matches_nist_vector_matches_expected() {
            // Test Case 2: 128-bit plaintext
            let vector = &AES_128_GCM_VECTORS[1];
            assert_eq!(
                vector.plaintext.len(),
                32,
                "Second test vector should have 16-byte (32 hex) plaintext"
            );

            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            // Verify ciphertext + tag
            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);
            assert_eq!(in_out, expected_output, "Ciphertext+tag mismatch for 128-bit plaintext");
        }

        #[test]
        fn test_aes_128_gcm_256bit_plaintext_matches_nist_vector_matches_expected() {
            // Test Case 3: 256-bit plaintext with different key
            let vector = &AES_128_GCM_VECTORS[2];
            assert!(vector.plaintext.len() > 32, "Third test vector should have longer plaintext");

            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            // Verify ciphertext + tag
            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);
            assert_eq!(in_out, expected_output, "Ciphertext+tag mismatch for 256-bit plaintext");

            // Test decryption
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = decode_hex(vector.nonce).unwrap().try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let decrypted =
                key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut in_out).unwrap();

            assert_eq!(decrypted, plaintext.as_slice(), "Decrypted plaintext mismatch");
        }

        #[test]
        fn test_aes_128_gcm_all_vectors_individually_succeed_matches_expected() {
            for vector in AES_128_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();
                let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
                let expected_tag = decode_hex(vector.expected_tag).unwrap();

                let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);

                let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let mut in_out = plaintext.clone();
                key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out)
                    .unwrap();

                let mut expected_output = expected_ciphertext.clone();
                expected_output.extend_from_slice(&expected_tag);

                assert_eq!(
                    in_out, expected_output,
                    "AES-128-GCM test '{}' failed",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_128_gcm_roundtrip_succeeds() {
            for vector in AES_128_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();

                // Encrypt
                let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);
                let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let mut ciphertext = plaintext.clone();
                key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                    .unwrap();

                // Decrypt
                let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let key_2 = LessSafeKey::new(unbound_key_2);
                let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

                let decrypted = key_2
                    .open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext)
                    .unwrap();

                assert_eq!(
                    decrypted,
                    plaintext.as_slice(),
                    "Roundtrip failed for '{}'",
                    vector.test_name
                );
            }
        }
    }

    // =============================================================================
    // AES-256-GCM KAT Tests
    // =============================================================================

    mod aes_256_gcm_tests {
        use super::*;

        #[test]
        fn test_run_aes_256_gcm_kat_all_vectors_pass_matches_expected() {
            let result = run_aes_256_gcm_kat();
            assert!(result.is_ok(), "AES-256-GCM KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_aes_256_gcm_vector_count_is_correct() {
            assert!(
                AES_256_GCM_VECTORS.len() >= 3,
                "AES-256-GCM should have at least 3 test vectors, found {}",
                AES_256_GCM_VECTORS.len()
            );
        }

        #[test]
        fn test_aes_256_gcm_vector_names_have_correct_format_succeeds() {
            for (i, vector) in AES_256_GCM_VECTORS.iter().enumerate() {
                assert!(
                    !vector.test_name.is_empty(),
                    "Vector {} should have a non-empty test name",
                    i
                );
                assert!(
                    vector.test_name.contains("AES-256-GCM"),
                    "Vector {} name should contain 'AES-256-GCM', got: {}",
                    i,
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_key_lengths_are_correct() {
            // AES-256 requires 32-byte (64 hex chars) keys
            for vector in AES_256_GCM_VECTORS {
                assert_eq!(
                    vector.key.len(),
                    64,
                    "AES-256-GCM key should be 64 hex chars (32 bytes), got {} for {}",
                    vector.key.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_nonce_lengths_are_correct() {
            // GCM nonces should be 12 bytes (24 hex chars)
            for vector in AES_256_GCM_VECTORS {
                assert_eq!(
                    vector.nonce.len(),
                    24,
                    "GCM nonce should be 24 hex chars (12 bytes), got {} for {}",
                    vector.nonce.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_tag_lengths_are_correct() {
            // GCM tags should be 16 bytes (32 hex chars)
            for vector in AES_256_GCM_VECTORS {
                assert_eq!(
                    vector.expected_tag.len(),
                    32,
                    "GCM tag should be 32 hex chars (16 bytes), got {} for {}",
                    vector.expected_tag.len(),
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_empty_plaintext_matches_expected() {
            let vector = &AES_256_GCM_VECTORS[0];
            assert!(vector.plaintext.is_empty(), "First test vector should have empty plaintext");
            assert!(
                vector.expected_ciphertext.is_empty(),
                "Empty plaintext should produce empty ciphertext"
            );

            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = Vec::new();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            assert_eq!(
                in_out.len(),
                16,
                "Empty plaintext encryption should produce 16-byte tag only"
            );
            assert_eq!(in_out, expected_tag, "Tag mismatch for empty plaintext");
        }

        #[test]
        fn test_aes_256_gcm_128bit_plaintext_matches_nist_vector_matches_expected() {
            let vector = &AES_256_GCM_VECTORS[1];
            assert_eq!(
                vector.plaintext.len(),
                32,
                "Second test vector should have 16-byte (32 hex) plaintext"
            );

            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);
            assert_eq!(in_out, expected_output, "Ciphertext+tag mismatch for 128-bit plaintext");
        }

        #[test]
        fn test_aes_256_gcm_256bit_plaintext_matches_nist_vector_matches_expected() {
            let vector = &AES_256_GCM_VECTORS[2];
            assert!(vector.plaintext.len() > 32, "Third test vector should have longer plaintext");

            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);

            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut in_out = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);
            assert_eq!(in_out, expected_output, "Ciphertext+tag mismatch for 256-bit plaintext");

            // Test decryption
            let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = decode_hex(vector.nonce).unwrap().try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let decrypted =
                key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut in_out).unwrap();

            assert_eq!(decrypted, plaintext.as_slice(), "Decrypted plaintext mismatch");
        }

        #[test]
        fn test_aes_256_gcm_all_vectors_individually_succeed_matches_expected() {
            for vector in AES_256_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();
                let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
                let expected_tag = decode_hex(vector.expected_tag).unwrap();

                let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);

                let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let mut in_out = plaintext.clone();
                key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out)
                    .unwrap();

                let mut expected_output = expected_ciphertext.clone();
                expected_output.extend_from_slice(&expected_tag);

                assert_eq!(
                    in_out, expected_output,
                    "AES-256-GCM test '{}' failed",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_roundtrip_succeeds() {
            for vector in AES_256_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();

                // Encrypt
                let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);
                let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let mut ciphertext = plaintext.clone();
                key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                    .unwrap();

                // Decrypt
                let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
                let key_2 = LessSafeKey::new(unbound_key_2);
                let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

                let decrypted = key_2
                    .open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext)
                    .unwrap();

                assert_eq!(
                    decrypted,
                    plaintext.as_slice(),
                    "Roundtrip failed for '{}'",
                    vector.test_name
                );
            }
        }
    }

    // =============================================================================
    // Test Vector Structure Tests
    // =============================================================================

    mod test_vector_structure_tests {
        use super::*;

        #[test]
        fn test_aes_gcm_test_vector_fields_are_all_accessible_matches_expected() {
            // Test that we can access all fields of AesGcmTestVector
            let vector = &AES_128_GCM_VECTORS[0];

            // Verify all fields are accessible
            let _test_name: &str = vector.test_name;
            let _key: &str = vector.key;
            let _nonce: &str = vector.nonce;
            let _aad: &str = vector.aad;
            let _plaintext: &str = vector.plaintext;
            let _expected_ciphertext: &str = vector.expected_ciphertext;
            let _expected_tag: &str = vector.expected_tag;

            // Verify basic expectations
            assert!(!vector.test_name.is_empty());
            assert!(!vector.key.is_empty());
            assert!(!vector.nonce.is_empty());
            assert!(!vector.expected_tag.is_empty());
        }

        #[test]
        fn test_all_aes_128_vectors_have_valid_hex_matches_expected() {
            for vector in AES_128_GCM_VECTORS {
                assert!(
                    decode_hex(vector.key).is_ok(),
                    "Invalid hex in key for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.nonce).is_ok(),
                    "Invalid hex in nonce for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.aad).is_ok(),
                    "Invalid hex in aad for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.plaintext).is_ok(),
                    "Invalid hex in plaintext for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_ciphertext).is_ok(),
                    "Invalid hex in expected_ciphertext for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_tag).is_ok(),
                    "Invalid hex in expected_tag for {}",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_all_aes_256_vectors_have_valid_hex_matches_expected() {
            for vector in AES_256_GCM_VECTORS {
                assert!(
                    decode_hex(vector.key).is_ok(),
                    "Invalid hex in key for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.nonce).is_ok(),
                    "Invalid hex in nonce for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.aad).is_ok(),
                    "Invalid hex in aad for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.plaintext).is_ok(),
                    "Invalid hex in plaintext for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_ciphertext).is_ok(),
                    "Invalid hex in expected_ciphertext for {}",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_tag).is_ok(),
                    "Invalid hex in expected_tag for {}",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_plaintext_ciphertext_length_match_is_correct() {
            // Plaintext and ciphertext (excluding tag) should have same length
            for vector in AES_128_GCM_VECTORS {
                assert_eq!(
                    vector.plaintext.len(),
                    vector.expected_ciphertext.len(),
                    "Plaintext/ciphertext length mismatch for {} (AES-128)",
                    vector.test_name
                );
            }

            for vector in AES_256_GCM_VECTORS {
                assert_eq!(
                    vector.plaintext.len(),
                    vector.expected_ciphertext.len(),
                    "Plaintext/ciphertext length mismatch for {} (AES-256)",
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
        fn test_decode_hex_invalid_characters_returns_error() {
            // Test with invalid hex characters
            let result = decode_hex("zzzz");
            assert!(result.is_err(), "decode_hex should fail for invalid hex characters");

            if let Err(NistKatError::HexError(msg)) = result {
                assert!(!msg.is_empty(), "Error message should not be empty");
            } else {
                panic!("Expected HexError");
            }
        }

        #[test]
        fn test_decode_hex_odd_length_returns_error() {
            // Test with odd-length hex string
            let result = decode_hex("abc");
            assert!(result.is_err(), "decode_hex should fail for odd-length hex strings");
        }

        #[test]
        fn test_decode_hex_empty_string_succeeds() {
            // Empty string should decode successfully to empty vec
            let result = decode_hex("");
            assert!(result.is_ok(), "decode_hex should succeed for empty string");
            assert!(result.unwrap().is_empty(), "Empty string should decode to empty vec");
        }

        #[test]
        fn test_decode_hex_valid_strings_succeed_succeeds() {
            // Test various valid hex strings
            let test_cases = [
                ("00", vec![0u8]),
                ("ff", vec![255u8]),
                ("0123456789abcdef", vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
                ("ABCDEF", vec![0xab, 0xcd, 0xef]),
            ];

            for (input, expected) in test_cases {
                let result = decode_hex(input).unwrap();
                assert_eq!(result, expected, "decode_hex failed for '{}'", input);
            }
        }

        #[test]
        fn test_nist_kat_error_display_has_correct_format() {
            // Test TestFailed error formatting
            let err = NistKatError::TestFailed {
                algorithm: "AES-128-GCM".to_string(),
                test_name: "TEST-1".to_string(),
                message: "Output mismatch".to_string(),
            };
            let display = format!("{err}");
            assert!(display.contains("AES-128-GCM"));
            assert!(display.contains("TEST-1"));
            assert!(display.contains("Output mismatch"));

            // Test HexError error formatting
            let err = NistKatError::HexError("Invalid character".to_string());
            let display = format!("{err}");
            assert!(display.contains("Invalid character"));

            // Test ImplementationError error formatting
            let err = NistKatError::ImplementationError("Key creation failed".to_string());
            let display = format!("{err}");
            assert!(display.contains("Key creation failed"));

            // Test UnsupportedAlgorithm error formatting
            let err = NistKatError::UnsupportedAlgorithm("Unknown-ALG".to_string());
            let display = format!("{err}");
            assert!(display.contains("Unknown-ALG"));
        }

        #[test]
        fn test_nist_kat_error_debug_has_correct_format() {
            // Test Debug trait implementation
            let err = NistKatError::TestFailed {
                algorithm: "AES-128-GCM".to_string(),
                test_name: "TEST-1".to_string(),
                message: "Output mismatch".to_string(),
            };
            let debug = format!("{:?}", err);
            assert!(debug.contains("TestFailed"));
        }
    }

    // =============================================================================
    // Edge Cases and Boundary Tests
    // =============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_aes_128_gcm_tag_verification_failure_fails() {
            // Test that tampered ciphertext fails authentication
            let vector = &AES_128_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Tamper with ciphertext
            if !ciphertext.is_empty() {
                ciphertext[0] ^= 0xFF; // Flip all bits of first byte
            }

            // Attempt decryption - should fail
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for tampered ciphertext");
        }

        #[test]
        fn test_aes_256_gcm_tag_verification_failure_fails() {
            // Test that tampered ciphertext fails authentication
            let vector = &AES_256_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Tamper with ciphertext
            if !ciphertext.is_empty() {
                ciphertext[0] ^= 0xFF;
            }

            // Attempt decryption - should fail
            let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for tampered ciphertext");
        }

        #[test]
        fn test_aes_128_gcm_wrong_aad_fails() {
            // Test that wrong AAD fails authentication
            let vector = &AES_128_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different AAD
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let wrong_aad = vec![0xFF; 16];
            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&wrong_aad), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong AAD");
        }

        #[test]
        fn test_aes_256_gcm_wrong_aad_fails() {
            // Test that wrong AAD fails authentication
            let vector = &AES_256_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different AAD
            let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let wrong_aad = vec![0xFF; 16];
            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&wrong_aad), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong AAD");
        }

        #[test]
        fn test_aes_128_gcm_wrong_nonce_fails() {
            // Test that wrong nonce fails authentication
            let vector = &AES_128_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different nonce
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let wrong_nonce: [u8; 12] = [0xFF; 12];
            let nonce_obj_2 = Nonce::assume_unique_for_key(wrong_nonce);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong nonce");
        }

        #[test]
        fn test_aes_256_gcm_wrong_nonce_fails() {
            // Test that wrong nonce fails authentication
            let vector = &AES_256_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different nonce
            let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let wrong_nonce: [u8; 12] = [0xFF; 12];
            let nonce_obj_2 = Nonce::assume_unique_for_key(wrong_nonce);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong nonce");
        }

        #[test]
        fn test_aes_128_gcm_wrong_key_fails() {
            // Test that wrong key fails authentication
            let vector = &AES_128_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different key
            let wrong_key_bytes = vec![0xFF; 16];
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &wrong_key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong key");
        }

        #[test]
        fn test_aes_256_gcm_wrong_key_fails() {
            // Test that wrong key fails authentication
            let vector = &AES_256_GCM_VECTORS[1];
            let key_bytes = decode_hex(vector.key).unwrap();
            let nonce_bytes = decode_hex(vector.nonce).unwrap();
            let aad_bytes = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_array: [u8; 12] = nonce_bytes.clone().try_into().unwrap();
            let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

            let mut ciphertext = plaintext.clone();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext)
                .unwrap();

            // Attempt decryption with different key
            let wrong_key_bytes = vec![0xFF; 32];
            let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &wrong_key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_array_2: [u8; 12] = nonce_bytes.try_into().unwrap();
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

            let result = key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext);
            assert!(result.is_err(), "Decryption should fail for wrong key");
        }

        #[test]
        fn test_aes_gcm_with_aad_roundtrip() {
            // Test encryption/decryption with non-empty AAD
            let key_bytes = vec![0u8; 16];
            let nonce_bytes: [u8; 12] = [0; 12];
            let aad = b"Additional Authenticated Data";
            let plaintext = b"Hello, World!";

            // Encrypt
            let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key = LessSafeKey::new(unbound_key);
            let nonce_obj = Nonce::assume_unique_for_key(nonce_bytes);

            let mut ciphertext = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad[..]), &mut ciphertext).unwrap();

            // Decrypt
            let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
            let key_2 = LessSafeKey::new(unbound_key_2);
            let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_bytes);

            let decrypted =
                key_2.open_in_place(nonce_obj_2, Aad::from(&aad[..]), &mut ciphertext).unwrap();

            assert_eq!(decrypted, plaintext.as_slice());
        }
    }

    // =============================================================================
    // Cross-Algorithm Consistency Tests
    // =============================================================================

    mod consistency_tests {
        use super::*;

        #[test]
        fn test_aes_128_256_produce_different_outputs_succeeds() {
            // Same key (padded), nonce, plaintext should produce different ciphertext
            let key_128 = vec![0u8; 16];
            let key_256 = vec![0u8; 32];
            let nonce: [u8; 12] = [0; 12];
            let plaintext = b"Test plaintext for comparison";

            // AES-128-GCM
            let unbound_key_128 = UnboundKey::new(&AES_128_GCM, &key_128).unwrap();
            let key128 = LessSafeKey::new(unbound_key_128);
            let nonce_128 = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext_128 = plaintext.to_vec();
            key128.seal_in_place_append_tag(nonce_128, Aad::empty(), &mut ciphertext_128).unwrap();

            // AES-256-GCM
            let unbound_key_256 = UnboundKey::new(&AES_256_GCM, &key_256).unwrap();
            let key256 = LessSafeKey::new(unbound_key_256);
            let nonce_256 = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext_256 = plaintext.to_vec();
            key256.seal_in_place_append_tag(nonce_256, Aad::empty(), &mut ciphertext_256).unwrap();

            // Ciphertexts should be different
            assert_ne!(
                ciphertext_128, ciphertext_256,
                "AES-128 and AES-256 should produce different ciphertexts"
            );
        }

        #[test]
        fn test_different_nonces_produce_different_outputs_are_unique() {
            // Same key, different nonces should produce different ciphertext
            let key = vec![0u8; 16];
            let nonce1: [u8; 12] = [0; 12];
            let nonce2: [u8; 12] = [1; 12];
            let plaintext = b"Test plaintext";

            // First encryption
            let unbound_key1 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key1 = LessSafeKey::new(unbound_key1);
            let nonce_obj1 = Nonce::assume_unique_for_key(nonce1);
            let mut ciphertext1 = plaintext.to_vec();
            key1.seal_in_place_append_tag(nonce_obj1, Aad::empty(), &mut ciphertext1).unwrap();

            // Second encryption with different nonce
            let unbound_key2 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key2 = LessSafeKey::new(unbound_key2);
            let nonce_obj2 = Nonce::assume_unique_for_key(nonce2);
            let mut ciphertext2 = plaintext.to_vec();
            key2.seal_in_place_append_tag(nonce_obj2, Aad::empty(), &mut ciphertext2).unwrap();

            // Ciphertexts should be different
            assert_ne!(
                ciphertext1, ciphertext2,
                "Different nonces should produce different ciphertexts"
            );
        }

        #[test]
        fn test_same_input_produces_same_output_is_deterministic() {
            // Same key, nonce, plaintext should produce same ciphertext
            let key = vec![0u8; 16];
            let nonce: [u8; 12] = [0; 12];
            let plaintext = b"Test plaintext";

            // First encryption
            let unbound_key1 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key1 = LessSafeKey::new(unbound_key1);
            let nonce_obj1 = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext1 = plaintext.to_vec();
            key1.seal_in_place_append_tag(nonce_obj1, Aad::empty(), &mut ciphertext1).unwrap();

            // Second encryption with same parameters
            let unbound_key2 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key2 = LessSafeKey::new(unbound_key2);
            let nonce_obj2 = Nonce::assume_unique_for_key(nonce);
            let mut ciphertext2 = plaintext.to_vec();
            key2.seal_in_place_append_tag(nonce_obj2, Aad::empty(), &mut ciphertext2).unwrap();

            // Ciphertexts should be identical
            assert_eq!(ciphertext1, ciphertext2, "Same inputs should produce same ciphertexts");
        }
    }

    // =============================================================================
    // KatTestResult Tests
    // =============================================================================

    mod kat_test_result_tests {
        use latticearc_tests::validation::nist_kat::KatTestResult;

        #[test]
        fn test_kat_test_result_passed_matches_expected() {
            let result =
                KatTestResult::passed("test-case-1".to_string(), "AES-128-GCM".to_string(), 100);

            assert!(result.passed);
            assert!(result.error_message.is_none());
            assert_eq!(result.test_case, "test-case-1");
            assert_eq!(result.algorithm, "AES-128-GCM");
            assert_eq!(result.execution_time_us, 100);
        }

        #[test]
        fn test_kat_test_result_failed_matches_expected() {
            let result = KatTestResult::failed(
                "test-case-2".to_string(),
                "AES-256-GCM".to_string(),
                "Output mismatch".to_string(),
                200,
            );

            assert!(!result.passed);
            assert!(result.error_message.is_some());
            assert_eq!(result.error_message.as_ref().unwrap(), "Output mismatch");
            assert_eq!(result.test_case, "test-case-2");
            assert_eq!(result.algorithm, "AES-256-GCM");
            assert_eq!(result.execution_time_us, 200);
        }

        #[test]
        fn test_kat_test_result_clone_succeeds() {
            let result =
                KatTestResult::passed("test-case-1".to_string(), "AES-128-GCM".to_string(), 100);

            let cloned = result.clone();
            assert_eq!(cloned.passed, result.passed);
            assert_eq!(cloned.test_case, result.test_case);
            assert_eq!(cloned.algorithm, result.algorithm);
        }

        #[test]
        fn test_kat_test_result_debug_has_correct_format() {
            let result =
                KatTestResult::passed("test-case-1".to_string(), "AES-128-GCM".to_string(), 100);

            let debug_str = format!("{:?}", result);
            assert!(debug_str.contains("KatTestResult"));
            assert!(debug_str.contains("test-case-1"));
        }
    }

    // =============================================================================
    // Additional Coverage Tests for Internal Functions
    // =============================================================================

    mod coverage_enhancement_tests {
        use super::*;

        #[test]
        fn test_aes_128_gcm_all_vectors_decryption_succeeds() {
            // Test decryption path explicitly for all vectors
            for vector in AES_128_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();
                let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
                let expected_tag = decode_hex(vector.expected_tag).unwrap();

                // Build the encrypted data
                let mut encrypted_data = expected_ciphertext.clone();
                encrypted_data.extend_from_slice(&expected_tag);

                // Decrypt
                let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);
                let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let decrypted = key
                    .open_in_place(nonce_obj, Aad::from(&aad_bytes), &mut encrypted_data)
                    .unwrap();

                assert_eq!(
                    decrypted,
                    plaintext.as_slice(),
                    "Decryption failed for '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_aes_256_gcm_all_vectors_decryption_succeeds() {
            // Test decryption path explicitly for all vectors
            for vector in AES_256_GCM_VECTORS {
                let key_bytes = decode_hex(vector.key).unwrap();
                let nonce_bytes = decode_hex(vector.nonce).unwrap();
                let aad_bytes = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();
                let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
                let expected_tag = decode_hex(vector.expected_tag).unwrap();

                // Build the encrypted data
                let mut encrypted_data = expected_ciphertext.clone();
                encrypted_data.extend_from_slice(&expected_tag);

                // Decrypt
                let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
                let key = LessSafeKey::new(unbound_key);
                let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
                let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

                let decrypted = key
                    .open_in_place(nonce_obj, Aad::from(&aad_bytes), &mut encrypted_data)
                    .unwrap();

                assert_eq!(
                    decrypted,
                    plaintext.as_slice(),
                    "Decryption failed for '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_long_plaintext_encryption_succeeds() {
            // Test with a longer plaintext (multiple blocks)
            let key = vec![0u8; 16];
            let nonce: [u8; 12] = [0; 12];
            let plaintext = vec![0xABu8; 1024]; // 1KB of data

            let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key_obj = LessSafeKey::new(unbound_key);
            let nonce_obj = Nonce::assume_unique_for_key(nonce);

            let mut ciphertext = plaintext.clone();
            key_obj.seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut ciphertext).unwrap();

            // Ciphertext should be plaintext length + 16 (tag)
            assert_eq!(ciphertext.len(), 1024 + 16);

            // Verify decryption
            let unbound_key2 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key_obj2 = LessSafeKey::new(unbound_key2);
            let nonce_obj2 = Nonce::assume_unique_for_key(nonce);

            let decrypted =
                key_obj2.open_in_place(nonce_obj2, Aad::empty(), &mut ciphertext).unwrap();

            assert_eq!(decrypted, plaintext.as_slice());
        }

        #[test]
        fn test_max_aad_size_succeeds() {
            // Test with large AAD
            let key = vec![0u8; 16];
            let nonce: [u8; 12] = [0; 12];
            let plaintext = b"Test";
            let large_aad = vec![0xCDu8; 4096]; // 4KB AAD

            let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key_obj = LessSafeKey::new(unbound_key);
            let nonce_obj = Nonce::assume_unique_for_key(nonce);

            let mut ciphertext = plaintext.to_vec();
            key_obj
                .seal_in_place_append_tag(nonce_obj, Aad::from(&large_aad[..]), &mut ciphertext)
                .unwrap();

            // Verify decryption with same AAD
            let unbound_key2 = UnboundKey::new(&AES_128_GCM, &key).unwrap();
            let key_obj2 = LessSafeKey::new(unbound_key2);
            let nonce_obj2 = Nonce::assume_unique_for_key(nonce);

            let decrypted = key_obj2
                .open_in_place(nonce_obj2, Aad::from(&large_aad[..]), &mut ciphertext)
                .unwrap();

            assert_eq!(decrypted, plaintext.as_slice());
        }

        #[test]
        fn test_vector_test_name_has_correct_format() {
            // Verify test name format matches expected pattern
            for (i, vector) in AES_128_GCM_VECTORS.iter().enumerate() {
                let expected_pattern = format!("AES-128-GCM-KAT-{}", i + 1);
                assert_eq!(vector.test_name, expected_pattern, "Test name mismatch at index {}", i);
            }

            for (i, vector) in AES_256_GCM_VECTORS.iter().enumerate() {
                let expected_pattern = format!("AES-256-GCM-KAT-{}", i + 1);
                assert_eq!(vector.test_name, expected_pattern, "Test name mismatch at index {}", i);
            }
        }

        #[test]
        fn test_vectors_static_lifetime_succeeds() {
            // Verify vectors have static lifetime (compile-time check)
            let _: &'static [AesGcmTestVector] = AES_128_GCM_VECTORS;
            let _: &'static [AesGcmTestVector] = AES_256_GCM_VECTORS;
        }

        #[test]
        fn test_hex_decoding_uppercase_succeeds() {
            // Verify hex decoding works with uppercase
            let result = decode_hex("ABCDEF");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
        }

        #[test]
        fn test_hex_decoding_mixed_case_succeeds() {
            // Verify hex decoding works with mixed case
            let result = decode_hex("AbCdEf");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
        }
    }
}

// Originally: fips_chacha20_poly1305_kat_tests.rs
mod chacha20_poly1305 {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::redundant_closure,
        clippy::redundant_clone,
        clippy::print_stdout,
        clippy::useless_vec
    )]

    //! Comprehensive Tests for ChaCha20-Poly1305 Known Answer Tests
    //!
    //! This module provides extensive test coverage for the ChaCha20-Poly1305 KAT implementation
    //! in `arc-validation/src/nist_kat/chacha20_poly1305_kat.rs`.
    //!
    //! ## Test Categories
    //! 1. Public API functions (run_chacha20_poly1305_kat)
    //! 2. Test vector validation and structure
    //! 3. Error handling paths (all NistKatError variants)
    //! 4. Edge cases and boundary conditions
    //! 5. AEAD encryption/decryption verification

    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    use latticearc_tests::validation::nist_kat::chacha20_poly1305_kat::{
        CHACHA20_POLY1305_VECTORS, run_chacha20_poly1305_kat,
    };
    use latticearc_tests::validation::nist_kat::{NistKatError, decode_hex};

    // =============================================================================
    // Public API Tests
    // =============================================================================

    mod public_api_tests {
        use super::*;

        #[test]
        fn test_run_chacha20_poly1305_kat_passes() {
            let result = run_chacha20_poly1305_kat();
            assert!(result.is_ok(), "ChaCha20-Poly1305 KAT should pass: {:?}", result.err());
        }

        #[test]
        fn test_run_chacha20_poly1305_kat_multiple_times_succeeds() {
            // Running KAT multiple times should always succeed (deterministic)
            for _ in 0..5 {
                let result = run_chacha20_poly1305_kat();
                assert!(result.is_ok(), "ChaCha20-Poly1305 KAT should be deterministic");
            }
        }
    }

    // =============================================================================
    // Test Vector Structure Tests
    // =============================================================================

    mod test_vector_structure_tests {
        use super::*;

        #[test]
        fn test_vector_count_matches_expected() {
            // Ensure we have at least one test vector
            assert!(!CHACHA20_POLY1305_VECTORS.is_empty(), "Should have at least one test vector");
        }

        #[test]
        fn test_vector_names_not_empty_matches_expected() {
            for vector in CHACHA20_POLY1305_VECTORS {
                assert!(!vector.test_name.is_empty(), "Test name should not be empty");
            }
        }

        #[test]
        fn test_vector_key_length_matches_rfc_vector_matches_expected() {
            // ChaCha20-Poly1305 requires 256-bit (32-byte) keys = 64 hex chars
            for vector in CHACHA20_POLY1305_VECTORS {
                assert_eq!(
                    vector.key.len(),
                    64,
                    "Key should be 64 hex chars (32 bytes) for test '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_vector_nonce_length_matches_rfc_vector_matches_expected() {
            // ChaCha20-Poly1305 uses 96-bit (12-byte) nonces = 24 hex chars
            for vector in CHACHA20_POLY1305_VECTORS {
                assert_eq!(
                    vector.nonce.len(),
                    24,
                    "Nonce should be 24 hex chars (12 bytes) for test '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_vector_tag_length_matches_rfc_vector_matches_expected() {
            // Poly1305 produces 128-bit (16-byte) tags = 32 hex chars
            for vector in CHACHA20_POLY1305_VECTORS {
                assert_eq!(
                    vector.expected_tag.len(),
                    32,
                    "Tag should be 32 hex chars (16 bytes) for test '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_vector_ciphertext_length_matches_plaintext_matches_expected() {
            // Ciphertext length should equal plaintext length (stream cipher)
            for vector in CHACHA20_POLY1305_VECTORS {
                assert_eq!(
                    vector.expected_ciphertext.len(),
                    vector.plaintext.len(),
                    "Ciphertext length should match plaintext length for test '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_vector_hex_strings_valid_matches_expected() {
            for vector in CHACHA20_POLY1305_VECTORS {
                assert!(
                    decode_hex(vector.key).is_ok(),
                    "Key should be valid hex for test '{}'",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.nonce).is_ok(),
                    "Nonce should be valid hex for test '{}'",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.aad).is_ok(),
                    "AAD should be valid hex for test '{}'",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.plaintext).is_ok(),
                    "Plaintext should be valid hex for test '{}'",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_ciphertext).is_ok(),
                    "Ciphertext should be valid hex for test '{}'",
                    vector.test_name
                );
                assert!(
                    decode_hex(vector.expected_tag).is_ok(),
                    "Tag should be valid hex for test '{}'",
                    vector.test_name
                );
            }
        }

        #[test]
        fn test_vector_struct_fields_accessible_succeeds() {
            // Verify all struct fields are accessible
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let _name: &str = vector.test_name;
            let _key: &str = vector.key;
            let _nonce: &str = vector.nonce;
            let _aad: &str = vector.aad;
            let _plaintext: &str = vector.plaintext;
            let _ciphertext: &str = vector.expected_ciphertext;
            let _tag: &str = vector.expected_tag;
        }
    }

    // =============================================================================
    // Individual Vector Validation Tests
    // =============================================================================

    mod vector_validation_tests {
        use super::*;

        #[test]
        fn test_rfc8439_test_vector_1_matches_rfc_vector_matches_expected() {
            // Manually verify RFC 8439 Section 2.8.2 test vector
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            assert_eq!(vector.test_name, "RFC-8439-Test-Vector-1");

            let key = decode_hex(vector.key).unwrap();
            let nonce = decode_hex(vector.nonce).unwrap();
            let aad = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            // Create cipher
            let key_array: [u8; 32] = key.clone().try_into().expect("key is 32 bytes");
            let cipher = ChaCha20Poly1305::new(&key_array.into());

            // Test encryption
            let payload = Payload { msg: &plaintext, aad: &aad };
            let ciphertext_with_tag =
                cipher.encrypt((&nonce[..]).into(), payload).expect("encryption should succeed");

            // Verify ciphertext
            let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
            assert_eq!(ct_part, expected_ciphertext.as_slice());
            assert_eq!(tag_part, expected_tag.as_slice());
        }

        #[test]
        fn test_all_vectors_individually_match_rfc_vector_matches_expected() {
            for vector in CHACHA20_POLY1305_VECTORS {
                let key = decode_hex(vector.key).unwrap();
                let nonce = decode_hex(vector.nonce).unwrap();
                let aad = decode_hex(vector.aad).unwrap();
                let plaintext = decode_hex(vector.plaintext).unwrap();
                let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
                let expected_tag = decode_hex(vector.expected_tag).unwrap();

                let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
                let cipher = ChaCha20Poly1305::new(&key_array.into());

                // Test encryption
                let payload = Payload { msg: &plaintext, aad: &aad };
                let ciphertext_with_tag = cipher
                    .encrypt((&nonce[..]).into(), payload)
                    .expect("encryption should succeed");

                let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
                assert_eq!(
                    ct_part,
                    expected_ciphertext.as_slice(),
                    "Ciphertext mismatch for test '{}'",
                    vector.test_name
                );
                assert_eq!(
                    tag_part,
                    expected_tag.as_slice(),
                    "Tag mismatch for test '{}'",
                    vector.test_name
                );

                // Test decryption
                let payload_dec = Payload { msg: &ciphertext_with_tag, aad: &aad };
                let decrypted = cipher
                    .decrypt((&nonce[..]).into(), payload_dec)
                    .expect("decryption should succeed");

                assert_eq!(
                    decrypted.as_slice(),
                    plaintext.as_slice(),
                    "Decryption mismatch for test '{}'",
                    vector.test_name
                );
            }
        }
    }

    // =============================================================================
    // AEAD Property Tests
    // =============================================================================

    mod aead_property_tests {
        use super::*;

        #[test]
        fn test_encryption_decryption_roundtrip_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"test message for ChaCha20-Poly1305";
            let aad = b"additional authenticated data";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_empty_plaintext_encryption_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Empty plaintext produces only the 16-byte tag
            assert_eq!(ciphertext.len(), 16);

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert!(decrypted.is_empty());
        }

        #[test]
        fn test_empty_aad_encryption_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"message without aad";
            let aad = b"";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_both_empty_encryption_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"";
            let aad = b"";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            assert_eq!(ciphertext.len(), 16);

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert!(decrypted.is_empty());
        }

        #[test]
        fn test_large_plaintext_encryption_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = vec![0x61u8; 1024 * 64]; // 64 KB
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                .expect("encryption should succeed");

            // Ciphertext = plaintext length + 16 byte tag
            assert_eq!(ciphertext.len(), plaintext.len() + 16);

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }

        #[test]
        fn test_large_aad_encryption_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"message";
            let aad = vec![0x42u8; 1024 * 16]; // 16 KB AAD

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad: &aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad: &aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_ciphertext_length_matches_expected() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            // Test various plaintext lengths
            for len in [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256] {
                let plaintext = vec![0x61u8; len];
                let ciphertext = cipher
                    .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                    .expect("encryption should succeed");

                assert_eq!(
                    ciphertext.len(),
                    len + 16,
                    "Ciphertext should be plaintext length + 16 for {} byte plaintext",
                    len
                );
            }
        }
    }

    // =============================================================================
    // Authentication Tests
    // =============================================================================

    mod authentication_tests {
        use super::*;

        #[test]
        fn test_wrong_key_decryption_fails() {
            let key1 = [0x42u8; 32];
            let key2 = [0x43u8; 32]; // Different key
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher1 = ChaCha20Poly1305::new(&key1.into());
            let cipher2 = ChaCha20Poly1305::new(&key2.into());

            let ciphertext = cipher1
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Decryption with wrong key should fail
            let result = cipher2.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
            assert!(result.is_err(), "Decryption with wrong key should fail");
        }

        #[test]
        fn test_wrong_nonce_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce1 = [0u8; 12];
            let nonce2 = [1u8; 12]; // Different nonce
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce1).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Decryption with wrong nonce should fail
            let result = cipher.decrypt((&nonce2).into(), Payload { msg: &ciphertext, aad });
            assert!(result.is_err(), "Decryption with wrong nonce should fail");
        }

        #[test]
        fn test_wrong_aad_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad1 = b"correct aad";
            let aad2 = b"wrong aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad: aad1 })
                .expect("encryption should succeed");

            // Decryption with wrong AAD should fail
            let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad: aad2 });
            assert!(result.is_err(), "Decryption with wrong AAD should fail");
        }

        #[test]
        fn test_tampered_ciphertext_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let mut ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Tamper with ciphertext
            ciphertext[0] ^= 0x01;

            // Decryption should fail
            let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
            assert!(result.is_err(), "Decryption of tampered ciphertext should fail");
        }

        #[test]
        fn test_tampered_tag_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let mut ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Tamper with tag (last 16 bytes)
            let tag_start = ciphertext.len() - 16;
            ciphertext[tag_start] ^= 0x01;

            // Decryption should fail
            let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
            assert!(result.is_err(), "Decryption with tampered tag should fail");
        }

        #[test]
        fn test_truncated_ciphertext_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Truncate ciphertext
            let truncated = &ciphertext[..ciphertext.len() - 1];

            // Decryption should fail
            let result = cipher.decrypt((&nonce).into(), Payload { msg: truncated, aad });
            assert!(result.is_err(), "Decryption of truncated ciphertext should fail");
        }

        #[test]
        fn test_extended_ciphertext_decryption_fails() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"secret message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let mut ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            // Extend ciphertext
            ciphertext.push(0x00);

            // Decryption should fail
            let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
            assert!(result.is_err(), "Decryption of extended ciphertext should fail");
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
                algorithm: "ChaCha20-Poly1305".to_string(),
                test_name: "RFC-8439-Test-Vector-1".to_string(),
                message: "ciphertext mismatch".to_string(),
            };

            let display = format!("{error}");
            assert!(display.contains("ChaCha20-Poly1305"));
            assert!(display.contains("RFC-8439-Test-Vector-1"));
            assert!(display.contains("ciphertext mismatch"));
        }

        #[test]
        fn test_nist_kat_error_hex_error_display_matches_expected() {
            let error = NistKatError::HexError("invalid hex character".to_string());

            let display = format!("{error}");
            assert!(display.contains("Hex decode error"));
            assert!(display.contains("invalid hex character"));
        }

        #[test]
        fn test_nist_kat_error_implementation_error_display_matches_expected() {
            let error = NistKatError::ImplementationError("Invalid key length".to_string());

            let display = format!("{error}");
            assert!(display.contains("Implementation error"));
            assert!(display.contains("Invalid key length"));
        }

        #[test]
        fn test_decode_hex_valid_succeeds() {
            let result = decode_hex("616263");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0x61, 0x62, 0x63]);
        }

        #[test]
        fn test_decode_hex_empty_succeeds() {
            let result = decode_hex("");
            assert!(result.is_ok());
            assert!(result.unwrap().is_empty());
        }

        #[test]
        fn test_decode_hex_invalid_chars_fails() {
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
        fn test_decode_hex_odd_length_has_correct_size() {
            let result = decode_hex("abc");
            assert!(result.is_err());
            match result {
                Err(NistKatError::HexError(msg)) => {
                    println!("Got expected hex error for odd length: {}", msg);
                }
                _ => panic!("Expected HexError variant"),
            }
        }

        #[test]
        fn test_decode_hex_uppercase_succeeds() {
            let result = decode_hex("ABCDEF");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
        }

        #[test]
        fn test_decode_hex_mixed_case_succeeds() {
            let result = decode_hex("AbCdEf");
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
        }
    }

    // =============================================================================
    // Edge Case Tests for KAT Validation
    // =============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_single_byte_plaintext_roundtrip() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = [0x61u8];
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                .expect("encryption should succeed");

            assert_eq!(ciphertext.len(), 17); // 1 byte ciphertext + 16 byte tag

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), &plaintext);
        }

        #[test]
        fn test_all_zeros_key_roundtrip() {
            let key = [0u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"test message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_all_ones_key_roundtrip() {
            let key = [0xFFu8; 32];
            let nonce = [0xFFu8; 12];
            let plaintext = b"test message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_different_nonces_produce_different_ciphertext_are_unique() {
            let key = [0x42u8; 32];
            let nonce1 = [0u8; 12];
            let nonce2 = [1u8; 12];
            let plaintext = b"same message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext1 = cipher
                .encrypt((&nonce1).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let ciphertext2 = cipher
                .encrypt((&nonce2).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            assert_ne!(
                ciphertext1, ciphertext2,
                "Different nonces should produce different ciphertexts"
            );
        }

        #[test]
        fn test_same_nonce_produces_same_ciphertext_succeeds() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"same message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext1 = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let ciphertext2 = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            assert_eq!(ciphertext1, ciphertext2, "Same inputs should produce same ciphertext");
        }
    }

    // =============================================================================
    // Boundary Condition Tests
    // =============================================================================

    mod boundary_tests {
        use super::*;

        #[test]
        fn test_block_boundary_plaintexts_roundtrip() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            // ChaCha20 has a 64-byte block size
            for len in [63, 64, 65, 127, 128, 129, 191, 192, 193] {
                let plaintext = vec![0x61u8; len];

                let ciphertext = cipher
                    .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                    .expect("encryption should succeed");

                let decrypted = cipher
                    .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                    .expect("decryption should succeed");

                assert_eq!(
                    decrypted.as_slice(),
                    plaintext.as_slice(),
                    "Roundtrip failed for {} byte plaintext",
                    len
                );
            }
        }

        #[test]
        fn test_maximum_nonce_value_roundtrip() {
            let key = [0x42u8; 32];
            let nonce = [0xFFu8; 12]; // Maximum nonce value
            let plaintext = b"test message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_minimum_nonce_value_roundtrip() {
            let key = [0x42u8; 32];
            let nonce = [0x00u8; 12]; // Minimum nonce value
            let plaintext = b"test message";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted.as_slice(), plaintext);
        }

        #[test]
        fn test_single_bit_difference_in_key_matches_expected() {
            let key1 = [0x42u8; 32];
            let mut key2 = key1;
            key2[0] ^= 0x01; // Single bit difference

            let nonce = [0u8; 12];
            let plaintext = b"test message";
            let aad = b"aad";

            let cipher1 = ChaCha20Poly1305::new(&key1.into());
            let cipher2 = ChaCha20Poly1305::new(&key2.into());

            let ciphertext1 = cipher1
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            let ciphertext2 = cipher2
                .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                .expect("encryption should succeed");

            assert_ne!(
                ciphertext1, ciphertext2,
                "Single bit key difference should produce completely different ciphertext"
            );
        }
    }

    // =============================================================================
    // Determinism Tests
    // =============================================================================

    mod determinism_tests {
        use super::*;

        #[test]
        fn test_encryption_is_deterministic_for_same_inputs_is_deterministic() {
            let key = [0x42u8; 32];
            let nonce = [0u8; 12];
            let plaintext = b"deterministic test";
            let aad = b"aad";

            let cipher = ChaCha20Poly1305::new(&key.into());

            let ciphertexts: Vec<Vec<u8>> = (0..10)
                .map(|_| {
                    cipher
                        .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                        .expect("encryption should succeed")
                })
                .collect();

            // All ciphertexts should be identical
            for ct in &ciphertexts[1..] {
                assert_eq!(ct, &ciphertexts[0], "Encryption should be deterministic");
            }
        }

        #[test]
        fn test_kat_is_deterministic_for_same_vectors_matches_expected() {
            // Run KAT multiple times and verify consistency
            for _ in 0..10 {
                let result = run_chacha20_poly1305_kat();
                assert!(result.is_ok(), "KAT should always pass");
            }
        }
    }

    // =============================================================================
    // Integration with KatRunner Tests
    // =============================================================================

    mod integration_tests {
        use super::*;
        use latticearc_tests::validation::nist_kat::{KatRunner, KatSummary};

        #[test]
        fn test_chacha20_poly1305_kat_runner_integration_succeeds() {
            let mut runner = KatRunner::new();

            runner.run_test("ChaCha20-Poly1305", "AEAD", || run_chacha20_poly1305_kat());

            let summary: KatSummary = runner.finish();

            assert!(
                summary.all_passed(),
                "ChaCha20-Poly1305 KAT should pass. Failed: {}/{}",
                summary.failed,
                summary.total
            );
            assert_eq!(summary.total, 1, "Should have run 1 test");
        }
    }

    // =============================================================================
    // RFC 8439 Compliance Tests
    // =============================================================================

    mod rfc8439_compliance_tests {
        use super::*;

        #[test]
        fn test_rfc8439_key_size_matches_rfc_vector_matches_expected() {
            // RFC 8439 specifies 256-bit keys
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let key = decode_hex(vector.key).unwrap();
            assert_eq!(key.len(), 32, "RFC 8439 requires 256-bit (32 byte) keys");
        }

        #[test]
        fn test_rfc8439_nonce_size_matches_rfc_vector_matches_expected() {
            // RFC 8439 specifies 96-bit nonces for IETF variant
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let nonce = decode_hex(vector.nonce).unwrap();
            assert_eq!(nonce.len(), 12, "RFC 8439 requires 96-bit (12 byte) nonces");
        }

        #[test]
        fn test_rfc8439_tag_size_matches_rfc_vector_matches_expected() {
            // RFC 8439 specifies 128-bit authentication tags
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let tag = decode_hex(vector.expected_tag).unwrap();
            assert_eq!(tag.len(), 16, "RFC 8439 requires 128-bit (16 byte) tags");
        }

        #[test]
        fn test_rfc8439_aead_construction_matches_rfc_vector_matches_expected() {
            // Verify the AEAD construction follows RFC 8439 Section 2.8
            let vector = &CHACHA20_POLY1305_VECTORS[0];

            let key = decode_hex(vector.key).unwrap();
            let nonce = decode_hex(vector.nonce).unwrap();
            let aad = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();

            let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
            let cipher = ChaCha20Poly1305::new(&key_array.into());

            let ciphertext = cipher
                .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
                .expect("encryption should succeed");

            // The ciphertext length should be plaintext + tag
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
        }
    }

    // =============================================================================
    // Test Vector Content Verification
    // =============================================================================

    mod content_verification_tests {
        use super::*;

        #[test]
        fn test_rfc8439_plaintext_content_matches_rfc_vector_matches_expected() {
            // RFC 8439 Section 2.8.2 plaintext is the Sunscreen message
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let plaintext = decode_hex(vector.plaintext).unwrap();

            // The plaintext should decode to ASCII text
            let text = String::from_utf8(plaintext.clone());
            assert!(text.is_ok(), "Plaintext should be valid UTF-8");

            let text_str = text.unwrap();
            assert!(
                text_str.contains("Ladies and Gentlemen"),
                "Plaintext should contain the famous Sunscreen speech"
            );
            assert!(text_str.contains("sunscreen"), "Plaintext should mention sunscreen");
        }

        #[test]
        fn test_rfc8439_aad_content_matches_rfc_vector_matches_expected() {
            // RFC 8439 Section 2.8.2 AAD
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let aad = decode_hex(vector.aad).unwrap();

            // AAD should be 12 bytes as specified in the RFC
            assert_eq!(aad.len(), 12, "AAD should be 12 bytes");
        }

        #[test]
        fn test_rfc8439_nonce_content_matches_rfc_vector_matches_expected() {
            // RFC 8439 Section 2.8.2 nonce
            let vector = &CHACHA20_POLY1305_VECTORS[0];
            let nonce = decode_hex(vector.nonce).unwrap();

            // First 4 bytes should be common/constant prefix (07 00 00 00)
            assert_eq!(nonce[0], 0x07);
            assert_eq!(nonce[1], 0x00);
            assert_eq!(nonce[2], 0x00);
            assert_eq!(nonce[3], 0x00);
        }
    }

    // =============================================================================
    // Cross-validation Tests
    // =============================================================================

    mod cross_validation_tests {
        use super::*;

        #[test]
        fn test_verify_against_known_chacha20_output_matches_rfc_vector_matches_expected() {
            // Additional verification using known test vectors
            let key =
                decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                    .unwrap();
            let nonce = decode_hex("070000004041424344454647").unwrap();
            let aad = decode_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
            let plaintext = decode_hex(
                "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
            )
            .unwrap();
            let expected_ciphertext = decode_hex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
            )
            .unwrap();
            let expected_tag = decode_hex("1ae10b594f09e26a7e902ecbd0600691").unwrap();

            let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
            let cipher = ChaCha20Poly1305::new(&key_array.into());

            let ciphertext_with_tag = cipher
                .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
                .expect("encryption should succeed");

            let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());

            assert_eq!(ct_part, expected_ciphertext.as_slice(), "Ciphertext mismatch");
            assert_eq!(tag_part, expected_tag.as_slice(), "Tag mismatch");
        }
    }

    // =============================================================================
    // Comprehensive Summary Test
    // =============================================================================

    #[test]
    fn test_chacha20_poly1305_comprehensive_summary_matches_expected() {
        println!("\n========================================");
        println!("ChaCha20-Poly1305 KAT Test Summary");
        println!("========================================\n");

        // Run main KAT
        let kat_result = run_chacha20_poly1305_kat();
        println!("Main KAT: {}", if kat_result.is_ok() { "PASS" } else { "FAIL" });
        assert!(kat_result.is_ok());

        // Count test vectors
        let vector_count = CHACHA20_POLY1305_VECTORS.len();
        println!("Test Vectors: {}", vector_count);

        // Verify all vectors
        for vector in CHACHA20_POLY1305_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let nonce = decode_hex(vector.nonce).unwrap();
            let aad = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
            let cipher = ChaCha20Poly1305::new(&key_array.into());

            let ciphertext_with_tag = cipher
                .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
                .expect("encryption should succeed");

            let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
            let ct_match = ct_part == expected_ciphertext.as_slice();
            let tag_match = tag_part == expected_tag.as_slice();

            println!(
                "  [{}] {} - CT: {} TAG: {}",
                if ct_match && tag_match { "PASS" } else { "FAIL" },
                vector.test_name,
                if ct_match { "OK" } else { "MISMATCH" },
                if tag_match { "OK" } else { "MISMATCH" }
            );

            assert!(ct_match, "Ciphertext mismatch for {}", vector.test_name);
            assert!(tag_match, "Tag mismatch for {}", vector.test_name);
        }

        println!("\n========================================");
        println!("All Tests Passed!");
        println!("========================================\n");
    }
}
