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

use arc_validation::nist_kat::aes_gcm_kat::{
    AES_128_GCM_VECTORS, AES_256_GCM_VECTORS, AesGcmTestVector, run_aes_128_gcm_kat,
    run_aes_256_gcm_kat,
};
use arc_validation::nist_kat::{NistKatError, decode_hex};
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

// =============================================================================
// AES-128-GCM KAT Tests
// =============================================================================

mod aes_128_gcm_tests {
    use super::*;

    #[test]
    fn test_run_aes_128_gcm_kat_passes() {
        let result = run_aes_128_gcm_kat();
        assert!(result.is_ok(), "AES-128-GCM KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_aes_128_gcm_vector_count() {
        // Ensure we have expected number of test vectors
        assert!(
            AES_128_GCM_VECTORS.len() >= 3,
            "AES-128-GCM should have at least 3 test vectors, found {}",
            AES_128_GCM_VECTORS.len()
        );
    }

    #[test]
    fn test_aes_128_gcm_vector_names() {
        // Verify all test vectors have proper names
        for (i, vector) in AES_128_GCM_VECTORS.iter().enumerate() {
            assert!(!vector.test_name.is_empty(), "Vector {} should have a non-empty test name", i);
            assert!(
                vector.test_name.contains("AES-128-GCM"),
                "Vector {} name should contain 'AES-128-GCM', got: {}",
                i,
                vector.test_name
            );
        }
    }

    #[test]
    fn test_aes_128_gcm_key_lengths() {
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
    fn test_aes_128_gcm_nonce_lengths() {
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
    fn test_aes_128_gcm_tag_lengths() {
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
    fn test_aes_128_gcm_empty_plaintext() {
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
        assert_eq!(in_out.len(), 16, "Empty plaintext encryption should produce 16-byte tag only");
        assert_eq!(in_out, expected_tag, "Tag mismatch for empty plaintext");
    }

    #[test]
    fn test_aes_128_gcm_128bit_plaintext() {
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
    fn test_aes_128_gcm_256bit_plaintext() {
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
    fn test_aes_128_gcm_all_vectors_individually() {
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
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);

            assert_eq!(in_out, expected_output, "AES-128-GCM test '{}' failed", vector.test_name);
        }
    }

    #[test]
    fn test_aes_128_gcm_roundtrip() {
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

            let decrypted =
                key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
    fn test_run_aes_256_gcm_kat_passes() {
        let result = run_aes_256_gcm_kat();
        assert!(result.is_ok(), "AES-256-GCM KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_aes_256_gcm_vector_count() {
        assert!(
            AES_256_GCM_VECTORS.len() >= 3,
            "AES-256-GCM should have at least 3 test vectors, found {}",
            AES_256_GCM_VECTORS.len()
        );
    }

    #[test]
    fn test_aes_256_gcm_vector_names() {
        for (i, vector) in AES_256_GCM_VECTORS.iter().enumerate() {
            assert!(!vector.test_name.is_empty(), "Vector {} should have a non-empty test name", i);
            assert!(
                vector.test_name.contains("AES-256-GCM"),
                "Vector {} name should contain 'AES-256-GCM', got: {}",
                i,
                vector.test_name
            );
        }
    }

    #[test]
    fn test_aes_256_gcm_key_lengths() {
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
    fn test_aes_256_gcm_nonce_lengths() {
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
    fn test_aes_256_gcm_tag_lengths() {
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
    fn test_aes_256_gcm_empty_plaintext() {
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

        assert_eq!(in_out.len(), 16, "Empty plaintext encryption should produce 16-byte tag only");
        assert_eq!(in_out, expected_tag, "Tag mismatch for empty plaintext");
    }

    #[test]
    fn test_aes_256_gcm_128bit_plaintext() {
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
    fn test_aes_256_gcm_256bit_plaintext() {
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
    fn test_aes_256_gcm_all_vectors_individually() {
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
            key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut in_out).unwrap();

            let mut expected_output = expected_ciphertext.clone();
            expected_output.extend_from_slice(&expected_tag);

            assert_eq!(in_out, expected_output, "AES-256-GCM test '{}' failed", vector.test_name);
        }
    }

    #[test]
    fn test_aes_256_gcm_roundtrip() {
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

            let decrypted =
                key_2.open_in_place(nonce_obj_2, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
    fn test_aes_gcm_test_vector_fields() {
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
    fn test_all_aes_128_vectors_have_valid_hex() {
        for vector in AES_128_GCM_VECTORS {
            assert!(decode_hex(vector.key).is_ok(), "Invalid hex in key for {}", vector.test_name);
            assert!(
                decode_hex(vector.nonce).is_ok(),
                "Invalid hex in nonce for {}",
                vector.test_name
            );
            assert!(decode_hex(vector.aad).is_ok(), "Invalid hex in aad for {}", vector.test_name);
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
    fn test_all_aes_256_vectors_have_valid_hex() {
        for vector in AES_256_GCM_VECTORS {
            assert!(decode_hex(vector.key).is_ok(), "Invalid hex in key for {}", vector.test_name);
            assert!(
                decode_hex(vector.nonce).is_ok(),
                "Invalid hex in nonce for {}",
                vector.test_name
            );
            assert!(decode_hex(vector.aad).is_ok(), "Invalid hex in aad for {}", vector.test_name);
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
    fn test_plaintext_ciphertext_length_match() {
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
    fn test_decode_hex_invalid_characters() {
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
    fn test_decode_hex_odd_length() {
        // Test with odd-length hex string
        let result = decode_hex("abc");
        assert!(result.is_err(), "decode_hex should fail for odd-length hex strings");
    }

    #[test]
    fn test_decode_hex_empty_string() {
        // Empty string should decode successfully to empty vec
        let result = decode_hex("");
        assert!(result.is_ok(), "decode_hex should succeed for empty string");
        assert!(result.unwrap().is_empty(), "Empty string should decode to empty vec");
    }

    #[test]
    fn test_decode_hex_valid_strings() {
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
    fn test_nist_kat_error_display() {
        // Test TestFailed error formatting
        let err = NistKatError::TestFailed {
            algorithm: "AES-128-GCM".to_string(),
            test_name: "TEST-1".to_string(),
            message: "Output mismatch".to_string(),
        };
        let display = format!("{}", err);
        assert!(display.contains("AES-128-GCM"));
        assert!(display.contains("TEST-1"));
        assert!(display.contains("Output mismatch"));

        // Test HexError error formatting
        let err = NistKatError::HexError("Invalid character".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Invalid character"));

        // Test ImplementationError error formatting
        let err = NistKatError::ImplementationError("Key creation failed".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Key creation failed"));

        // Test UnsupportedAlgorithm error formatting
        let err = NistKatError::UnsupportedAlgorithm("Unknown-ALG".to_string());
        let display = format!("{}", err);
        assert!(display.contains("Unknown-ALG"));
    }

    #[test]
    fn test_nist_kat_error_debug() {
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
    fn test_aes_128_gcm_tag_verification_failure() {
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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
    fn test_aes_256_gcm_tag_verification_failure() {
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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
        key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad_bytes), &mut ciphertext).unwrap();

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
    fn test_aes_gcm_with_aad() {
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
    fn test_aes_128_256_produce_different_output() {
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
    fn test_different_nonces_produce_different_output() {
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
    fn test_same_input_produces_same_output() {
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
    use arc_validation::nist_kat::KatTestResult;

    #[test]
    fn test_kat_test_result_passed() {
        let result =
            KatTestResult::passed("test-case-1".to_string(), "AES-128-GCM".to_string(), 100);

        assert!(result.passed);
        assert!(result.error_message.is_none());
        assert_eq!(result.test_case, "test-case-1");
        assert_eq!(result.algorithm, "AES-128-GCM");
        assert_eq!(result.execution_time_us, 100);
    }

    #[test]
    fn test_kat_test_result_failed() {
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
    fn test_kat_test_result_clone() {
        let result =
            KatTestResult::passed("test-case-1".to_string(), "AES-128-GCM".to_string(), 100);

        let cloned = result.clone();
        assert_eq!(cloned.passed, result.passed);
        assert_eq!(cloned.test_case, result.test_case);
        assert_eq!(cloned.algorithm, result.algorithm);
    }

    #[test]
    fn test_kat_test_result_debug() {
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
    fn test_aes_128_gcm_all_vectors_decryption() {
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

            let decrypted =
                key.open_in_place(nonce_obj, Aad::from(&aad_bytes), &mut encrypted_data).unwrap();

            assert_eq!(
                decrypted,
                plaintext.as_slice(),
                "Decryption failed for '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_aes_256_gcm_all_vectors_decryption() {
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

            let decrypted =
                key.open_in_place(nonce_obj, Aad::from(&aad_bytes), &mut encrypted_data).unwrap();

            assert_eq!(
                decrypted,
                plaintext.as_slice(),
                "Decryption failed for '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_long_plaintext_encryption() {
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

        let decrypted = key_obj2.open_in_place(nonce_obj2, Aad::empty(), &mut ciphertext).unwrap();

        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_max_aad_size() {
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

        let decrypted =
            key_obj2.open_in_place(nonce_obj2, Aad::from(&large_aad[..]), &mut ciphertext).unwrap();

        assert_eq!(decrypted, plaintext.as_slice());
    }

    #[test]
    fn test_vector_test_name_format() {
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
    fn test_vectors_static_lifetime() {
        // Verify vectors have static lifetime (compile-time check)
        let _: &'static [AesGcmTestVector] = AES_128_GCM_VECTORS;
        let _: &'static [AesGcmTestVector] = AES_256_GCM_VECTORS;
    }

    #[test]
    fn test_hex_decoding_uppercase() {
        // Verify hex decoding works with uppercase
        let result = decode_hex("ABCDEF");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_hex_decoding_mixed_case() {
        // Verify hex decoding works with mixed case
        let result = decode_hex("AbCdEf");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }
}
