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

use arc_validation::nist_kat::hkdf_kat::HKDF_SHA256_VECTORS;
use arc_validation::nist_kat::{NistKatError, decode_hex, hkdf_kat};
use hkdf::Hkdf;
use sha2::Sha256;

// Helper type alias for explicit type usage (HkdfTestVector is accessed via HKDF_SHA256_VECTORS)
type TestVectorSlice = &'static [hkdf_kat::HkdfTestVector];

// =============================================================================
// HkdfTestVector Struct Tests
// =============================================================================

mod hkdf_test_vector_tests {
    use super::*;

    #[test]
    fn test_vector_slice_type() {
        // Verify the slice type is correctly exported
        let vectors: TestVectorSlice = HKDF_SHA256_VECTORS;
        assert_eq!(vectors.len(), 3);
    }

    #[test]
    fn test_vector_struct_fields_accessible() {
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
    fn test_vector_count() {
        // RFC 5869 defines 3 SHA-256 test vectors
        assert_eq!(HKDF_SHA256_VECTORS.len(), 3, "HKDF-SHA256 should have exactly 3 test vectors");
    }

    #[test]
    fn test_vector_test_names() {
        // Verify all test vectors have proper RFC names
        assert_eq!(HKDF_SHA256_VECTORS[0].test_name, "RFC-5869-Test-Case-1");
        assert_eq!(HKDF_SHA256_VECTORS[1].test_name, "RFC-5869-Test-Case-2");
        assert_eq!(HKDF_SHA256_VECTORS[2].test_name, "RFC-5869-Test-Case-3");
    }

    #[test]
    fn test_vector_lengths() {
        // Verify OKM lengths match expected values
        assert_eq!(HKDF_SHA256_VECTORS[0].length, 42);
        assert_eq!(HKDF_SHA256_VECTORS[1].length, 82);
        assert_eq!(HKDF_SHA256_VECTORS[2].length, 42);
    }

    #[test]
    fn test_vector_ikm_decode() {
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
    fn test_vector_salt_decode() {
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
    fn test_vector_info_decode() {
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
    fn test_vector_prk_decode() {
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
    fn test_vector_okm_decode() {
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
    fn test_run_hkdf_sha256_kat_passes() {
        let result = hkdf_kat::run_hkdf_sha256_kat();
        assert!(result.is_ok(), "HKDF-SHA256 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_run_hkdf_sha256_kat_returns_ok() {
        // Explicit test that the function returns Ok(()) on success
        match hkdf_kat::run_hkdf_sha256_kat() {
            Ok(()) => {} // Expected
            Err(e) => panic!("Expected Ok(()), got Err: {:?}", e),
        }
    }

    #[test]
    fn test_all_vectors_pass() {
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
    fn test_case_1_ikm() {
        let vector = &HKDF_SHA256_VECTORS[0];
        let ikm = decode_hex(vector.ikm).unwrap();
        assert_eq!(ikm.len(), 22, "Test case 1 IKM should be 22 bytes");
        // IKM is 0x0b repeated 22 times
        for byte in &ikm {
            assert_eq!(*byte, 0x0b);
        }
    }

    #[test]
    fn test_case_1_salt() {
        let vector = &HKDF_SHA256_VECTORS[0];
        let salt = decode_hex(vector.salt).unwrap();
        assert_eq!(salt.len(), 13, "Test case 1 salt should be 13 bytes");
        // Salt is 0x00..0x0c
        for (i, byte) in salt.iter().enumerate() {
            assert_eq!(*byte, i as u8);
        }
    }

    #[test]
    fn test_case_1_info() {
        let vector = &HKDF_SHA256_VECTORS[0];
        let info = decode_hex(vector.info).unwrap();
        assert_eq!(info.len(), 10, "Test case 1 info should be 10 bytes");
        // Info is 0xf0..0xf9
        for (i, byte) in info.iter().enumerate() {
            assert_eq!(*byte, (0xf0 + i) as u8);
        }
    }

    #[test]
    fn test_case_1_prk_extraction() {
        let vector = &HKDF_SHA256_VECTORS[0];
        let ikm = decode_hex(vector.ikm).unwrap();
        let salt = decode_hex(vector.salt).unwrap();
        let expected_prk = decode_hex(vector.expected_prk).unwrap();

        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice());
    }

    #[test]
    fn test_case_1_okm_expansion() {
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
    fn test_case_2_ikm_length() {
        let vector = &HKDF_SHA256_VECTORS[1];
        let ikm = decode_hex(vector.ikm).unwrap();
        assert_eq!(ikm.len(), 80, "Test case 2 IKM should be 80 bytes");
    }

    #[test]
    fn test_case_2_salt_length() {
        let vector = &HKDF_SHA256_VECTORS[1];
        let salt = decode_hex(vector.salt).unwrap();
        assert_eq!(salt.len(), 80, "Test case 2 salt should be 80 bytes");
    }

    #[test]
    fn test_case_2_info_length() {
        let vector = &HKDF_SHA256_VECTORS[1];
        let info = decode_hex(vector.info).unwrap();
        assert_eq!(info.len(), 80, "Test case 2 info should be 80 bytes");
    }

    #[test]
    fn test_case_2_okm_length() {
        let vector = &HKDF_SHA256_VECTORS[1];
        assert_eq!(vector.length, 82, "Test case 2 OKM should be 82 bytes");
    }

    #[test]
    fn test_case_2_full_flow() {
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
    fn test_case_3_empty_salt() {
        let vector = &HKDF_SHA256_VECTORS[2];
        let salt = decode_hex(vector.salt).unwrap();
        assert!(salt.is_empty(), "Test case 3 salt should be empty");
    }

    #[test]
    fn test_case_3_empty_info() {
        let vector = &HKDF_SHA256_VECTORS[2];
        let info = decode_hex(vector.info).unwrap();
        assert!(info.is_empty(), "Test case 3 info should be empty");
    }

    #[test]
    fn test_case_3_prk_with_empty_salt() {
        let vector = &HKDF_SHA256_VECTORS[2];
        let ikm = decode_hex(vector.ikm).unwrap();
        let expected_prk = decode_hex(vector.expected_prk).unwrap();

        // Using None for salt (empty salt scenario)
        let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice());
    }

    #[test]
    fn test_case_3_okm_with_empty_info() {
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
    fn test_case_3_full_flow_empty_params() {
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
    fn test_hkdf_deterministic() {
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
    fn test_hkdf_different_info_different_output() {
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
    fn test_hkdf_different_salt_different_prk() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt1 = decode_hex("000102030405060708090a0b0c").unwrap();
        let salt2 = decode_hex("000102030405060708090a0b0d").unwrap(); // Different last byte

        let (prk1, _) = Hkdf::<Sha256>::extract(Some(salt1.as_slice()), &ikm);
        let (prk2, _) = Hkdf::<Sha256>::extract(Some(salt2.as_slice()), &ikm);

        assert_ne!(prk1.as_slice(), prk2.as_slice(), "Different salt should produce different PRK");
    }

    #[test]
    fn test_hkdf_different_ikm_different_prk() {
        let ikm1 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let ikm2 = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c").unwrap(); // Different last byte
        let salt = decode_hex("000102030405060708090a0b0c").unwrap();

        let (prk1, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm1);
        let (prk2, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm2);

        assert_ne!(prk1.as_slice(), prk2.as_slice(), "Different IKM should produce different PRK");
    }

    #[test]
    fn test_hkdf_prk_length() {
        // PRK should always be hash output length (32 bytes for SHA-256)
        for vector in HKDF_SHA256_VECTORS {
            let prk = decode_hex(vector.expected_prk).unwrap();
            assert_eq!(prk.len(), 32, "PRK should be 32 bytes for SHA-256");
        }
    }

    #[test]
    fn test_hkdf_okm_max_length() {
        // HKDF-SHA256 can generate up to 255 * 32 = 8160 bytes
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        // Test a reasonably large output (255 bytes, which is still < max)
        let mut okm = vec![0u8; 255];
        let result = hk.expand(&[], &mut okm);
        assert!(result.is_ok(), "Should handle 255-byte OKM");
    }

    #[test]
    fn test_hkdf_empty_ikm() {
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
    fn test_hkdf_single_byte_ikm() {
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
    fn test_extract_returns_hkdf_instance() {
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
    fn test_extract_with_none_salt() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();

        let (prk, _) = Hkdf::<Sha256>::extract(None, &ikm);
        assert_eq!(prk.len(), 32);

        // Compare with test case 3 which uses empty salt
        let expected_prk =
            decode_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();
        assert_eq!(prk.as_slice(), expected_prk.as_slice());
    }

    #[test]
    fn test_extract_prk_matches_expected() {
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
    fn test_expand_zero_length() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        let mut okm: Vec<u8> = vec![];
        let result = hk.expand(&[], &mut okm);
        assert!(result.is_ok(), "Should handle zero-length OKM");
    }

    #[test]
    fn test_expand_one_byte() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        let mut okm = vec![0u8; 1];
        let result = hk.expand(&[], &mut okm);
        assert!(result.is_ok(), "Should handle single-byte OKM");
        assert_ne!(okm[0], 0, "OKM should not be zero (very unlikely)");
    }

    #[test]
    fn test_expand_exactly_hash_length() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        let mut okm = vec![0u8; 32]; // Exactly SHA-256 output length
        let result = hk.expand(&[], &mut okm);
        assert!(result.is_ok(), "Should handle hash-length OKM");
    }

    #[test]
    fn test_expand_multiple_hash_lengths() {
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
    fn test_expand_with_info() {
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
    fn test_expand_without_info() {
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
    fn test_expand_okm_matches_expected() {
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
    fn test_invalid_hex_in_ikm() {
        let result = decode_hex("invalid_hex");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {} // Expected
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_odd_length_hex() {
        let result = decode_hex("123");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {} // Expected
            _ => panic!("Expected HexError"),
        }
    }

    #[test]
    fn test_nist_kat_error_test_failed_display() {
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
    fn test_nist_kat_error_hex_error_display() {
        let error = NistKatError::HexError("invalid character".to_string());
        let display = format!("{}", error);
        assert!(display.contains("invalid character"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display() {
        let error = NistKatError::ImplementationError("expand failed".to_string());
        let display = format!("{}", error);
        assert!(display.contains("expand failed"));
    }

    #[test]
    fn test_hkdf_expand_too_long() {
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
    fn test_rfc_appendix_a_test_case_1() {
        // RFC 5869 Appendix A - Test Case 1
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = decode_hex("000102030405060708090a0b0c").unwrap();
        let info = decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_prk =
            decode_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
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
    fn test_rfc_appendix_a_test_case_2() {
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
            decode_hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();
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
    fn test_rfc_appendix_a_test_case_3() {
        // RFC 5869 Appendix A - Test Case 3 (zero-length salt/info)
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let expected_prk =
            decode_hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();
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
    fn test_hkdf_kat_module_integration() {
        // Test that the KAT module integrates properly with the validation framework
        let result = hkdf_kat::run_hkdf_sha256_kat();
        assert!(result.is_ok());
    }

    #[test]
    fn test_vectors_accessible_from_module() {
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
    fn test_decode_hex_from_module() {
        // Test that decode_hex is properly exported from nist_kat
        let result = decode_hex("0123456789abcdef");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn test_full_hkdf_workflow() {
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
    fn test_very_short_info() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        // Single byte info
        let info = vec![0x01];
        let mut okm = vec![0u8; 32];
        let result = hk.expand(&info, &mut okm);
        assert!(result.is_ok());
    }

    #[test]
    fn test_very_long_info() {
        let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let hk = Hkdf::<Sha256>::new(None, &ikm);

        // 1024 byte info
        let info = vec![0xab; 1024];
        let mut okm = vec![0u8; 32];
        let result = hk.expand(&info, &mut okm);
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_zeros_ikm() {
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
    fn test_all_ones_ikm() {
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
    fn test_repeated_expand_calls() {
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
    fn test_boundary_okm_lengths() {
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
    fn test_hkdf_performance_reasonable() {
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
    fn test_kat_runner_performance() {
        let iterations = 100;
        let start = Instant::now();

        for _ in 0..iterations {
            let result = hkdf_kat::run_hkdf_sha256_kat();
            assert!(result.is_ok());
        }

        let duration = start.elapsed();
        let per_run_ms = duration.as_millis() / iterations as u128;

        // KAT run should complete in < 10ms
        assert!(per_run_ms < 10, "KAT runner should complete in < 10ms, took {} ms", per_run_ms);
    }
}
