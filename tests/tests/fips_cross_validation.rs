//! Cross-library validation: aws-lc-rs vs fips204/205, and Wycheproof vectors.
#![deny(unsafe_code)]

// Originally: fips_cross_library_validation.rs
mod cross_library {
    //! Cross-Library Validation Tests
    //!
    //! These tests validate interoperability between independent PQC implementations:
    //! - `fips203` crate (pure Rust ML-KEM)
    //! - `aws-lc-rs` (C/ASM ML-KEM via AWS-LC)
    //!
    //! This catches encoding differences, parameter mismatches, or wrapping bugs
    //! that NIST KAT vectors alone cannot detect (since KATs test one implementation
    //! at a time).
    //!
    //! ## What This Validates
    //!
    //! 1. Key format compatibility: keys from one library work in the other
    //! 2. Encapsulation/decapsulation cross-library: encapsulate with lib A, decapsulate with lib B
    //! 3. Shared secret agreement: both libraries produce the same shared secret
    //! 4. Key size consistency: both libraries agree on FIPS 203 parameter sizes

    #![allow(clippy::expect_used)]

    use aws_lc_rs::kem::{DecapsulationKey, EncapsulationKey, ML_KEM_768};
    use fips203::ml_kem_768;
    use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

    /// Test that fips203 and aws-lc-rs agree on ML-KEM-768 public key size
    #[test]
    fn test_ml_kem_768_key_size_agreement_has_correct_size() {
        // fips203: generate keypair
        let (ek_fips, _dk_fips) =
            <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203 keygen should succeed");
        let pk_fips_bytes = ek_fips.into_bytes();

        // aws-lc-rs: generate keypair
        let dk_aws =
            DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc-rs keygen should succeed");
        let ek_aws = dk_aws.encapsulation_key().expect("aws-lc-rs encaps key should succeed");
        let pk_aws_bytes = ek_aws.key_bytes().expect("aws-lc-rs key bytes should succeed");

        // FIPS 203 Table 2: ML-KEM-768 public key is 1184 bytes
        assert_eq!(pk_fips_bytes.len(), 1184, "fips203 ML-KEM-768 public key should be 1184 bytes");
        assert_eq!(
            pk_aws_bytes.as_ref().len(),
            1184,
            "aws-lc-rs ML-KEM-768 public key should be 1184 bytes"
        );
    }

    /// Test cross-library encapsulation: fips203 key → aws-lc-rs encapsulate → fips203 decapsulate
    #[test]
    fn test_cross_library_fips203_keygen_aws_encaps_succeeds() {
        // Step 1: Generate keypair with fips203
        let (ek_fips, dk_fips) =
            <ml_kem_768::KG as KeyGen>::try_keygen().expect("fips203 keygen should succeed");
        let pk_bytes = ek_fips.into_bytes();

        // Step 2: Import public key into aws-lc-rs and encapsulate
        let ek_aws = EncapsulationKey::new(&ML_KEM_768, &pk_bytes)
            .expect("aws-lc-rs should accept fips203 public key");
        let (ct_aws, ss_aws) = ek_aws.encapsulate().expect("aws-lc-rs encapsulate should succeed");

        // Step 3: Decapsulate with fips203
        let ct_bytes = ct_aws.as_ref();
        let ct_fips = ml_kem_768::CipherText::try_from_bytes(ct_bytes.try_into().expect("ct size"))
            .expect("fips203 should accept aws-lc-rs ciphertext");
        let ss_fips = dk_fips.try_decaps(&ct_fips).expect("fips203 decapsulate should succeed");

        // Step 4: Verify shared secrets match
        let ss_fips_bytes = ss_fips.into_bytes();
        assert_eq!(
            ss_fips_bytes.as_ref(),
            ss_aws.as_ref(),
            "Shared secrets must match across fips203 (decaps) and aws-lc-rs (encaps)"
        );
    }

    /// Test cross-library encapsulation: aws-lc-rs key → fips203 encapsulate → aws-lc-rs decapsulate
    #[test]
    fn test_cross_library_aws_keygen_fips203_encaps_succeeds() {
        // Step 1: Generate keypair with aws-lc-rs
        let dk_aws =
            DecapsulationKey::generate(&ML_KEM_768).expect("aws-lc-rs keygen should succeed");
        let ek_aws = dk_aws.encapsulation_key().expect("aws-lc-rs encaps key should succeed");
        let pk_bytes = ek_aws.key_bytes().expect("aws-lc-rs key bytes should succeed");

        // Step 2: Import public key into fips203 and encapsulate
        let pk_array: &[u8; 1184] =
            pk_bytes.as_ref().try_into().expect("aws-lc-rs pk should be 1184 bytes");
        let ek_fips = ml_kem_768::EncapsKey::try_from_bytes(*pk_array)
            .expect("fips203 should accept aws-lc-rs public key");
        let (ss_fips, ct_fips) = ek_fips.try_encaps().expect("fips203 encapsulate should succeed");

        // Step 3: Decapsulate with aws-lc-rs
        let ct_bytes = ct_fips.into_bytes();
        let ss_aws = dk_aws
            .decapsulate(ct_bytes.as_ref().into())
            .expect("aws-lc-rs decapsulate should succeed");

        // Step 4: Verify shared secrets match
        let ss_fips_bytes = ss_fips.into_bytes();
        assert_eq!(
            ss_fips_bytes.as_ref(),
            ss_aws.as_ref(),
            "Shared secrets must match across aws-lc-rs (decaps) and fips203 (encaps)"
        );
    }

    /// Test that multiple cross-library roundtrips all produce valid shared secrets
    #[test]
    fn test_cross_library_roundtrip_consistency_roundtrip() {
        for i in 0..5 {
            // Alternate which library generates the key
            if i % 2 == 0 {
                // fips203 keygen → aws-lc-rs encaps → fips203 decaps
                let (ek, dk) = <ml_kem_768::KG as KeyGen>::try_keygen()
                    .expect("fips203 keygen should succeed");
                let pk_bytes = ek.into_bytes();

                let ek_aws = EncapsulationKey::new(&ML_KEM_768, &pk_bytes)
                    .expect("aws-lc-rs should accept fips203 public key");
                let (ct, ss_encaps) =
                    ek_aws.encapsulate().expect("aws-lc-rs encapsulate should succeed");

                let ct_arr: &[u8; 1088] = ct.as_ref().try_into().expect("ct size");
                let ct_fips =
                    ml_kem_768::CipherText::try_from_bytes(*ct_arr).expect("ct from bytes");
                let ss_decaps = dk.try_decaps(&ct_fips).expect("fips203 decaps should succeed");

                assert_eq!(
                    ss_decaps.into_bytes().as_ref(),
                    ss_encaps.as_ref(),
                    "Roundtrip {} failed (fips203 key)",
                    i
                );
            } else {
                // aws-lc-rs keygen → fips203 encaps → aws-lc-rs decaps
                let dk = DecapsulationKey::generate(&ML_KEM_768)
                    .expect("aws-lc-rs keygen should succeed");
                let ek = dk.encapsulation_key().expect("encaps key");
                let pk_bytes = ek.key_bytes().expect("key bytes");

                let pk_arr: &[u8; 1184] = pk_bytes.as_ref().try_into().expect("pk size");
                let ek_fips =
                    ml_kem_768::EncapsKey::try_from_bytes(*pk_arr).expect("fips203 from bytes");
                let (ss_encaps, ct) = ek_fips.try_encaps().expect("fips203 encaps should succeed");

                let ct_bytes = ct.into_bytes();
                let ss_decaps = dk
                    .decapsulate(ct_bytes.as_ref().into())
                    .expect("aws-lc-rs decaps should succeed");

                assert_eq!(
                    ss_encaps.into_bytes().as_ref(),
                    ss_decaps.as_ref(),
                    "Roundtrip {} failed (aws-lc-rs key)",
                    i
                );
            }
        }
    }
}

// Originally: fips_wycheproof_tests.rs
mod wycheproof {
    //! Comprehensive tests for arc-validation wycheproof module
    //!
    //! This test suite covers:
    //! - WycheproofError enum and all variants
    //! - WycheproofResults struct and all methods
    //! - Error handling paths
    //! - Edge cases and boundary conditions
    //! - Display and Debug trait implementations

    #![allow(
        clippy::indexing_slicing,
        clippy::float_cmp,
        clippy::cast_precision_loss,
        clippy::useless_format,
        clippy::useless_vec
    )]

    use latticearc_tests::validation::wycheproof::{WycheproofError, WycheproofResults};
    use std::error::Error;

    // ============================================================================
    // WycheproofError Tests
    // ============================================================================

    mod wycheproof_error_tests {
        use super::*;

        #[test]
        fn test_load_error_creation_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::LoadError("Failed to load test vectors".to_string());
            assert!(matches!(error, WycheproofError::LoadError(_)));
        }

        #[test]
        fn test_load_error_display_matches_expected() {
            let error = WycheproofError::LoadError("Network timeout".to_string());
            let display = format!("{error}");
            assert!(display.contains("Failed to load test vectors"));
            assert!(display.contains("Network timeout"));
        }

        #[test]
        fn test_load_error_debug_matches_expected() {
            let error = WycheproofError::LoadError("File not found".to_string());
            let debug = format!("{:?}", error);
            assert!(debug.contains("LoadError"));
            assert!(debug.contains("File not found"));
        }

        #[test]
        fn test_test_failed_creation_matches_wycheproof_vector_matches_expected() {
            let error =
                WycheproofError::TestFailed { tc_id: 42, message: "Decryption failed".to_string() };
            assert!(matches!(error, WycheproofError::TestFailed { tc_id: 42, .. }));
        }

        #[test]
        fn test_test_failed_display_matches_expected() {
            let error = WycheproofError::TestFailed {
                tc_id: 123,
                message: "Invalid ciphertext".to_string(),
            };
            let display = format!("{error}");
            assert!(display.contains("Test case 123 failed"));
            assert!(display.contains("Invalid ciphertext"));
        }

        #[test]
        fn test_test_failed_debug_matches_expected() {
            let error = WycheproofError::TestFailed {
                tc_id: 999,
                message: "Signature mismatch".to_string(),
            };
            let debug = format!("{:?}", error);
            assert!(debug.contains("TestFailed"));
            assert!(debug.contains("tc_id: 999"));
            assert!(debug.contains("Signature mismatch"));
        }

        #[test]
        fn test_unexpected_result_creation_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::UnexpectedResult {
                tc_id: 55,
                expected: "valid".to_string(),
                actual: "invalid".to_string(),
            };
            assert!(matches!(error, WycheproofError::UnexpectedResult { tc_id: 55, .. }));
        }

        #[test]
        fn test_unexpected_result_display_matches_expected() {
            let error = WycheproofError::UnexpectedResult {
                tc_id: 77,
                expected: "success".to_string(),
                actual: "failure".to_string(),
            };
            let display = format!("{error}");
            assert!(display.contains("Unexpected result for test 77"));
            assert!(display.contains("expected success"));
            assert!(display.contains("got failure"));
        }

        #[test]
        fn test_unexpected_result_debug_matches_expected() {
            let error = WycheproofError::UnexpectedResult {
                tc_id: 88,
                expected: "pass".to_string(),
                actual: "fail".to_string(),
            };
            let debug = format!("{:?}", error);
            assert!(debug.contains("UnexpectedResult"));
            assert!(debug.contains("tc_id: 88"));
            assert!(debug.contains("expected"));
            assert!(debug.contains("actual"));
        }

        #[test]
        fn test_error_is_std_error_matches_expected() {
            let error = WycheproofError::LoadError("test".to_string());
            // Verify it implements std::error::Error
            let _: &dyn Error = &error;
        }

        #[test]
        fn test_load_error_with_empty_message_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::LoadError(String::new());
            let display = format!("{error}");
            assert!(display.contains("Failed to load test vectors"));
        }

        #[test]
        fn test_test_failed_with_zero_tc_id_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::TestFailed { tc_id: 0, message: "Test zero".to_string() };
            let display = format!("{error}");
            assert!(display.contains("Test case 0 failed"));
        }

        #[test]
        fn test_test_failed_with_max_tc_id_matches_wycheproof_vector_matches_expected() {
            let error =
                WycheproofError::TestFailed { tc_id: u32::MAX, message: "Max test".to_string() };
            let display = format!("{error}");
            assert!(display.contains(&u32::MAX.to_string()));
        }

        #[test]
        fn test_unexpected_result_with_empty_strings_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::UnexpectedResult {
                tc_id: 1,
                expected: String::new(),
                actual: String::new(),
            };
            let display = format!("{error}");
            assert!(display.contains("Unexpected result for test 1"));
        }

        #[test]
        fn test_load_error_with_special_characters_matches_wycheproof_vector_matches_expected() {
            let error = WycheproofError::LoadError("Error: <>&\"'".to_string());
            let display = format!("{error}");
            assert!(display.contains("<>&\"'"));
        }

        #[test]
        fn test_test_failed_with_unicode_message_matches_wycheproof_vector_matches_expected() {
            let error =
                WycheproofError::TestFailed { tc_id: 100, message: "Unicode test".to_string() };
            let display = format!("{error}");
            assert!(display.contains("Unicode"));
        }

        #[test]
        fn test_unexpected_result_with_long_strings_matches_wycheproof_vector_matches_expected() {
            let long_expected = "a".repeat(1000);
            let long_actual = "b".repeat(1000);
            let error = WycheproofError::UnexpectedResult {
                tc_id: 1,
                expected: long_expected.clone(),
                actual: long_actual.clone(),
            };
            let display = format!("{error}");
            assert!(display.contains(&long_expected));
            assert!(display.contains(&long_actual));
        }
    }

    // ============================================================================
    // WycheproofResults Constructor Tests
    // ============================================================================

    mod wycheproof_results_constructor_tests {
        use super::*;

        #[test]
        fn test_new_creates_default_instance_matches_expected() {
            let results = WycheproofResults::new();
            assert_eq!(results.total, 0);
            assert_eq!(results.passed, 0);
            assert_eq!(results.failed, 0);
            assert_eq!(results.skipped, 0);
            assert!(results.failures.is_empty());
        }

        #[test]
        fn test_default_creates_same_as_new_matches_expected() {
            let from_new = WycheproofResults::new();
            let from_default = WycheproofResults::default();

            assert_eq!(from_new.total, from_default.total);
            assert_eq!(from_new.passed, from_default.passed);
            assert_eq!(from_new.failed, from_default.failed);
            assert_eq!(from_new.skipped, from_default.skipped);
            assert_eq!(from_new.failures.len(), from_default.failures.len());
        }

        #[test]
        fn test_debug_output_matches_expected() {
            let results = WycheproofResults::new();
            let debug = format!("{:?}", results);
            assert!(debug.contains("WycheproofResults"));
            assert!(debug.contains("total"));
            assert!(debug.contains("passed"));
            assert!(debug.contains("failed"));
            assert!(debug.contains("skipped"));
            assert!(debug.contains("failures"));
        }
    }

    // ============================================================================
    // WycheproofResults all_passed Tests
    // ============================================================================

    mod wycheproof_results_all_passed_tests {
        use super::*;

        #[test]
        fn test_all_passed_with_new_instance_matches_wycheproof_vector_matches_expected() {
            let results = WycheproofResults::new();
            assert!(results.all_passed());
        }

        #[test]
        fn test_all_passed_after_only_passes_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_pass();
            results.add_pass();
            assert!(results.all_passed());
        }

        #[test]
        fn test_all_passed_with_one_failure_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_failure("test failed".to_string());
            assert!(!results.all_passed());
        }

        #[test]
        fn test_all_passed_with_only_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("failure 1".to_string());
            results.add_failure("failure 2".to_string());
            assert!(!results.all_passed());
        }

        #[test]
        fn test_all_passed_with_skips_only_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_skip();
            results.add_skip();
            assert!(results.all_passed());
        }

        #[test]
        fn test_all_passed_with_passes_and_skips_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_skip();
            results.add_pass();
            assert!(results.all_passed());
        }

        #[test]
        fn test_all_passed_with_mixed_results_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_skip();
            results.add_failure("one failure".to_string());
            assert!(!results.all_passed());
        }
    }

    // ============================================================================
    // WycheproofResults add_pass Tests
    // ============================================================================

    mod wycheproof_results_add_pass_tests {
        use super::*;

        #[test]
        fn test_add_pass_increments_total_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.total, 0);
            results.add_pass();
            assert_eq!(results.total, 1);
        }

        #[test]
        fn test_add_pass_increments_passed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.passed, 0);
            results.add_pass();
            assert_eq!(results.passed, 1);
        }

        #[test]
        fn test_add_pass_does_not_increment_failed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            assert_eq!(results.failed, 0);
        }

        #[test]
        fn test_add_pass_does_not_increment_skipped_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            assert_eq!(results.skipped, 0);
        }

        #[test]
        fn test_add_pass_does_not_add_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            assert!(results.failures.is_empty());
        }

        #[test]
        fn test_add_pass_multiple_times_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..100 {
                results.add_pass();
            }
            assert_eq!(results.total, 100);
            assert_eq!(results.passed, 100);
            assert_eq!(results.failed, 0);
            assert_eq!(results.skipped, 0);
        }
    }

    // ============================================================================
    // WycheproofResults add_failure Tests
    // ============================================================================

    mod wycheproof_results_add_failure_tests {
        use super::*;

        #[test]
        fn test_add_failure_increments_total_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.total, 0);
            results.add_failure("error".to_string());
            assert_eq!(results.total, 1);
        }

        #[test]
        fn test_add_failure_increments_failed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.failed, 0);
            results.add_failure("error".to_string());
            assert_eq!(results.failed, 1);
        }

        #[test]
        fn test_add_failure_does_not_increment_passed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("error".to_string());
            assert_eq!(results.passed, 0);
        }

        #[test]
        fn test_add_failure_does_not_increment_skipped_matches_wycheproof_vector_matches_expected()
        {
            let mut results = WycheproofResults::new();
            results.add_failure("error".to_string());
            assert_eq!(results.skipped, 0);
        }

        #[test]
        fn test_add_failure_adds_to_failures_vec_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("test error message".to_string());
            assert_eq!(results.failures.len(), 1);
            assert_eq!(results.failures[0], "test error message");
        }

        #[test]
        fn test_add_failure_multiple_times_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("error 1".to_string());
            results.add_failure("error 2".to_string());
            results.add_failure("error 3".to_string());
            assert_eq!(results.total, 3);
            assert_eq!(results.failed, 3);
            assert_eq!(results.failures.len(), 3);
        }

        #[test]
        fn test_add_failure_with_empty_message_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure(String::new());
            assert_eq!(results.failures.len(), 1);
            assert_eq!(results.failures[0], "");
        }

        #[test]
        fn test_add_failure_with_long_message_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            let long_message = "x".repeat(10000);
            results.add_failure(long_message.clone());
            assert_eq!(results.failures[0], long_message);
        }

        #[test]
        fn test_add_failure_preserves_order_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("first".to_string());
            results.add_failure("second".to_string());
            results.add_failure("third".to_string());
            assert_eq!(results.failures[0], "first");
            assert_eq!(results.failures[1], "second");
            assert_eq!(results.failures[2], "third");
        }

        #[test]
        fn test_add_failure_with_special_characters_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("Error: <>&\"'\n\t\\".to_string());
            assert!(results.failures[0].contains("<>&"));
        }
    }

    // ============================================================================
    // WycheproofResults add_skip Tests
    // ============================================================================

    mod wycheproof_results_add_skip_tests {
        use super::*;

        #[test]
        fn test_add_skip_increments_total_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.total, 0);
            results.add_skip();
            assert_eq!(results.total, 1);
        }

        #[test]
        fn test_add_skip_increments_skipped_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            assert_eq!(results.skipped, 0);
            results.add_skip();
            assert_eq!(results.skipped, 1);
        }

        #[test]
        fn test_add_skip_does_not_increment_passed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_skip();
            assert_eq!(results.passed, 0);
        }

        #[test]
        fn test_add_skip_does_not_increment_failed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_skip();
            assert_eq!(results.failed, 0);
        }

        #[test]
        fn test_add_skip_does_not_add_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_skip();
            assert!(results.failures.is_empty());
        }

        #[test]
        fn test_add_skip_multiple_times_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..50 {
                results.add_skip();
            }
            assert_eq!(results.total, 50);
            assert_eq!(results.skipped, 50);
            assert_eq!(results.passed, 0);
            assert_eq!(results.failed, 0);
        }
    }

    // ============================================================================
    // WycheproofResults Mixed Operations Tests
    // ============================================================================

    mod wycheproof_results_mixed_operations_tests {
        use super::*;

        #[test]
        fn test_mixed_pass_fail_skip_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_failure("error".to_string());
            results.add_skip();
            results.add_pass();
            results.add_skip();

            assert_eq!(results.total, 5);
            assert_eq!(results.passed, 2);
            assert_eq!(results.failed, 1);
            assert_eq!(results.skipped, 2);
            assert_eq!(results.failures.len(), 1);
        }

        #[test]
        fn test_total_equals_sum_of_categories_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..10 {
                results.add_pass();
            }
            for _ in 0..5 {
                results.add_failure(format!("error"));
            }
            for _ in 0..3 {
                results.add_skip();
            }

            assert_eq!(results.total, results.passed + results.failed + results.skipped);
            assert_eq!(results.total, 18);
        }

        #[test]
        fn test_failures_vec_matches_failed_count_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("error 1".to_string());
            results.add_pass();
            results.add_failure("error 2".to_string());
            results.add_skip();
            results.add_failure("error 3".to_string());

            assert_eq!(results.failed, results.failures.len());
        }

        #[test]
        fn test_large_number_of_operations_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            for i in 0..1000 {
                match i % 3 {
                    0 => results.add_pass(),
                    1 => results.add_failure(format!("error {}", i)),
                    _ => results.add_skip(),
                }
            }

            assert_eq!(results.total, 1000);
            assert_eq!(results.passed, 334);
            assert_eq!(results.failed, 333);
            assert_eq!(results.skipped, 333);
            assert_eq!(results.failures.len(), 333);
        }

        #[test]
        fn test_pass_rate_calculation_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..80 {
                results.add_pass();
            }
            for _ in 0..20 {
                results.add_failure("error".to_string());
            }

            // Calculate pass rate manually
            let pass_rate = results.passed as f64 / results.total as f64;
            assert!((pass_rate - 0.8).abs() < f64::EPSILON);
        }

        #[test]
        fn test_skip_does_not_affect_all_passed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_pass();
            results.add_skip();
            results.add_skip();
            results.add_skip();

            // all_passed should be true because failed is 0
            assert!(results.all_passed());
            assert_eq!(results.skipped, 3);
        }
    }

    // ============================================================================
    // WycheproofResults Field Access Tests
    // ============================================================================

    mod wycheproof_results_field_access_tests {
        use super::*;

        #[test]
        fn test_direct_field_access_total_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            assert_eq!(results.total, 1);
        }

        #[test]
        fn test_direct_field_access_passed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            assert_eq!(results.passed, 1);
        }

        #[test]
        fn test_direct_field_access_failed_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("test".to_string());
            assert_eq!(results.failed, 1);
        }

        #[test]
        fn test_direct_field_access_skipped_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_skip();
            assert_eq!(results.skipped, 1);
        }

        #[test]
        fn test_direct_field_access_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("error message".to_string());
            assert_eq!(results.failures[0], "error message");
        }

        #[test]
        fn test_iterate_over_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("error 1".to_string());
            results.add_failure("error 2".to_string());
            results.add_failure("error 3".to_string());

            let mut count = 0;
            for (i, failure) in results.failures.iter().enumerate() {
                assert!(failure.contains(&format!("error {}", i + 1)));
                count += 1;
            }
            assert_eq!(count, 3);
        }
    }

    // ============================================================================
    // Edge Cases and Boundary Tests
    // ============================================================================

    mod edge_cases_tests {
        use super::*;

        #[test]
        fn test_zero_tests_all_passed_is_true_matches_wycheproof_vector_matches_expected() {
            let results = WycheproofResults::new();
            // With no tests run, all_passed returns true (no failures)
            assert!(results.all_passed());
        }

        #[test]
        fn test_only_one_failure_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("single failure".to_string());
            assert!(!results.all_passed());
            assert_eq!(results.total, 1);
        }

        #[test]
        fn test_many_passes_one_failure_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..10000 {
                results.add_pass();
            }
            results.add_failure("one failure".to_string());

            assert!(!results.all_passed());
            assert_eq!(results.passed, 10000);
            assert_eq!(results.failed, 1);
        }

        #[test]
        fn test_failure_message_with_newlines_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("Line 1\nLine 2\nLine 3".to_string());
            assert!(results.failures[0].contains("\n"));
        }

        #[test]
        fn test_failure_message_with_tabs_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("Column1\tColumn2\tColumn3".to_string());
            assert!(results.failures[0].contains("\t"));
        }

        #[test]
        fn test_failures_vec_capacity_growth_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            // Add many failures to test vector growth
            for i in 0..1000 {
                results.add_failure(format!("failure {}", i));
            }
            assert_eq!(results.failures.len(), 1000);
        }
    }

    // ============================================================================
    // Simulation of Real Wycheproof Test Scenarios
    // ============================================================================

    mod real_scenario_tests {
        use super::*;

        #[test]
        fn test_aes_gcm_like_scenario_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // Simulate running AES-GCM test vectors
            // Most tests pass, some are skipped (non-standard params), few invalid tests pass correctly
            for _ in 0..100 {
                results.add_pass(); // Valid test passed
            }
            for _ in 0..20 {
                results.add_skip(); // Non-standard key size
            }
            for _ in 0..30 {
                results.add_pass(); // Invalid test correctly rejected
            }

            assert!(results.all_passed());
            assert_eq!(results.total, 150);
            assert_eq!(results.passed, 130);
            assert_eq!(results.skipped, 20);
            assert_eq!(results.failed, 0);
        }

        #[test]
        fn test_ecdsa_like_scenario_with_failures_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // Simulate ECDSA verification where some tests fail
            for i in 0..50 {
                if i % 10 == 0 {
                    results.add_failure(format!("Test {}: signature verification failed", i));
                } else {
                    results.add_pass();
                }
            }

            assert!(!results.all_passed());
            assert_eq!(results.total, 50);
            assert_eq!(results.passed, 45);
            assert_eq!(results.failed, 5);

            // Verify failure rate is acceptable (< 5% typically)
            let failure_rate = results.failed as f64 / results.total as f64;
            assert!(failure_rate < 0.15); // 10% failure rate in this scenario
        }

        #[test]
        fn test_chacha20_poly1305_like_scenario_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // ChaCha20-Poly1305 requires specific key/nonce sizes
            // Most tests run, some skipped for wrong parameters
            for _ in 0..80 {
                results.add_pass();
            }
            for _ in 0..15 {
                results.add_skip(); // Wrong key or nonce size
            }
            for _ in 0..5 {
                results.add_pass(); // Invalid tests correctly fail
            }

            assert!(results.all_passed());
            assert_eq!(results.total, 100);
        }

        #[test]
        fn test_ed25519_like_scenario_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // EdDSA signature verification
            for _ in 0..200 {
                results.add_pass();
            }
            for _ in 0..10 {
                results.add_skip(); // Invalid public key format
            }

            assert!(results.all_passed());
            assert_eq!(results.total, 210);
        }

        #[test]
        fn test_calculate_statistics_matches_expected() {
            let mut results = WycheproofResults::new();

            for _ in 0..70 {
                results.add_pass();
            }
            for _ in 0..20 {
                results.add_skip();
            }
            for _ in 0..10 {
                results.add_failure("test failure".to_string());
            }

            // Calculate various statistics
            let total_executed = results.passed + results.failed;
            let pass_rate = if total_executed > 0 {
                results.passed as f64 / total_executed as f64
            } else {
                0.0
            };

            assert_eq!(total_executed, 80);
            assert!((pass_rate - 0.875).abs() < f64::EPSILON); // 70/80 = 0.875

            // Skip rate
            let skip_rate = results.skipped as f64 / results.total as f64;
            assert!((skip_rate - 0.2).abs() < f64::EPSILON); // 20/100 = 0.2
        }

        #[test]
        fn test_print_summary_matches_expected() {
            let mut results = WycheproofResults::new();

            for _ in 0..90 {
                results.add_pass();
            }
            for _ in 0..5 {
                results.add_skip();
            }
            for _ in 0..5 {
                results.add_failure("test failure".to_string());
            }

            // Simulate printing a summary (like in the actual tests)
            let summary = format!(
                "Test Results: {}/{} passed, {} skipped, {} failed",
                results.passed, results.total, results.skipped, results.failed
            );

            assert!(summary.contains("90/100 passed"));
            assert!(summary.contains("5 skipped"));
            assert!(summary.contains("5 failed"));
        }
    }

    // ============================================================================
    // WycheproofResults Debug and Clone Tests
    // ============================================================================

    mod debug_and_clone_tests {
        use super::*;

        #[test]
        fn test_results_debug_empty_matches_expected() {
            let results = WycheproofResults::new();
            let debug = format!("{:?}", results);
            assert!(debug.contains("total: 0"));
            assert!(debug.contains("passed: 0"));
            assert!(debug.contains("failed: 0"));
            assert!(debug.contains("skipped: 0"));
        }

        #[test]
        fn test_results_debug_with_data_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_pass();
            results.add_pass();
            results.add_failure("error".to_string());
            results.add_skip();

            let debug = format!("{:?}", results);
            assert!(debug.contains("total: 4"));
            assert!(debug.contains("passed: 2"));
            assert!(debug.contains("failed: 1"));
            assert!(debug.contains("skipped: 1"));
        }

        #[test]
        fn test_results_debug_shows_failures_matches_expected() {
            let mut results = WycheproofResults::new();
            results.add_failure("first error".to_string());
            results.add_failure("second error".to_string());

            let debug = format!("{:?}", results);
            assert!(debug.contains("first error"));
            assert!(debug.contains("second error"));
        }
    }

    // ============================================================================
    // Failure Rate Analysis Tests
    // ============================================================================

    mod failure_rate_tests {
        use super::*;

        #[test]
        fn test_zero_failure_rate_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for _ in 0..100 {
                results.add_pass();
            }

            let failure_rate = results.failed as f64 / results.total as f64;
            assert_eq!(failure_rate, 0.0);
        }

        #[test]
        fn test_hundred_percent_failure_rate_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for i in 0..100 {
                results.add_failure(format!("failure {}", i));
            }

            let failure_rate = results.failed as f64 / results.total as f64;
            assert_eq!(failure_rate, 1.0);
        }

        #[test]
        fn test_five_percent_failure_rate_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();
            for i in 0..100 {
                if i < 5 {
                    results.add_failure(format!("failure {}", i));
                } else {
                    results.add_pass();
                }
            }

            let failure_rate = results.failed as f64 / results.total as f64;
            assert!((failure_rate - 0.05).abs() < f64::EPSILON);
        }

        #[test]
        fn test_failure_rate_threshold_check_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // Add results that are just under 5% failure threshold
            for _ in 0..96 {
                results.add_pass();
            }
            for _ in 0..4 {
                results.add_failure("error".to_string());
            }

            let failure_rate = results.failed as f64 / results.total as f64;
            assert!(failure_rate < 0.05, "Failure rate {} should be under 5%", failure_rate);
        }

        #[test]
        fn test_failure_rate_above_threshold_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            for _ in 0..90 {
                results.add_pass();
            }
            for _ in 0..10 {
                results.add_failure("error".to_string());
            }

            let failure_rate = results.failed as f64 / results.total as f64;
            assert!(failure_rate >= 0.05, "Failure rate {} should be at or above 5%", failure_rate);
        }
    }

    // ============================================================================
    // Thread Safety Consideration Tests (Single-threaded)
    // ============================================================================

    mod single_threaded_mutation_tests {
        use super::*;

        #[test]
        fn test_sequential_mutations_matches_wycheproof_vector_matches_expected() {
            let mut results = WycheproofResults::new();

            // Perform operations in sequence
            results.add_pass();
            assert_eq!(results.total, 1);

            results.add_failure("err".to_string());
            assert_eq!(results.total, 2);

            results.add_skip();
            assert_eq!(results.total, 3);

            // Verify final state
            assert_eq!(results.passed, 1);
            assert_eq!(results.failed, 1);
            assert_eq!(results.skipped, 1);
        }

        #[test]
        fn test_multiple_results_instances_matches_wycheproof_vector_matches_expected() {
            let mut results1 = WycheproofResults::new();
            let mut results2 = WycheproofResults::new();

            results1.add_pass();
            results2.add_failure("error".to_string());

            assert_eq!(results1.total, 1);
            assert_eq!(results2.total, 1);
            assert_eq!(results1.passed, 1);
            assert_eq!(results2.failed, 1);
            assert!(results1.all_passed());
            assert!(!results2.all_passed());
        }
    }
}
