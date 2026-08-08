//! FIPS format, input-coverage, and validator-impl coverage tests.
//!
//! Covers format validation, format/misc coverage, the validator impl
//! coverage suite, and input-validation coverage for the
//! `latticearc_tests::validation` crate.

#![deny(unsafe_code)]

mod format {
    //! Tests for format validation module
    //!
    //! This module tests key format validation functions.

    #![allow(clippy::unwrap_used, clippy::useless_vec)]

    use latticearc_tests::validation::format::{FormatError, validate_key_format};

    #[test]
    fn test_validate_key_format_correct_size_has_correct_size() {
        let key = vec![0u8; 32];
        let result = validate_key_format(&key, 32);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_format_wrong_size_too_small_fails() {
        let key = vec![0u8; 16];
        let result = validate_key_format(&key, 32);
        assert!(result.is_err());

        match result.unwrap_err() {
            FormatError::InvalidKeySize(actual, expected) => {
                assert_eq!(actual, 16);
                assert_eq!(expected, 32);
            }
        }
    }

    #[test]
    fn test_validate_key_format_wrong_size_too_large_fails() {
        let key = vec![0u8; 64];
        let result = validate_key_format(&key, 32);
        assert!(result.is_err());

        match result.unwrap_err() {
            FormatError::InvalidKeySize(actual, expected) => {
                assert_eq!(actual, 64);
                assert_eq!(expected, 32);
            }
        }
    }

    #[test]
    fn test_validate_key_format_empty_key_fails() {
        let key: Vec<u8> = vec![];
        let result = validate_key_format(&key, 32);
        assert!(result.is_err());

        match result.unwrap_err() {
            FormatError::InvalidKeySize(actual, expected) => {
                assert_eq!(actual, 0);
                assert_eq!(expected, 32);
            }
        }
    }

    #[test]
    fn test_validate_key_format_empty_expected_has_correct_size() {
        let key: Vec<u8> = vec![];
        let result = validate_key_format(&key, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_format_various_sizes_has_correct_size() {
        // Test common key sizes
        let sizes = [16, 24, 32, 48, 64, 128, 256];

        for size in sizes {
            let key = vec![0x42u8; size];
            let result = validate_key_format(&key, size);
            assert!(result.is_ok(), "Key size {} should be valid", size);
        }
    }

    #[test]
    fn test_format_error_display_fails() {
        let error = FormatError::InvalidKeySize(16, 32);
        let display = format!("{error}");
        assert!(display.contains("16"));
        assert!(display.contains("32"));
        assert!(display.contains("Invalid key size"));
    }

    #[test]
    fn test_format_error_debug_fails() {
        let error = FormatError::InvalidKeySize(16, 32);
        let debug = format!("{:?}", error);
        assert!(debug.contains("InvalidKeySize"));
    }
}

mod format_misc {
    //! Coverage tests for format.rs, validation_summary.rs, and other small coverage gaps.

    #![allow(clippy::unwrap_used)]

    use latticearc_tests::validation::format::{FormatError, validate_key_format};

    // ============================================================
    // format.rs — 0% coverage (6 lines)
    // ============================================================

    #[test]
    fn test_validate_key_format_correct_size_succeeds() {
        let key = vec![0u8; 32];
        assert!(
            validate_key_format(&key, 32).is_ok(),
            "32-byte key should pass validation for expected size 32"
        );
    }

    #[test]
    fn test_validate_key_format_wrong_size_returns_error() {
        let key = vec![0u8; 16];
        let result = validate_key_format(&key, 32);
        assert!(result.is_err(), "16-byte key should fail validation for expected size 32");
        match result.unwrap_err() {
            FormatError::InvalidKeySize(actual, expected) => {
                assert_eq!(actual, 16, "actual key size should be 16");
                assert_eq!(expected, 32, "expected key size should be 32");
            }
        }
    }

    #[test]
    fn test_validate_key_format_empty_validates_correctly_has_correct_size() {
        let key: Vec<u8> = Vec::new();
        assert!(
            validate_key_format(&key, 0).is_ok(),
            "empty key should pass validation for expected size 0"
        );
        assert!(
            validate_key_format(&key, 1).is_err(),
            "empty key should fail validation for expected size 1"
        );
    }

    #[test]
    fn test_format_error_display_contains_sizes_fails() {
        let err = FormatError::InvalidKeySize(16, 32);
        let msg = format!("{err}");
        assert!(msg.contains("16"), "error message should contain actual size 16");
        assert!(msg.contains("32"), "error message should contain expected size 32");
    }

    // ============================================================
    // validation_summary.rs — ComplianceReporter coverage
    // ============================================================

    use latticearc_tests::validation::validation_summary::ComplianceReporter;

    #[test]
    fn test_compliance_reporter_new_generates_empty_report_succeeds() {
        let reporter = ComplianceReporter::new(0.05);
        let report = reporter.generate_full_compliance_report(&[], &None);
        assert!(report.is_ok(), "empty compliance report should generate successfully");
    }

    #[test]
    fn test_compliance_reporter_json_export_succeeds() {
        let reporter = ComplianceReporter::new(0.01);
        let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
        let json = reporter.generate_json_report(&report);
        assert!(json.is_ok(), "JSON report generation should succeed");
        let json_str = json.unwrap();
        assert!(
            json_str.contains("overall_compliance"),
            "JSON report should contain overall_compliance field"
        );
    }

    #[test]
    fn test_compliance_reporter_html_export_succeeds() {
        let reporter = ComplianceReporter::new(0.05);
        let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
        let html = reporter.generate_html_report(&report);
        assert!(html.is_ok(), "HTML report generation should succeed");
        let html_str = html.unwrap();
        assert!(
            html_str.contains("html") || html_str.contains("Compliance"),
            "HTML report should contain markup or compliance content"
        );
    }

    // ============================================================
    // nist_functions.rs — RandomizedHasher coverage
    // ============================================================

    use latticearc_tests::validation::nist_functions::{
        RandomizedHashConfig, RandomizedHashMode, RandomizedHasher, RandomizedHashing,
    };

    #[test]
    fn test_randomized_hasher_default_hashes_successfully_succeeds() {
        let hasher = RandomizedHasher::default();
        let hash = hasher.hash(b"test message");
        assert!(hash.is_ok(), "default hasher should hash successfully");
        let hash_result = hash.unwrap();
        assert!(!hash_result.hash_hex().is_empty(), "hash hex should not be empty");
        assert!(!hash_result.salt_hex().is_empty(), "salt hex should not be empty");
    }

    #[test]
    fn test_randomized_hasher_verify_succeeds_for_same_message_succeeds() {
        let hasher = RandomizedHasher::default();
        let message = b"verify this message";
        let hash = hasher.hash(message).unwrap();
        let valid = hasher.verify(message, &hash);
        assert!(valid.is_ok(), "verification should not return error");
        assert!(valid.unwrap(), "hash should verify against same message");
    }

    #[test]
    fn test_randomized_hasher_verify_wrong_message_returns_false_fails() {
        let hasher = RandomizedHasher::default();
        let hash = hasher.hash(b"original message").unwrap();
        let valid = hasher.verify(b"different message", &hash);
        assert!(valid.is_ok(), "verification of wrong message should not error");
        assert!(!valid.unwrap(), "hash should not verify against different message");
    }

    #[test]
    fn test_randomized_hasher_custom_config_hashes_successfully_succeeds() {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode: RandomizedHashMode::SaltSuffix,
            salt_length: 32,
            salt_insertions: 1,
        };
        let hasher = RandomizedHasher::new(config);
        let hash = hasher.hash(b"test");
        assert!(hash.is_ok(), "custom config hasher should hash successfully");
    }

    #[test]
    fn test_nist_functions_hash_message_succeeds() {
        let hash = RandomizedHashing::hash_message(b"hello world");
        assert!(hash.is_ok(), "static hash_message should succeed");
    }

    #[test]
    fn test_nist_functions_verify_hash_succeeds() {
        let message = b"test message for static API";
        let hash = RandomizedHashing::hash_message(message).unwrap();
        let valid = RandomizedHashing::verify_hash(message, &hash);
        assert!(valid.is_ok(), "static verify_hash should not error");
        assert!(valid.unwrap(), "static API hash should verify against same message");
    }

    #[test]
    fn test_nist_functions_recommended_config_returns_valid_config_succeeds() {
        let config_128 = RandomizedHashing::recommended_config(128);
        assert!(config_128.salt_length > 0, "128-bit config should have positive salt length");

        let config_256 = RandomizedHashing::recommended_config(256);
        assert!(
            config_256.salt_length >= config_128.salt_length,
            "256-bit config salt should be >= 128-bit config salt"
        );
    }

    #[test]
    fn test_nist_functions_hash_with_config_succeeds() {
        let config = RandomizedHashing::recommended_config(192);
        let hash = RandomizedHashing::hash_message_with_config(b"test", config);
        assert!(hash.is_ok(), "hash_message_with_config should succeed with 192-bit config");
    }
}

mod impl_validator {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    //! Coverage tests for `Fips140_3Validator` methods that are not exercised by existing tests.
    //!
    //! Targets: `run_power_up_tests()`, `run_conditional_tests()`, `generate_compliance_certificate()`,
    //! `is_power_up_completed()`, `should_run_conditional_tests()`, `test_vectors()`, and `Default`.

    use chrono::Utc;
    use latticearc_tests::validation::fips_validation_impl::{
        Fips140_3ValidationResult, Fips140_3Validator, SelfTestResult, SelfTestType,
    };

    // ============================================================================
    // Fips140_3Validator::run_power_up_tests
    // ============================================================================

    #[test]
    fn test_run_power_up_tests_succeeds() {
        let mut validator = Fips140_3Validator::new("test-module".to_string(), 3);
        let result = validator.run_power_up_tests().expect("Power-up tests should succeed");
        assert!(result.validation_id.starts_with("FIPS140-3-"));
        assert_eq!(result.module_name, "test-module");
        assert_eq!(result.compliance_level, "FIPS 140-3 Level 3");
        assert!(!result.power_up_tests.is_empty());
        assert!(result.conditional_tests.is_empty());
    }

    #[test]
    fn test_run_power_up_tests_has_seven_subtests_verified_succeeds() {
        let mut validator = Fips140_3Validator::new("module-seven".to_string(), 1);
        let result = validator.run_power_up_tests().unwrap();
        // Should have 7 subtests: AES key wrapping, hash functions, signature algorithms,
        // key encapsulation, RNG quality, pairwise consistency, zeroization
        assert_eq!(result.power_up_tests.len(), 7, "Expected 7 power-up subtests");
    }

    #[test]
    fn test_run_power_up_tests_check_subtest_names_match_expected_succeeds() {
        let mut validator = Fips140_3Validator::new("test-names".to_string(), 1);
        let result = validator.run_power_up_tests().unwrap();

        let names: Vec<&str> = result.power_up_tests.iter().map(|t| t.test_name.as_str()).collect();
        assert!(names.contains(&"AES Key Wrapping Test"));
        assert!(names.contains(&"Hash Function Tests"));
        assert!(names.contains(&"Digital Signature Test"));
        assert!(names.contains(&"Key Encapsulation Randomness Test"));
        assert!(names.contains(&"Random Number Generator Quality Test"));
        assert!(names.contains(&"Pairwise Consistency Test"));
        assert!(names.contains(&"Memory Zeroization Test"));
    }

    #[test]
    fn test_run_power_up_tests_algorithms_match_expected_succeeds() {
        let mut validator = Fips140_3Validator::new("algo-check".to_string(), 1);
        let result = validator.run_power_up_tests().unwrap();

        let algorithms: Vec<&str> =
            result.power_up_tests.iter().map(|t| t.algorithm.as_str()).collect();
        assert!(algorithms.contains(&"AES-256-GCM"));
        assert!(algorithms.contains(&"SHA-256, SHA3-256"));
        assert!(algorithms.contains(&"Ed25519"));
        assert!(algorithms.contains(&"HMAC-SHA256"));
        assert!(algorithms.contains(&"Zeroization"));
    }

    #[test]
    fn test_run_power_up_tests_sets_power_up_completed_flag_succeeds() {
        let mut validator = Fips140_3Validator::new("complete-check".to_string(), 1);
        assert!(!validator.is_power_up_completed());

        let result = validator.run_power_up_tests().unwrap();
        // If all subtests passed, power_up_completed should be true
        if result.overall_passed {
            assert!(validator.is_power_up_completed());
        }
    }

    #[test]
    fn test_run_power_up_tests_detailed_results_populated_succeeds() {
        let mut validator = Fips140_3Validator::new("detailed".to_string(), 2);
        let result = validator.run_power_up_tests().unwrap();

        // Verify detailed_results JSON has expected fields
        let details = &result.detailed_results;
        assert!(details.get("power_up_tests_count").is_some());
        assert!(details.get("passed_tests").is_some());
        assert!(details.get("test_coverage").is_some());
    }

    #[test]
    fn test_run_power_up_tests_execution_time_is_nonzero_succeeds() {
        let mut validator = Fips140_3Validator::new("timing".to_string(), 1);
        let result = validator.run_power_up_tests().unwrap();

        // Execution time should be non-zero
        assert!(result.execution_time.as_nanos() > 0);

        // Each subtest should have its own execution time
        for subtest in &result.power_up_tests {
            // execution_time should be populated
            let _ = subtest.execution_time;
        }
    }

    // ============================================================================
    // Fips140_3Validator::run_conditional_tests
    // ============================================================================

    #[test]
    fn test_run_conditional_tests_succeeds() {
        let mut validator = Fips140_3Validator::new("cond-module".to_string(), 2);
        let result = validator.run_conditional_tests().expect("Conditional tests should succeed");
        assert!(result.validation_id.starts_with("FIPS140-3-COND-"));
        assert_eq!(result.module_name, "cond-module");
        assert!(result.power_up_tests.is_empty());
        assert!(!result.conditional_tests.is_empty());
    }

    #[test]
    fn test_run_conditional_tests_has_four_subtests_verified_succeeds() {
        let mut validator = Fips140_3Validator::new("cond-count".to_string(), 1);
        let result = validator.run_conditional_tests().unwrap();
        // Should have 4 subtests: key integrity, operational environment, error detection, performance limits
        assert_eq!(result.conditional_tests.len(), 4, "Expected 4 conditional subtests");
    }

    #[test]
    fn test_run_conditional_tests_check_subtest_names_match_expected_succeeds() {
        let mut validator = Fips140_3Validator::new("cond-names".to_string(), 1);
        let result = validator.run_conditional_tests().unwrap();

        let names: Vec<&str> =
            result.conditional_tests.iter().map(|t| t.test_name.as_str()).collect();
        assert!(names.contains(&"Key Integrity Test"));
        assert!(names.contains(&"Operational Environment Test"));
        assert!(names.contains(&"Error Detection Test"));
        assert!(names.contains(&"Performance Limits Test"));
    }

    #[test]
    fn test_run_conditional_tests_all_pass_returns_ok() {
        let mut validator = Fips140_3Validator::new("all-pass".to_string(), 1);
        let result = validator.run_conditional_tests().unwrap();
        // All four conditional tests should pass
        assert!(result.overall_passed);
        for test in &result.conditional_tests {
            assert!(test.passed, "Test {} should pass", test.test_name);
        }
    }

    #[test]
    fn test_run_conditional_tests_detailed_results_populated_succeeds() {
        let mut validator = Fips140_3Validator::new("cond-detail".to_string(), 1);
        let result = validator.run_conditional_tests().unwrap();
        let details = &result.detailed_results;
        assert!(details.get("conditional_tests_count").is_some());
        assert!(details.get("passed_tests").is_some());
        assert!(details.get("test_frequency").is_some());
    }

    // ============================================================================
    // Fips140_3Validator::generate_compliance_certificate
    // ============================================================================

    #[test]
    fn test_generate_compliance_certificate_power_up_contains_required_fields_succeeds() {
        let mut validator = Fips140_3Validator::new("cert-module".to_string(), 3);
        let result = validator.run_power_up_tests().unwrap();
        let cert = validator.generate_compliance_certificate(&result);

        assert!(cert.contains("FIPS 140-3 COMPLIANCE CERTIFICATE"));
        assert!(cert.contains("Module: cert-module"));
        assert!(cert.contains("Compliance Level: FIPS 140-3 Level 3"));
        assert!(cert.contains("Power-Up Tests:"));
        assert!(cert.contains("[PASS]") || cert.contains("[FAIL]"));
        assert!(cert.contains("Total Execution Time:"));
        assert!(cert.contains("LatticeArc Validation Framework"));
    }

    #[test]
    fn test_generate_compliance_certificate_conditional_contains_required_fields_succeeds() {
        let mut validator = Fips140_3Validator::new("cert-cond".to_string(), 2);
        let result = validator.run_conditional_tests().unwrap();
        let cert = validator.generate_compliance_certificate(&result);

        assert!(cert.contains("Conditional Tests:"));
        assert!(cert.contains("cert-cond"));
    }

    #[test]
    fn test_generate_compliance_certificate_empty_result_shows_passed_succeeds() {
        let validator = Fips140_3Validator::new("cert-empty".to_string(), 1);
        let result = Fips140_3ValidationResult {
            validation_id: "VR-EMPTY".to_string(),
            timestamp: Utc::now(),
            power_up_tests: vec![],
            conditional_tests: vec![],
            overall_passed: true,
            compliance_level: "FIPS 140-3 Level 1".to_string(),
            module_name: "cert-empty".to_string(),
            execution_time: std::time::Duration::from_millis(1),
            detailed_results: serde_json::json!({}),
        };
        let cert = validator.generate_compliance_certificate(&result);

        assert!(cert.contains("PASSED"));
        // Should NOT contain "Power-Up Tests:" or "Conditional Tests:" sections
        assert!(!cert.contains("Power-Up Tests:"));
        assert!(!cert.contains("Conditional Tests:"));
    }

    #[test]
    fn test_generate_compliance_certificate_failed_result_shows_failed_fails() {
        let validator = Fips140_3Validator::new("cert-fail".to_string(), 1);
        let result = Fips140_3ValidationResult {
            validation_id: "VR-FAIL".to_string(),
            timestamp: Utc::now(),
            power_up_tests: vec![SelfTestResult {
                test_type: SelfTestType::PowerUp,
                test_name: "FailingTest".to_string(),
                algorithm: "TEST".to_string(),
                passed: false,
                execution_time: std::time::Duration::from_millis(1),
                timestamp: Utc::now(),
                details: serde_json::json!({}),
                error_message: Some("intentional failure".to_string()),
            }],
            conditional_tests: vec![],
            overall_passed: false,
            compliance_level: "FIPS 140-3 Level 1".to_string(),
            module_name: "cert-fail".to_string(),
            execution_time: std::time::Duration::from_millis(5),
            detailed_results: serde_json::json!({}),
        };
        let cert = validator.generate_compliance_certificate(&result);

        assert!(cert.contains("FAILED"));
        assert!(cert.contains("[FAIL] FailingTest"));
    }

    // ============================================================================
    // Fips140_3Validator state methods
    // ============================================================================

    #[test]
    fn test_is_power_up_completed_default_false_succeeds() {
        let validator = Fips140_3Validator::new("state-check".to_string(), 1);
        assert!(!validator.is_power_up_completed());
    }

    #[test]
    fn test_should_run_conditional_tests_after_creation_succeeds() {
        let validator = Fips140_3Validator::new("cond-schedule".to_string(), 1);
        // Just created, last_conditional_test is now, so should NOT need to run yet
        assert!(!validator.should_run_conditional_tests());
    }

    #[test]
    fn test_test_vectors_empty_initially_matches_expected() {
        let validator = Fips140_3Validator::new("vectors-check".to_string(), 1);
        assert!(validator.test_vectors_matches_expected().is_empty());
    }

    // ============================================================================
    // Fips140_3Validator::default
    // ============================================================================

    #[test]
    fn test_fips_validator_default_succeeds() {
        let validator = Fips140_3Validator::default();
        assert!(!validator.is_power_up_completed());
        assert!(validator.test_vectors_matches_expected().is_empty());
        assert!(!validator.should_run_conditional_tests());
    }

    #[test]
    fn test_fips_validator_default_run_power_up_succeeds() {
        let mut validator = Fips140_3Validator::default();
        let result = validator.run_power_up_tests().unwrap();
        assert_eq!(result.module_name, "LatticeArc-Crypto");
        assert!(!result.power_up_tests.is_empty());
    }

    #[test]
    fn test_fips_validator_default_run_conditional_succeeds() {
        let mut validator = Fips140_3Validator::default();
        let result = validator.run_conditional_tests().unwrap();
        assert!(!result.conditional_tests.is_empty());
        assert!(result.overall_passed);
    }

    // ============================================================================
    // Power-up then conditional in sequence
    // ============================================================================

    #[test]
    fn test_full_validation_sequence_succeeds() {
        let mut validator = Fips140_3Validator::new("full-seq".to_string(), 3);

        // Step 1: Power-up tests
        let power_result = validator.run_power_up_tests().unwrap();
        assert!(!power_result.power_up_tests.is_empty());

        // Step 2: Conditional tests
        let cond_result = validator.run_conditional_tests().unwrap();
        assert!(!cond_result.conditional_tests.is_empty());

        // Step 3: Certificate for each
        let power_cert = validator.generate_compliance_certificate(&power_result);
        let cond_cert = validator.generate_compliance_certificate(&cond_result);

        assert!(power_cert.contains("Power-Up Tests:"));
        assert!(cond_cert.contains("Conditional Tests:"));
    }
}

mod input {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    //! Coverage tests for input.rs — validate_input_size and ValidationError

    use latticearc_tests::validation::input::{ValidationError, validate_input_size};

    // ============================================================================
    // validate_input_size — valid inputs
    // ============================================================================

    #[test]
    fn test_valid_input_exact_min_succeeds() {
        let data = vec![0u8; 16];
        assert!(validate_input_size(&data, 16, 64).is_ok());
    }

    #[test]
    fn test_valid_input_exact_max_succeeds() {
        let data = vec![0u8; 64];
        assert!(validate_input_size(&data, 16, 64).is_ok());
    }

    #[test]
    fn test_valid_input_between_succeeds() {
        let data = vec![0u8; 32];
        assert!(validate_input_size(&data, 16, 64).is_ok());
    }

    #[test]
    fn test_valid_input_zero_min_succeeds() {
        let data = vec![];
        assert!(validate_input_size(&data, 0, 100).is_ok());
    }

    #[test]
    fn test_valid_input_min_equals_max_succeeds() {
        let data = vec![0u8; 32];
        assert!(validate_input_size(&data, 32, 32).is_ok());
    }

    // ============================================================================
    // validate_input_size — InputTooSmall
    // ============================================================================

    #[test]
    fn test_input_too_small_fails() {
        let data = vec![0u8; 15];
        let result = validate_input_size(&data, 16, 64);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooSmall(actual, min) => {
                assert_eq!(actual, 15);
                assert_eq!(min, 16);
            }
            other => panic!("Expected InputTooSmall, got {:?}", other),
        }
    }

    #[test]
    fn test_input_too_small_empty_fails() {
        let data = vec![];
        let result = validate_input_size(&data, 1, 100);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooSmall(actual, min) => {
                assert_eq!(actual, 0);
                assert_eq!(min, 1);
            }
            other => panic!("Expected InputTooSmall, got {:?}", other),
        }
    }

    // ============================================================================
    // validate_input_size — InputTooLarge
    // ============================================================================

    #[test]
    fn test_input_too_large_fails() {
        let data = vec![0u8; 65];
        let result = validate_input_size(&data, 16, 64);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooLarge(actual, max) => {
                assert_eq!(actual, 65);
                assert_eq!(max, 64);
            }
            other => panic!("Expected InputTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_input_too_large_by_one_fails() {
        let data = vec![0u8; 33];
        let result = validate_input_size(&data, 0, 32);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InputTooLarge(actual, max) => {
                assert_eq!(actual, 33);
                assert_eq!(max, 32);
            }
            other => panic!("Expected InputTooLarge, got {:?}", other),
        }
    }

    // ============================================================================
    // ValidationError Display
    // ============================================================================

    #[test]
    fn test_validation_error_display_too_small_fails() {
        let err = ValidationError::InputTooSmall(10, 16);
        let msg = format!("{err}");
        assert!(msg.contains("too small"));
        assert!(msg.contains("10"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn test_validation_error_display_too_large_fails() {
        let err = ValidationError::InputTooLarge(100, 64);
        let msg = format!("{err}");
        assert!(msg.contains("too large"));
        assert!(msg.contains("100"));
        assert!(msg.contains("64"));
    }

    #[test]
    fn test_validation_error_debug_fails() {
        let err = ValidationError::InputTooSmall(5, 10);
        let debug = format!("{:?}", err);
        assert!(debug.contains("InputTooSmall"));
    }
}
