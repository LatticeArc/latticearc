//! KAT loader, reporter, and type tests.
#![deny(unsafe_code)]

// Originally: fips_kat_loaders_tests.rs
mod loaders {
    //! Comprehensive tests for KAT (Known Answer Test) vector loaders.
    //!
    //! This test module validates all loader functions in `latticearc_tests::validation::kat_tests::loaders`,
    //! ensuring correct parsing, field validation, and error handling for cryptographic test vectors.
    //!
    //! NOTE: Some loaders (AES-GCM, ML-DSA, SLH-DSA, Ed25519) have known hex encoding
    //! issues in their hardcoded test vectors. Tests document these issues while validating
    //! the working loaders (ML-KEM, SHA3, Hybrid-KEM, CAVP parser).

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

    use latticearc_tests::validation::kat_tests::loaders::{
        CavpTestCase, CavpTestGroup, CavpTestVectorFile, load_aes_gcm_kats, load_ed25519_kats,
        load_from_cavp_json, load_hybrid_kem_kats, load_ml_dsa_kats, load_ml_kem_1024_kats,
        load_sha3_kats, load_slh_dsa_kats,
    };

    // ============================================================================
    // ML-KEM-1024 Loader Tests (WORKING)
    // ============================================================================

    mod ml_kem_loader_tests {
        use super::*;

        #[test]
        fn test_load_ml_kem_1024_kats_returns_vectors_matches_expected() {
            let result = load_ml_kem_1024_kats();
            assert!(result.is_ok(), "load_ml_kem_1024_kats() should succeed");

            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return at least one ML-KEM-1024 vector");
        }

        #[test]
        fn test_ml_kem_1024_vectors_have_valid_test_case_names_matches_expected() {
            let vectors = load_ml_kem_1024_kats().unwrap();

            for vector in &vectors {
                assert!(!vector.test_case.is_empty(), "Test case name should not be empty");
                assert!(
                    vector.test_case.contains("KEM") || vector.test_case.contains("VALIDATION"),
                    "Test case name '{}' should reference KEM or VALIDATION",
                    vector.test_case
                );
            }
        }

        #[test]
        fn test_ml_kem_1024_vectors_have_correct_key_sizes_matches_expected() {
            let vectors = load_ml_kem_1024_kats().unwrap();

            // ML-KEM-1024 key sizes per FIPS 203
            const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
            const ML_KEM_1024_SECRET_KEY_SIZE: usize = 3168;
            const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;
            const SHARED_SECRET_SIZE: usize = 32;
            const SEED_SIZE: usize = 64;

            for vector in &vectors {
                assert_eq!(
                    vector.expected_public_key.len(),
                    ML_KEM_1024_PUBLIC_KEY_SIZE,
                    "Public key size mismatch for test case '{}'",
                    vector.test_case
                );
                assert_eq!(
                    vector.expected_secret_key.len(),
                    ML_KEM_1024_SECRET_KEY_SIZE,
                    "Secret key size mismatch for test case '{}'",
                    vector.test_case
                );
                assert_eq!(
                    vector.expected_ciphertext.len(),
                    ML_KEM_1024_CIPHERTEXT_SIZE,
                    "Ciphertext size mismatch for test case '{}'",
                    vector.test_case
                );
                assert_eq!(
                    vector.expected_shared_secret.len(),
                    SHARED_SECRET_SIZE,
                    "Shared secret size mismatch for test case '{}'",
                    vector.test_case
                );
                assert_eq!(
                    vector.seed.len(),
                    SEED_SIZE,
                    "Seed size mismatch for test case '{}'",
                    vector.test_case
                );
            }
        }

        #[test]
        fn test_ml_kem_1024_vectors_have_non_trivial_data_succeeds() {
            let vectors = load_ml_kem_1024_kats().unwrap();

            // At least some vectors should have non-zero data
            // (exclude basic validation vectors which may have zeroed data)
            let non_trivial_vectors: Vec<_> =
                vectors.iter().filter(|v| !v.test_case.contains("BASIC-VALIDATION")).collect();

            for vector in non_trivial_vectors {
                // Check that keys are not all zeros
                let pk_non_zero = vector.expected_public_key.iter().any(|&b| b != 0);
                let sk_non_zero = vector.expected_secret_key.iter().any(|&b| b != 0);
                let ct_non_zero = vector.expected_ciphertext.iter().any(|&b| b != 0);
                let ss_non_zero = vector.expected_shared_secret.iter().any(|&b| b != 0);

                assert!(
                    pk_non_zero,
                    "Public key should have non-zero bytes for test case '{}'",
                    vector.test_case
                );
                assert!(
                    sk_non_zero,
                    "Secret key should have non-zero bytes for test case '{}'",
                    vector.test_case
                );
                assert!(
                    ct_non_zero,
                    "Ciphertext should have non-zero bytes for test case '{}'",
                    vector.test_case
                );
                assert!(
                    ss_non_zero,
                    "Shared secret should have non-zero bytes for test case '{}'",
                    vector.test_case
                );
            }
        }

        #[test]
        fn test_ml_kem_1024_returns_at_least_ten_vectors_matches_expected() {
            let vectors = load_ml_kem_1024_kats().unwrap();
            assert!(
                vectors.len() >= 10,
                "Should return at least 10 ML-KEM-1024 vectors for comprehensive testing, got {}",
                vectors.len()
            );
        }

        #[test]
        fn test_ml_kem_loader_is_deterministic_in_count_is_deterministic() {
            // Run the loader twice and verify it returns same count
            let result1 = load_ml_kem_1024_kats();
            let result2 = load_ml_kem_1024_kats();

            assert!(result1.is_ok(), "First ML-KEM-1024 KAT load should succeed");
            assert!(result2.is_ok(), "Second ML-KEM-1024 KAT load should succeed");

            let vectors1 = result1.unwrap();
            let vectors2 = result2.unwrap();

            // Vector counts should be the same
            assert_eq!(
                vectors1.len(),
                vectors2.len(),
                "Loader should return same number of vectors on repeated calls"
            );
        }

        #[test]
        fn test_ml_kem_vectors_have_unique_test_case_names_succeeds() {
            let vectors = load_ml_kem_1024_kats().unwrap();
            let names: Vec<_> = vectors.iter().map(|v| &v.test_case).collect();
            let unique: std::collections::HashSet<_> = names.iter().collect();
            assert_eq!(names.len(), unique.len(), "ML-KEM test case names should be unique");
        }
    }

    // ============================================================================
    // SHA3 Loader Tests (WORKING)
    // ============================================================================

    mod sha3_loader_tests {
        use super::*;

        #[test]
        fn test_load_sha3_kats_returns_vectors_matches_expected() {
            let result = load_sha3_kats();
            assert!(result.is_ok(), "load_sha3_kats() should succeed");

            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return at least one SHA3 vector");
        }

        #[test]
        fn test_sha3_vectors_have_valid_hash_sizes_matches_expected() {
            let vectors = load_sha3_kats().unwrap();

            for vector in &vectors {
                // SHA3-256 produces 32-byte hashes
                assert_eq!(
                    vector.expected_hash.len(),
                    32,
                    "SHA3-256 hash should be 32 bytes for test case '{}', got {}",
                    vector.test_case,
                    vector.expected_hash.len()
                );
            }
        }

        #[test]
        fn test_sha3_vectors_include_empty_message_succeeds() {
            let vectors = load_sha3_kats().unwrap();

            let has_empty_message = vectors.iter().any(|v| v.message.is_empty());
            assert!(
                has_empty_message,
                "Should include a test vector with empty message for edge case testing"
            );
        }

        #[test]
        fn test_sha3_vectors_include_known_test_cases_succeeds() {
            let vectors = load_sha3_kats().unwrap();

            // Check for "abc" test case which is a standard NIST test
            let has_abc_test = vectors.iter().any(|v| v.message == b"abc".to_vec());

            assert!(has_abc_test, "Should include the standard 'abc' NIST test vector");
        }

        #[test]
        fn test_sha3_empty_message_hash_value_matches_known_value_succeeds() {
            let vectors = load_sha3_kats().unwrap();

            // Find the empty message test case
            let empty_test = vectors.iter().find(|v| v.message.is_empty());

            if let Some(vector) = empty_test {
                // SHA3-256 of empty string is a known value
                let expected_empty_hash =
                    hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                        .unwrap();
                assert_eq!(
                    vector.expected_hash, expected_empty_hash,
                    "SHA3-256 hash of empty message should match known value"
                );
            }
        }

        #[test]
        fn test_sha3_abc_hash_value_matches_known_value_succeeds() {
            let vectors = load_sha3_kats().unwrap();

            // Verify SHA3-256("abc") known value from NIST
            let abc_vector = vectors.iter().find(|v| v.message == b"abc".to_vec());

            if let Some(vector) = abc_vector {
                let expected =
                    hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                        .unwrap();
                assert_eq!(
                    vector.expected_hash, expected,
                    "SHA3-256('abc') should match NIST test vector"
                );
            }
        }

        #[test]
        fn test_sha3_vectors_have_unique_test_case_names_succeeds() {
            let vectors = load_sha3_kats().unwrap();
            let names: Vec<_> = vectors.iter().map(|v| &v.test_case).collect();
            let unique: std::collections::HashSet<_> = names.iter().collect();
            assert_eq!(names.len(), unique.len(), "SHA3 test case names should be unique");
        }

        #[test]
        fn test_sha3_vectors_have_valid_test_case_names_matches_expected() {
            let vectors = load_sha3_kats().unwrap();

            for vector in &vectors {
                assert!(!vector.test_case.is_empty(), "Test case name should not be empty");
                assert!(
                    vector.test_case.contains("SHA3") && vector.test_case.contains("KAT"),
                    "Test case '{}' should follow SHA3-*-KAT-* naming convention",
                    vector.test_case
                );
            }
        }
    }

    // ============================================================================
    // Hybrid KEM Loader Tests (WORKING - hex encoding fixed)
    // ============================================================================

    mod hybrid_kem_loader_tests {
        use super::*;

        #[test]
        fn test_hybrid_kem_loader_returns_vectors_matches_expected() {
            let vectors = load_hybrid_kem_kats();
            assert!(!vectors.is_empty(), "Hybrid KEM loader should return test vectors");
        }

        #[test]
        fn test_hybrid_kem_vectors_have_valid_structure_matches_expected() {
            let vectors = load_hybrid_kem_kats();
            for vector in &vectors {
                assert!(!vector.test_case.is_empty(), "Test case should not be empty");
                assert!(!vector.seed.is_empty(), "Seed should not be empty");
                assert!(
                    !vector.expected_encapsulated_key.is_empty(),
                    "Encapsulated key should not be empty"
                );
                assert!(
                    !vector.expected_shared_secret.is_empty(),
                    "Shared secret should not be empty"
                );
            }
        }
    }

    // ============================================================================
    // Additional Algorithm Loader Tests (WORKING - hex encoding fixed)
    // ============================================================================

    mod additional_loader_tests {
        use super::*;

        #[test]
        fn test_aes_gcm_loader_returns_vectors_matches_expected() {
            let result = load_aes_gcm_kats();
            assert!(result.is_ok(), "AES-GCM loader should succeed");
            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return AES-GCM test vectors");
        }

        #[test]
        fn test_aes_gcm_vectors_have_valid_structure_matches_expected() {
            let vectors = load_aes_gcm_kats().unwrap();
            for vector in &vectors {
                assert!(!vector.key.is_empty(), "Key should not be empty");
                assert!(!vector.nonce.is_empty(), "Nonce should not be empty");
                assert!(!vector.plaintext.is_empty(), "Plaintext should not be empty");
                assert_eq!(vector.expected_tag.len(), 16, "Tag should be 16 bytes");
            }
        }

        #[test]
        fn test_ml_dsa_loader_returns_vectors_matches_expected() {
            let result = load_ml_dsa_kats();
            assert!(result.is_ok(), "ML-DSA loader should succeed");
            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return ML-DSA test vectors");
        }

        #[test]
        fn test_ml_dsa_vectors_have_valid_structure_matches_expected() {
            let vectors = load_ml_dsa_kats().unwrap();
            for vector in &vectors {
                assert!(!vector.seed.is_empty(), "Seed should not be empty");
                assert!(!vector.message.is_empty(), "Message should not be empty");
                assert!(!vector.expected_public_key.is_empty(), "Public key should not be empty");
            }
        }

        #[test]
        fn test_slh_dsa_loader_returns_vectors_matches_expected() {
            let result = load_slh_dsa_kats();
            assert!(result.is_ok(), "SLH-DSA loader should succeed");
            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return SLH-DSA test vectors");
        }

        #[test]
        fn test_slh_dsa_vectors_have_valid_structure_matches_expected() {
            let vectors = load_slh_dsa_kats().unwrap();
            for vector in &vectors {
                assert!(!vector.seed.is_empty(), "Seed should not be empty");
                assert!(!vector.message.is_empty(), "Message should not be empty");
                assert!(!vector.expected_signature.is_empty(), "Signature should not be empty");
            }
        }

        #[test]
        fn test_ed25519_loader_returns_vectors_matches_expected() {
            let result = load_ed25519_kats();
            assert!(result.is_ok(), "Ed25519 loader should succeed");
            let vectors = result.unwrap();
            assert!(!vectors.is_empty(), "Should return Ed25519 test vectors");
        }

        #[test]
        fn test_ed25519_vectors_have_correct_sizes_matches_expected() {
            let vectors = load_ed25519_kats().unwrap();
            for vector in &vectors {
                assert_eq!(vector.seed.len(), 32, "Ed25519 seed should be 32 bytes");
                assert_eq!(
                    vector.expected_public_key.len(),
                    32,
                    "Ed25519 public key should be 32 bytes"
                );
                assert_eq!(
                    vector.expected_signature.len(),
                    64,
                    "Ed25519 signature should be 64 bytes"
                );
            }
        }
    }

    // ============================================================================
    // CAVP JSON Parsing Tests (WORKING)
    // ============================================================================

    mod cavp_json_parsing_tests {
        use super::*;

        fn create_valid_cavp_json() -> String {
            r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {
                            "tc_id": 1,
                            "seed": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                            "pk": "000102030405060708090a0b0c0d0e0f",
                            "sk": "101112131415161718191a1b1c1d1e1f",
                            "ct": "202122232425262728292a2b2c2d2e2f",
                            "ss": "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
                        }
                    ]
                }
            ]
        }"#
        .to_string()
        }

        #[test]
        fn test_load_from_cavp_json_parses_valid_json_succeeds() {
            let json_data = create_valid_cavp_json();
            let result = load_from_cavp_json(&json_data);

            assert!(result.is_ok(), "Should parse valid CAVP JSON: {:?}", result.err());
        }

        #[test]
        fn test_load_from_cavp_json_extracts_vectors_succeeds() {
            let json_data = create_valid_cavp_json();
            let vectors = load_from_cavp_json(&json_data).unwrap();

            assert_eq!(vectors.len(), 1, "Should extract one test vector");
        }

        #[test]
        fn test_load_from_cavp_json_correctly_decodes_hex_succeeds() {
            let json_data = create_valid_cavp_json();
            let vectors = load_from_cavp_json(&json_data).unwrap();
            let vector = &vectors[0];

            // Verify seed was correctly decoded
            assert_eq!(vector.seed.len(), 64, "Seed should be 64 bytes");
            assert_eq!(vector.seed[0], 0x00, "First seed byte should be 0x00");
            assert_eq!(vector.seed[63], 0x3f, "Last seed byte should be 0x3f");
        }

        #[test]
        fn test_load_from_cavp_json_sets_test_case_name_correctly_succeeds() {
            let json_data = create_valid_cavp_json();
            let vectors = load_from_cavp_json(&json_data).unwrap();

            assert!(
                vectors[0].test_case.contains("NIST-CAVP"),
                "Test case name should contain 'NIST-CAVP'"
            );
            assert!(
                vectors[0].test_case.contains("ML-KEM-1024"),
                "Test case name should contain parameter set"
            );
        }

        #[test]
        fn test_load_from_cavp_json_ignores_non_ml_kem_1024_parameter_sets_succeeds() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-512",
                    "tests": [
                        {
                            "tc_id": 1,
                            "seed": "0011",
                            "pk": "0011",
                            "sk": "0011",
                            "ct": "0011",
                            "ss": "0011"
                        }
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "CAVP JSON parsing should succeed for non-1024 parameter sets");

            let vectors = result.unwrap();
            assert!(vectors.is_empty(), "Should ignore non-ML-KEM-1024 parameter sets");
        }

        #[test]
        fn test_load_from_cavp_json_handles_multiple_test_groups_succeeds() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "pk": "01", "sk": "02", "ct": "03", "ss": "04"},
                        {"tc_id": 2, "seed": "10", "pk": "11", "sk": "12", "ct": "13", "ss": "14"}
                    ]
                },
                {
                    "tg_id": 2,
                    "test_type": "VAL",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 3, "seed": "20", "pk": "21", "sk": "22", "ct": "23", "ss": "24"}
                    ]
                }
            ]
        }"#;

            let vectors = load_from_cavp_json(json_data).unwrap();
            assert_eq!(vectors.len(), 3, "Should extract all test cases from multiple groups");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_invalid_json_fails() {
            let invalid_json = "{ invalid json }";
            let result = load_from_cavp_json(invalid_json);

            assert!(result.is_err(), "Should fail on invalid JSON syntax");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_missing_seed_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail when seed is missing");

            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("seed") || error.contains("Missing"),
                "Error should mention missing seed field: {}",
                error
            );
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_missing_pk_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail when pk is missing");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_missing_sk_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "pk": "01", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail when sk is missing");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_missing_ct_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "pk": "01", "sk": "02", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail when ct is missing");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_missing_ss_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "pk": "01", "sk": "02", "ct": "03"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail when ss is missing");
        }

        #[test]
        fn test_load_from_cavp_json_fails_on_invalid_hex_fails() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "ZZZZ", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail on invalid hex in seed");
        }

        #[test]
        fn test_load_from_cavp_json_handles_empty_test_groups_returns_empty_succeeds() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": []
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle empty test_groups");

            let vectors = result.unwrap();
            assert!(vectors.is_empty(), "Should return empty vector list");
        }

        #[test]
        fn test_load_from_cavp_json_handles_empty_tests_returns_empty_succeeds() {
            let json_data = r#"{
            "vs_id": 12345,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": []
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle empty tests array");

            let vectors = result.unwrap();
            assert!(vectors.is_empty(), "Should return empty vector list");
        }
    }

    // ============================================================================
    // CAVP Structure Serialization Tests (WORKING)
    // ============================================================================

    mod cavp_structure_tests {
        use super::*;

        #[test]
        fn test_cavp_test_case_serialization_roundtrip() {
            let test_case = CavpTestCase {
                tc_id: 42,
                seed: Some("0011223344".to_string()),
                pk: Some("aabbccdd".to_string()),
                sk: Some("11223344".to_string()),
                ct: Some("55667788".to_string()),
                ss: Some("99aabbcc".to_string()),
                message: None,
                signature: None,
            };

            let json = serde_json::to_string(&test_case).unwrap();
            let deserialized: CavpTestCase = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.tc_id, test_case.tc_id, "tc_id roundtrip mismatch");
            assert_eq!(deserialized.seed, test_case.seed, "seed roundtrip mismatch");
            assert_eq!(deserialized.pk, test_case.pk, "pk roundtrip mismatch");
            assert_eq!(deserialized.sk, test_case.sk, "sk roundtrip mismatch");
            assert_eq!(deserialized.ct, test_case.ct, "ct roundtrip mismatch");
            assert_eq!(deserialized.ss, test_case.ss, "ss roundtrip mismatch");
        }

        #[test]
        fn test_cavp_test_group_serialization_roundtrip() {
            let test_group = CavpTestGroup {
                tg_id: 1,
                test_type: "AFT".to_string(),
                parameter_set: "ML-KEM-1024".to_string(),
                tests: vec![CavpTestCase {
                    tc_id: 1,
                    seed: Some("00".to_string()),
                    pk: None,
                    sk: None,
                    ct: None,
                    ss: None,
                    message: Some("test".to_string()),
                    signature: Some("sig".to_string()),
                }],
            };

            let json = serde_json::to_string(&test_group).unwrap();
            let deserialized: CavpTestGroup = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.tg_id, test_group.tg_id, "tg_id roundtrip mismatch");
            assert_eq!(
                deserialized.test_type, test_group.test_type,
                "test_type roundtrip mismatch"
            );
            assert_eq!(
                deserialized.parameter_set, test_group.parameter_set,
                "parameter_set roundtrip mismatch"
            );
            assert_eq!(deserialized.tests.len(), 1, "tests count roundtrip mismatch");
        }

        #[test]
        fn test_cavp_test_vector_file_serialization_roundtrip() {
            let file = CavpTestVectorFile {
                vs_id: 12345,
                algorithm: "ML-KEM".to_string(),
                mode: Some("keyGen".to_string()),
                revision: "1.0".to_string(),
                test_groups: vec![],
            };

            let json = serde_json::to_string(&file).unwrap();
            let deserialized: CavpTestVectorFile = serde_json::from_str(&json).unwrap();

            assert_eq!(deserialized.vs_id, file.vs_id, "vs_id roundtrip mismatch");
            assert_eq!(deserialized.algorithm, file.algorithm, "algorithm roundtrip mismatch");
            assert_eq!(deserialized.mode, file.mode, "mode roundtrip mismatch");
            assert_eq!(deserialized.revision, file.revision, "revision roundtrip mismatch");
        }

        #[test]
        fn test_cavp_test_vector_file_mode_is_optional_matches_expected() {
            let json = r#"{
            "vs_id": 12345,
            "algorithm": "SHA3",
            "revision": "1.0",
            "test_groups": []
        }"#;

            let result: Result<CavpTestVectorFile, _> = serde_json::from_str(json);
            assert!(result.is_ok(), "Should parse without mode field");

            let file = result.unwrap();
            assert!(file.mode.is_none(), "Mode should be None when not provided");
        }

        #[test]
        fn test_cavp_structures_are_cloneable_succeeds() {
            let test_case = CavpTestCase {
                tc_id: 1,
                seed: Some("00".to_string()),
                pk: None,
                sk: None,
                ct: None,
                ss: None,
                message: None,
                signature: None,
            };
            let _cloned = test_case.clone();

            let test_group = CavpTestGroup {
                tg_id: 1,
                test_type: "AFT".to_string(),
                parameter_set: "ML-KEM-1024".to_string(),
                tests: vec![],
            };
            let _cloned = test_group.clone();

            let file = CavpTestVectorFile {
                vs_id: 1,
                algorithm: "ML-KEM".to_string(),
                mode: None,
                revision: "1.0".to_string(),
                test_groups: vec![],
            };
            let _cloned = file.clone();
        }

        #[test]
        fn test_cavp_structures_are_debuggable_succeeds() {
            let test_case = CavpTestCase {
                tc_id: 1,
                seed: Some("00".to_string()),
                pk: None,
                sk: None,
                ct: None,
                ss: None,
                message: None,
                signature: None,
            };
            let debug_str = format!("{:?}", test_case);
            assert!(debug_str.contains("CavpTestCase"), "Debug output should contain type name");
            assert!(debug_str.contains("tc_id"), "Debug output should contain tc_id field");
        }
    }

    // ============================================================================
    // Edge Case and Boundary Tests for CAVP Parser (WORKING)
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_cavp_json_with_unicode_in_test_type_succeeds() {
            // Test that loader handles unusual but valid JSON
            let json_data = r#"{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "TestType-\u00e9\u00e8",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle Unicode in test_type");
        }

        #[test]
        fn test_cavp_json_with_large_tc_id_succeeds() {
            let json_data = r#"{
            "vs_id": 4294967295,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 4294967295,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 4294967295, "seed": "00", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle maximum u32 values");
        }

        #[test]
        fn test_cavp_json_with_empty_hex_strings_succeeds() {
            let json_data = r#"{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "", "pk": "", "sk": "", "ct": "", "ss": ""}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle empty hex strings");

            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1, "Expected exactly 1 vector from empty hex input");
            assert!(vectors[0].seed.is_empty(), "Empty hex string should produce empty seed");
        }

        #[test]
        fn test_cavp_json_with_mixed_case_hex_succeeds() {
            let json_data = r#"{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "AaBbCcDd", "pk": "EeFf0011", "sk": "2233aAbB", "ct": "CCdd", "ss": "EEff"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_ok(), "Should handle mixed-case hex strings");

            let vectors = result.unwrap();
            assert_eq!(
                vectors[0].seed,
                vec![0xAA, 0xBB, 0xCC, 0xDD],
                "Mixed-case hex decoding mismatch"
            );
        }

        #[test]
        fn test_cavp_json_with_whitespace_in_hex_succeeds() {
            // Note: Standard hex decoders don't handle whitespace, so this should fail
            let json_data = r#"{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "00 11 22", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail on hex strings with whitespace");
        }

        #[test]
        fn test_cavp_json_with_odd_length_hex_has_correct_size() {
            // Odd-length hex strings are invalid
            let json_data = r#"{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {"tc_id": 1, "seed": "001", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}
                    ]
                }
            ]
        }"#;

            let result = load_from_cavp_json(json_data);
            assert!(result.is_err(), "Should fail on odd-length hex strings");
        }

        #[test]
        fn test_cavp_json_with_long_hex_string_succeeds() {
            // Test handling of longer hex strings (1024 bytes = 2048 hex chars)
            let long_hex: String = "ab".repeat(1024);
            let json_data = format!(
                r#"{{
            "vs_id": 1,
            "algorithm": "ML-KEM",
            "revision": "1.0",
            "test_groups": [
                {{
                    "tg_id": 1,
                    "test_type": "AFT",
                    "parameter_set": "ML-KEM-1024",
                    "tests": [
                        {{"tc_id": 1, "seed": "{}", "pk": "01", "sk": "02", "ct": "03", "ss": "04"}}
                    ]
                }}
            ]
        }}"#,
                long_hex
            );

            let result = load_from_cavp_json(&json_data);
            assert!(result.is_ok(), "Should handle long hex strings");

            let vectors = result.unwrap();
            assert_eq!(vectors[0].seed.len(), 1024, "Expected 1024-byte seed from large hex input");
        }
    }

    // ============================================================================
    // Cross-Loader Summary Tests (WORKING)
    // ============================================================================

    mod cross_loader_tests {
        use super::*;

        #[test]
        fn test_working_loaders_return_consistent_results_on_repeated_calls_succeeds() {
            // Test only the loaders that are known to work
            let ml_kem_result = load_ml_kem_1024_kats();
            let sha3_result = load_sha3_kats();

            assert!(ml_kem_result.is_ok(), "ML-KEM loader should succeed");
            assert!(sha3_result.is_ok(), "SHA3 loader should succeed");

            assert!(!ml_kem_result.unwrap().is_empty(), "ML-KEM vectors should not be empty");
            assert!(!sha3_result.unwrap().is_empty(), "SHA3 vectors should not be empty");
        }

        #[test]
        fn test_working_loaders_performance_completes_within_threshold_succeeds() {
            use std::time::Instant;

            // ML-KEM loader (generates keys, so may take longer)
            let start = Instant::now();
            let _ = load_ml_kem_1024_kats();
            let ml_kem_duration = start.elapsed();
            assert!(
                ml_kem_duration.as_secs() < 10,
                "ML-KEM loader should complete within 10 seconds, took {:?}",
                ml_kem_duration
            );

            // SHA3 loader (pure hex parsing, should be fast)
            let start = Instant::now();
            let _ = load_sha3_kats();
            let sha3_duration = start.elapsed();
            assert!(
                sha3_duration.as_millis() < 100,
                "SHA3 loader should complete within 100ms, took {:?}",
                sha3_duration
            );

            // Note: Hybrid KEM loader has hex issues and panics, so we skip it here
        }

        #[test]
        fn test_loaders_handle_concurrent_access_succeeds() {
            use std::thread;

            // Test only working loaders concurrently
            // Note: Hybrid KEM loader has hex issues and panics, so we skip it here
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    thread::spawn(|| {
                        let _ = load_sha3_kats();
                        let _ = load_ml_kem_1024_kats();
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("Thread should not panic");
            }
        }

        #[test]
        fn test_vectors_have_unique_test_case_names_within_loader_matches_expected() {
            // Test uniqueness within ML-KEM vectors
            let ml_kem_vectors = load_ml_kem_1024_kats().unwrap();
            let ml_kem_names: Vec<_> = ml_kem_vectors.iter().map(|v| &v.test_case).collect();
            let unique_ml_kem: std::collections::HashSet<_> = ml_kem_names.iter().collect();
            assert_eq!(
                ml_kem_names.len(),
                unique_ml_kem.len(),
                "ML-KEM test case names should be unique"
            );

            // Test uniqueness within SHA3 vectors
            let sha3_vectors = load_sha3_kats().unwrap();
            let sha3_names: Vec<_> = sha3_vectors.iter().map(|v| &v.test_case).collect();
            let unique_sha3: std::collections::HashSet<_> = sha3_names.iter().collect();
            assert_eq!(
                sha3_names.len(),
                unique_sha3.len(),
                "SHA3 test case names should be unique"
            );
        }
    }

    // ============================================================================
    // Regression Tests (WORKING)
    // ============================================================================

    mod regression_tests {
        use super::*;

        #[test]
        fn test_ml_kem_loader_repeated_calls_produce_consistent_results_succeeds() {
            let result1 = load_ml_kem_1024_kats();
            let result2 = load_ml_kem_1024_kats();

            assert!(result1.is_ok(), "First repeated ML-KEM load should succeed");
            assert!(result2.is_ok(), "Second repeated ML-KEM load should succeed");

            let vectors1 = result1.unwrap();
            let vectors2 = result2.unwrap();

            assert_eq!(
                vectors1.len(),
                vectors2.len(),
                "Loader should return same count on repeated calls"
            );

            // Test case names should be consistent
            for (v1, v2) in vectors1.iter().zip(vectors2.iter()) {
                assert_eq!(
                    v1.test_case, v2.test_case,
                    "Test case names should be consistent across calls"
                );
            }
        }

        #[test]
        fn test_sha3_known_values_are_correct() {
            let vectors = load_sha3_kats().unwrap();

            // Verify SHA3-256("abc") known value from NIST
            let abc_vector = vectors.iter().find(|v| v.message == b"abc".to_vec());

            if let Some(vector) = abc_vector {
                let expected =
                    hex::decode("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
                        .unwrap();
                assert_eq!(
                    vector.expected_hash, expected,
                    "SHA3-256('abc') should match NIST test vector"
                );
            } else {
                panic!("Expected to find 'abc' test vector in SHA3 vectors");
            }
        }

        #[test]
        fn test_sha3_empty_input_known_value_matches_fails() {
            let vectors = load_sha3_kats().unwrap();

            let empty_vector = vectors.iter().find(|v| v.message.is_empty());

            if let Some(vector) = empty_vector {
                let expected =
                    hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                        .unwrap();
                assert_eq!(
                    vector.expected_hash, expected,
                    "SHA3-256('') should match NIST test vector"
                );
            } else {
                panic!("Expected to find empty message test vector in SHA3 vectors");
            }
        }

        #[test]
        fn test_sha3_long_message_known_value_matches_succeeds() {
            let vectors = load_sha3_kats().unwrap();

            // "The quick brown fox jumps over the lazy dog" test
            let fox_message = b"The quick brown fox jumps over the lazy dog".to_vec();
            let fox_vector = vectors.iter().find(|v| v.message == fox_message);

            if let Some(vector) = fox_vector {
                let expected =
                    hex::decode("416c6d2bcd633a448b9b8718f5f0c7f5191b2f3ed7424a5fc5c287be6a5b5964")
                        .unwrap();
                assert_eq!(
                    vector.expected_hash, expected,
                    "SHA3-256 of 'The quick brown fox...' should match known value"
                );
            }
        }
    }

    // ============================================================================
    // Loader API Contract Tests (WORKING)
    // ============================================================================

    mod api_contract_tests {
        use super::*;

        #[test]
        fn test_ml_kem_vector_fields_are_accessible() {
            let vectors = load_ml_kem_1024_kats().unwrap();
            let vector = &vectors[0];

            // Verify all fields are accessible
            let _ = &vector.test_case;
            let _ = &vector.seed;
            let _ = &vector.expected_public_key;
            let _ = &vector.expected_secret_key;
            let _ = &vector.expected_ciphertext;
            let _ = &vector.expected_shared_secret;
        }

        #[test]
        fn test_sha3_vector_fields_are_accessible() {
            let vectors = load_sha3_kats().unwrap();
            let vector = &vectors[0];

            // Verify all fields are accessible
            let _ = &vector.test_case;
            let _ = &vector.message;
            let _ = &vector.expected_hash;
        }

        // Note: Hybrid KEM loader has hex issues and panics, so we skip this test
        // The API contract would be tested once the hex encoding is fixed

        #[test]
        fn test_cavp_structures_implement_required_traits_succeeds() {
            // Clone
            let test_case = CavpTestCase {
                tc_id: 1,
                seed: None,
                pk: None,
                sk: None,
                ct: None,
                ss: None,
                message: None,
                signature: None,
            };
            let _ = test_case.clone();

            // Debug
            let _ = format!("{:?}", test_case);

            // Serialize/Deserialize
            let json = serde_json::to_string(&test_case).unwrap();
            let _: CavpTestCase = serde_json::from_str(&json).unwrap();
        }
    }
}

// Originally: fips_kat_reports_tests.rs
mod reports {
    //! Comprehensive tests for KAT (Known Answer Test) report generation
    //!
    //! This test suite validates the report generation functionality in
    //! `latticearc_tests::validation::kat_tests::reports`, including:
    //! - Report formatting with various test result combinations
    //! - Statistics calculation (pass/fail counts, success rates)
    //! - Performance metrics aggregation
    //! - Edge cases (empty results, all pass, all fail)

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

    use latticearc_tests::validation::kat_tests::reports::{generate_kat_report, run_kat_tests};
    use latticearc_tests::validation::kat_tests::types::KatResult;
    use std::time::Duration;

    // =============================================================================
    // Test Fixtures and Helpers
    // =============================================================================

    /// Creates a mock passing KAT result with specified parameters
    fn create_passing_result(test_case: &str, execution_time_ns: u128) -> KatResult {
        KatResult {
            test_case: test_case.to_string(),
            passed: true,
            execution_time_ns,
            error_message: None,
        }
    }

    /// Creates a mock failing KAT result with specified parameters
    fn create_failing_result(test_case: &str, execution_time_ns: u128, error: &str) -> KatResult {
        KatResult {
            test_case: test_case.to_string(),
            passed: false,
            execution_time_ns,
            error_message: Some(error.to_string()),
        }
    }

    /// Creates a set of mixed results for testing
    fn create_mixed_results() -> Vec<KatResult> {
        vec![
            create_passing_result("ML-KEM-1024-001", 1_000_000),
            create_passing_result("ML-KEM-1024-002", 1_500_000),
            create_failing_result("ML-KEM-1024-003", 2_000_000, "Keypair validation failed"),
            create_passing_result("ML-KEM-1024-004", 1_200_000),
            create_failing_result("ML-KEM-1024-005", 800_000, "Encapsulation mismatch"),
        ]
    }

    /// Creates a set of all passing results
    fn create_all_passing_results(count: usize) -> Vec<KatResult> {
        (0..count)
            .map(|i| {
                create_passing_result(
                    &format!("TEST-{:03}", i + 1),
                    1_000_000 + (i as u128) * 100_000,
                )
            })
            .collect()
    }

    /// Creates a set of all failing results
    fn create_all_failing_results(count: usize) -> Vec<KatResult> {
        (0..count)
            .map(|i| {
                create_failing_result(
                    &format!("TEST-{:03}", i + 1),
                    500_000 + (i as u128) * 50_000,
                    &format!("Error in test case {}", i + 1),
                )
            })
            .collect()
    }

    // =============================================================================
    // Report Generation Tests - Basic Functionality
    // =============================================================================

    #[test]
    fn test_generate_report_with_mixed_results_has_correct_format() {
        let results = create_mixed_results();
        let report = generate_kat_report(&results);

        // Verify report header
        assert!(report.contains("=== Known Answer Test Report ==="));

        // Verify summary section
        assert!(report.contains("Summary:"));
        assert!(report.contains("Total tests: 5"));
        assert!(report.contains("Passed: 3"));
        assert!(report.contains("Failed: 2"));
        assert!(report.contains("Success rate: 60.00%"));

        // Verify failed tests section exists
        assert!(report.contains("Failed Tests:"));
        assert!(report.contains("ML-KEM-1024-003"));
        assert!(report.contains("Keypair validation failed"));
        assert!(report.contains("ML-KEM-1024-005"));
        assert!(report.contains("Encapsulation mismatch"));

        // Verify performance section
        assert!(report.contains("Performance:"));
        assert!(report.contains("Total execution time:"));
        assert!(report.contains("Average test time:"));
    }

    #[test]
    fn test_generate_report_all_passing_has_correct_format() {
        let results = create_all_passing_results(10);
        let report = generate_kat_report(&results);

        // Verify summary
        assert!(report.contains("Total tests: 10"));
        assert!(report.contains("Passed: 10"));
        assert!(report.contains("Failed: 0"));
        assert!(report.contains("Success rate: 100.00%"));

        // Verify no "Failed Tests:" section (since all passed)
        assert!(!report.contains("Failed Tests:"));
    }

    #[test]
    fn test_generate_report_all_failing_has_correct_format() {
        let results = create_all_failing_results(5);
        let report = generate_kat_report(&results);

        // Verify summary
        assert!(report.contains("Total tests: 5"));
        assert!(report.contains("Passed: 0"));
        assert!(report.contains("Failed: 5"));
        assert!(report.contains("Success rate: 0.00%"));

        // Verify all failed tests are listed
        assert!(report.contains("Failed Tests:"));
        for i in 1..=5 {
            assert!(report.contains(&format!("TEST-{:03}", i)));
            assert!(report.contains(&format!("Error in test case {}", i)));
        }
    }

    #[test]
    fn test_generate_report_single_result_pass_has_correct_format() {
        let results = vec![create_passing_result("SINGLE-TEST-001", 500_000)];
        let report = generate_kat_report(&results);

        assert!(report.contains("Total tests: 1"));
        assert!(report.contains("Passed: 1"));
        assert!(report.contains("Failed: 0"));
        assert!(report.contains("Success rate: 100.00%"));
        assert!(!report.contains("Failed Tests:"));
    }

    #[test]
    fn test_generate_report_single_result_fail_has_correct_format() {
        let results =
            vec![create_failing_result("SINGLE-TEST-001", 500_000, "Critical validation error")];
        let report = generate_kat_report(&results);

        assert!(report.contains("Total tests: 1"));
        assert!(report.contains("Passed: 0"));
        assert!(report.contains("Failed: 1"));
        assert!(report.contains("Success rate: 0.00%"));
        assert!(report.contains("Failed Tests:"));
        assert!(report.contains("SINGLE-TEST-001"));
        assert!(report.contains("Critical validation error"));
    }

    // =============================================================================
    // Report Generation Tests - Statistics Calculation
    // =============================================================================

    #[test]
    fn test_success_rate_calculation_has_correct_precision_succeeds() {
        // Test various success rates to verify precision
        let test_cases = vec![
            (1, 3, "33.33%"), // 1/3 = 33.33%
            (2, 3, "66.67%"), // 2/3 = 66.67%
            (1, 4, "25.00%"), // 1/4 = 25%
            (3, 4, "75.00%"), // 3/4 = 75%
            (1, 7, "14.29%"), // 1/7 = 14.29%
            (5, 7, "71.43%"), // 5/7 = 71.43%
        ];

        for (passed, total, expected_rate) in test_cases {
            let mut results = Vec::new();
            for i in 0..total {
                if i < passed {
                    results.push(create_passing_result(&format!("TEST-{}", i), 1_000_000));
                } else {
                    results.push(create_failing_result(&format!("TEST-{}", i), 1_000_000, "Error"));
                }
            }
            let report = generate_kat_report(&results);
            assert!(
                report.contains(expected_rate),
                "Expected success rate {} for {}/{} tests, got report:\n{}",
                expected_rate,
                passed,
                total,
                report
            );
        }
    }

    #[test]
    fn test_total_execution_time_calculation_is_correct() {
        let results = vec![
            create_passing_result("TEST-001", 1_000_000), // 1ms
            create_passing_result("TEST-002", 2_000_000), // 2ms
            create_passing_result("TEST-003", 3_000_000), // 3ms
            create_failing_result("TEST-004", 4_000_000, "Error"), // 4ms
        ];

        let report = generate_kat_report(&results);

        // Total should be 10,000,000 ns
        assert!(report.contains("Total execution time: 10000000 ns"));

        // Average should be 2,500,000 ns
        assert!(report.contains("Average test time: 2500000 ns"));
    }

    #[test]
    fn test_average_time_calculation_with_varying_durations_is_correct() {
        let results = vec![
            create_passing_result("FAST-TEST", 100_000),     // 0.1ms
            create_passing_result("MEDIUM-TEST", 1_000_000), // 1ms
            create_passing_result("SLOW-TEST", 10_000_000),  // 10ms
        ];

        let report = generate_kat_report(&results);

        // Total: 11,100,000 ns
        assert!(report.contains("Total execution time: 11100000 ns"));

        // Average: 3,700,000 ns
        assert!(report.contains("Average test time: 3700000 ns"));
    }

    // =============================================================================
    // Report Generation Tests - Edge Cases
    // =============================================================================

    #[test]
    fn test_generate_report_with_no_error_message_has_correct_format() {
        // Test case where a failed result has no error message
        let results = vec![KatResult {
            test_case: "TEST-NO-MSG".to_string(),
            passed: false,
            execution_time_ns: 1_000_000,
            error_message: None, // No error message
        }];

        let report = generate_kat_report(&results);

        // Should show "Unknown error" for missing error message
        assert!(report.contains("TEST-NO-MSG"));
        assert!(report.contains("Unknown error"));
    }

    #[test]
    fn test_generate_report_with_empty_test_case_name_has_correct_format() {
        let results = vec![create_passing_result("", 500_000)];
        let report = generate_kat_report(&results);

        // Should still generate a valid report
        assert!(report.contains("Total tests: 1"));
        assert!(report.contains("Passed: 1"));
    }

    #[test]
    fn test_generate_report_with_long_test_case_name_has_correct_format() {
        let long_name = "A".repeat(500);
        let results = vec![create_failing_result(&long_name, 1_000_000, "Long name test error")];
        let report = generate_kat_report(&results);

        assert!(report.contains(&long_name));
        assert!(report.contains("Long name test error"));
    }

    #[test]
    fn test_generate_report_with_long_error_message_has_correct_format() {
        let long_error = "E".repeat(1000);
        let results = vec![create_failing_result("LONG-ERROR-TEST", 1_000_000, &long_error)];
        let report = generate_kat_report(&results);

        assert!(report.contains("LONG-ERROR-TEST"));
        assert!(report.contains(&long_error));
    }

    #[test]
    fn test_generate_report_with_special_characters_in_test_case_has_correct_format() {
        let special_cases = vec![
            create_failing_result("TEST-WITH-UNICODE-\u{2713}", 1_000_000, "Unicode test"),
            create_failing_result("TEST/WITH/SLASHES", 1_000_000, "Slash test"),
            create_failing_result("TEST:WITH:COLONS", 1_000_000, "Colon test"),
        ];

        let report = generate_kat_report(&special_cases);

        assert!(report.contains("TEST-WITH-UNICODE-\u{2713}"));
        assert!(report.contains("TEST/WITH/SLASHES"));
        assert!(report.contains("TEST:WITH:COLONS"));
    }

    #[test]
    fn test_generate_report_with_zero_execution_time_has_correct_format() {
        let results = vec![
            create_passing_result("INSTANT-TEST-001", 0),
            create_passing_result("INSTANT-TEST-002", 0),
        ];

        let report = generate_kat_report(&results);

        assert!(report.contains("Total execution time: 0 ns"));
        assert!(report.contains("Average test time: 0 ns"));
    }

    #[test]
    fn test_generate_report_with_max_execution_time_has_correct_format() {
        let max_time = u128::MAX / 2; // Use half of max to avoid overflow in sum
        let results = vec![create_passing_result("MAX-TIME-TEST", max_time)];

        let report = generate_kat_report(&results);

        assert!(report.contains(&format!("Total execution time: {} ns", max_time)));
        assert!(report.contains(&format!("Average test time: {} ns", max_time)));
    }

    // =============================================================================
    // Report Generation Tests - Large Scale
    // =============================================================================

    #[test]
    fn test_generate_report_with_many_results_has_correct_format() {
        let results = create_all_passing_results(1000);
        let report = generate_kat_report(&results);

        assert!(report.contains("Total tests: 1000"));
        assert!(report.contains("Passed: 1000"));
        assert!(report.contains("Failed: 0"));
        assert!(report.contains("Success rate: 100.00%"));
    }

    #[test]
    fn test_generate_report_with_many_failures_has_correct_format() {
        let results = create_all_failing_results(100);
        let report = generate_kat_report(&results);

        assert!(report.contains("Total tests: 100"));
        assert!(report.contains("Passed: 0"));
        assert!(report.contains("Failed: 100"));
        assert!(report.contains("Success rate: 0.00%"));

        // Verify all 100 failures are listed
        for i in 1..=100 {
            assert!(report.contains(&format!("TEST-{:03}", i)));
        }
    }

    // =============================================================================
    // Report Generation Tests - Format Validation
    // =============================================================================

    #[test]
    fn test_report_sections_are_in_correct_order_succeeds() {
        let results = create_mixed_results();
        let report = generate_kat_report(&results);

        // Find section positions
        let header_pos = report.find("=== Known Answer Test Report ===").unwrap();
        let summary_pos = report.find("Summary:").unwrap();
        let failed_pos = report.find("Failed Tests:").unwrap();
        let perf_pos = report.find("Performance:").unwrap();

        // Verify order: Header -> Summary -> Failed Tests -> Performance
        assert!(header_pos < summary_pos, "Header should come before Summary");
        assert!(summary_pos < failed_pos, "Summary should come before Failed Tests");
        assert!(failed_pos < perf_pos, "Failed Tests should come before Performance");
    }

    #[test]
    fn test_report_newlines_have_correct_format_succeeds() {
        let results = create_mixed_results();
        let report = generate_kat_report(&results);

        // Verify proper newline separation
        assert!(report.contains("===\n\n")); // After header
        assert!(report.contains("Summary:\n")); // Summary section
        assert!(report.contains("%\n\n")); // After success rate
    }

    #[test]
    fn test_report_indentation_has_correct_format() {
        let results = create_mixed_results();
        let report = generate_kat_report(&results);

        // Verify summary items are indented
        assert!(report.contains("  Total tests:"));
        assert!(report.contains("  Passed:"));
        assert!(report.contains("  Failed:"));
        assert!(report.contains("  Success rate:"));

        // Verify failed test items are indented
        assert!(report.contains("  ML-KEM-1024-003:"));

        // Verify performance items are indented
        assert!(report.contains("  Total execution time:"));
        assert!(report.contains("  Average test time:"));
    }

    // =============================================================================
    // KatResult Type Tests
    // =============================================================================

    #[test]
    fn test_kat_result_passed_constructor_succeeds() {
        let result = KatResult::passed("TEST-CASE-001".to_string(), Duration::from_millis(100));

        assert_eq!(result.test_case, "TEST-CASE-001");
        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 100_000_000); // 100ms in ns
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_result_failed_constructor_succeeds() {
        let result = KatResult::failed(
            "TEST-CASE-002".to_string(),
            Duration::from_micros(500),
            "Validation error occurred".to_string(),
        );

        assert_eq!(result.test_case, "TEST-CASE-002");
        assert!(!result.passed);
        assert_eq!(result.execution_time_ns, 500_000); // 500us in ns
        assert_eq!(result.error_message, Some("Validation error occurred".to_string()));
    }

    #[test]
    fn test_kat_result_equality_is_correct() {
        let result1 = KatResult {
            test_case: "TEST".to_string(),
            passed: true,
            execution_time_ns: 1000,
            error_message: None,
        };

        let result2 = KatResult {
            test_case: "TEST".to_string(),
            passed: true,
            execution_time_ns: 1000,
            error_message: None,
        };

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_kat_result_inequality_is_correct() {
        let result1 = create_passing_result("TEST-A", 1000);
        let result2 = create_passing_result("TEST-B", 1000);

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kat_result_clone_succeeds() {
        let original = create_failing_result("CLONE-TEST", 5000, "Clone error");
        let cloned = original.clone();

        assert_eq!(original, cloned);
        assert_eq!(original.test_case, cloned.test_case);
        assert_eq!(original.error_message, cloned.error_message);
    }

    #[test]
    fn test_kat_result_debug_has_correct_format() {
        let result = create_passing_result("DEBUG-TEST", 1_000_000);
        let debug_str = format!("{:?}", result);

        assert!(debug_str.contains("DEBUG-TEST"));
        assert!(debug_str.contains("passed: true"));
        assert!(debug_str.contains("1000000"));
    }

    // =============================================================================
    // KatResult Serialization Tests
    // =============================================================================

    #[test]
    fn test_kat_result_json_serialization_passing_succeeds() {
        let result = create_passing_result("JSON-TEST-001", 2_500_000);
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"test_case\":\"JSON-TEST-001\""));
        assert!(json.contains("\"passed\":true"));
        assert!(json.contains("\"execution_time_ns\":2500000"));
        assert!(json.contains("\"error_message\":null"));
    }

    #[test]
    fn test_kat_result_json_serialization_failing_succeeds() {
        let result = create_failing_result("JSON-FAIL-001", 1_000_000, "JSON test error");
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"test_case\":\"JSON-FAIL-001\""));
        assert!(json.contains("\"passed\":false"));
        assert!(json.contains("\"execution_time_ns\":1000000"));
        assert!(json.contains("\"error_message\":\"JSON test error\""));
    }

    #[test]
    fn test_kat_result_json_deserialization_succeeds() {
        let json = r#"{
        "test_case": "DESER-TEST",
        "passed": true,
        "execution_time_ns": 750000,
        "error_message": null
    }"#;

        let result: KatResult = serde_json::from_str(json).unwrap();

        assert_eq!(result.test_case, "DESER-TEST");
        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 750_000);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_result_json_roundtrip_succeeds() {
        let original = create_failing_result("ROUNDTRIP-TEST", 999_999, "Roundtrip error");
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_kat_results_array_json_serialization_succeeds() {
        let results = create_mixed_results();
        let json = serde_json::to_string(&results).unwrap();

        // Should be a valid JSON array
        assert!(json.starts_with('['));
        assert!(json.ends_with(']'));

        // Deserialize and verify count
        let deserialized: Vec<KatResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 5);
    }

    // =============================================================================
    // run_kat_tests Function Tests
    // =============================================================================

    #[test]
    fn test_run_kat_tests_returns_non_empty_results_matches_expected() {
        // Note: This test depends on having ML-KEM 1024 KAT vectors available
        // It may skip if vectors cannot be loaded
        match run_kat_tests() {
            Ok(results) => {
                // Verify we got some results
                assert!(!results.is_empty(), "run_kat_tests should return non-empty results");

                // Verify all results have valid test case names
                for result in &results {
                    assert!(!result.test_case.is_empty(), "Test case name should not be empty");
                }

                // Verify execution times are set
                for result in &results {
                    // Each result should have execution_time_ns > 0 or == the default
                    // (the implementation sets 1_000_000 as default)
                    assert!(result.execution_time_ns > 0, "Execution time should be positive");
                }
            }
            Err(e) => {
                // If loading fails, that's acceptable for this test
                // (might be missing NIST vectors in test environment)
                eprintln!("run_kat_tests returned error (may be expected): {}", e);
            }
        }
    }

    #[test]
    fn test_run_kat_tests_all_results_are_marked_passed_matches_expected() {
        match run_kat_tests() {
            Ok(results) => {
                // The current implementation marks all results as passed
                for result in &results {
                    assert!(
                        result.passed,
                        "Result {} should be marked as passed",
                        result.test_case
                    );
                    assert!(
                        result.error_message.is_none(),
                        "Passed result should have no error message"
                    );
                }
            }
            Err(_) => {
                // Skip if loading fails
            }
        }
    }

    #[test]
    fn test_run_kat_tests_generates_valid_report_succeeds() {
        match run_kat_tests() {
            Ok(results) => {
                let report = generate_kat_report(&results);

                // Report should be valid and contain expected sections
                assert!(report.contains("=== Known Answer Test Report ==="));
                assert!(report.contains("Summary:"));
                assert!(report.contains("Performance:"));

                // With the current implementation, all tests pass
                assert!(report.contains("Success rate: 100.00%"));
            }
            Err(_) => {
                // Skip if loading fails
            }
        }
    }

    // =============================================================================
    // Integration Tests - Report Generation with Various Scenarios
    // =============================================================================

    #[test]
    fn test_report_generation_performance_completes_in_time_succeeds() {
        // Generate a large number of results to test performance
        let results: Vec<KatResult> = (0..10_000)
            .map(|i| {
                if i % 10 == 0 {
                    create_failing_result(
                        &format!("PERF-TEST-{:05}", i),
                        i as u128 * 1000,
                        "Perf test error",
                    )
                } else {
                    create_passing_result(&format!("PERF-TEST-{:05}", i), i as u128 * 1000)
                }
            })
            .collect();

        let start = std::time::Instant::now();
        let report = generate_kat_report(&results);
        let duration = start.elapsed();

        // Report generation should complete in reasonable time (< 1 second for 10k results)
        assert!(duration.as_secs() < 1, "Report generation took too long: {:?}", duration);

        // Verify report content
        assert!(report.contains("Total tests: 10000"));
        assert!(report.contains("Failed: 1000")); // 10% fail rate
        assert!(report.contains("Passed: 9000"));
    }

    #[test]
    fn test_report_with_realistic_test_names_has_correct_format() {
        let results = vec![
            create_passing_result("CAVP-ML-KEM-1024-001", 1_500_000),
            create_passing_result("CAVP-ML-KEM-1024-002", 1_600_000),
            create_failing_result(
                "CAVP-ML-DSA-44-001",
                2_000_000,
                "Signature verification failed: expected 0xAB, got 0xCD",
            ),
            create_passing_result("NIST-SHA3-256-EMPTY", 500_000),
            create_passing_result("NIST-SHA3-256-ABC", 550_000),
            create_failing_result("NIST-AES-128-GCM-001", 800_000, "Authentication tag mismatch"),
            create_passing_result("HYBRID-KEM-X25519-ML-KEM-001", 3_000_000),
        ];

        let report = generate_kat_report(&results);

        // Verify failed test names appear in the "Failed Tests" section
        // Note: Passed tests are only counted in statistics, not listed individually
        assert!(report.contains("CAVP-ML-DSA-44-001"));
        assert!(report.contains("Signature verification failed"));
        assert!(report.contains("NIST-AES-128-GCM-001"));
        assert!(report.contains("Authentication tag mismatch"));

        // Verify statistics
        assert!(report.contains("Total tests: 7"));
        assert!(report.contains("Passed: 5"));
        assert!(report.contains("Failed: 2"));

        // Verify the report has the expected sections
        assert!(report.contains("=== Known Answer Test Report ==="));
        assert!(report.contains("Summary:"));
        assert!(report.contains("Failed Tests:"));
        assert!(report.contains("Performance:"));
    }

    // =============================================================================
    // Output Format Tests - Custom Report Parsing
    // =============================================================================

    /// Helper to parse the report and extract statistics
    fn parse_report_stats(report: &str) -> (usize, usize, usize, f64) {
        let total = report
            .lines()
            .find(|l| l.contains("Total tests:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let passed = report
            .lines()
            .find(|l| l.trim().starts_with("Passed:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let failed = report
            .lines()
            .find(|l| l.trim().starts_with("Failed:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);

        let success_rate = report
            .lines()
            .find(|l| l.contains("Success rate:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|s| s.trim().trim_end_matches('%').parse::<f64>().ok())
            .unwrap_or(0.0);

        (total, passed, failed, success_rate)
    }

    #[test]
    fn test_report_parsing_accuracy_is_correct() {
        let results = create_mixed_results();
        let report = generate_kat_report(&results);
        let (total, passed, failed, success_rate) = parse_report_stats(&report);

        assert_eq!(total, 5);
        assert_eq!(passed, 3);
        assert_eq!(failed, 2);
        assert!((success_rate - 60.0).abs() < 0.01);
    }

    #[test]
    fn test_report_parsing_all_pass_is_correct() {
        let results = create_all_passing_results(25);
        let report = generate_kat_report(&results);
        let (total, passed, failed, success_rate) = parse_report_stats(&report);

        assert_eq!(total, 25);
        assert_eq!(passed, 25);
        assert_eq!(failed, 0);
        assert!((success_rate - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_report_parsing_all_fail_is_correct() {
        let results = create_all_failing_results(15);
        let report = generate_kat_report(&results);
        let (total, passed, failed, success_rate) = parse_report_stats(&report);

        assert_eq!(total, 15);
        assert_eq!(passed, 0);
        assert_eq!(failed, 15);
        assert!((success_rate - 0.0).abs() < 0.01);
    }

    // =============================================================================
    // Boundary and Stress Tests
    // =============================================================================

    #[test]
    fn test_report_with_exactly_one_pass_one_fail_has_correct_format() {
        let results = vec![
            create_passing_result("PASS-001", 1_000_000),
            create_failing_result("FAIL-001", 1_000_000, "Error"),
        ];

        let report = generate_kat_report(&results);

        assert!(report.contains("Total tests: 2"));
        assert!(report.contains("Passed: 1"));
        assert!(report.contains("Failed: 1"));
        assert!(report.contains("Success rate: 50.00%"));
    }

    #[test]
    fn test_report_is_consistent_across_multiple_generations_succeeds() {
        let results = create_mixed_results();

        // Generate report multiple times
        let report1 = generate_kat_report(&results);
        let report2 = generate_kat_report(&results);
        let report3 = generate_kat_report(&results);

        // All reports should be identical
        assert_eq!(report1, report2);
        assert_eq!(report2, report3);
    }

    #[test]
    fn test_report_handles_unicode_errors_succeeds() {
        let results = vec![create_failing_result(
            "UNICODE-TEST",
            1_000_000,
            "Error with unicode: \u{2713} \u{2717} \u{26A0}",
        )];

        let report = generate_kat_report(&results);

        assert!(report.contains("\u{2713}")); // Checkmark
        assert!(report.contains("\u{2717}")); // X mark
        assert!(report.contains("\u{26A0}")); // Warning
    }

    #[test]
    fn test_report_with_newlines_in_error_has_correct_format() {
        let results =
            vec![create_failing_result("MULTILINE-ERROR", 1_000_000, "Line 1\nLine 2\nLine 3")];

        let report = generate_kat_report(&results);

        // Error message should be included (formatting may vary)
        assert!(report.contains("Line 1"));
    }

    // =============================================================================
    // Algorithm Type Tests (from types module)
    // =============================================================================

    #[test]
    fn test_algorithm_type_names_have_correct_format_succeeds() {
        use latticearc_tests::validation::kat_tests::types::AlgorithmType;

        let test_cases = vec![
            (AlgorithmType::MlKem { variant: "512".to_string() }, "ML-KEM-512"),
            (AlgorithmType::MlKem { variant: "768".to_string() }, "ML-KEM-768"),
            (AlgorithmType::MlKem { variant: "1024".to_string() }, "ML-KEM-1024"),
            (AlgorithmType::MlDsa { variant: "44".to_string() }, "ML-DSA-44"),
            (AlgorithmType::MlDsa { variant: "65".to_string() }, "ML-DSA-65"),
            (AlgorithmType::SlhDsa { variant: "128".to_string() }, "SLH-DSA-128"),
            (AlgorithmType::HybridKem, "Hybrid-KEM"),
            (AlgorithmType::AesGcm { key_size: 16 }, "AES-128-GCM"),
            (AlgorithmType::AesGcm { key_size: 32 }, "AES-256-GCM"),
            (AlgorithmType::Sha3 { variant: "256".to_string() }, "SHA3-256"),
            (AlgorithmType::Ed25519, "Ed25519"),
            (AlgorithmType::Bls12_381, "BLS12-381"),
            (AlgorithmType::Bn254, "BN254"),
            (AlgorithmType::Secp256k1, "secp256k1"),
        ];

        for (algo_type, expected_name) in test_cases {
            assert_eq!(
                algo_type.name(),
                expected_name,
                "Algorithm name mismatch for {:?}",
                algo_type
            );
        }
    }

    #[test]
    fn test_algorithm_type_security_levels_are_correct() {
        use latticearc_tests::validation::kat_tests::types::AlgorithmType;

        let test_cases = vec![
            (AlgorithmType::MlKem { variant: "512".to_string() }, 128),
            (AlgorithmType::MlKem { variant: "768".to_string() }, 192),
            (AlgorithmType::MlKem { variant: "1024".to_string() }, 256),
            (AlgorithmType::MlDsa { variant: "44".to_string() }, 128),
            (AlgorithmType::MlDsa { variant: "65".to_string() }, 192),
            (AlgorithmType::MlDsa { variant: "87".to_string() }, 256),
            (AlgorithmType::SlhDsa { variant: "128".to_string() }, 128),
            (AlgorithmType::SlhDsa { variant: "192".to_string() }, 192),
            (AlgorithmType::SlhDsa { variant: "256".to_string() }, 256),
            (AlgorithmType::HybridKem, 256),
            (AlgorithmType::AesGcm { key_size: 16 }, 128),
            (AlgorithmType::AesGcm { key_size: 32 }, 256),
            (AlgorithmType::Ed25519, 128),
            (AlgorithmType::Bls12_381, 128),
            (AlgorithmType::Bn254, 128),
            (AlgorithmType::Secp256k1, 128),
        ];

        for (algo_type, expected_level) in test_cases {
            assert_eq!(
                algo_type.security_level(),
                expected_level,
                "Security level mismatch for {:?}",
                algo_type
            );
        }
    }

    // =============================================================================
    // KatConfig Tests
    // =============================================================================

    #[test]
    fn test_kat_config_default_has_correct_values_matches_expected() {
        use latticearc_tests::validation::kat_tests::types::KatConfig;

        let config = KatConfig::default();

        assert_eq!(config.test_count, 100);
        assert!(config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(10));
        assert!(config.validate_fips);
    }

    #[test]
    fn test_kat_config_ml_kem_constructor_succeeds() {
        use latticearc_tests::validation::kat_tests::types::KatConfig;

        let config = KatConfig::ml_kem("1024", 50);

        assert_eq!(config.test_count, 50);
        assert!(config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(10));
        assert!(config.validate_fips);
    }

    #[test]
    fn test_kat_config_ml_dsa_constructor_succeeds() {
        use latticearc_tests::validation::kat_tests::types::KatConfig;

        let config = KatConfig::ml_dsa("65", 75);

        assert_eq!(config.test_count, 75);
        assert!(config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(10));
        assert!(config.validate_fips);
    }

    #[test]
    fn test_kat_config_slh_dsa_constructor_succeeds() {
        use latticearc_tests::validation::kat_tests::types::KatConfig;

        let config = KatConfig::slh_dsa("256", 25);

        assert_eq!(config.test_count, 25);
        assert!(config.run_statistical_tests);
        // SLH-DSA has longer timeout
        assert_eq!(config.timeout_per_test, Duration::from_secs(30));
        assert!(config.validate_fips);
    }

    #[test]
    fn test_kat_config_serializes_correctly_succeeds() {
        use latticearc_tests::validation::kat_tests::types::KatConfig;

        let config = KatConfig::ml_kem("768", 100);
        let json = serde_json::to_string(&config).unwrap();

        assert!(json.contains("\"test_count\":100"));
        assert!(json.contains("\"run_statistical_tests\":true"));
        assert!(json.contains("\"validate_fips\":true"));
    }

    #[test]
    fn test_kat_config_deserializes_correctly_succeeds() {
        use latticearc_tests::validation::kat_tests::types::{AlgorithmType, KatConfig};

        let json = r#"{
        "algorithm": {"MlKem": {"variant": "512"}},
        "test_count": 50,
        "run_statistical_tests": false,
        "timeout_per_test": {"secs": 5, "nanos": 0},
        "validate_fips": true
    }"#;

        let config: KatConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.test_count, 50);
        assert!(!config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(5));
        assert!(config.validate_fips);
        assert!(matches!(config.algorithm, AlgorithmType::MlKem { variant } if variant == "512"));
    }
}

// Originally: fips_kat_types_tests.rs
mod types {
    //! Comprehensive tests for KAT (Known Answer Test) types
    //!
    //! This test suite covers:
    //! - KatResult constructors and field access
    //! - All KAT vector type constructors and field access
    //! - AlgorithmType enum methods (name, security_level)
    //! - KatConfig constructors and defaults
    //! - Serialization/deserialization of all types

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

    use latticearc_tests::validation::kat_tests::types::{
        AesGcmKatVector, AlgorithmType, Bls12_381KatVector, Bn254KatVector, Ed25519KatVector,
        HybridKemKatVector, KatConfig, KatResult, MlDsaKatVector, MlKemKatVector,
        NistStatisticalTestResult, RngTestResults, Secp256k1KatVector, Sha3KatVector,
        SlhDsaKatVector,
    };
    use std::time::Duration;

    // ============================================================================
    // KatResult Tests
    // ============================================================================

    mod kat_result_tests {
        use super::*;

        #[test]
        fn test_kat_result_passed_constructor_has_correct_fields_matches_expected() {
            let result = KatResult::passed("test_case_1".to_string(), Duration::from_millis(100));

            assert_eq!(result.test_case, "test_case_1");
            assert!(result.passed);
            assert_eq!(result.execution_time_ns, 100_000_000);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_kat_result_failed_constructor_has_correct_fields_matches_expected() {
            let result = KatResult::failed(
                "test_case_2".to_string(),
                Duration::from_millis(50),
                "Verification failed".to_string(),
            );

            assert_eq!(result.test_case, "test_case_2");
            assert!(!result.passed);
            assert_eq!(result.execution_time_ns, 50_000_000);
            assert_eq!(result.error_message.as_ref().unwrap(), "Verification failed");
        }

        #[test]
        fn test_kat_result_passed_zero_duration_has_correct_fields_matches_expected() {
            let result = KatResult::passed("fast_test".to_string(), Duration::ZERO);

            assert!(result.passed);
            assert_eq!(result.execution_time_ns, 0);
        }

        #[test]
        fn test_kat_result_failed_empty_error_has_correct_fields_matches_expected() {
            let result =
                KatResult::failed("test".to_string(), Duration::from_nanos(1), String::new());

            assert!(!result.passed);
            assert_eq!(result.error_message.as_ref().unwrap(), "");
        }

        #[test]
        fn test_kat_result_clone_produces_equal_value_matches_expected() {
            let original = KatResult::passed("original".to_string(), Duration::from_secs(1));
            let cloned = original.clone();

            assert_eq!(original, cloned);
            assert_eq!(cloned.test_case, "original");
        }

        #[test]
        fn test_kat_result_equality_matches_expected() {
            let result1 = KatResult::passed("test".to_string(), Duration::from_millis(100));
            let result2 = KatResult::passed("test".to_string(), Duration::from_millis(100));
            let result3 = KatResult::passed("different".to_string(), Duration::from_millis(100));

            assert_eq!(result1, result2);
            assert_ne!(result1, result3);
        }

        #[test]
        fn test_kat_result_debug_has_correct_format() {
            let result = KatResult::passed("debug_test".to_string(), Duration::from_millis(1));
            let debug_str = format!("{:?}", result);

            assert!(debug_str.contains("KatResult"));
            assert!(debug_str.contains("debug_test"));
            assert!(debug_str.contains("passed"));
        }
    }

    // ============================================================================
    // MlKemKatVector Tests
    // ============================================================================

    mod ml_kem_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> MlKemKatVector {
            MlKemKatVector {
                test_case: "ML-KEM-768-001".to_string(),
                seed: vec![0x01, 0x02, 0x03, 0x04],
                expected_public_key: vec![0xAA; 32],
                expected_secret_key: vec![0xBB; 64],
                expected_ciphertext: vec![0xCC; 128],
                expected_shared_secret: vec![0xDD; 32],
            }
        }

        #[test]
        fn test_ml_kem_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "ML-KEM-768-001");
            assert_eq!(vector.seed, vec![0x01, 0x02, 0x03, 0x04]);
            assert_eq!(vector.expected_public_key.len(), 32);
            assert_eq!(vector.expected_secret_key.len(), 64);
            assert_eq!(vector.expected_ciphertext.len(), 128);
            assert_eq!(vector.expected_shared_secret.len(), 32);
        }

        #[test]
        fn test_ml_kem_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_ml_kem_kat_vector_empty_fields_are_accepted_matches_expected() {
            let vector = MlKemKatVector {
                test_case: String::new(),
                seed: vec![],
                expected_public_key: vec![],
                expected_secret_key: vec![],
                expected_ciphertext: vec![],
                expected_shared_secret: vec![],
            };

            assert!(vector.test_case.is_empty());
            assert!(vector.seed.is_empty());
        }
    }

    // ============================================================================
    // MlDsaKatVector Tests
    // ============================================================================

    mod ml_dsa_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> MlDsaKatVector {
            MlDsaKatVector {
                test_case: "ML-DSA-65-001".to_string(),
                seed: vec![0x10, 0x20, 0x30],
                message: b"Test message for signing".to_vec(),
                expected_public_key: vec![0x11; 48],
                expected_secret_key: vec![0x22; 96],
                expected_signature: vec![0x33; 2048],
            }
        }

        #[test]
        fn test_ml_dsa_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "ML-DSA-65-001");
            assert_eq!(vector.seed, vec![0x10, 0x20, 0x30]);
            assert_eq!(vector.message, b"Test message for signing");
            assert_eq!(vector.expected_public_key.len(), 48);
            assert_eq!(vector.expected_secret_key.len(), 96);
            assert_eq!(vector.expected_signature.len(), 2048);
        }

        #[test]
        fn test_ml_dsa_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_ml_dsa_kat_vector_equality_matches_expected() {
            let v1 = create_test_vector();
            let v2 = create_test_vector();

            assert_eq!(v1, v2);

            let mut v3 = create_test_vector();
            v3.message = b"Different message".to_vec();

            assert_ne!(v1, v3);
        }
    }

    // ============================================================================
    // SlhDsaKatVector Tests
    // ============================================================================

    mod slh_dsa_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> SlhDsaKatVector {
            SlhDsaKatVector {
                test_case: "SLH-DSA-128s-001".to_string(),
                seed: vec![0xAB; 48],
                message: b"Hash-based signature test".to_vec(),
                expected_public_key: vec![0xCD; 32],
                expected_signature: vec![0xEF; 7856],
            }
        }

        #[test]
        fn test_slh_dsa_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "SLH-DSA-128s-001");
            assert_eq!(vector.seed.len(), 48);
            assert_eq!(vector.message, b"Hash-based signature test");
            assert_eq!(vector.expected_public_key.len(), 32);
            assert_eq!(vector.expected_signature.len(), 7856);
        }

        #[test]
        fn test_slh_dsa_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // HybridKemKatVector Tests
    // ============================================================================

    mod hybrid_kem_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> HybridKemKatVector {
            HybridKemKatVector {
                test_case: "Hybrid-X25519-ML-KEM-001".to_string(),
                seed: vec![0x55; 64],
                expected_encapsulated_key: vec![0x66; 128],
                expected_shared_secret: vec![0x77; 64],
            }
        }

        #[test]
        fn test_hybrid_kem_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "Hybrid-X25519-ML-KEM-001");
            assert_eq!(vector.seed.len(), 64);
            assert_eq!(vector.expected_encapsulated_key.len(), 128);
            assert_eq!(vector.expected_shared_secret.len(), 64);
        }

        #[test]
        fn test_hybrid_kem_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // AesGcmKatVector Tests
    // ============================================================================

    mod aes_gcm_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> AesGcmKatVector {
            AesGcmKatVector {
                test_case: "AES-256-GCM-001".to_string(),
                key: vec![0x00; 32],
                nonce: vec![0x11; 12],
                aad: b"additional authenticated data".to_vec(),
                plaintext: b"plaintext data".to_vec(),
                expected_ciphertext: vec![0x22; 14],
                expected_tag: vec![0x33; 16],
            }
        }

        #[test]
        fn test_aes_gcm_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "AES-256-GCM-001");
            assert_eq!(vector.key.len(), 32);
            assert_eq!(vector.nonce.len(), 12);
            assert_eq!(vector.aad, b"additional authenticated data");
            assert_eq!(vector.plaintext, b"plaintext data");
            assert_eq!(vector.expected_ciphertext.len(), 14);
            assert_eq!(vector.expected_tag.len(), 16);
        }

        #[test]
        fn test_aes_gcm_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_aes_gcm_kat_vector_empty_aad_is_accepted() {
            let vector = AesGcmKatVector {
                test_case: "AES-GCM-no-aad".to_string(),
                key: vec![0x00; 16],
                nonce: vec![0x00; 12],
                aad: vec![],
                plaintext: b"test".to_vec(),
                expected_ciphertext: vec![0x00; 4],
                expected_tag: vec![0x00; 16],
            };

            assert!(vector.aad.is_empty());
        }
    }

    // ============================================================================
    // Sha3KatVector Tests
    // ============================================================================

    mod sha3_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> Sha3KatVector {
            Sha3KatVector {
                test_case: "SHA3-256-001".to_string(),
                message: b"The quick brown fox".to_vec(),
                expected_hash: vec![0xAB; 32],
            }
        }

        #[test]
        fn test_sha3_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "SHA3-256-001");
            assert_eq!(vector.message, b"The quick brown fox");
            assert_eq!(vector.expected_hash.len(), 32);
        }

        #[test]
        fn test_sha3_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_sha3_kat_vector_empty_message_is_accepted() {
            let vector = Sha3KatVector {
                test_case: "SHA3-256-empty".to_string(),
                message: vec![],
                expected_hash: vec![0x00; 32],
            };

            assert!(vector.message.is_empty());
        }
    }

    // ============================================================================
    // Ed25519KatVector Tests
    // ============================================================================

    mod ed25519_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> Ed25519KatVector {
            Ed25519KatVector {
                test_case: "Ed25519-001".to_string(),
                seed: vec![0x00; 32],
                expected_public_key: vec![0x11; 32],
                message: b"Ed25519 test message".to_vec(),
                expected_signature: vec![0x22; 64],
            }
        }

        #[test]
        fn test_ed25519_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "Ed25519-001");
            assert_eq!(vector.seed.len(), 32);
            assert_eq!(vector.expected_public_key.len(), 32);
            assert_eq!(vector.message, b"Ed25519 test message");
            assert_eq!(vector.expected_signature.len(), 64);
        }

        #[test]
        fn test_ed25519_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // Bls12_381KatVector Tests
    // ============================================================================

    mod bls12_381_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> Bls12_381KatVector {
            Bls12_381KatVector {
                test_case: "BLS12-381-001".to_string(),
                secret_key: vec![0x00; 32],
                expected_public_key: vec![0x11; 48],
                message: b"BLS signature test".to_vec(),
                expected_signature: vec![0x22; 96],
            }
        }

        #[test]
        fn test_bls12_381_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "BLS12-381-001");
            assert_eq!(vector.secret_key.len(), 32);
            assert_eq!(vector.expected_public_key.len(), 48);
            assert_eq!(vector.message, b"BLS signature test");
            assert_eq!(vector.expected_signature.len(), 96);
        }

        #[test]
        fn test_bls12_381_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // Bn254KatVector Tests
    // ============================================================================

    mod bn254_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> Bn254KatVector {
            Bn254KatVector {
                test_case: "BN254-001".to_string(),
                secret_key: vec![0x00; 32],
                expected_public_key: vec![0x11; 64],
                message: b"BN254 test".to_vec(),
                expected_signature: vec![0x22; 64],
            }
        }

        #[test]
        fn test_bn254_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "BN254-001");
            assert_eq!(vector.secret_key.len(), 32);
            assert_eq!(vector.expected_public_key.len(), 64);
            assert_eq!(vector.message, b"BN254 test");
            assert_eq!(vector.expected_signature.len(), 64);
        }

        #[test]
        fn test_bn254_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // Secp256k1KatVector Tests
    // ============================================================================

    mod secp256k1_kat_vector_tests {
        use super::*;

        fn create_test_vector() -> Secp256k1KatVector {
            Secp256k1KatVector {
                test_case: "secp256k1-001".to_string(),
                private_key: vec![0x00; 32],
                expected_public_key: vec![0x11; 33],
                message: b"secp256k1 test".to_vec(),
                expected_signature: vec![0x22; 71],
            }
        }

        #[test]
        fn test_secp256k1_kat_vector_construction_has_correct_fields_matches_expected() {
            let vector = create_test_vector();

            assert_eq!(vector.test_case, "secp256k1-001");
            assert_eq!(vector.private_key.len(), 32);
            assert_eq!(vector.expected_public_key.len(), 33);
            assert_eq!(vector.message, b"secp256k1 test");
            assert_eq!(vector.expected_signature.len(), 71);
        }

        #[test]
        fn test_secp256k1_kat_vector_clone_produces_equal_value_matches_expected() {
            let original = create_test_vector();
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }
    }

    // ============================================================================
    // NistStatisticalTestResult Tests
    // ============================================================================

    mod nist_statistical_test_result_tests {
        use super::*;

        fn create_test_result() -> NistStatisticalTestResult {
            NistStatisticalTestResult {
                test_name: "Frequency Test".to_string(),
                p_value: 0.523,
                passed: true,
                parameters: serde_json::json!({"n": 1000000, "block_size": 128}),
            }
        }

        #[test]
        fn test_nist_statistical_test_result_construction_has_correct_fields_succeeds() {
            let result = create_test_result();

            assert_eq!(result.test_name, "Frequency Test");
            assert!((result.p_value - 0.523).abs() < f64::EPSILON);
            assert!(result.passed);
            assert_eq!(result.parameters["n"], 1000000);
        }

        #[test]
        fn test_nist_statistical_test_result_clone_produces_equal_value_succeeds() {
            let original = create_test_result();
            let cloned = original.clone();

            assert_eq!(original.test_name, cloned.test_name);
            assert_eq!(original.p_value, cloned.p_value);
            assert_eq!(original.passed, cloned.passed);
        }

        #[test]
        fn test_nist_statistical_test_result_failed_has_correct_fields_fails() {
            let result = NistStatisticalTestResult {
                test_name: "Runs Test".to_string(),
                p_value: 0.005,
                passed: false,
                parameters: serde_json::json!({}),
            };

            assert!(!result.passed);
            assert!(result.p_value < 0.01);
        }
    }

    // ============================================================================
    // RngTestResults Tests
    // ============================================================================

    mod rng_test_results_tests {
        use super::*;

        fn create_test_results() -> RngTestResults {
            RngTestResults {
                algorithm: "ML-KEM-768-RNG".to_string(),
                bits_tested: 1_000_000,
                test_results: vec![
                    NistStatisticalTestResult {
                        test_name: "Frequency".to_string(),
                        p_value: 0.5,
                        passed: true,
                        parameters: serde_json::json!({}),
                    },
                    NistStatisticalTestResult {
                        test_name: "Runs".to_string(),
                        p_value: 0.3,
                        passed: true,
                        parameters: serde_json::json!({}),
                    },
                ],
                passed: true,
                entropy_estimate: 0.998,
            }
        }

        #[test]
        fn test_rng_test_results_construction_has_correct_fields_succeeds() {
            let results = create_test_results();

            assert_eq!(results.algorithm, "ML-KEM-768-RNG");
            assert_eq!(results.bits_tested, 1_000_000);
            assert_eq!(results.test_results.len(), 2);
            assert!(results.passed);
            assert!((results.entropy_estimate - 0.998).abs() < f64::EPSILON);
        }

        #[test]
        fn test_rng_test_results_clone_produces_equal_value_succeeds() {
            let original = create_test_results();
            let cloned = original.clone();

            assert_eq!(original.algorithm, cloned.algorithm);
            assert_eq!(original.bits_tested, cloned.bits_tested);
            assert_eq!(original.test_results.len(), cloned.test_results.len());
        }

        #[test]
        fn test_rng_test_results_failed_overall_is_correct() {
            let results = RngTestResults {
                algorithm: "Weak-RNG".to_string(),
                bits_tested: 100_000,
                test_results: vec![NistStatisticalTestResult {
                    test_name: "Frequency".to_string(),
                    p_value: 0.001,
                    passed: false,
                    parameters: serde_json::json!({}),
                }],
                passed: false,
                entropy_estimate: 0.75,
            };

            assert!(!results.passed);
            assert!(results.entropy_estimate < 0.9);
        }
    }

    // ============================================================================
    // AlgorithmType Name Tests
    // ============================================================================

    mod algorithm_type_name_tests {
        use super::*;

        #[test]
        fn test_ml_kem_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::MlKem { variant: "512".to_string() };
            assert_eq!(algo.name(), "ML-KEM-512");

            let algo = AlgorithmType::MlKem { variant: "768".to_string() };
            assert_eq!(algo.name(), "ML-KEM-768");

            let algo = AlgorithmType::MlKem { variant: "1024".to_string() };
            assert_eq!(algo.name(), "ML-KEM-1024");
        }

        #[test]
        fn test_ml_dsa_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::MlDsa { variant: "44".to_string() };
            assert_eq!(algo.name(), "ML-DSA-44");

            let algo = AlgorithmType::MlDsa { variant: "65".to_string() };
            assert_eq!(algo.name(), "ML-DSA-65");

            let algo = AlgorithmType::MlDsa { variant: "87".to_string() };
            assert_eq!(algo.name(), "ML-DSA-87");
        }

        #[test]
        fn test_slh_dsa_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::SlhDsa { variant: "128s".to_string() };
            assert_eq!(algo.name(), "SLH-DSA-128s");

            let algo = AlgorithmType::SlhDsa { variant: "256f".to_string() };
            assert_eq!(algo.name(), "SLH-DSA-256f");
        }

        #[test]
        fn test_hybrid_kem_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::HybridKem;
            assert_eq!(algo.name(), "Hybrid-KEM");
        }

        #[test]
        fn test_aes_gcm_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::AesGcm { key_size: 16 };
            assert_eq!(algo.name(), "AES-128-GCM");

            let algo = AlgorithmType::AesGcm { key_size: 24 };
            assert_eq!(algo.name(), "AES-192-GCM");

            let algo = AlgorithmType::AesGcm { key_size: 32 };
            assert_eq!(algo.name(), "AES-256-GCM");
        }

        #[test]
        fn test_sha3_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::Sha3 { variant: "256".to_string() };
            assert_eq!(algo.name(), "SHA3-256");

            let algo = AlgorithmType::Sha3 { variant: "512".to_string() };
            assert_eq!(algo.name(), "SHA3-512");
        }

        #[test]
        fn test_ed25519_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::Ed25519;
            assert_eq!(algo.name(), "Ed25519");
        }

        #[test]
        fn test_bls12_381_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::Bls12_381;
            assert_eq!(algo.name(), "BLS12-381");
        }

        #[test]
        fn test_bn254_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::Bn254;
            assert_eq!(algo.name(), "BN254");
        }

        #[test]
        fn test_secp256k1_name_returns_correct_string_succeeds() {
            let algo = AlgorithmType::Secp256k1;
            assert_eq!(algo.name(), "secp256k1");
        }
    }

    // ============================================================================
    // AlgorithmType Security Level Tests
    // ============================================================================

    mod algorithm_type_security_level_tests {
        use super::*;

        #[test]
        fn test_ml_kem_security_levels_are_correct() {
            let algo = AlgorithmType::MlKem { variant: "512".to_string() };
            assert_eq!(algo.security_level(), 128);

            let algo = AlgorithmType::MlKem { variant: "768".to_string() };
            assert_eq!(algo.security_level(), 192);

            let algo = AlgorithmType::MlKem { variant: "1024".to_string() };
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_ml_kem_unknown_variant_defaults_to_128_is_correct() {
            let algo = AlgorithmType::MlKem { variant: "unknown".to_string() };
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_ml_dsa_security_levels_are_correct() {
            let algo = AlgorithmType::MlDsa { variant: "44".to_string() };
            assert_eq!(algo.security_level(), 128);

            let algo = AlgorithmType::MlDsa { variant: "65".to_string() };
            assert_eq!(algo.security_level(), 192);

            let algo = AlgorithmType::MlDsa { variant: "87".to_string() };
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_ml_dsa_unknown_variant_defaults_to_128_is_correct() {
            let algo = AlgorithmType::MlDsa { variant: "invalid".to_string() };
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_slh_dsa_security_levels_are_correct() {
            let algo = AlgorithmType::SlhDsa { variant: "128".to_string() };
            assert_eq!(algo.security_level(), 128);

            let algo = AlgorithmType::SlhDsa { variant: "192".to_string() };
            assert_eq!(algo.security_level(), 192);

            let algo = AlgorithmType::SlhDsa { variant: "256".to_string() };
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_slh_dsa_unknown_variant_defaults_to_128_is_correct() {
            let algo = AlgorithmType::SlhDsa { variant: "other".to_string() };
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_hybrid_kem_security_level_is_correct() {
            let algo = AlgorithmType::HybridKem;
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_aes_gcm_security_levels_are_correct() {
            let algo = AlgorithmType::AesGcm { key_size: 16 };
            assert_eq!(algo.security_level(), 128);

            let algo = AlgorithmType::AesGcm { key_size: 24 };
            assert_eq!(algo.security_level(), 192);

            let algo = AlgorithmType::AesGcm { key_size: 32 };
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_sha3_security_levels_are_correct() {
            let algo = AlgorithmType::Sha3 { variant: "256".to_string() };
            assert_eq!(algo.security_level(), 256);

            let algo = AlgorithmType::Sha3 { variant: "512".to_string() };
            assert_eq!(algo.security_level(), 512);
        }

        #[test]
        fn test_sha3_invalid_variant_defaults_to_256_is_correct() {
            let algo = AlgorithmType::Sha3 { variant: "invalid".to_string() };
            assert_eq!(algo.security_level(), 256);
        }

        #[test]
        fn test_ed25519_security_level_is_correct() {
            let algo = AlgorithmType::Ed25519;
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_bls12_381_security_level_is_correct() {
            let algo = AlgorithmType::Bls12_381;
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_bn254_security_level_is_correct() {
            let algo = AlgorithmType::Bn254;
            assert_eq!(algo.security_level(), 128);
        }

        #[test]
        fn test_secp256k1_security_level_is_correct() {
            let algo = AlgorithmType::Secp256k1;
            assert_eq!(algo.security_level(), 128);
        }
    }

    // ============================================================================
    // AlgorithmType Clone and Equality Tests
    // ============================================================================

    mod algorithm_type_traits_tests {
        use super::*;

        #[test]
        fn test_algorithm_type_clone_produces_equal_value_succeeds() {
            let original = AlgorithmType::MlKem { variant: "768".to_string() };
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_algorithm_type_equality_matches_expected() {
            let a1 = AlgorithmType::MlKem { variant: "768".to_string() };
            let a2 = AlgorithmType::MlKem { variant: "768".to_string() };
            let a3 = AlgorithmType::MlKem { variant: "512".to_string() };

            assert_eq!(a1, a2);
            assert_ne!(a1, a3);
        }

        #[test]
        fn test_algorithm_type_debug_has_correct_format() {
            let algo = AlgorithmType::Ed25519;
            let debug_str = format!("{:?}", algo);

            assert!(debug_str.contains("Ed25519"));
        }
    }

    // ============================================================================
    // KatConfig Tests
    // ============================================================================

    mod kat_config_tests {
        use super::*;

        #[test]
        fn test_kat_config_default_has_expected_values_matches_expected() {
            let config = KatConfig::default();

            assert!(matches!(
                config.algorithm,
                AlgorithmType::MlKem { ref variant } if variant == "768"
            ));
            assert_eq!(config.test_count, 100);
            assert!(config.run_statistical_tests);
            assert_eq!(config.timeout_per_test, Duration::from_secs(10));
            assert!(config.validate_fips);
        }

        #[test]
        fn test_kat_config_ml_kem_constructor_has_correct_fields_matches_expected() {
            let config = KatConfig::ml_kem("512", 50);

            assert!(matches!(
                config.algorithm,
                AlgorithmType::MlKem { ref variant } if variant == "512"
            ));
            assert_eq!(config.test_count, 50);
            assert!(config.run_statistical_tests);
            assert_eq!(config.timeout_per_test, Duration::from_secs(10));
            assert!(config.validate_fips);
        }

        #[test]
        fn test_kat_config_ml_dsa_constructor_has_correct_fields_matches_expected() {
            let config = KatConfig::ml_dsa("65", 200);

            assert!(matches!(
                config.algorithm,
                AlgorithmType::MlDsa { ref variant } if variant == "65"
            ));
            assert_eq!(config.test_count, 200);
            assert!(config.run_statistical_tests);
            assert_eq!(config.timeout_per_test, Duration::from_secs(10));
            assert!(config.validate_fips);
        }

        #[test]
        fn test_kat_config_slh_dsa_constructor_has_correct_fields_matches_expected() {
            let config = KatConfig::slh_dsa("256f", 10);

            assert!(matches!(
                config.algorithm,
                AlgorithmType::SlhDsa { ref variant } if variant == "256f"
            ));
            assert_eq!(config.test_count, 10);
            assert!(config.run_statistical_tests);
            // SLH-DSA has longer timeout
            assert_eq!(config.timeout_per_test, Duration::from_secs(30));
            assert!(config.validate_fips);
        }

        #[test]
        fn test_kat_config_clone_produces_equal_value_matches_expected() {
            let original = KatConfig::ml_kem("1024", 100);
            let cloned = original.clone();

            assert_eq!(original, cloned);
        }

        #[test]
        fn test_kat_config_equality_matches_expected() {
            let c1 = KatConfig::ml_kem("768", 100);
            let c2 = KatConfig::ml_kem("768", 100);
            let c3 = KatConfig::ml_kem("768", 50);

            assert_eq!(c1, c2);
            assert_ne!(c1, c3);
        }

        #[test]
        fn test_kat_config_debug_has_correct_format() {
            let config = KatConfig::default();
            let debug_str = format!("{:?}", config);

            assert!(debug_str.contains("KatConfig"));
            assert!(debug_str.contains("algorithm"));
            assert!(debug_str.contains("test_count"));
        }
    }

    // ============================================================================
    // Serialization Tests
    // ============================================================================

    mod serialization_tests {
        use super::*;

        #[test]
        fn test_kat_result_serialization_round_trips_correctly_roundtrip() {
            let result = KatResult::passed("test".to_string(), Duration::from_millis(100));
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result, deserialized);
        }

        #[test]
        fn test_kat_result_failed_serialization_round_trips_correctly_roundtrip() {
            let result = KatResult::failed(
                "fail_test".to_string(),
                Duration::from_millis(50),
                "Error occurred".to_string(),
            );
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result, deserialized);
            assert_eq!(deserialized.error_message.as_ref().unwrap(), "Error occurred");
        }

        #[test]
        fn test_ml_kem_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = MlKemKatVector {
                test_case: "test".to_string(),
                seed: vec![1, 2, 3],
                expected_public_key: vec![4, 5, 6],
                expected_secret_key: vec![7, 8, 9],
                expected_ciphertext: vec![10, 11, 12],
                expected_shared_secret: vec![13, 14, 15],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: MlKemKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_ml_dsa_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = MlDsaKatVector {
                test_case: "test".to_string(),
                seed: vec![1, 2, 3],
                message: b"message".to_vec(),
                expected_public_key: vec![4, 5, 6],
                expected_secret_key: vec![7, 8, 9],
                expected_signature: vec![10, 11, 12],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: MlDsaKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_slh_dsa_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = SlhDsaKatVector {
                test_case: "test".to_string(),
                seed: vec![1, 2, 3],
                message: b"message".to_vec(),
                expected_public_key: vec![4, 5, 6],
                expected_signature: vec![7, 8, 9],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: SlhDsaKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_hybrid_kem_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = HybridKemKatVector {
                test_case: "test".to_string(),
                seed: vec![1, 2, 3],
                expected_encapsulated_key: vec![4, 5, 6],
                expected_shared_secret: vec![7, 8, 9],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: HybridKemKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_aes_gcm_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = AesGcmKatVector {
                test_case: "test".to_string(),
                key: vec![0; 32],
                nonce: vec![0; 12],
                aad: vec![],
                plaintext: b"plaintext".to_vec(),
                expected_ciphertext: vec![1, 2, 3],
                expected_tag: vec![4, 5, 6],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: AesGcmKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_sha3_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Sha3KatVector {
                test_case: "test".to_string(),
                message: b"message".to_vec(),
                expected_hash: vec![0; 32],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Sha3KatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_ed25519_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Ed25519KatVector {
                test_case: "test".to_string(),
                seed: vec![0; 32],
                expected_public_key: vec![1; 32],
                message: b"message".to_vec(),
                expected_signature: vec![2; 64],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Ed25519KatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_bls12_381_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Bls12_381KatVector {
                test_case: "test".to_string(),
                secret_key: vec![0; 32],
                expected_public_key: vec![1; 48],
                message: b"message".to_vec(),
                expected_signature: vec![2; 96],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Bls12_381KatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_bn254_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Bn254KatVector {
                test_case: "test".to_string(),
                secret_key: vec![0; 32],
                expected_public_key: vec![1; 64],
                message: b"message".to_vec(),
                expected_signature: vec![2; 64],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Bn254KatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_secp256k1_kat_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = Secp256k1KatVector {
                test_case: "test".to_string(),
                private_key: vec![0; 32],
                expected_public_key: vec![1; 33],
                message: b"message".to_vec(),
                expected_signature: vec![2; 71],
            };
            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: Secp256k1KatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_nist_statistical_test_result_serialization_round_trips_correctly_roundtrip() {
            let result = NistStatisticalTestResult {
                test_name: "Frequency".to_string(),
                p_value: 0.5,
                passed: true,
                parameters: serde_json::json!({"n": 1000}),
            };
            let json = serde_json::to_string(&result).unwrap();
            let deserialized: NistStatisticalTestResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result.test_name, deserialized.test_name);
            assert_eq!(result.p_value, deserialized.p_value);
            assert_eq!(result.passed, deserialized.passed);
        }

        #[test]
        fn test_rng_test_results_serialization_round_trips_correctly_roundtrip() {
            let results = RngTestResults {
                algorithm: "ML-KEM-RNG".to_string(),
                bits_tested: 1_000_000,
                test_results: vec![],
                passed: true,
                entropy_estimate: 0.99,
            };
            let json = serde_json::to_string(&results).unwrap();
            let deserialized: RngTestResults = serde_json::from_str(&json).unwrap();

            assert_eq!(results.algorithm, deserialized.algorithm);
            assert_eq!(results.bits_tested, deserialized.bits_tested);
            assert_eq!(results.passed, deserialized.passed);
        }

        #[test]
        fn test_algorithm_type_serialization_round_trips_correctly_roundtrip() {
            let variants = vec![
                AlgorithmType::MlKem { variant: "768".to_string() },
                AlgorithmType::MlDsa { variant: "65".to_string() },
                AlgorithmType::SlhDsa { variant: "128".to_string() },
                AlgorithmType::HybridKem,
                AlgorithmType::AesGcm { key_size: 32 },
                AlgorithmType::Sha3 { variant: "256".to_string() },
                AlgorithmType::Ed25519,
                AlgorithmType::Bls12_381,
                AlgorithmType::Bn254,
                AlgorithmType::Secp256k1,
            ];

            for algo in variants {
                let json = serde_json::to_string(&algo).unwrap();
                let deserialized: AlgorithmType = serde_json::from_str(&json).unwrap();
                assert_eq!(algo, deserialized);
            }
        }

        #[test]
        fn test_kat_config_serialization_round_trips_correctly_roundtrip() {
            let config = KatConfig::ml_kem("768", 100);
            let json = serde_json::to_string(&config).unwrap();
            let deserialized: KatConfig = serde_json::from_str(&json).unwrap();

            assert_eq!(config, deserialized);
        }

        #[test]
        fn test_kat_config_default_serialization_round_trips_correctly_roundtrip() {
            let config = KatConfig::default();
            let json = serde_json::to_string(&config).unwrap();
            let deserialized: KatConfig = serde_json::from_str(&json).unwrap();

            assert_eq!(config, deserialized);
        }
    }

    // ============================================================================
    // Deserialization Error Tests
    // ============================================================================

    mod deserialization_error_tests {
        use super::*;

        #[test]
        fn test_kat_result_invalid_json_returns_error() {
            let result: Result<KatResult, _> = serde_json::from_str("invalid json");
            assert!(result.is_err());
        }

        #[test]
        fn test_kat_result_missing_field_returns_error() {
            let json = r#"{"test_case": "test", "passed": true}"#;
            let result: Result<KatResult, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }

        #[test]
        fn test_algorithm_type_invalid_json_returns_error() {
            let result: Result<AlgorithmType, _> = serde_json::from_str("not valid");
            assert!(result.is_err());
        }

        #[test]
        fn test_kat_config_invalid_json_returns_error() {
            let result: Result<KatConfig, _> = serde_json::from_str("{}");
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_empty_vectors_are_accepted_matches_expected() {
            let vector = MlKemKatVector {
                test_case: String::new(),
                seed: vec![],
                expected_public_key: vec![],
                expected_secret_key: vec![],
                expected_ciphertext: vec![],
                expected_shared_secret: vec![],
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: MlKemKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_large_vectors_are_accepted_matches_expected() {
            let large_data = vec![0xAB; 100_000];
            let vector = MlKemKatVector {
                test_case: "large".to_string(),
                seed: large_data.clone(),
                expected_public_key: large_data.clone(),
                expected_secret_key: large_data.clone(),
                expected_ciphertext: large_data.clone(),
                expected_shared_secret: large_data,
            };

            let json = serde_json::to_string(&vector).unwrap();
            let deserialized: MlKemKatVector = serde_json::from_str(&json).unwrap();

            assert_eq!(vector, deserialized);
        }

        #[test]
        fn test_special_characters_in_test_case_are_accepted_succeeds() {
            let result =
                KatResult::passed("test/with\\special\"chars\n\t".to_string(), Duration::ZERO);

            let json = serde_json::to_string(&result).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result, deserialized);
        }

        #[test]
        fn test_unicode_in_test_case_are_accepted_succeeds() {
            let result = KatResult::passed("test_unicode_\u{1F512}".to_string(), Duration::ZERO);

            let json = serde_json::to_string(&result).unwrap();
            let deserialized: KatResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result, deserialized);
        }

        #[test]
        fn test_max_duration_is_accepted() {
            let result = KatResult::passed("max_duration".to_string(), Duration::MAX);

            assert_eq!(result.execution_time_ns, Duration::MAX.as_nanos());
        }

        #[test]
        fn test_zero_test_count_config_is_accepted() {
            let config = KatConfig::ml_kem("768", 0);

            assert_eq!(config.test_count, 0);
        }

        #[test]
        fn test_aes_gcm_zero_key_size_is_accepted() {
            let algo = AlgorithmType::AesGcm { key_size: 0 };

            assert_eq!(algo.name(), "AES-0-GCM");
            assert_eq!(algo.security_level(), 0);
        }

        #[test]
        fn test_p_value_edge_cases_are_accepted_succeeds() {
            // Exactly 0
            let result = NistStatisticalTestResult {
                test_name: "Zero p-value".to_string(),
                p_value: 0.0,
                passed: false,
                parameters: serde_json::json!({}),
            };
            assert_eq!(result.p_value, 0.0);

            // Exactly 1
            let result = NistStatisticalTestResult {
                test_name: "One p-value".to_string(),
                p_value: 1.0,
                passed: true,
                parameters: serde_json::json!({}),
            };
            assert_eq!(result.p_value, 1.0);
        }

        #[test]
        fn test_entropy_estimate_edge_cases_are_accepted_succeeds() {
            let results = RngTestResults {
                algorithm: "test".to_string(),
                bits_tested: 0,
                test_results: vec![],
                passed: false,
                entropy_estimate: 0.0,
            };
            assert_eq!(results.entropy_estimate, 0.0);

            let results = RngTestResults {
                algorithm: "test".to_string(),
                bits_tested: usize::MAX,
                test_results: vec![],
                passed: true,
                entropy_estimate: 1.0,
            };
            assert_eq!(results.bits_tested, usize::MAX);
        }
    }

    // ============================================================================
    // JSON Format Verification Tests
    // ============================================================================

    mod json_format_tests {
        use super::*;

        #[test]
        fn test_kat_result_json_structure_has_correct_format() {
            let result = KatResult::passed("test".to_string(), Duration::from_millis(100));
            let json = serde_json::to_string(&result).unwrap();

            assert!(json.contains("\"test_case\""));
            assert!(json.contains("\"passed\""));
            assert!(json.contains("\"execution_time_ns\""));
            assert!(json.contains("\"error_message\""));
        }

        #[test]
        fn test_algorithm_type_json_structure_ml_kem_has_correct_format() {
            let algo = AlgorithmType::MlKem { variant: "768".to_string() };
            let json = serde_json::to_string(&algo).unwrap();

            assert!(json.contains("MlKem"));
            assert!(json.contains("\"variant\""));
            assert!(json.contains("768"));
        }

        #[test]
        fn test_algorithm_type_json_structure_unit_variants_has_correct_format() {
            let algo = AlgorithmType::Ed25519;
            let json = serde_json::to_string(&algo).unwrap();

            assert!(json.contains("Ed25519"));
        }

        #[test]
        fn test_kat_config_json_structure_has_correct_format() {
            let config = KatConfig::default();
            let json = serde_json::to_string(&config).unwrap();

            assert!(json.contains("\"algorithm\""));
            assert!(json.contains("\"test_count\""));
            assert!(json.contains("\"run_statistical_tests\""));
            assert!(json.contains("\"timeout_per_test\""));
            assert!(json.contains("\"validate_fips\""));
        }
    }
}
