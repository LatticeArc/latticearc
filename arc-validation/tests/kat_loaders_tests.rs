//! Comprehensive tests for KAT (Known Answer Test) vector loaders.
//!
//! This test module validates all loader functions in `arc_validation::kat_tests::loaders`,
//! ensuring correct parsing, field validation, and error handling for cryptographic test vectors.
//!
//! NOTE: Some loaders (AES-GCM, ML-DSA, SLH-DSA, Ed25519) have known hex encoding
//! issues in their hardcoded test vectors. Tests document these issues while validating
//! the working loaders (ML-KEM, SHA3, Hybrid-KEM, CAVP parser).

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

use arc_validation::kat_tests::loaders::{
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
    fn test_load_ml_kem_1024_kats_returns_vectors() {
        let result = load_ml_kem_1024_kats();
        assert!(result.is_ok(), "load_ml_kem_1024_kats() should succeed");

        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return at least one ML-KEM-1024 vector");
    }

    #[test]
    fn test_ml_kem_1024_vectors_have_valid_test_case_names() {
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
    fn test_ml_kem_1024_vectors_have_correct_key_sizes() {
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
    fn test_ml_kem_1024_vectors_have_non_trivial_data() {
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
    fn test_ml_kem_1024_returns_at_least_ten_vectors() {
        let vectors = load_ml_kem_1024_kats().unwrap();
        assert!(
            vectors.len() >= 10,
            "Should return at least 10 ML-KEM-1024 vectors for comprehensive testing, got {}",
            vectors.len()
        );
    }

    #[test]
    fn test_ml_kem_loader_is_deterministic_in_count() {
        // Run the loader twice and verify it returns same count
        let result1 = load_ml_kem_1024_kats();
        let result2 = load_ml_kem_1024_kats();

        assert!(result1.is_ok());
        assert!(result2.is_ok());

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
    fn test_ml_kem_vectors_have_unique_test_case_names() {
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
    fn test_load_sha3_kats_returns_vectors() {
        let result = load_sha3_kats();
        assert!(result.is_ok(), "load_sha3_kats() should succeed");

        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return at least one SHA3 vector");
    }

    #[test]
    fn test_sha3_vectors_have_valid_hash_sizes() {
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
    fn test_sha3_vectors_include_empty_message() {
        let vectors = load_sha3_kats().unwrap();

        let has_empty_message = vectors.iter().any(|v| v.message.is_empty());
        assert!(
            has_empty_message,
            "Should include a test vector with empty message for edge case testing"
        );
    }

    #[test]
    fn test_sha3_vectors_include_known_test_cases() {
        let vectors = load_sha3_kats().unwrap();

        // Check for "abc" test case which is a standard NIST test
        let has_abc_test = vectors.iter().any(|v| v.message == b"abc".to_vec());

        assert!(has_abc_test, "Should include the standard 'abc' NIST test vector");
    }

    #[test]
    fn test_sha3_empty_message_hash_value() {
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
    fn test_sha3_abc_hash_value() {
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
    fn test_sha3_vectors_have_unique_test_case_names() {
        let vectors = load_sha3_kats().unwrap();
        let names: Vec<_> = vectors.iter().map(|v| &v.test_case).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "SHA3 test case names should be unique");
    }

    #[test]
    fn test_sha3_vectors_have_valid_test_case_names() {
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
    fn test_hybrid_kem_loader_returns_vectors() {
        let vectors = load_hybrid_kem_kats();
        assert!(!vectors.is_empty(), "Hybrid KEM loader should return test vectors");
    }

    #[test]
    fn test_hybrid_kem_vectors_have_valid_structure() {
        let vectors = load_hybrid_kem_kats();
        for vector in &vectors {
            assert!(!vector.test_case.is_empty(), "Test case should not be empty");
            assert!(!vector.seed.is_empty(), "Seed should not be empty");
            assert!(
                !vector.expected_encapsulated_key.is_empty(),
                "Encapsulated key should not be empty"
            );
            assert!(!vector.expected_shared_secret.is_empty(), "Shared secret should not be empty");
        }
    }
}

// ============================================================================
// Additional Algorithm Loader Tests (WORKING - hex encoding fixed)
// ============================================================================

mod additional_loader_tests {
    use super::*;

    #[test]
    fn test_aes_gcm_loader_returns_vectors() {
        let result = load_aes_gcm_kats();
        assert!(result.is_ok(), "AES-GCM loader should succeed");
        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return AES-GCM test vectors");
    }

    #[test]
    fn test_aes_gcm_vectors_have_valid_structure() {
        let vectors = load_aes_gcm_kats().unwrap();
        for vector in &vectors {
            assert!(!vector.key.is_empty(), "Key should not be empty");
            assert!(!vector.nonce.is_empty(), "Nonce should not be empty");
            assert!(!vector.plaintext.is_empty(), "Plaintext should not be empty");
            assert_eq!(vector.expected_tag.len(), 16, "Tag should be 16 bytes");
        }
    }

    #[test]
    fn test_ml_dsa_loader_returns_vectors() {
        let result = load_ml_dsa_kats();
        assert!(result.is_ok(), "ML-DSA loader should succeed");
        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return ML-DSA test vectors");
    }

    #[test]
    fn test_ml_dsa_vectors_have_valid_structure() {
        let vectors = load_ml_dsa_kats().unwrap();
        for vector in &vectors {
            assert!(!vector.seed.is_empty(), "Seed should not be empty");
            assert!(!vector.message.is_empty(), "Message should not be empty");
            assert!(!vector.expected_public_key.is_empty(), "Public key should not be empty");
        }
    }

    #[test]
    fn test_slh_dsa_loader_returns_vectors() {
        let result = load_slh_dsa_kats();
        assert!(result.is_ok(), "SLH-DSA loader should succeed");
        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return SLH-DSA test vectors");
    }

    #[test]
    fn test_slh_dsa_vectors_have_valid_structure() {
        let vectors = load_slh_dsa_kats().unwrap();
        for vector in &vectors {
            assert!(!vector.seed.is_empty(), "Seed should not be empty");
            assert!(!vector.message.is_empty(), "Message should not be empty");
            assert!(!vector.expected_signature.is_empty(), "Signature should not be empty");
        }
    }

    #[test]
    fn test_ed25519_loader_returns_vectors() {
        let result = load_ed25519_kats();
        assert!(result.is_ok(), "Ed25519 loader should succeed");
        let vectors = result.unwrap();
        assert!(!vectors.is_empty(), "Should return Ed25519 test vectors");
    }

    #[test]
    fn test_ed25519_vectors_have_correct_sizes() {
        let vectors = load_ed25519_kats().unwrap();
        for vector in &vectors {
            assert_eq!(vector.seed.len(), 32, "Ed25519 seed should be 32 bytes");
            assert_eq!(
                vector.expected_public_key.len(),
                32,
                "Ed25519 public key should be 32 bytes"
            );
            assert_eq!(vector.expected_signature.len(), 64, "Ed25519 signature should be 64 bytes");
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
    fn test_load_from_cavp_json_parses_valid_json() {
        let json_data = create_valid_cavp_json();
        let result = load_from_cavp_json(&json_data);

        assert!(result.is_ok(), "Should parse valid CAVP JSON: {:?}", result.err());
    }

    #[test]
    fn test_load_from_cavp_json_extracts_vectors() {
        let json_data = create_valid_cavp_json();
        let vectors = load_from_cavp_json(&json_data).unwrap();

        assert_eq!(vectors.len(), 1, "Should extract one test vector");
    }

    #[test]
    fn test_load_from_cavp_json_correctly_decodes_hex() {
        let json_data = create_valid_cavp_json();
        let vectors = load_from_cavp_json(&json_data).unwrap();
        let vector = &vectors[0];

        // Verify seed was correctly decoded
        assert_eq!(vector.seed.len(), 64, "Seed should be 64 bytes");
        assert_eq!(vector.seed[0], 0x00, "First seed byte should be 0x00");
        assert_eq!(vector.seed[63], 0x3f, "Last seed byte should be 0x3f");
    }

    #[test]
    fn test_load_from_cavp_json_sets_test_case_name() {
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
    fn test_load_from_cavp_json_ignores_non_ml_kem_1024() {
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
        assert!(result.is_ok());

        let vectors = result.unwrap();
        assert!(vectors.is_empty(), "Should ignore non-ML-KEM-1024 parameter sets");
    }

    #[test]
    fn test_load_from_cavp_json_handles_multiple_test_groups() {
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
    fn test_load_from_cavp_json_fails_on_invalid_json() {
        let invalid_json = "{ invalid json }";
        let result = load_from_cavp_json(invalid_json);

        assert!(result.is_err(), "Should fail on invalid JSON syntax");
    }

    #[test]
    fn test_load_from_cavp_json_fails_on_missing_seed() {
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
    fn test_load_from_cavp_json_fails_on_missing_pk() {
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
    fn test_load_from_cavp_json_fails_on_missing_sk() {
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
    fn test_load_from_cavp_json_fails_on_missing_ct() {
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
    fn test_load_from_cavp_json_fails_on_missing_ss() {
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
    fn test_load_from_cavp_json_fails_on_invalid_hex() {
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
    fn test_load_from_cavp_json_handles_empty_test_groups() {
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
    fn test_load_from_cavp_json_handles_empty_tests() {
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

        assert_eq!(deserialized.tc_id, test_case.tc_id);
        assert_eq!(deserialized.seed, test_case.seed);
        assert_eq!(deserialized.pk, test_case.pk);
        assert_eq!(deserialized.sk, test_case.sk);
        assert_eq!(deserialized.ct, test_case.ct);
        assert_eq!(deserialized.ss, test_case.ss);
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

        assert_eq!(deserialized.tg_id, test_group.tg_id);
        assert_eq!(deserialized.test_type, test_group.test_type);
        assert_eq!(deserialized.parameter_set, test_group.parameter_set);
        assert_eq!(deserialized.tests.len(), 1);
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

        assert_eq!(deserialized.vs_id, file.vs_id);
        assert_eq!(deserialized.algorithm, file.algorithm);
        assert_eq!(deserialized.mode, file.mode);
        assert_eq!(deserialized.revision, file.revision);
    }

    #[test]
    fn test_cavp_test_vector_file_mode_is_optional() {
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
    fn test_cavp_structures_are_cloneable() {
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
    fn test_cavp_structures_are_debuggable() {
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
        assert!(debug_str.contains("CavpTestCase"));
        assert!(debug_str.contains("tc_id"));
    }
}

// ============================================================================
// Edge Case and Boundary Tests for CAVP Parser (WORKING)
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_cavp_json_with_unicode_in_test_type() {
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
    fn test_cavp_json_with_large_tc_id() {
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
    fn test_cavp_json_with_empty_hex_strings() {
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
        assert_eq!(vectors.len(), 1);
        assert!(vectors[0].seed.is_empty());
    }

    #[test]
    fn test_cavp_json_with_mixed_case_hex() {
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
        assert_eq!(vectors[0].seed, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_cavp_json_with_whitespace_in_hex() {
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
    fn test_cavp_json_with_odd_length_hex() {
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
    fn test_cavp_json_with_long_hex_string() {
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
        assert_eq!(vectors[0].seed.len(), 1024);
    }
}

// ============================================================================
// Cross-Loader Summary Tests (WORKING)
// ============================================================================

mod cross_loader_tests {
    use super::*;

    #[test]
    fn test_working_loaders_return_consistent_results() {
        // Test only the loaders that are known to work
        let ml_kem_result = load_ml_kem_1024_kats();
        let sha3_result = load_sha3_kats();

        assert!(ml_kem_result.is_ok(), "ML-KEM loader should succeed");
        assert!(sha3_result.is_ok(), "SHA3 loader should succeed");

        assert!(!ml_kem_result.unwrap().is_empty());
        assert!(!sha3_result.unwrap().is_empty());
    }

    #[test]
    fn test_working_loaders_performance() {
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
    fn test_loaders_handle_concurrent_access() {
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
    fn test_vectors_have_unique_test_case_names_within_loader() {
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
        assert_eq!(sha3_names.len(), unique_sha3.len(), "SHA3 test case names should be unique");
    }
}

// ============================================================================
// Regression Tests (WORKING)
// ============================================================================

mod regression_tests {
    use super::*;

    #[test]
    fn test_ml_kem_loader_repeated_calls_consistent() {
        let result1 = load_ml_kem_1024_kats();
        let result2 = load_ml_kem_1024_kats();

        assert!(result1.is_ok());
        assert!(result2.is_ok());

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
    fn test_sha3_empty_input_known_value() {
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
    fn test_sha3_long_message_known_value() {
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
    fn test_cavp_structures_implement_required_traits() {
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
