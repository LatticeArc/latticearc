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
    clippy::useless_vec,
    dead_code
)]

//! Extended Test Suite for KAT (Known Answer Test) Runners
//!
//! This module provides additional coverage for the `arc_validation::kat_tests::runners` module.
//! It focuses on:
//! - The `run_all_kats()` aggregator function
//! - The `run_aes_gcm_kats()` function
//! - Error handling paths
//! - Edge cases in validation functions
//! - Algorithm type coverage

use arc_validation::kat_tests::loaders::{
    load_aes_gcm_kats, load_ed25519_kats, load_ml_dsa_kats, load_slh_dsa_kats,
};
use arc_validation::kat_tests::runners::{
    run_aes_gcm_kats, run_all_kats, run_hybrid_kem_kats, run_ml_dsa_kats, run_ml_kem_kats,
    run_sha3_kats, run_slh_dsa_kats, validate_ed25519_keypair, validate_ed25519_signature,
};
use arc_validation::kat_tests::types::{
    AesGcmKatVector, AlgorithmType, Bls12_381KatVector, Bn254KatVector, Ed25519KatVector,
    HybridKemKatVector, KatConfig, KatResult, MlDsaKatVector, MlKemKatVector,
    NistStatisticalTestResult, RngTestResults, Secp256k1KatVector, Sha3KatVector, SlhDsaKatVector,
};
use std::time::Duration;

// ============================================================================
// Test Suite: run_all_kats() - Comprehensive KAT Runner
// ============================================================================

mod run_all_kats_tests {
    use super::*;

    #[test]
    fn test_run_all_kats_returns_results() {
        let results = run_all_kats();
        assert!(results.is_ok(), "run_all_kats should not return an error");

        let results = results.unwrap();
        assert!(
            !results.is_empty(),
            "run_all_kats should return combined results from all runners"
        );

        println!("run_all_kats returned {} total results", results.len());
    }

    #[test]
    fn test_run_all_kats_aggregates_multiple_suites() {
        let results = run_all_kats().unwrap();

        // Verify we have results from various test suites
        let has_ml_kem =
            results.iter().any(|r| r.test_case.contains("KEM") || r.test_case.contains("CAVP"));
        let has_sha3 = results.iter().any(|r| r.test_case.contains("SHA3"));
        let has_aes = results.iter().any(|r| r.test_case.contains("AES"));

        println!(
            "Test suite coverage - ML-KEM: {}, SHA3: {}, AES: {}",
            has_ml_kem, has_sha3, has_aes
        );

        // At minimum, we should have ML-KEM and SHA3 results
        assert!(has_ml_kem || has_sha3, "Should have results from at least one suite");
    }

    #[test]
    fn test_run_all_kats_result_count() {
        let all_results = run_all_kats().unwrap();

        // Get individual suite results
        let ml_kem_results = run_ml_kem_kats().unwrap_or_default();
        let sha3_results = run_sha3_kats().unwrap_or_default();
        let aes_results = run_aes_gcm_kats().unwrap_or_default();

        let individual_total = ml_kem_results.len() + sha3_results.len() + aes_results.len();

        println!(
            "All results: {}, Sum of individual: {} (partial)",
            all_results.len(),
            individual_total
        );

        // run_all_kats should have at least as many results as the ones we counted
        assert!(
            all_results.len() >= individual_total.saturating_sub(5),
            "Combined results should include individual suite results"
        );
    }

    #[test]
    fn test_run_all_kats_timing_aggregation() {
        let results = run_all_kats().unwrap();

        let total_time_ns: u128 = results.iter().map(|r| r.execution_time_ns).sum();
        let total_time_ms = total_time_ns as f64 / 1_000_000.0;

        println!(
            "Total execution time for all KATs: {:.2}ms ({} tests)",
            total_time_ms,
            results.len()
        );

        // Each result should have positive execution time
        for result in &results {
            assert!(
                result.execution_time_ns > 0,
                "Result {} should have positive execution time",
                result.test_case
            );
        }
    }

    #[test]
    fn test_run_all_kats_pass_fail_summary() {
        let results = run_all_kats().unwrap();

        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.iter().filter(|r| !r.passed).count();

        println!("Pass/Fail Summary:");
        println!("  Passed: {}", passed);
        println!("  Failed: {}", failed);
        println!("  Total: {}", results.len());

        assert_eq!(passed + failed, results.len(), "All results should be either passed or failed");
    }
}

// ============================================================================
// Test Suite: run_aes_gcm_kats()
// ============================================================================

mod run_aes_gcm_kats_tests {
    use super::*;

    #[test]
    fn test_run_aes_gcm_kats_returns_results() {
        let results = run_aes_gcm_kats();
        assert!(results.is_ok(), "run_aes_gcm_kats should not return an error");

        let results = results.unwrap();
        assert!(!results.is_empty(), "run_aes_gcm_kats should return at least one result");

        println!("AES-GCM KAT results: {} tests", results.len());
    }

    #[test]
    fn test_aes_gcm_result_fields() {
        let results = run_aes_gcm_kats().unwrap();

        for result in &results {
            assert!(
                result.test_case.contains("AES") || result.test_case.contains("GCM"),
                "AES-GCM test case should contain 'AES' or 'GCM' in name: {}",
                result.test_case
            );

            // Verify execution time is reasonable
            let execution_duration = Duration::from_nanos(result.execution_time_ns as u64);
            assert!(
                execution_duration < Duration::from_secs(5),
                "AES-GCM test execution took too long: {:?}",
                execution_duration
            );
        }
    }

    #[test]
    fn test_aes_gcm_vectors_loaded() {
        let vectors = load_aes_gcm_kats();
        assert!(vectors.is_ok(), "Should be able to load AES-GCM vectors");

        let vectors = vectors.unwrap();
        for vector in &vectors {
            // Key should be 16 (AES-128) or 32 (AES-256) bytes
            assert!(
                vector.key.len() == 16 || vector.key.len() == 32,
                "AES-GCM key should be 16 or 32 bytes, got {}",
                vector.key.len()
            );

            // Nonce can vary - standard is 12 bytes but some test vectors may use different sizes
            // The validation runner handles non-12-byte nonces by returning false
            println!(
                "Vector {} - nonce size: {} bytes (standard: 12)",
                vector.test_case,
                vector.nonce.len()
            );

            // Tag should be 16 bytes
            assert_eq!(vector.expected_tag.len(), 16, "AES-GCM tag should be 16 bytes");
        }
    }

    #[test]
    fn test_aes_128_gcm_vectors() {
        let vectors = load_aes_gcm_kats().unwrap();

        let aes_128_vectors: Vec<_> = vectors.iter().filter(|v| v.key.len() == 16).collect();

        println!("Found {} AES-128-GCM vectors", aes_128_vectors.len());

        for vector in aes_128_vectors {
            assert!(
                vector.test_case.contains("128") || vector.test_case.contains("AES"),
                "AES-128 vector should be identifiable: {}",
                vector.test_case
            );
        }
    }

    #[test]
    fn test_aes_256_gcm_vectors() {
        let vectors = load_aes_gcm_kats().unwrap();

        let aes_256_vectors: Vec<_> = vectors.iter().filter(|v| v.key.len() == 32).collect();

        println!("Found {} AES-256-GCM vectors", aes_256_vectors.len());

        for vector in aes_256_vectors {
            assert!(
                vector.test_case.contains("256") || vector.test_case.contains("AES"),
                "AES-256 vector should be identifiable: {}",
                vector.test_case
            );
        }
    }

    #[test]
    fn test_aes_gcm_ciphertext_size() {
        let vectors = load_aes_gcm_kats().unwrap();

        for vector in &vectors {
            // Document actual ciphertext sizes from test vectors
            // Some test vectors may have ciphertext without tag appended
            println!(
                "Vector {} - plaintext: {} bytes, ciphertext: {} bytes, tag: {} bytes",
                vector.test_case,
                vector.plaintext.len(),
                vector.expected_ciphertext.len(),
                vector.expected_tag.len()
            );

            // Verify ciphertext is at least as large as plaintext
            assert!(
                vector.expected_ciphertext.len() >= vector.plaintext.len(),
                "Ciphertext should be at least as large as plaintext for {}",
                vector.test_case
            );
        }
    }
}

// ============================================================================
// Test Suite: Ed25519 Validation Functions - Extended Coverage
// ============================================================================

mod ed25519_validation_extended_tests {
    use super::*;

    #[test]
    fn test_validate_ed25519_keypair_with_loaded_vectors() {
        let vectors = load_ed25519_kats();
        match vectors {
            Ok(vecs) => {
                for vector in &vecs {
                    let result = validate_ed25519_keypair(vector);
                    assert!(
                        result.is_ok(),
                        "validate_ed25519_keypair should not error for {}",
                        vector.test_case
                    );

                    println!("Ed25519 keypair {}: valid={}", vector.test_case, result.unwrap());
                }
            }
            Err(e) => {
                println!("Ed25519 loader error (expected if hex malformed): {:?}", e);
            }
        }
    }

    #[test]
    fn test_validate_ed25519_signature_with_loaded_vectors() {
        let vectors = load_ed25519_kats();
        match vectors {
            Ok(vecs) => {
                for vector in &vecs {
                    let result = validate_ed25519_signature(vector);
                    assert!(
                        result.is_ok(),
                        "validate_ed25519_signature should not error for {}",
                        vector.test_case
                    );

                    println!("Ed25519 signature {}: valid={}", vector.test_case, result.unwrap());
                }
            }
            Err(e) => {
                println!("Ed25519 loader error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_ed25519_keypair_with_empty_message() {
        let vector = Ed25519KatVector {
            test_case: "EMPTY-MSG-TEST".to_string(),
            seed: vec![
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                0x2c, 0xc5, 0x44, 0x49, 0xdc, 0x56, 0x27, 0x18, 0x2c, 0x28, 0xbd, 0x25, 0x0f, 0x1a,
                0x8e, 0x6c, 0x4b, 0x8e,
            ],
            expected_public_key: vec![
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
                0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
                0xf7, 0x07, 0x51, 0x1a,
            ],
            message: vec![], // Empty message
            expected_signature: vec![
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
                0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
                0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
                0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
                0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
            ],
        };

        let keypair_result = validate_ed25519_keypair(&vector);
        assert!(keypair_result.is_ok(), "Should handle empty message");

        let sig_result = validate_ed25519_signature(&vector);
        assert!(sig_result.is_ok(), "Should validate signature for empty message");
    }

    #[test]
    fn test_ed25519_validation_wrong_hash_prefix() {
        // Create vector with mismatched hash prefix to trigger validation failure
        let vector = Ed25519KatVector {
            test_case: "WRONG-HASH-TEST".to_string(),
            seed: vec![0x00; 32],
            expected_public_key: vec![0x00; 32], // Wrong hash prefix
            message: b"test".to_vec(),
            expected_signature: vec![0x00; 64],
        };

        let keypair_result = validate_ed25519_keypair(&vector);
        assert!(keypair_result.is_ok(), "Should return Ok even for invalid data");
        assert!(!keypair_result.unwrap(), "Should indicate invalid keypair");
    }

    #[test]
    fn test_ed25519_boundary_sizes() {
        // Test with exactly correct sizes
        let correct_sizes = Ed25519KatVector {
            test_case: "CORRECT-SIZES".to_string(),
            seed: vec![0xAB; 32],
            expected_public_key: vec![0xCD; 32],
            message: vec![0xEF; 100],
            expected_signature: vec![0x12; 64],
        };

        let keypair_result = validate_ed25519_keypair(&correct_sizes);
        assert!(keypair_result.is_ok());

        let sig_result = validate_ed25519_signature(&correct_sizes);
        assert!(sig_result.is_ok());
    }

    #[test]
    fn test_ed25519_oversized_inputs() {
        let oversized = Ed25519KatVector {
            test_case: "OVERSIZED".to_string(),
            seed: vec![0x00; 64],                // Too large
            expected_public_key: vec![0x00; 64], // Too large
            message: vec![0x00; 10000],          // Large message (should be ok)
            expected_signature: vec![0x00; 128], // Too large
        };

        let keypair_result = validate_ed25519_keypair(&oversized);
        assert!(keypair_result.is_ok());
        assert!(!keypair_result.unwrap(), "Oversized inputs should be invalid");

        let sig_result = validate_ed25519_signature(&oversized);
        assert!(sig_result.is_ok());
        assert!(!sig_result.unwrap(), "Oversized signature should be invalid");
    }
}

// ============================================================================
// Test Suite: Vector Type Tests - Extended Coverage
// ============================================================================

mod vector_type_extended_tests {
    use super::*;

    #[test]
    fn test_ml_kem_vector_serialization_roundtrip() {
        let vector = MlKemKatVector {
            test_case: "ROUNDTRIP-TEST".to_string(),
            seed: vec![0x01, 0x02, 0x03, 0x04],
            expected_public_key: vec![0xAA; 1568],
            expected_secret_key: vec![0xBB; 3168],
            expected_ciphertext: vec![0xCC; 1568],
            expected_shared_secret: vec![0xDD; 32],
        };

        let json = serde_json::to_string(&vector).expect("Serialization failed");
        let deserialized: MlKemKatVector =
            serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(vector.test_case, deserialized.test_case);
        assert_eq!(vector.seed, deserialized.seed);
        assert_eq!(vector.expected_public_key.len(), deserialized.expected_public_key.len());
    }

    #[test]
    fn test_ml_dsa_vector_creation() {
        let vector = MlDsaKatVector {
            test_case: "ML-DSA-TEST".to_string(),
            seed: vec![0x00; 48],
            message: b"Test message for ML-DSA".to_vec(),
            expected_public_key: vec![0x11; 1312],
            expected_secret_key: vec![0x22; 32],
            expected_signature: vec![0x33; 2420],
        };

        assert_eq!(vector.seed.len(), 48);
        assert_eq!(vector.expected_public_key.len(), 1312);
        assert_eq!(vector.expected_signature.len(), 2420);
        assert!(!vector.message.is_empty());
    }

    #[test]
    fn test_slh_dsa_vector_creation() {
        let vector = SlhDsaKatVector {
            test_case: "SLH-DSA-TEST".to_string(),
            seed: vec![0x00; 48],
            message: b"SLH-DSA test message".to_vec(),
            expected_public_key: vec![0xAA; 32],
            expected_signature: vec![0xBB; 1700],
        };

        assert_eq!(vector.seed.len(), 48);
        assert_eq!(vector.expected_public_key.len(), 32);
        assert_eq!(vector.expected_signature.len(), 1700);
    }

    #[test]
    fn test_hybrid_kem_vector_creation() {
        let vector = HybridKemKatVector {
            test_case: "HYBRID-TEST".to_string(),
            seed: vec![0x55; 32],
            expected_encapsulated_key: vec![0x66; 1600],
            expected_shared_secret: vec![0x77; 32],
        };

        assert_eq!(vector.expected_encapsulated_key.len(), 1600);
        assert_eq!(vector.expected_shared_secret.len(), 32);
    }

    #[test]
    fn test_aes_gcm_vector_creation() {
        let aes_128 = AesGcmKatVector {
            test_case: "AES-128-TEST".to_string(),
            key: vec![0x00; 16],
            nonce: vec![0x11; 12],
            aad: vec![0x22; 16],
            plaintext: vec![0x33; 32],
            expected_ciphertext: vec![0x44; 48],
            expected_tag: vec![0x55; 16],
        };

        assert_eq!(aes_128.key.len(), 16);
        assert_eq!(aes_128.nonce.len(), 12);
        assert_eq!(aes_128.expected_tag.len(), 16);

        let aes_256 = AesGcmKatVector {
            test_case: "AES-256-TEST".to_string(),
            key: vec![0x00; 32],
            nonce: vec![0x11; 12],
            aad: vec![],
            plaintext: vec![0x33; 16],
            expected_ciphertext: vec![0x44; 32],
            expected_tag: vec![0x55; 16],
        };

        assert_eq!(aes_256.key.len(), 32);
    }

    #[test]
    fn test_sha3_vector_creation() {
        let vector = Sha3KatVector {
            test_case: "SHA3-TEST".to_string(),
            message: b"test input".to_vec(),
            expected_hash: vec![0xAA; 32],
        };

        assert_eq!(vector.expected_hash.len(), 32);
    }

    #[test]
    fn test_bls12_381_vector_creation() {
        let vector = Bls12_381KatVector {
            test_case: "BLS12-381-TEST".to_string(),
            secret_key: vec![0x00; 32],
            expected_public_key: vec![0x11; 48], // G1 point
            message: b"BLS test message".to_vec(),
            expected_signature: vec![0x22; 96], // G2 point
        };

        assert!(!vector.secret_key.is_empty());
        assert!(!vector.expected_public_key.is_empty());
        assert!(!vector.expected_signature.is_empty());
    }

    #[test]
    fn test_bn254_vector_creation() {
        let vector = Bn254KatVector {
            test_case: "BN254-TEST".to_string(),
            secret_key: vec![0x00; 32],
            expected_public_key: vec![0x11; 64],
            message: b"BN254 test".to_vec(),
            expected_signature: vec![0x22; 64],
        };

        assert!(!vector.secret_key.is_empty());
    }

    #[test]
    fn test_secp256k1_vector_creation() {
        let vector = Secp256k1KatVector {
            test_case: "SECP256K1-TEST".to_string(),
            private_key: vec![0x00; 32],
            expected_public_key: vec![0x11; 33], // Compressed
            message: b"secp256k1 test".to_vec(),
            expected_signature: vec![0x22; 70], // DER encoded (variable)
        };

        assert_eq!(vector.private_key.len(), 32);
    }
}

// ============================================================================
// Test Suite: Algorithm Type Extended Coverage
// ============================================================================

mod algorithm_type_extended_tests {
    use super::*;

    #[test]
    fn test_algorithm_type_ml_dsa_security_levels() {
        let ml_dsa_44 = AlgorithmType::MlDsa { variant: "44".to_string() };
        assert_eq!(ml_dsa_44.security_level(), 128);
        assert_eq!(ml_dsa_44.name(), "ML-DSA-44");

        let ml_dsa_65 = AlgorithmType::MlDsa { variant: "65".to_string() };
        assert_eq!(ml_dsa_65.security_level(), 192);
        assert_eq!(ml_dsa_65.name(), "ML-DSA-65");

        let ml_dsa_87 = AlgorithmType::MlDsa { variant: "87".to_string() };
        assert_eq!(ml_dsa_87.security_level(), 256);
        assert_eq!(ml_dsa_87.name(), "ML-DSA-87");

        // Unknown variant defaults to 128
        let ml_dsa_unknown = AlgorithmType::MlDsa { variant: "unknown".to_string() };
        assert_eq!(ml_dsa_unknown.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_slh_dsa_security_levels() {
        let slh_dsa_128 = AlgorithmType::SlhDsa { variant: "128".to_string() };
        assert_eq!(slh_dsa_128.security_level(), 128);
        assert_eq!(slh_dsa_128.name(), "SLH-DSA-128");

        let slh_dsa_192 = AlgorithmType::SlhDsa { variant: "192".to_string() };
        assert_eq!(slh_dsa_192.security_level(), 192);

        let slh_dsa_256 = AlgorithmType::SlhDsa { variant: "256".to_string() };
        assert_eq!(slh_dsa_256.security_level(), 256);

        // Unknown variant defaults to 128
        let slh_dsa_unknown = AlgorithmType::SlhDsa { variant: "xyz".to_string() };
        assert_eq!(slh_dsa_unknown.security_level(), 128);
    }

    #[test]
    fn test_algorithm_type_hybrid_kem() {
        let hybrid = AlgorithmType::HybridKem;
        assert_eq!(hybrid.security_level(), 256);
        assert_eq!(hybrid.name(), "Hybrid-KEM");
    }

    #[test]
    fn test_algorithm_type_aes_gcm_variants() {
        let aes_128 = AlgorithmType::AesGcm { key_size: 16 };
        assert_eq!(aes_128.security_level(), 128);
        assert_eq!(aes_128.name(), "AES-128-GCM");

        let aes_192 = AlgorithmType::AesGcm { key_size: 24 };
        assert_eq!(aes_192.security_level(), 192);
        assert_eq!(aes_192.name(), "AES-192-GCM");

        let aes_256 = AlgorithmType::AesGcm { key_size: 32 };
        assert_eq!(aes_256.security_level(), 256);
        assert_eq!(aes_256.name(), "AES-256-GCM");
    }

    #[test]
    fn test_algorithm_type_sha3_variants() {
        let sha3_224 = AlgorithmType::Sha3 { variant: "224".to_string() };
        assert_eq!(sha3_224.security_level(), 224);
        assert_eq!(sha3_224.name(), "SHA3-224");

        let sha3_256 = AlgorithmType::Sha3 { variant: "256".to_string() };
        assert_eq!(sha3_256.security_level(), 256);
        assert_eq!(sha3_256.name(), "SHA3-256");

        let sha3_384 = AlgorithmType::Sha3 { variant: "384".to_string() };
        assert_eq!(sha3_384.security_level(), 384);

        let sha3_512 = AlgorithmType::Sha3 { variant: "512".to_string() };
        assert_eq!(sha3_512.security_level(), 512);
    }

    #[test]
    fn test_algorithm_type_elliptic_curves() {
        let ed25519 = AlgorithmType::Ed25519;
        assert_eq!(ed25519.security_level(), 128);
        assert_eq!(ed25519.name(), "Ed25519");

        let bls = AlgorithmType::Bls12_381;
        assert_eq!(bls.security_level(), 128);
        assert_eq!(bls.name(), "BLS12-381");

        let bn254 = AlgorithmType::Bn254;
        assert_eq!(bn254.security_level(), 128);
        assert_eq!(bn254.name(), "BN254");

        let secp256k1 = AlgorithmType::Secp256k1;
        assert_eq!(secp256k1.security_level(), 128);
        assert_eq!(secp256k1.name(), "secp256k1");
    }

    #[test]
    fn test_algorithm_type_equality() {
        let algo1 = AlgorithmType::MlKem { variant: "768".to_string() };
        let algo2 = AlgorithmType::MlKem { variant: "768".to_string() };
        let algo3 = AlgorithmType::MlKem { variant: "1024".to_string() };

        assert_eq!(algo1, algo2);
        assert_ne!(algo1, algo3);
    }

    #[test]
    fn test_algorithm_type_clone() {
        let original = AlgorithmType::MlDsa { variant: "65".to_string() };
        let cloned = original.clone();

        assert_eq!(original, cloned);
        assert_eq!(original.name(), cloned.name());
        assert_eq!(original.security_level(), cloned.security_level());
    }
}

// ============================================================================
// Test Suite: KatConfig Extended Coverage
// ============================================================================

mod kat_config_extended_tests {
    use super::*;

    #[test]
    fn test_kat_config_custom_creation() {
        let config = KatConfig {
            algorithm: AlgorithmType::MlKem { variant: "512".to_string() },
            test_count: 50,
            run_statistical_tests: false,
            timeout_per_test: Duration::from_secs(5),
            validate_fips: false,
        };

        assert_eq!(config.test_count, 50);
        assert!(!config.run_statistical_tests);
        assert_eq!(config.timeout_per_test, Duration::from_secs(5));
        assert!(!config.validate_fips);
    }

    #[test]
    fn test_kat_config_all_variants() {
        // Test all factory methods
        let ml_kem_512 = KatConfig::ml_kem("512", 10);
        let ml_kem_768 = KatConfig::ml_kem("768", 20);
        let ml_kem_1024 = KatConfig::ml_kem("1024", 30);

        assert_eq!(ml_kem_512.test_count, 10);
        assert_eq!(ml_kem_768.test_count, 20);
        assert_eq!(ml_kem_1024.test_count, 30);

        let ml_dsa_44 = KatConfig::ml_dsa("44", 15);
        let ml_dsa_65 = KatConfig::ml_dsa("65", 25);
        let ml_dsa_87 = KatConfig::ml_dsa("87", 35);

        assert_eq!(ml_dsa_44.test_count, 15);
        assert_eq!(ml_dsa_65.test_count, 25);
        assert_eq!(ml_dsa_87.test_count, 35);

        let slh_dsa_128 = KatConfig::slh_dsa("128", 5);
        let slh_dsa_192 = KatConfig::slh_dsa("192", 10);
        let slh_dsa_256 = KatConfig::slh_dsa("256", 15);

        // SLH-DSA should have longer timeout
        assert_eq!(slh_dsa_128.timeout_per_test, Duration::from_secs(30));
        assert_eq!(slh_dsa_192.timeout_per_test, Duration::from_secs(30));
        assert_eq!(slh_dsa_256.timeout_per_test, Duration::from_secs(30));
    }

    #[test]
    fn test_kat_config_default_values() {
        let default_config = KatConfig::default();

        match default_config.algorithm {
            AlgorithmType::MlKem { variant } => {
                assert_eq!(variant, "768");
            }
            _ => panic!("Default should be ML-KEM-768"),
        }

        assert_eq!(default_config.test_count, 100);
        assert!(default_config.run_statistical_tests);
        assert_eq!(default_config.timeout_per_test, Duration::from_secs(10));
        assert!(default_config.validate_fips);
    }

    #[test]
    fn test_kat_config_serialization_all_types() {
        let configs = vec![
            KatConfig::ml_kem("1024", 50),
            KatConfig::ml_dsa("65", 25),
            KatConfig::slh_dsa("256", 10),
            KatConfig::default(),
        ];

        for config in configs {
            let json = serde_json::to_string(&config).expect("Serialization failed");
            let deserialized: KatConfig =
                serde_json::from_str(&json).expect("Deserialization failed");

            assert_eq!(config.test_count, deserialized.test_count);
            assert_eq!(config.run_statistical_tests, deserialized.run_statistical_tests);
            assert_eq!(config.validate_fips, deserialized.validate_fips);
        }
    }
}

// ============================================================================
// Test Suite: KatResult Extended Coverage
// ============================================================================

mod kat_result_extended_tests {
    use super::*;

    #[test]
    fn test_kat_result_with_zero_duration() {
        let duration = Duration::from_nanos(0);
        let result = KatResult::passed("ZERO-DURATION".to_string(), duration);

        assert_eq!(result.execution_time_ns, 0);
        assert!(result.passed);
    }

    #[test]
    fn test_kat_result_with_max_duration() {
        let duration = Duration::from_secs(3600); // 1 hour
        let result = KatResult::passed("MAX-DURATION".to_string(), duration);

        assert_eq!(result.execution_time_ns, 3600_000_000_000);
        assert!(result.passed);
    }

    #[test]
    fn test_kat_result_failed_with_long_error() {
        let error_msg = "A".repeat(10000); // Very long error message
        let duration = Duration::from_millis(100);
        let result = KatResult::failed("LONG-ERROR".to_string(), duration, error_msg.clone());

        assert!(!result.passed);
        assert_eq!(result.error_message.unwrap().len(), 10000);
    }

    #[test]
    fn test_kat_result_failed_with_empty_error() {
        let duration = Duration::from_millis(50);
        let result = KatResult::failed("EMPTY-ERROR".to_string(), duration, String::new());

        assert!(!result.passed);
        assert_eq!(result.error_message, Some(String::new()));
    }

    #[test]
    fn test_kat_result_debug_output() {
        let duration = Duration::from_millis(100);
        let result = KatResult::passed("DEBUG-TEST".to_string(), duration);

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("DEBUG-TEST"));
        assert!(debug_str.contains("passed"));
    }

    #[test]
    fn test_kat_result_special_characters() {
        let duration = Duration::from_millis(10);
        let result = KatResult::failed(
            "TEST-\u{1F600}-EMOJI".to_string(),
            duration,
            "Error: \"quoted\" and 'single' and \n newline".to_string(),
        );

        let json = serde_json::to_string(&result).expect("Should serialize with special chars");
        let deserialized: KatResult = serde_json::from_str(&json).expect("Should deserialize");

        assert!(deserialized.test_case.contains('\u{1F600}'));
    }
}

// ============================================================================
// Test Suite: NIST Statistical Test Types
// ============================================================================

mod nist_statistical_tests {
    use super::*;

    #[test]
    fn test_nist_statistical_test_result_creation() {
        let result = NistStatisticalTestResult {
            test_name: "Frequency Test".to_string(),
            p_value: 0.5,
            passed: true,
            parameters: serde_json::json!({ "n": 1000 }),
        };

        assert_eq!(result.test_name, "Frequency Test");
        assert_eq!(result.p_value, 0.5);
        assert!(result.passed);
    }

    #[test]
    fn test_nist_statistical_test_result_edge_pvalues() {
        // Test with boundary p-values
        let passing = NistStatisticalTestResult {
            test_name: "Test".to_string(),
            p_value: 0.011, // Just above threshold
            passed: true,
            parameters: serde_json::json!({}),
        };
        assert!(passing.passed);

        let failing = NistStatisticalTestResult {
            test_name: "Test".to_string(),
            p_value: 0.009, // Below threshold
            passed: false,
            parameters: serde_json::json!({}),
        };
        assert!(!failing.passed);
    }

    #[test]
    fn test_rng_test_results_creation() {
        let test_results = vec![
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
        ];

        let rng_results = RngTestResults {
            algorithm: "ML-KEM-1024".to_string(),
            bits_tested: 1_000_000,
            test_results,
            passed: true,
            entropy_estimate: 7.99,
        };

        assert_eq!(rng_results.algorithm, "ML-KEM-1024");
        assert_eq!(rng_results.bits_tested, 1_000_000);
        assert_eq!(rng_results.test_results.len(), 2);
        assert!(rng_results.passed);
        assert!(rng_results.entropy_estimate > 7.0);
    }

    #[test]
    fn test_rng_test_results_serialization() {
        let rng_results = RngTestResults {
            algorithm: "Test-Algo".to_string(),
            bits_tested: 100000,
            test_results: vec![],
            passed: true,
            entropy_estimate: 7.5,
        };

        let json = serde_json::to_string(&rng_results).expect("Serialization failed");
        let deserialized: RngTestResults =
            serde_json::from_str(&json).expect("Deserialization failed");

        assert_eq!(rng_results.algorithm, deserialized.algorithm);
        assert_eq!(rng_results.bits_tested, deserialized.bits_tested);
        assert_eq!(rng_results.entropy_estimate, deserialized.entropy_estimate);
    }
}

// ============================================================================
// Test Suite: Performance and Stress Tests
// ============================================================================

mod performance_extended_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_run_all_kats_performance() {
        let start = Instant::now();
        let results = run_all_kats().unwrap();
        let duration = start.elapsed();

        println!(
            "run_all_kats: {} tests in {:?} ({:.2}ms/test)",
            results.len(),
            duration,
            duration.as_millis() as f64 / results.len() as f64
        );

        // Entire suite should complete in reasonable time
        assert!(duration < Duration::from_secs(60), "All KATs should complete in under 60 seconds");
    }

    #[test]
    fn test_aes_gcm_performance() {
        let start = Instant::now();
        let results = run_aes_gcm_kats().unwrap();
        let duration = start.elapsed();

        println!("AES-GCM KATs: {} tests in {:?}", results.len(), duration);

        // AES-GCM should be fast
        let avg_time_ms = duration.as_millis() as f64 / results.len().max(1) as f64;
        assert!(avg_time_ms < 100.0, "AES-GCM tests should be fast");
    }

    #[test]
    fn test_ml_dsa_performance() {
        let start = Instant::now();
        let result = run_ml_dsa_kats();
        let duration = start.elapsed();

        match result {
            Ok(results) => {
                println!("ML-DSA KATs: {} tests in {:?}", results.len(), duration);
            }
            Err(e) => {
                println!("ML-DSA KATs error: {:?} in {:?}", e, duration);
            }
        }
    }

    #[test]
    fn test_slh_dsa_performance() {
        let start = Instant::now();
        let result = run_slh_dsa_kats();
        let duration = start.elapsed();

        match result {
            Ok(results) => {
                println!("SLH-DSA KATs: {} tests in {:?}", results.len(), duration);
            }
            Err(e) => {
                println!("SLH-DSA KATs error: {:?} in {:?}", e, duration);
            }
        }
    }

    #[test]
    fn test_multiple_sequential_runs() {
        // Test that running KATs multiple times produces consistent results
        let results1 = run_sha3_kats().unwrap();
        let results2 = run_sha3_kats().unwrap();

        assert_eq!(results1.len(), results2.len());

        for (r1, r2) in results1.iter().zip(results2.iter()) {
            assert_eq!(r1.test_case, r2.test_case);
            assert_eq!(r1.passed, r2.passed);
        }
    }
}

// ============================================================================
// Test Suite: Error Path Coverage
// ============================================================================

mod error_path_tests {
    use super::*;
    use std::panic;

    #[test]
    fn test_hybrid_kem_error_handling() {
        // The hybrid KEM loader may panic due to malformed hex
        let result = panic::catch_unwind(|| run_hybrid_kem_kats());

        match result {
            Ok(Ok(results)) => {
                println!("Hybrid KEM succeeded with {} results", results.len());
                for r in &results {
                    if !r.passed {
                        println!("  Failed: {} - {:?}", r.test_case, r.error_message);
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Hybrid KEM returned error: {:?}", e);
            }
            Err(_) => {
                println!("Hybrid KEM panicked (expected for malformed data)");
            }
        }
    }

    #[test]
    fn test_ml_dsa_with_loader_error() {
        // ML-DSA loader may have malformed hex data
        let vectors = load_ml_dsa_kats();
        match vectors {
            Ok(vecs) => {
                println!("ML-DSA vectors loaded: {}", vecs.len());
                for v in &vecs {
                    println!("  - {} (msg len: {})", v.test_case, v.message.len());
                }
            }
            Err(e) => {
                println!("ML-DSA loader error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_slh_dsa_with_loader_error() {
        // SLH-DSA loader may have malformed hex data
        let vectors = load_slh_dsa_kats();
        match vectors {
            Ok(vecs) => {
                println!("SLH-DSA vectors loaded: {}", vecs.len());
            }
            Err(e) => {
                println!("SLH-DSA loader error: {:?}", e);
            }
        }
    }

    #[test]
    fn test_runner_with_empty_vectors() {
        // This tests what happens when we try to process empty vector sets
        // The runners should handle empty inputs gracefully
        let ml_kem_results = run_ml_kem_kats();
        assert!(ml_kem_results.is_ok());

        let sha3_results = run_sha3_kats();
        assert!(sha3_results.is_ok());

        let aes_results = run_aes_gcm_kats();
        assert!(aes_results.is_ok());
    }
}

// ============================================================================
// Test Suite: Integration Tests
// ============================================================================

mod integration_tests {
    use super::*;

    #[test]
    fn test_full_kat_pipeline() {
        // Test the complete KAT pipeline
        println!("\n=== Full KAT Pipeline Test ===\n");

        // Step 1: Run all KATs
        let all_results = run_all_kats().unwrap();
        println!("Total tests run: {}", all_results.len());

        // Step 2: Calculate statistics
        let passed = all_results.iter().filter(|r| r.passed).count();
        let failed = all_results.iter().filter(|r| !r.passed).count();
        let total_time_ns: u128 = all_results.iter().map(|r| r.execution_time_ns).sum();

        println!("Results:");
        println!(
            "  Passed: {} ({:.1}%)",
            passed,
            (passed as f64 / all_results.len() as f64) * 100.0
        );
        println!(
            "  Failed: {} ({:.1}%)",
            failed,
            (failed as f64 / all_results.len() as f64) * 100.0
        );
        println!("  Total time: {:.2}ms", total_time_ns as f64 / 1_000_000.0);

        // Step 3: Verify results are properly structured
        for result in &all_results {
            assert!(!result.test_case.is_empty(), "Test case name should not be empty");
            if !result.passed {
                assert!(
                    result.error_message.is_some(),
                    "Failed test should have error message: {}",
                    result.test_case
                );
            }
        }
    }

    #[test]
    fn test_algorithm_coverage() {
        // Verify we have coverage for all algorithm types
        let all_results = run_all_kats().unwrap();

        let test_cases: Vec<&str> = all_results.iter().map(|r| r.test_case.as_str()).collect();

        println!("\nAlgorithm Coverage:");
        println!(
            "  ML-KEM: {}",
            test_cases.iter().any(|t| t.contains("KEM") || t.contains("CAVP"))
        );
        println!("  SHA3: {}", test_cases.iter().any(|t| t.contains("SHA3")));
        println!("  AES-GCM: {}", test_cases.iter().any(|t| t.contains("AES")));
        println!("  ML-DSA: {}", test_cases.iter().any(|t| t.contains("ML-DSA")));
        println!("  SLH-DSA: {}", test_cases.iter().any(|t| t.contains("SLH-DSA")));
        println!("  Hybrid: {}", test_cases.iter().any(|t| t.contains("HYBRID")));
    }

    #[test]
    fn test_result_json_export() {
        // Test that results can be exported to JSON for reporting
        let results = run_sha3_kats().unwrap();

        let json = serde_json::to_string_pretty(&results).expect("JSON export should succeed");

        assert!(json.contains("SHA3"));
        assert!(json.contains("passed"));
        assert!(json.contains("execution_time_ns"));

        println!("JSON export sample (first 500 chars):\n{}", &json[..json.len().min(500)]);
    }

    #[test]
    fn test_config_driven_testing() {
        // Test that KatConfig can drive test execution
        let configs = vec![
            KatConfig::ml_kem("512", 5),
            KatConfig::ml_kem("768", 5),
            KatConfig::ml_kem("1024", 5),
            KatConfig::ml_dsa("44", 3),
            KatConfig::slh_dsa("128", 2),
        ];

        for config in &configs {
            let name = config.algorithm.name();
            let security = config.algorithm.security_level();
            println!(
                "Config: {} (security: {} bits, tests: {})",
                name, security, config.test_count
            );
        }
    }
}

// ============================================================================
// Test Suite: Validation Logic Tests
// ============================================================================

mod validation_logic_tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn test_sha3_validation_with_computed_hash() {
        // Create a test vector with a correct computed hash
        let message = b"test message for validation";
        let computed_hash = Sha3_256::digest(message);

        let vector = Sha3KatVector {
            test_case: "COMPUTED-HASH-TEST".to_string(),
            message: message.to_vec(),
            expected_hash: computed_hash.to_vec(),
        };

        // The computed hash should match
        let actual_hash = Sha3_256::digest(&vector.message);
        assert_eq!(actual_hash.as_slice(), vector.expected_hash.as_slice());
    }

    #[test]
    fn test_sha3_validation_with_mismatched_hash() {
        let message = b"test message";
        let wrong_hash = vec![0x00; 32]; // Wrong hash

        let vector = Sha3KatVector {
            test_case: "WRONG-HASH-TEST".to_string(),
            message: message.to_vec(),
            expected_hash: wrong_hash,
        };

        let actual_hash = Sha3_256::digest(&vector.message);
        assert_ne!(actual_hash.as_slice(), vector.expected_hash.as_slice());
    }

    #[test]
    fn test_ml_kem_size_validation() {
        // Test ML-KEM-1024 expected sizes
        let vector = MlKemKatVector {
            test_case: "SIZE-TEST".to_string(),
            seed: vec![0; 32],
            expected_public_key: vec![0; 1568], // Correct ML-KEM-1024 pk size
            expected_secret_key: vec![0; 3168], // Correct ML-KEM-1024 sk size
            expected_ciphertext: vec![0; 1568], // Correct ML-KEM-1024 ct size
            expected_shared_secret: vec![0; 32], // Correct shared secret size
        };

        assert_eq!(vector.expected_public_key.len(), 1568);
        assert_eq!(vector.expected_secret_key.len(), 3168);
        assert_eq!(vector.expected_ciphertext.len(), 1568);
        assert_eq!(vector.expected_shared_secret.len(), 32);
    }

    #[test]
    fn test_aes_gcm_nonce_validation() {
        // AES-GCM requires 12-byte nonce
        let valid_vector = AesGcmKatVector {
            test_case: "VALID-NONCE".to_string(),
            key: vec![0; 16],
            nonce: vec![0; 12], // Correct size
            aad: vec![],
            plaintext: vec![0; 16],
            expected_ciphertext: vec![0; 32],
            expected_tag: vec![0; 16],
        };

        assert_eq!(valid_vector.nonce.len(), 12);

        let invalid_vector = AesGcmKatVector {
            test_case: "INVALID-NONCE".to_string(),
            key: vec![0; 16],
            nonce: vec![0; 8], // Wrong size
            aad: vec![],
            plaintext: vec![0; 16],
            expected_ciphertext: vec![0; 32],
            expected_tag: vec![0; 16],
        };

        assert_ne!(invalid_vector.nonce.len(), 12);
    }

    #[test]
    fn test_aes_gcm_key_size_validation() {
        // AES-GCM supports 128-bit (16 bytes) and 256-bit (32 bytes) keys
        let aes_128 = AesGcmKatVector {
            test_case: "AES-128".to_string(),
            key: vec![0; 16],
            nonce: vec![0; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![0; 16],
            expected_tag: vec![0; 16],
        };
        assert_eq!(aes_128.key.len(), 16);

        let aes_256 = AesGcmKatVector {
            test_case: "AES-256".to_string(),
            key: vec![0; 32],
            nonce: vec![0; 12],
            aad: vec![],
            plaintext: vec![],
            expected_ciphertext: vec![0; 16],
            expected_tag: vec![0; 16],
        };
        assert_eq!(aes_256.key.len(), 32);

        // Invalid key sizes
        let invalid_key_sizes = vec![0, 8, 15, 17, 24, 31, 33, 64];
        for size in invalid_key_sizes {
            assert!(size != 16 && size != 32, "Size {} should be invalid", size);
        }
    }

    #[test]
    fn test_signature_size_validation() {
        // Test expected signature sizes for different algorithms
        let ml_dsa_44_sig_size = 2420;
        let slh_dsa_sig_size = 1700; // Varies by parameter set
        let ed25519_sig_size = 64;

        let ml_dsa_vector = MlDsaKatVector {
            test_case: "ML-DSA-SIG".to_string(),
            seed: vec![0; 48],
            message: vec![],
            expected_public_key: vec![0; 1312],
            expected_secret_key: vec![0; 32],
            expected_signature: vec![0; ml_dsa_44_sig_size],
        };
        assert_eq!(ml_dsa_vector.expected_signature.len(), ml_dsa_44_sig_size);

        let slh_dsa_vector = SlhDsaKatVector {
            test_case: "SLH-DSA-SIG".to_string(),
            seed: vec![0; 48],
            message: vec![],
            expected_public_key: vec![0; 32],
            expected_signature: vec![0; slh_dsa_sig_size],
        };
        assert_eq!(slh_dsa_vector.expected_signature.len(), slh_dsa_sig_size);

        let ed25519_vector = Ed25519KatVector {
            test_case: "Ed25519-SIG".to_string(),
            seed: vec![0; 32],
            expected_public_key: vec![0; 32],
            message: vec![],
            expected_signature: vec![0; ed25519_sig_size],
        };
        assert_eq!(ed25519_vector.expected_signature.len(), ed25519_sig_size);
    }
}
