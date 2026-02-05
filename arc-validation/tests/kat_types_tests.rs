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

use arc_validation::kat_tests::types::{
    AesGcmKatVector, AlgorithmType, Bls12_381KatVector, Bn254KatVector, Ed25519KatVector,
    HybridKemKatVector, KatConfig, KatResult, MlDsaKatVector, MlKemKatVector,
    NistStatisticalTestResult, RngTestResults, Secp256k1KatVector, Sha3KatVector, SlhDsaKatVector,
};
use std::time::Duration;

// ============================================================================
// KatResult Tests
// ============================================================================

mod kat_result_tests {
    use super::*;

    #[test]
    fn test_kat_result_passed_constructor() {
        let result = KatResult::passed("test_case_1".to_string(), Duration::from_millis(100));

        assert_eq!(result.test_case, "test_case_1");
        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 100_000_000);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_kat_result_failed_constructor() {
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
    fn test_kat_result_passed_zero_duration() {
        let result = KatResult::passed("fast_test".to_string(), Duration::ZERO);

        assert!(result.passed);
        assert_eq!(result.execution_time_ns, 0);
    }

    #[test]
    fn test_kat_result_failed_empty_error() {
        let result = KatResult::failed("test".to_string(), Duration::from_nanos(1), String::new());

        assert!(!result.passed);
        assert_eq!(result.error_message.as_ref().unwrap(), "");
    }

    #[test]
    fn test_kat_result_clone() {
        let original = KatResult::passed("original".to_string(), Duration::from_secs(1));
        let cloned = original.clone();

        assert_eq!(original, cloned);
        assert_eq!(cloned.test_case, "original");
    }

    #[test]
    fn test_kat_result_equality() {
        let result1 = KatResult::passed("test".to_string(), Duration::from_millis(100));
        let result2 = KatResult::passed("test".to_string(), Duration::from_millis(100));
        let result3 = KatResult::passed("different".to_string(), Duration::from_millis(100));

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_kat_result_debug() {
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
    fn test_ml_kem_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "ML-KEM-768-001");
        assert_eq!(vector.seed, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(vector.expected_public_key.len(), 32);
        assert_eq!(vector.expected_secret_key.len(), 64);
        assert_eq!(vector.expected_ciphertext.len(), 128);
        assert_eq!(vector.expected_shared_secret.len(), 32);
    }

    #[test]
    fn test_ml_kem_kat_vector_clone() {
        let original = create_test_vector();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_ml_kem_kat_vector_empty_fields() {
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
    fn test_ml_dsa_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "ML-DSA-65-001");
        assert_eq!(vector.seed, vec![0x10, 0x20, 0x30]);
        assert_eq!(vector.message, b"Test message for signing");
        assert_eq!(vector.expected_public_key.len(), 48);
        assert_eq!(vector.expected_secret_key.len(), 96);
        assert_eq!(vector.expected_signature.len(), 2048);
    }

    #[test]
    fn test_ml_dsa_kat_vector_clone() {
        let original = create_test_vector();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_ml_dsa_kat_vector_equality() {
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
    fn test_slh_dsa_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "SLH-DSA-128s-001");
        assert_eq!(vector.seed.len(), 48);
        assert_eq!(vector.message, b"Hash-based signature test");
        assert_eq!(vector.expected_public_key.len(), 32);
        assert_eq!(vector.expected_signature.len(), 7856);
    }

    #[test]
    fn test_slh_dsa_kat_vector_clone() {
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
    fn test_hybrid_kem_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "Hybrid-X25519-ML-KEM-001");
        assert_eq!(vector.seed.len(), 64);
        assert_eq!(vector.expected_encapsulated_key.len(), 128);
        assert_eq!(vector.expected_shared_secret.len(), 64);
    }

    #[test]
    fn test_hybrid_kem_kat_vector_clone() {
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
    fn test_aes_gcm_kat_vector_construction() {
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
    fn test_aes_gcm_kat_vector_clone() {
        let original = create_test_vector();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_aes_gcm_kat_vector_empty_aad() {
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
    fn test_sha3_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "SHA3-256-001");
        assert_eq!(vector.message, b"The quick brown fox");
        assert_eq!(vector.expected_hash.len(), 32);
    }

    #[test]
    fn test_sha3_kat_vector_clone() {
        let original = create_test_vector();
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_sha3_kat_vector_empty_message() {
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
    fn test_ed25519_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "Ed25519-001");
        assert_eq!(vector.seed.len(), 32);
        assert_eq!(vector.expected_public_key.len(), 32);
        assert_eq!(vector.message, b"Ed25519 test message");
        assert_eq!(vector.expected_signature.len(), 64);
    }

    #[test]
    fn test_ed25519_kat_vector_clone() {
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
    fn test_bls12_381_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "BLS12-381-001");
        assert_eq!(vector.secret_key.len(), 32);
        assert_eq!(vector.expected_public_key.len(), 48);
        assert_eq!(vector.message, b"BLS signature test");
        assert_eq!(vector.expected_signature.len(), 96);
    }

    #[test]
    fn test_bls12_381_kat_vector_clone() {
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
    fn test_bn254_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "BN254-001");
        assert_eq!(vector.secret_key.len(), 32);
        assert_eq!(vector.expected_public_key.len(), 64);
        assert_eq!(vector.message, b"BN254 test");
        assert_eq!(vector.expected_signature.len(), 64);
    }

    #[test]
    fn test_bn254_kat_vector_clone() {
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
    fn test_secp256k1_kat_vector_construction() {
        let vector = create_test_vector();

        assert_eq!(vector.test_case, "secp256k1-001");
        assert_eq!(vector.private_key.len(), 32);
        assert_eq!(vector.expected_public_key.len(), 33);
        assert_eq!(vector.message, b"secp256k1 test");
        assert_eq!(vector.expected_signature.len(), 71);
    }

    #[test]
    fn test_secp256k1_kat_vector_clone() {
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
    fn test_nist_statistical_test_result_construction() {
        let result = create_test_result();

        assert_eq!(result.test_name, "Frequency Test");
        assert!((result.p_value - 0.523).abs() < f64::EPSILON);
        assert!(result.passed);
        assert_eq!(result.parameters["n"], 1000000);
    }

    #[test]
    fn test_nist_statistical_test_result_clone() {
        let original = create_test_result();
        let cloned = original.clone();

        assert_eq!(original.test_name, cloned.test_name);
        assert_eq!(original.p_value, cloned.p_value);
        assert_eq!(original.passed, cloned.passed);
    }

    #[test]
    fn test_nist_statistical_test_result_failed() {
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
    fn test_rng_test_results_construction() {
        let results = create_test_results();

        assert_eq!(results.algorithm, "ML-KEM-768-RNG");
        assert_eq!(results.bits_tested, 1_000_000);
        assert_eq!(results.test_results.len(), 2);
        assert!(results.passed);
        assert!((results.entropy_estimate - 0.998).abs() < f64::EPSILON);
    }

    #[test]
    fn test_rng_test_results_clone() {
        let original = create_test_results();
        let cloned = original.clone();

        assert_eq!(original.algorithm, cloned.algorithm);
        assert_eq!(original.bits_tested, cloned.bits_tested);
        assert_eq!(original.test_results.len(), cloned.test_results.len());
    }

    #[test]
    fn test_rng_test_results_failed_overall() {
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
    fn test_ml_kem_name() {
        let algo = AlgorithmType::MlKem { variant: "512".to_string() };
        assert_eq!(algo.name(), "ML-KEM-512");

        let algo = AlgorithmType::MlKem { variant: "768".to_string() };
        assert_eq!(algo.name(), "ML-KEM-768");

        let algo = AlgorithmType::MlKem { variant: "1024".to_string() };
        assert_eq!(algo.name(), "ML-KEM-1024");
    }

    #[test]
    fn test_ml_dsa_name() {
        let algo = AlgorithmType::MlDsa { variant: "44".to_string() };
        assert_eq!(algo.name(), "ML-DSA-44");

        let algo = AlgorithmType::MlDsa { variant: "65".to_string() };
        assert_eq!(algo.name(), "ML-DSA-65");

        let algo = AlgorithmType::MlDsa { variant: "87".to_string() };
        assert_eq!(algo.name(), "ML-DSA-87");
    }

    #[test]
    fn test_slh_dsa_name() {
        let algo = AlgorithmType::SlhDsa { variant: "128s".to_string() };
        assert_eq!(algo.name(), "SLH-DSA-128s");

        let algo = AlgorithmType::SlhDsa { variant: "256f".to_string() };
        assert_eq!(algo.name(), "SLH-DSA-256f");
    }

    #[test]
    fn test_hybrid_kem_name() {
        let algo = AlgorithmType::HybridKem;
        assert_eq!(algo.name(), "Hybrid-KEM");
    }

    #[test]
    fn test_aes_gcm_name() {
        let algo = AlgorithmType::AesGcm { key_size: 16 };
        assert_eq!(algo.name(), "AES-128-GCM");

        let algo = AlgorithmType::AesGcm { key_size: 24 };
        assert_eq!(algo.name(), "AES-192-GCM");

        let algo = AlgorithmType::AesGcm { key_size: 32 };
        assert_eq!(algo.name(), "AES-256-GCM");
    }

    #[test]
    fn test_sha3_name() {
        let algo = AlgorithmType::Sha3 { variant: "256".to_string() };
        assert_eq!(algo.name(), "SHA3-256");

        let algo = AlgorithmType::Sha3 { variant: "512".to_string() };
        assert_eq!(algo.name(), "SHA3-512");
    }

    #[test]
    fn test_ed25519_name() {
        let algo = AlgorithmType::Ed25519;
        assert_eq!(algo.name(), "Ed25519");
    }

    #[test]
    fn test_bls12_381_name() {
        let algo = AlgorithmType::Bls12_381;
        assert_eq!(algo.name(), "BLS12-381");
    }

    #[test]
    fn test_bn254_name() {
        let algo = AlgorithmType::Bn254;
        assert_eq!(algo.name(), "BN254");
    }

    #[test]
    fn test_secp256k1_name() {
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
    fn test_ml_kem_security_levels() {
        let algo = AlgorithmType::MlKem { variant: "512".to_string() };
        assert_eq!(algo.security_level(), 128);

        let algo = AlgorithmType::MlKem { variant: "768".to_string() };
        assert_eq!(algo.security_level(), 192);

        let algo = AlgorithmType::MlKem { variant: "1024".to_string() };
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_ml_kem_unknown_variant_defaults_to_128() {
        let algo = AlgorithmType::MlKem { variant: "unknown".to_string() };
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_ml_dsa_security_levels() {
        let algo = AlgorithmType::MlDsa { variant: "44".to_string() };
        assert_eq!(algo.security_level(), 128);

        let algo = AlgorithmType::MlDsa { variant: "65".to_string() };
        assert_eq!(algo.security_level(), 192);

        let algo = AlgorithmType::MlDsa { variant: "87".to_string() };
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_ml_dsa_unknown_variant_defaults_to_128() {
        let algo = AlgorithmType::MlDsa { variant: "invalid".to_string() };
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_slh_dsa_security_levels() {
        let algo = AlgorithmType::SlhDsa { variant: "128".to_string() };
        assert_eq!(algo.security_level(), 128);

        let algo = AlgorithmType::SlhDsa { variant: "192".to_string() };
        assert_eq!(algo.security_level(), 192);

        let algo = AlgorithmType::SlhDsa { variant: "256".to_string() };
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_slh_dsa_unknown_variant_defaults_to_128() {
        let algo = AlgorithmType::SlhDsa { variant: "other".to_string() };
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_hybrid_kem_security_level() {
        let algo = AlgorithmType::HybridKem;
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_aes_gcm_security_levels() {
        let algo = AlgorithmType::AesGcm { key_size: 16 };
        assert_eq!(algo.security_level(), 128);

        let algo = AlgorithmType::AesGcm { key_size: 24 };
        assert_eq!(algo.security_level(), 192);

        let algo = AlgorithmType::AesGcm { key_size: 32 };
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_sha3_security_levels() {
        let algo = AlgorithmType::Sha3 { variant: "256".to_string() };
        assert_eq!(algo.security_level(), 256);

        let algo = AlgorithmType::Sha3 { variant: "512".to_string() };
        assert_eq!(algo.security_level(), 512);
    }

    #[test]
    fn test_sha3_invalid_variant_defaults_to_256() {
        let algo = AlgorithmType::Sha3 { variant: "invalid".to_string() };
        assert_eq!(algo.security_level(), 256);
    }

    #[test]
    fn test_ed25519_security_level() {
        let algo = AlgorithmType::Ed25519;
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_bls12_381_security_level() {
        let algo = AlgorithmType::Bls12_381;
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_bn254_security_level() {
        let algo = AlgorithmType::Bn254;
        assert_eq!(algo.security_level(), 128);
    }

    #[test]
    fn test_secp256k1_security_level() {
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
    fn test_algorithm_type_clone() {
        let original = AlgorithmType::MlKem { variant: "768".to_string() };
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_algorithm_type_equality() {
        let a1 = AlgorithmType::MlKem { variant: "768".to_string() };
        let a2 = AlgorithmType::MlKem { variant: "768".to_string() };
        let a3 = AlgorithmType::MlKem { variant: "512".to_string() };

        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    #[test]
    fn test_algorithm_type_debug() {
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
    fn test_kat_config_default() {
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
    fn test_kat_config_ml_kem_constructor() {
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
    fn test_kat_config_ml_dsa_constructor() {
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
    fn test_kat_config_slh_dsa_constructor() {
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
    fn test_kat_config_clone() {
        let original = KatConfig::ml_kem("1024", 100);
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_kat_config_equality() {
        let c1 = KatConfig::ml_kem("768", 100);
        let c2 = KatConfig::ml_kem("768", 100);
        let c3 = KatConfig::ml_kem("768", 50);

        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_kat_config_debug() {
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
    fn test_kat_result_serialization() {
        let result = KatResult::passed("test".to_string(), Duration::from_millis(100));
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_kat_result_failed_serialization() {
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
    fn test_ml_kem_kat_vector_serialization() {
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
    fn test_ml_dsa_kat_vector_serialization() {
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
    fn test_slh_dsa_kat_vector_serialization() {
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
    fn test_hybrid_kem_kat_vector_serialization() {
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
    fn test_aes_gcm_kat_vector_serialization() {
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
    fn test_sha3_kat_vector_serialization() {
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
    fn test_ed25519_kat_vector_serialization() {
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
    fn test_bls12_381_kat_vector_serialization() {
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
    fn test_bn254_kat_vector_serialization() {
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
    fn test_secp256k1_kat_vector_serialization() {
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
    fn test_nist_statistical_test_result_serialization() {
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
    fn test_rng_test_results_serialization() {
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
    fn test_algorithm_type_serialization() {
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
    fn test_kat_config_serialization() {
        let config = KatConfig::ml_kem("768", 100);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: KatConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_kat_config_default_serialization() {
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
    fn test_kat_result_invalid_json() {
        let result: Result<KatResult, _> = serde_json::from_str("invalid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_kat_result_missing_field() {
        let json = r#"{"test_case": "test", "passed": true}"#;
        let result: Result<KatResult, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_algorithm_type_invalid_json() {
        let result: Result<AlgorithmType, _> = serde_json::from_str("not valid");
        assert!(result.is_err());
    }

    #[test]
    fn test_kat_config_invalid_json() {
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
    fn test_empty_vectors() {
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
    fn test_large_vectors() {
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
    fn test_special_characters_in_test_case() {
        let result = KatResult::passed("test/with\\special\"chars\n\t".to_string(), Duration::ZERO);

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_unicode_in_test_case() {
        let result = KatResult::passed("test_unicode_\u{1F512}".to_string(), Duration::ZERO);

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: KatResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_max_duration() {
        let result = KatResult::passed("max_duration".to_string(), Duration::MAX);

        assert_eq!(result.execution_time_ns, Duration::MAX.as_nanos());
    }

    #[test]
    fn test_zero_test_count_config() {
        let config = KatConfig::ml_kem("768", 0);

        assert_eq!(config.test_count, 0);
    }

    #[test]
    fn test_aes_gcm_zero_key_size() {
        let algo = AlgorithmType::AesGcm { key_size: 0 };

        assert_eq!(algo.name(), "AES-0-GCM");
        assert_eq!(algo.security_level(), 0);
    }

    #[test]
    fn test_p_value_edge_cases() {
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
    fn test_entropy_estimate_edge_cases() {
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
    fn test_kat_result_json_structure() {
        let result = KatResult::passed("test".to_string(), Duration::from_millis(100));
        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"test_case\""));
        assert!(json.contains("\"passed\""));
        assert!(json.contains("\"execution_time_ns\""));
        assert!(json.contains("\"error_message\""));
    }

    #[test]
    fn test_algorithm_type_json_structure_ml_kem() {
        let algo = AlgorithmType::MlKem { variant: "768".to_string() };
        let json = serde_json::to_string(&algo).unwrap();

        assert!(json.contains("MlKem"));
        assert!(json.contains("\"variant\""));
        assert!(json.contains("768"));
    }

    #[test]
    fn test_algorithm_type_json_structure_unit_variants() {
        let algo = AlgorithmType::Ed25519;
        let json = serde_json::to_string(&algo).unwrap();

        assert!(json.contains("Ed25519"));
    }

    #[test]
    fn test_kat_config_json_structure() {
        let config = KatConfig::default();
        let json = serde_json::to_string(&config).unwrap();

        assert!(json.contains("\"algorithm\""));
        assert!(json.contains("\"test_count\""));
        assert!(json.contains("\"run_statistical_tests\""));
        assert!(json.contains("\"timeout_per_test\""));
        assert!(json.contains("\"validate_fips\""));
    }
}
