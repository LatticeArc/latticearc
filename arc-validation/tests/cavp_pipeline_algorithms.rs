//! Algorithm-specific CAVP pipeline tests
//!
//! These tests focus on the actual cryptographic algorithm implementations
//! in the CAVP pipeline, testing real ML-KEM, ML-DSA, SLH-DSA, and FN-DSA operations.

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

use arc_validation::cavp::pipeline::{CavpTestExecutor, PipelineConfig};
use arc_validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
use arc_validation::cavp::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Test ML-KEM-768 key generation
#[tokio::test]
async fn test_mlkem_768_keygen() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "MLKEM-768-KEYGEN-001".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: Some(vec![0x42; 32]),
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0xAB; 1184 + 2400]), // ek + dk for ML-KEM-768
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "NIST".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("ML-KEM-768 keygen test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok(), "ML-KEM-768 keygen should succeed");

    let test_result = result.unwrap();
    assert!(!test_result.actual_result.is_empty());
    assert_eq!(test_result.algorithm.name(), "ML-KEM-768");
}

/// Test ML-KEM-768 encapsulation with invalid input (missing ek)
#[tokio::test]
async fn test_mlkem_768_encapsulation_missing_key() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "MLKEM-768-ENCAP-INVALID".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None, // Missing required ek
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: None,
            secret_key: None,
            ciphertext: Some(vec![0xCC; 1088]),
            signature: None,
            shared_secret: Some(vec![0xDD; 32]),
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::Encapsulation,
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("Invalid encapsulation test - missing ek".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    // Should fail with error message
    assert!(!test_result.passed || test_result.error_message.is_some());
}

/// Test ML-KEM-768 decapsulation with invalid ciphertext length
#[tokio::test]
async fn test_mlkem_768_decapsulation_invalid_ciphertext() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "MLKEM-768-DECAP-INVALID".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: Some(vec![0xEE; 16]), // Wrong length
            m: None,
            ek: None,
            dk: Some(vec![0xFF; 2400]), // ML-KEM-768 dk length
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: None,
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: Some(vec![0xAA; 32]),
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::Decapsulation,
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("Invalid decapsulation - wrong ciphertext length".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    // Should fail due to invalid input
    assert!(test_result.error_message.is_some() || !test_result.passed);
}

/// Test ML-DSA-44 key generation
#[tokio::test]
async fn test_mldsa_44_keygen() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "MLDSA-44-KEYGEN-001".to_string(),
        algorithm: CavpAlgorithm::MlDsa { variant: "44".to_string() },
        inputs: CavpVectorInputs {
            seed: Some(vec![0x11; 32]),
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0x22; 1312 + 2560]), // pk + sk for ML-DSA-44
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "NIST".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 128,
            notes: Some("ML-DSA-44 keygen test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok(), "ML-DSA-44 keygen should succeed");

    let test_result = result.unwrap();
    assert!(!test_result.actual_result.is_empty());
}

/// Test ML-DSA-65 and ML-DSA-87 variants
#[tokio::test]
async fn test_mldsa_variants() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let variants = vec!["44", "65", "87"];

    for variant in variants {
        let vector = CavpTestVector {
            id: format!("MLDSA-{}-TEST", variant),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x33; 512]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("ML-DSA-{} variant test", variant)),
            },
        };

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok(), "ML-DSA-{} should succeed", variant);
    }
}

/// Test SLH-DSA-SHAKE-128s key generation
#[tokio::test]
async fn test_slhdsa_shake_128s_keygen() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "SLHDSA-128S-KEYGEN-001".to_string(),
        algorithm: CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0x44; 32 + 64]), // pk + sk
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "NIST".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 128,
            notes: Some("SLH-DSA-SHAKE-128s keygen test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok(), "SLH-DSA-SHAKE-128s keygen should succeed");
}

/// Test SLH-DSA variants (192s, 256s)
#[tokio::test]
async fn test_slhdsa_variants() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let variants = vec!["shake-128s", "shake-192s", "shake-256s"];

    for variant in variants {
        let vector = CavpTestVector {
            id: format!("SLHDSA-{}-TEST", variant),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0x55; 256]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("SLH-DSA {} variant test", variant)),
            },
        };

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok(), "SLH-DSA {} should succeed", variant);
    }
}

/// Test FN-DSA-512 key generation
#[tokio::test]
async fn test_fndsa_512_keygen() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "FNDSA-512-KEYGEN-001".to_string(),
        algorithm: CavpAlgorithm::FnDsa { variant: "512".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0x66; 256]),
            secret_key: Some(vec![0x77; 512]),
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "NIST".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 128,
            notes: Some("FN-DSA-512 keygen test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok(), "FN-DSA-512 keygen should succeed");
}

/// Test FN-DSA-1024 variant
#[tokio::test]
async fn test_fndsa_1024_keygen() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "FNDSA-1024-KEYGEN-001".to_string(),
        algorithm: CavpAlgorithm::FnDsa { variant: "1024".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0x88; 512]),
            secret_key: Some(vec![0x99; 1024]),
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "NIST".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 256,
            notes: Some("FN-DSA-1024 keygen test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok(), "FN-DSA-1024 keygen should succeed");
}

/// Test unsupported ML-KEM variant
#[tokio::test]
async fn test_mlkem_unsupported_variant() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "MLKEM-INVALID-001".to_string(),
        algorithm: CavpAlgorithm::MlKem {
            variant: "9999".to_string(), // Unsupported variant
        },
        inputs: CavpVectorInputs {
            seed: Some(vec![0xAA; 32]),
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0xBB; 64]),
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 128,
            notes: Some("Unsupported variant test".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    // Should have error message for unsupported variant
    assert!(test_result.error_message.is_some() || !test_result.passed);
}

/// Test invalid test type for signature algorithm
#[tokio::test]
async fn test_signature_algorithm_with_encapsulation_type() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    // ML-DSA is a signature scheme, but we're testing encapsulation
    let vector = CavpTestVector {
        id: "MLDSA-WRONG-TYPE-001".to_string(),
        algorithm: CavpAlgorithm::MlDsa { variant: "44".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: Some(vec![0xCC; 128]),
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: None,
            secret_key: None,
            ciphertext: Some(vec![0xDD; 128]),
            signature: None,
            shared_secret: Some(vec![0xEE; 32]),
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::Encapsulation, // Wrong type for signature algorithm
            created_at: chrono::Utc::now(),
            security_level: 128,
            notes: Some("Invalid test type for algorithm".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    // Should fail or have error
    assert!(test_result.error_message.is_some() || !test_result.passed);
}

/// Test KEM algorithm with signature type
#[tokio::test]
async fn test_kem_algorithm_with_signature_type() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    // ML-KEM is a KEM scheme, but we're testing signature
    let vector = CavpTestVector {
        id: "MLKEM-WRONG-TYPE-001".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: Some(b"Test message".to_vec()),
            key_material: None,
            pk: None,
            sk: Some(vec![0xFF; 2400]),
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: None,
            secret_key: None,
            ciphertext: None,
            signature: Some(vec![0xAA; 256]),
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::Signature, // Wrong type for KEM
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("Invalid test type for KEM".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    // Should fail with error about invalid operation
    assert!(test_result.error_message.is_some() || !test_result.passed);
}

/// Test batch execution with timeout configuration
#[tokio::test]
async fn test_batch_with_custom_timeout() {
    let config = PipelineConfig {
        max_concurrent_tests: 2,
        test_timeout: Duration::from_secs(60),
        retry_count: 1,
        run_statistical_tests: false,
        generate_reports: false,
    };
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vectors = vec![CavpTestVector {
        id: "TIMEOUT-TEST-001".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0xCC; 64]),
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "1.0".to_string(),
            source: "Test".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("Timeout configuration test".to_string()),
        },
    }];

    let batch = executor.execute_test_vector_batch(vectors).await;
    assert!(batch.is_ok());
}

/// Test metadata capture in test results
#[tokio::test]
async fn test_metadata_capture_in_results() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    let vector = CavpTestVector {
        id: "METADATA-TEST-001".to_string(),
        algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
        inputs: CavpVectorInputs {
            seed: None,
            message: None,
            key_material: None,
            pk: None,
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: {
                let mut params = HashMap::new();
                params.insert("custom_param".to_string(), vec![0x11, 0x22]);
                params
            },
        },
        expected_outputs: CavpVectorOutputs {
            public_key: Some(vec![0xDD; 64]),
            secret_key: None,
            ciphertext: None,
            signature: None,
            shared_secret: None,
            additional: HashMap::new(),
        },
        metadata: CavpVectorMetadata {
            version: "2.0".to_string(),
            source: "CustomSource".to_string(),
            test_type: CavpTestType::KeyGen,
            created_at: chrono::Utc::now(),
            security_level: 192,
            notes: Some("Testing metadata capture".to_string()),
        },
    };

    let result = executor.execute_single_test_vector(&vector).await;
    assert!(result.is_ok());

    let test_result = result.unwrap();
    assert_eq!(test_result.metadata.vector_version, "2.0");
    assert_eq!(test_result.metadata.security_level, 192);
    assert!(!test_result.metadata.configuration.parameters.is_empty());
}
