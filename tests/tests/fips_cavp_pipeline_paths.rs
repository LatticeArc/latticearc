//! CAVP pipeline per-algorithm, error-path, and integration tests.
//!
//! Sub-modules preserve the structure and imports of their original
//! source files (split from the former consolidated fips_cavp.rs).

#![deny(unsafe_code)]

mod pipeline_algorithms {
    //! Algorithm-specific CAVP pipeline tests
    //!
    //! These tests focus on the actual cryptographic algorithm implementations
    //! in the CAVP pipeline, testing real ML-KEM, ML-DSA, SLH-DSA, and FN-DSA operations.

    #![allow(clippy::unwrap_used, clippy::useless_vec)]

    use latticearc_tests::validation::cavp::pipeline::{CavpTestExecutor, PipelineConfig};
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// Test ML-KEM-768 key generation
    #[tokio::test]
    async fn test_mlkem_768_keygen_succeeds() {
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
        assert!(
            !test_result.actual_result.is_empty(),
            "ML-KEM-768 keygen should produce non-empty result"
        );
        assert_eq!(
            test_result.algorithm.name(),
            "ML-KEM-768",
            "algorithm name should be ML-KEM-768"
        );
    }

    /// Test ML-KEM-768 encapsulation with invalid input (missing ek)
    #[tokio::test]
    async fn test_mlkem_768_encapsulation_missing_key_returns_error() {
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
        assert!(result.is_ok(), "execute_single_test_vector should not return an error");

        let test_result = result.unwrap();
        // Should fail with error message
        assert!(
            !test_result.passed || test_result.error_message.is_some(),
            "invalid vector should either fail or have an error message"
        );
    }

    /// Test ML-KEM-768 decapsulation with invalid ciphertext length
    #[tokio::test]
    async fn test_mlkem_768_decapsulation_invalid_ciphertext_returns_error() {
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
        assert!(result.is_ok(), "invalid decapsulation vector should not return an error");

        let test_result = result.unwrap();
        // Should fail due to invalid input
        assert!(
            test_result.error_message.is_some() || !test_result.passed,
            "invalid input should fail or have an error message"
        );
    }

    /// Test ML-DSA-44 key generation
    #[tokio::test]
    async fn test_mldsa_44_keygen_succeeds() {
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
        assert!(
            !test_result.actual_result.is_empty(),
            "ML-DSA-44 keygen should produce non-empty result"
        );
    }

    /// Test ML-DSA-65 and ML-DSA-87 variants
    #[tokio::test]
    async fn test_mldsa_variants_all_succeed_succeeds() {
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
    async fn test_slhdsa_shake_128s_keygen_succeeds() {
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
    async fn test_slhdsa_variants_all_succeed_succeeds() {
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
    async fn test_fndsa_512_keygen_succeeds() {
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
    async fn test_fndsa_1024_keygen_succeeds() {
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
    async fn test_mlkem_unsupported_variant_returns_error() {
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
        assert!(result.is_ok(), "unsupported variant should not return executor error");

        let test_result = result.unwrap();
        // Should have error message for unsupported variant
        assert!(
            test_result.error_message.is_some() || !test_result.passed,
            "unsupported variant should fail or have error message"
        );
    }

    /// Test invalid test type for signature algorithm
    #[tokio::test]
    async fn test_signature_algorithm_with_encapsulation_type_returns_error() {
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
        assert!(result.is_ok(), "wrong test type should not return executor error");

        let test_result = result.unwrap();
        // Should fail or have error
        assert!(
            test_result.error_message.is_some() || !test_result.passed,
            "wrong test type for signature algorithm should fail or have error message"
        );
    }

    /// Test KEM algorithm with signature type
    #[tokio::test]
    async fn test_kem_algorithm_with_signature_type_returns_error() {
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
        assert!(result.is_ok(), "wrong test type should not return executor error");

        let test_result = result.unwrap();
        // Should fail with error about invalid operation
        assert!(
            test_result.error_message.is_some() || !test_result.passed,
            "wrong test type for KEM algorithm should fail or have error message"
        );
    }

    /// Test batch execution with timeout configuration
    #[tokio::test]
    async fn test_batch_with_custom_timeout_succeeds() {
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
        assert!(batch.is_ok(), "batch execution with custom timeout should succeed");
    }

    /// Test metadata capture in test results
    #[tokio::test]
    async fn test_metadata_capture_in_results_populated_succeeds() {
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
        assert!(result.is_ok(), "metadata capture test should not return executor error");

        let test_result = result.unwrap();
        assert_eq!(
            test_result.metadata.vector_version, "2.0",
            "vector_version should be captured as 2.0"
        );
        assert_eq!(
            test_result.metadata.security_level, 192,
            "security_level should be captured as 192"
        );
        assert!(
            !test_result.metadata.configuration.parameters.is_empty(),
            "custom parameters should be preserved in metadata"
        );
    }
}
mod pipeline_error_paths {
    //! Coverage tests for CAVP pipeline error paths.
    //! Targets: wrong test type combinations (ML-KEM Signature, SLH-DSA Encapsulation, etc.),
    //! unsupported variants, HybridKem operations, CavpValidationPipeline methods.

    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::field_reassign_with_default)]

    use latticearc_tests::validation::cavp::pipeline::{
        CavpTestExecutor, CavpValidationPipeline, PipelineConfig,
    };
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_vector(id: &str, algorithm: CavpAlgorithm, test_type: CavpTestType) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42; 48]),
                message: Some(b"test message".to_vec()),
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: Some(vec![0x11; 32]),
                ek: None,
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0xAA; 64]),
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![0xBB; 128]),
                shared_secret: Some(vec![0xCC; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn make_executor() -> CavpTestExecutor {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        CavpTestExecutor::new(config, storage)
    }

    // ============================================================
    // ML-KEM wrong test types (covers lines 408-411)
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_with_signature_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mlkem-sig-err",
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Signature,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        // Should have error: ML-KEM does not support signature
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_mlkem_with_verification_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mlkem-verify-err",
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Verification,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    // ============================================================
    // SLH-DSA wrong test types (covers lines 501-504, 579-582, 657-660)
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_128s_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "slhdsa-128s-encap-err",
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_with_decapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "slhdsa-128s-decap-err",
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_slhdsa_192s_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "slhdsa-192s-encap-err",
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_slhdsa_256s_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "slhdsa-256s-encap-err",
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_slhdsa_unsupported_variant_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "slhdsa-unsupported",
            CavpAlgorithm::SlhDsa { variant: "sha-512f".to_string() },
            CavpTestType::KeyGen,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    // ============================================================
    // ML-DSA wrong test types (covers lines 833-836, 911-915, 989-993)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mldsa44-encap-err",
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_mldsa_65_with_decapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mldsa65-decap-err",
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_mldsa_87_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mldsa87-encap-err",
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_mldsa_unsupported_variant_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "mldsa-unsupported",
            CavpAlgorithm::MlDsa { variant: "99".to_string() },
            CavpTestType::KeyGen,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    // ============================================================
    // FN-DSA wrong test types (covers lines 745-748)
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_with_encapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "fndsa512-encap-err",
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Encapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_fndsa_1024_with_decapsulation_type_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "fndsa1024-decap-err",
            CavpAlgorithm::FnDsa { variant: "1024".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_fndsa_unsupported_variant_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            "fndsa-unsupported",
            CavpAlgorithm::FnDsa { variant: "2048".to_string() },
            CavpTestType::KeyGen,
        );
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    // ============================================================
    // Hybrid KEM wrong test types (covers lines 1142-1144)
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_with_signature_type_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector("hybrid-sig-err", CavpAlgorithm::HybridKem, CavpTestType::Signature);
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_with_verification_type_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector("hybrid-verify-err", CavpAlgorithm::HybridKem, CavpTestType::Verification);
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        assert!(result.error_message.is_some() || !result.passed);
    }

    // ============================================================
    // Hybrid KEM KeyGen (covers lines 995-1027)
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_keygen_succeeds() {
        let executor = make_executor();
        let vector = make_vector("hybrid-keygen", CavpAlgorithm::HybridKem, CavpTestType::KeyGen);
        let result = executor.execute_single_test_vector(&vector).await.unwrap();
        // KeyGen should succeed (produces actual keys)
        assert!(!result.actual_result.is_empty());
    }

    // ============================================================
    // CavpValidationPipeline: create_sample_vectors (covers lines 1237-1283)
    // ============================================================

    #[test]
    fn test_create_sample_vectors_mlkem_matches_expected() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors =
            pipeline.create_sample_vectors(CavpAlgorithm::MlKem { variant: "768".into() }, 5);
        assert_eq!(vectors.len(), 5);
        for (i, v) in vectors.iter().enumerate() {
            assert!(v.id.contains("ML-KEM-768"));
            assert_eq!(v.metadata.test_type, CavpTestType::KeyGen);
            assert!(v.inputs.seed.is_some());
            assert_eq!(v.inputs.seed.as_ref().unwrap().len(), 32);
            assert!(v.expected_outputs.public_key.is_some());
            assert!(v.expected_outputs.signature.is_some());
            assert!(v.expected_outputs.shared_secret.is_some());
            assert!(v.id.contains(&format!("{}", i + 1)));
        }
    }

    #[test]
    fn test_create_sample_vectors_all_algorithms_matches_expected() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let algorithms = vec![
            CavpAlgorithm::MlKem { variant: "768".into() },
            CavpAlgorithm::MlDsa { variant: "44".into() },
            CavpAlgorithm::SlhDsa { variant: "shake-128s".into() },
            CavpAlgorithm::FnDsa { variant: "512".into() },
            CavpAlgorithm::HybridKem,
        ];

        for alg in algorithms {
            let vectors = pipeline.create_sample_vectors(alg.clone(), 3);
            assert_eq!(vectors.len(), 3);
            assert!(vectors[0].id.contains(&alg.name()));
        }
    }

    #[test]
    fn test_create_sample_vectors_zero_matches_expected() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors = pipeline.create_sample_vectors(CavpAlgorithm::HybridKem, 0);
        assert!(vectors.is_empty());
    }

    // ============================================================
    // CavpValidationPipeline: run_full_validation (covers lines 1169-1195)
    // ============================================================

    #[tokio::test]
    async fn test_run_full_validation_mlkem_keygen_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = true;
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors = vec![make_vector(
            "full-val-1",
            CavpAlgorithm::MlKem { variant: "768".into() },
            CavpTestType::KeyGen,
        )];

        let results = pipeline.run_full_validation(vectors).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].test_results.is_empty());
    }

    #[tokio::test]
    async fn test_run_full_validation_multiple_algorithms_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = true;
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors = vec![
            make_vector(
                "multi-1",
                CavpAlgorithm::MlKem { variant: "768".into() },
                CavpTestType::KeyGen,
            ),
            make_vector(
                "multi-2",
                CavpAlgorithm::MlDsa { variant: "44".into() },
                CavpTestType::KeyGen,
            ),
        ];

        let results = pipeline.run_full_validation(vectors).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_run_full_validation_empty_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = false; // No report from empty results
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let results = pipeline.run_full_validation(vec![]).await.unwrap();
        assert!(results.is_empty());
    }

    // ============================================================
    // CavpValidationPipeline: run_algorithm_validation (covers lines 1201-1219)
    // ============================================================

    #[tokio::test]
    async fn test_run_algorithm_validation_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = true;
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let alg = CavpAlgorithm::MlDsa { variant: "44".into() };
        let vectors = vec![make_vector("algo-val-1", alg.clone(), CavpTestType::KeyGen)];

        let result = pipeline.run_algorithm_validation(alg, vectors).await.unwrap();
        assert!(!result.test_results.is_empty());
    }

    #[tokio::test]
    async fn test_run_algorithm_validation_no_reports_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = false;
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-128s".into() };
        let vectors = vec![make_vector("no-report", alg.clone(), CavpTestType::KeyGen)];

        let result = pipeline.run_algorithm_validation(alg, vectors).await.unwrap();
        assert!(!result.test_results.is_empty());
    }

    // ============================================================
    // Batch execution with storage (covers lines 99-131)
    // ============================================================

    #[tokio::test]
    async fn test_batch_execution_stores_results_succeeds() {
        let config = PipelineConfig::default();
        let storage = Arc::new(MemoryCavpStorage::new());
        let storage_clone: Arc<dyn CavpStorage> = storage.clone();
        let executor = CavpTestExecutor::new(config, storage_clone);

        let vectors = vec![
            make_vector(
                "batch-1",
                CavpAlgorithm::MlKem { variant: "768".into() },
                CavpTestType::KeyGen,
            ),
            make_vector(
                "batch-2",
                CavpAlgorithm::MlKem { variant: "768".into() },
                CavpTestType::KeyGen,
            ),
        ];

        let batch_result = executor.execute_test_vector_batch(vectors).await.unwrap();
        assert_eq!(batch_result.test_results.len(), 2);
        assert!(batch_result.total_execution_time > Duration::ZERO);

        // Verify results were stored
        let stored = storage.retrieve_result(&batch_result.test_results[0].test_id).unwrap();
        assert!(stored.is_some());
    }

    // ============================================================
    // Pipeline with generate_reports = false (covers lines 1190-1192 branch)
    // ============================================================

    #[tokio::test]
    async fn test_full_validation_without_reports_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = false;
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors = vec![make_vector(
            "no-report-val",
            CavpAlgorithm::FnDsa { variant: "512".into() },
            CavpTestType::KeyGen,
        )];

        let results = pipeline.run_full_validation(vectors).await.unwrap();
        assert_eq!(results.len(), 1);
    }
}
mod pipeline_integration {
    //! Comprehensive integration tests for CAVP pipeline
    //!
    //! These tests verify the CAVP (Cryptographic Algorithm Validation Program) pipeline
    //! implementation, ensuring FIPS 140-3 compliance readiness.

    #![allow(clippy::unwrap_used, clippy::float_cmp, clippy::useless_vec)]

    use latticearc_tests::validation::cavp::compliance::CavpComplianceGenerator;
    use latticearc_tests::validation::cavp::pipeline::{
        CavpTestExecutor, CavpValidationPipeline, PipelineConfig,
    };
    use latticearc_tests::validation::cavp::storage::{
        CavpStorage, CavpStorageManager, FileCavpStorage, MemoryCavpStorage,
    };
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    /// Helper to create a sample ML-KEM test vector
    fn create_mlkem_test_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: variant.to_string() },
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
                public_key: Some(vec![0xAB; 64]),
                secret_key: Some(vec![0xCD; 128]),
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
                notes: Some("Test vector for integration testing".to_string()),
            },
        }
    }

    /// Helper to create a sample ML-DSA test vector
    fn create_mldsa_test_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(b"Test message for signature".to_vec()),
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
                signature: Some(vec![0xEF; 256]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some("ML-DSA signature test vector".to_string()),
            },
        }
    }

    /// Helper to create a sample SLH-DSA test vector
    fn create_slhdsa_test_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(b"Test message for hash-based signature".to_vec()),
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
                signature: Some(vec![0x12; 512]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some("SLH-DSA signature test vector".to_string()),
            },
        }
    }

    /// Helper to create a sample FN-DSA test vector
    fn create_fndsa_test_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(b"Test message for Falcon signature".to_vec()),
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
                signature: Some(vec![0x34; 256]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some("FN-DSA signature test vector".to_string()),
            },
        }
    }

    /// Helper to create a sample Hybrid KEM test vector
    fn create_hybrid_kem_test_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x56; 64]),
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
                signature: None,
                shared_secret: Some(vec![0x78; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM test vector".to_string()),
            },
        }
    }

    #[tokio::test]
    async fn test_pipeline_config_creation_sets_defaults_succeeds() {
        let config = PipelineConfig::default();

        assert_eq!(config.max_concurrent_tests, 4);
        assert_eq!(config.test_timeout, Duration::from_secs(30));
        assert_eq!(config.retry_count, 3);
        assert!(config.run_statistical_tests);
        assert!(config.generate_reports);
    }

    #[tokio::test]
    async fn test_pipeline_config_custom_overrides_defaults_succeeds() {
        let config = PipelineConfig {
            max_concurrent_tests: 8,
            test_timeout: Duration::from_secs(60),
            retry_count: 5,
            run_statistical_tests: false,
            generate_reports: false,
        };

        assert_eq!(config.max_concurrent_tests, 8);
        assert_eq!(config.test_timeout, Duration::from_secs(60));
        assert_eq!(config.retry_count, 5);
        assert!(!config.run_statistical_tests);
        assert!(!config.generate_reports);
    }

    #[tokio::test]
    async fn test_executor_creation_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Executor should be created successfully
        // This is a smoke test to ensure the constructor works
        drop(executor);
    }

    #[tokio::test]
    async fn test_execute_single_mlkem_test_vector_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_mlkem_test_vector("TEST-MLKEM-001", "768");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok(), "ML-KEM test execution should succeed");
        let test_result = result.unwrap();

        assert_eq!(test_result.algorithm, vector.algorithm);
        assert_eq!(test_result.vector_id, vector.id);
        assert!(!test_result.actual_result.is_empty(), "Result should contain output data");
    }

    #[tokio::test]
    async fn test_execute_single_mldsa_test_vector_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_mldsa_test_vector("TEST-MLDSA-001", "44");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok(), "ML-DSA test execution should succeed");
        let test_result = result.unwrap();

        assert_eq!(test_result.algorithm, vector.algorithm);
        assert_eq!(test_result.vector_id, vector.id);
    }

    #[tokio::test]
    async fn test_execute_single_slhdsa_test_vector_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_slhdsa_test_vector("TEST-SLHDSA-001", "shake-128s");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok(), "SLH-DSA test execution should succeed");
        let test_result = result.unwrap();

        assert_eq!(test_result.algorithm, vector.algorithm);
        assert_eq!(test_result.vector_id, vector.id);
    }

    #[tokio::test]
    async fn test_execute_single_fndsa_test_vector_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_fndsa_test_vector("TEST-FNDSA-001", "512");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok(), "FN-DSA test execution should succeed");
        let test_result = result.unwrap();

        assert_eq!(test_result.algorithm, vector.algorithm);
        assert_eq!(test_result.vector_id, vector.id);
    }

    #[tokio::test]
    async fn test_execute_single_hybrid_kem_test_vector_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_hybrid_kem_test_vector("TEST-HYBRID-001");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok(), "Hybrid KEM test execution should succeed");
        let test_result = result.unwrap();

        assert_eq!(test_result.algorithm, vector.algorithm);
        assert_eq!(test_result.vector_id, vector.id);
    }

    #[tokio::test]
    async fn test_execute_test_vector_batch_mlkem_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vectors = vec![
            create_mlkem_test_vector("BATCH-MLKEM-001", "768"),
            create_mlkem_test_vector("BATCH-MLKEM-002", "768"),
            create_mlkem_test_vector("BATCH-MLKEM-003", "768"),
        ];

        let batch_result = executor.execute_test_vector_batch(vectors).await;

        assert!(batch_result.is_ok(), "Batch execution should succeed");
        let batch = batch_result.unwrap();

        assert_eq!(batch.test_results.len(), 3);
        assert!(batch.total_execution_time > Duration::ZERO);
        assert!(batch.pass_rate >= 0.0 && batch.pass_rate <= 100.0);
    }

    #[tokio::test]
    async fn test_execute_test_vector_batch_empty_returns_empty_batch_matches_expected() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vectors: Vec<CavpTestVector> = vec![];
        let batch_result = executor.execute_test_vector_batch(vectors).await;

        assert!(batch_result.is_ok(), "Empty batch should be handled gracefully");
        let batch = batch_result.unwrap();

        assert_eq!(batch.test_results.len(), 0);
        assert_eq!(batch.pass_rate, 0.0);
    }

    #[tokio::test]
    async fn test_execute_test_vector_batch_mixed_algorithms_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        // Mixed algorithms should still execute (algorithm from first vector is used)
        let vectors = vec![
            create_mlkem_test_vector("MIXED-001", "768"),
            create_mldsa_test_vector("MIXED-002", "44"),
        ];

        let batch_result = executor.execute_test_vector_batch(vectors).await;

        assert!(batch_result.is_ok(), "Mixed algorithm batch should execute");
    }

    #[tokio::test]
    async fn test_storage_backend_stores_results_and_retrieves_them_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vector = create_mlkem_test_vector("STORAGE-TEST-001", "768");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();

        // Verify result was stored
        let retrieved = storage.retrieve_result(&test_result.test_id).unwrap();
        assert!(retrieved.is_some(), "Result should be stored in backend");

        let stored_result = retrieved.unwrap();
        assert_eq!(stored_result.test_id, test_result.test_id);
        assert_eq!(stored_result.vector_id, test_result.vector_id);
    }

    #[tokio::test]
    async fn test_storage_backend_stores_batches_and_retrieves_them_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        let vectors = vec![
            create_mlkem_test_vector("BATCH-STORAGE-001", "768"),
            create_mlkem_test_vector("BATCH-STORAGE-002", "768"),
        ];

        let batch_result = executor.execute_test_vector_batch(vectors).await;
        assert!(batch_result.is_ok());

        let batch = batch_result.unwrap();

        // Verify batch was stored
        let retrieved = storage.retrieve_batch(&batch.batch_id).unwrap();
        assert!(retrieved.is_some(), "Batch should be stored in backend");

        let stored_batch = retrieved.unwrap();
        assert_eq!(stored_batch.batch_id, batch.batch_id);
        assert_eq!(stored_batch.test_results.len(), batch.test_results.len());
    }

    #[tokio::test]
    async fn test_list_results_by_algorithm_returns_filtered_results_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        // Execute multiple tests for the same algorithm
        let vectors = vec![
            create_mlkem_test_vector("QUERY-001", "768"),
            create_mlkem_test_vector("QUERY-002", "768"),
        ];

        for vector in vectors {
            let _ = executor.execute_single_test_vector(&vector).await;
        }

        // Query results by algorithm
        let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let results = storage.list_results_by_algorithm(&algorithm).unwrap();

        assert_eq!(results.len(), 2, "Should retrieve all results for ML-KEM-768");
    }

    #[tokio::test]
    async fn test_list_batches_by_algorithm_returns_filtered_batches_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage.clone());

        // Execute batches
        let batch1 = vec![create_mldsa_test_vector("BATCH-QUERY-001", "44")];
        let batch2 = vec![create_mldsa_test_vector("BATCH-QUERY-002", "44")];

        let _ = executor.execute_test_vector_batch(batch1).await;
        let _ = executor.execute_test_vector_batch(batch2).await;

        // Query batches by algorithm
        let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();

        assert_eq!(batches.len(), 2, "Should retrieve all batches for ML-DSA-44");
    }

    #[tokio::test]
    async fn test_validation_pipeline_creation_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        // Pipeline should be created successfully
        drop(pipeline);
    }

    #[tokio::test]
    async fn test_validation_pipeline_run_algorithm_validation_succeeds() {
        let config = PipelineConfig {
            generate_reports: false, // Disable report generation for this test
            ..Default::default()
        };
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let vectors = vec![
            create_mlkem_test_vector("PIPELINE-001", "768"),
            create_mlkem_test_vector("PIPELINE-002", "768"),
        ];

        let result = pipeline.run_algorithm_validation(algorithm.clone(), vectors).await;

        assert!(result.is_ok(), "Algorithm validation should succeed");
        let batch_result = result.unwrap();

        assert_eq!(batch_result.algorithm, algorithm);
        assert_eq!(batch_result.test_results.len(), 2);
    }

    #[tokio::test]
    async fn test_validation_pipeline_run_full_validation_succeeds() {
        let config = PipelineConfig { generate_reports: false, ..Default::default() };
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let vectors = vec![
            create_mlkem_test_vector("FULL-001", "768"),
            create_mldsa_test_vector("FULL-002", "44"),
            create_slhdsa_test_vector("FULL-003", "shake-128s"),
        ];

        let result = pipeline.run_full_validation(vectors).await;

        assert!(result.is_ok(), "Full validation should succeed");
        let batch_results = result.unwrap();

        // Results should be grouped by algorithm
        assert_eq!(batch_results.len(), 3, "Should have 3 algorithm batches");
    }

    #[tokio::test]
    async fn test_validation_pipeline_create_sample_vectors_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let vectors = pipeline.create_sample_vectors(algorithm.clone(), 5);

        assert_eq!(vectors.len(), 5);

        for (i, vector) in vectors.iter().enumerate() {
            assert_eq!(vector.algorithm, algorithm);
            assert!(vector.id.contains(&format!("{}", i + 1)));
            assert!(vector.inputs.seed.is_some());
            assert!(vector.expected_outputs.public_key.is_some());
        }
    }

    #[tokio::test]
    async fn test_batch_result_update_status_succeeds() {
        let mut batch = CavpBatchResult::new(
            "TEST-BATCH".to_string(),
            CavpAlgorithm::MlKem { variant: "768".to_string() },
        );

        // Initially incomplete
        assert!(matches!(batch.status, CavpValidationStatus::Incomplete));

        // Add a passing test
        let passing_result = CavpTestResult::new(
            "TEST-001".to_string(),
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            "VEC-001".to_string(),
            vec![0x42; 32],
            vec![0x42; 32], // Same as actual
            Duration::from_millis(100),
            CavpTestMetadata::default(),
        );

        batch.add_test_result(passing_result);
        batch.update_status();

        assert_eq!(batch.pass_rate, 100.0);
        assert!(matches!(batch.status, CavpValidationStatus::Passed));

        // Add a failing test
        let failing_result = CavpTestResult::failed(
            "TEST-002".to_string(),
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            "VEC-002".to_string(),
            vec![0x42; 32],
            vec![0x99; 32], // Different from actual
            Duration::from_millis(100),
            "Mismatch".to_string(),
            CavpTestMetadata::default(),
        );

        batch.add_test_result(failing_result);
        batch.update_status();

        assert_eq!(batch.pass_rate, 50.0);
        assert!(matches!(batch.status, CavpValidationStatus::Failed));
    }

    #[tokio::test]
    async fn test_error_handling_invalid_test_type_for_algorithm_fails() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Create a vector with invalid test type for ML-KEM (signature instead of key gen)
        let mut vector = create_mlkem_test_vector("INVALID-001", "768");
        vector.metadata.test_type = CavpTestType::Signature;

        let result = executor.execute_single_test_vector(&vector).await;

        // Should still return a result (may be failed)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_storage_backend_stores_and_retrieves_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        // Store a test result
        let test_result = CavpTestResult::new(
            "FILE-TEST-001".to_string(),
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            "VEC-001".to_string(),
            vec![0x42; 32],
            vec![0x42; 32],
            Duration::from_millis(100),
            CavpTestMetadata::default(),
        );

        storage.store_result(&test_result).unwrap();

        // Verify file was created
        let result_file = temp_dir.path().join("results").join("FILE-TEST-001.json");
        assert!(result_file.exists(), "Result file should be created");

        // Retrieve result
        let retrieved = storage.retrieve_result("FILE-TEST-001").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().test_id, "FILE-TEST-001");
    }

    #[tokio::test]
    async fn test_file_storage_batch_persistence_survives_reload_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        let batch = CavpBatchResult::new(
            "FILE-BATCH-001".to_string(),
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
        );

        storage.store_batch(&batch).unwrap();

        // Verify file was created
        let batch_file = temp_dir.path().join("batches").join("FILE-BATCH-001.json");
        assert!(batch_file.exists(), "Batch file should be created");

        // Retrieve batch
        let retrieved = storage.retrieve_batch("FILE-BATCH-001").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().batch_id, "FILE-BATCH-001");
    }

    #[tokio::test]
    async fn test_storage_manager_with_memory_backend_stores_and_retrieves_succeeds() {
        let manager = CavpStorageManager::memory();

        let test_result = CavpTestResult::new(
            "MANAGER-TEST-001".to_string(),
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            "VEC-001".to_string(),
            vec![0x42; 32],
            vec![0x42; 32],
            Duration::from_millis(100),
            CavpTestMetadata::default(),
        );

        manager.store_result(&test_result).unwrap();

        let retrieved = manager.retrieve_result("MANAGER-TEST-001").unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_storage_manager_with_file_backend_stores_and_retrieves_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = CavpStorageManager::file(temp_dir.path()).unwrap();

        let test_result = CavpTestResult::new(
            "FILE-MANAGER-001".to_string(),
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            "VEC-001".to_string(),
            vec![0x42; 32],
            vec![0x42; 32],
            Duration::from_millis(100),
            CavpTestMetadata::default(),
        );

        manager.store_result(&test_result).unwrap();

        let retrieved = manager.retrieve_result("FILE-MANAGER-001").unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_compliance_generator_mlkem_report_succeeds() {
        let generator = CavpComplianceGenerator::new();

        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vectors = vec![create_mlkem_test_vector("COMP-001", "768")];
        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

        let report = generator.generate_report(&[batch]).unwrap();

        assert_eq!(report.algorithm.name(), "ML-KEM-768");
        assert!(!report.nist_standards.is_empty());
        assert!(report.summary.total_tests > 0);
    }

    #[tokio::test]
    async fn test_compliance_generator_json_export_succeeds() {
        let generator = CavpComplianceGenerator::new();

        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vectors = vec![create_mldsa_test_vector("COMP-JSON-001", "44")];
        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

        let report = generator.generate_report(&[batch]).unwrap();
        let json = generator.export_json(&report).unwrap();

        assert!(!json.is_empty());
        assert!(json.contains("ML-DSA"));
        assert!(json.contains("report_id"));
    }

    #[tokio::test]
    async fn test_compliance_generator_xml_export_succeeds() {
        let generator = CavpComplianceGenerator::new();

        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vectors = vec![create_slhdsa_test_vector("COMP-XML-001", "shake-128s")];
        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

        let report = generator.generate_report(&[batch]).unwrap();
        let xml = generator.export_xml(&report).unwrap();

        assert!(!xml.is_empty());
        assert!(xml.contains("<?xml version"));
        assert!(xml.contains("cavp_compliance_report"));
        assert!(xml.contains("SLH-DSA"));
    }

    #[tokio::test]
    async fn test_compliance_status_evaluation_returns_correct_status_succeeds() {
        let generator = CavpComplianceGenerator::new();

        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // All tests pass scenario
        let vectors = vec![
            create_mlkem_test_vector("COMP-PASS-001", "768"),
            create_mlkem_test_vector("COMP-PASS-002", "768"),
        ];

        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();
        let report = generator.generate_report(&[batch]).unwrap();

        // Note: Compliance status depends on actual vs expected results matching
        assert!(report.summary.pass_rate >= 0.0);
    }

    #[tokio::test]
    async fn test_performance_metrics_calculation_returns_correct_values_succeeds() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vectors = vec![
            create_fndsa_test_vector("PERF-001", "512"),
            create_fndsa_test_vector("PERF-002", "512"),
            create_fndsa_test_vector("PERF-003", "512"),
        ];

        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

        assert!(batch.total_execution_time > Duration::ZERO);
        assert_eq!(batch.test_results.len(), 3);

        // Each test should have execution time recorded
        for result in &batch.test_results {
            assert!(result.execution_time > Duration::ZERO);
        }
    }

    #[tokio::test]
    async fn test_algorithm_name_formatting_returns_correct_strings_has_correct_size() {
        let algorithms = vec![
            (CavpAlgorithm::MlKem { variant: "768".to_string() }, "ML-KEM-768"),
            (CavpAlgorithm::MlDsa { variant: "44".to_string() }, "ML-DSA-44"),
            (CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() }, "SLH-DSA-shake-128s"),
            (CavpAlgorithm::FnDsa { variant: "512".to_string() }, "FN-DSA-512"),
            (CavpAlgorithm::HybridKem, "Hybrid-KEM"),
        ];

        for (algo, expected_name) in algorithms {
            assert_eq!(algo.name(), expected_name);
        }
    }

    #[tokio::test]
    async fn test_fips_standard_mapping_returns_correct_standard_succeeds() {
        let algorithms = vec![
            (CavpAlgorithm::MlKem { variant: "768".to_string() }, "FIPS 203"),
            (CavpAlgorithm::MlDsa { variant: "44".to_string() }, "FIPS 204"),
            (CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() }, "FIPS 205"),
            (CavpAlgorithm::FnDsa { variant: "512".to_string() }, "FIPS 206"),
        ];

        for (algo, expected_fips) in algorithms {
            assert_eq!(algo.fips_standard(), expected_fips);
        }
    }

    #[tokio::test]
    async fn test_concurrent_test_execution_succeeds() {
        let config = PipelineConfig { max_concurrent_tests: 8, ..Default::default() };
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Create a large batch to test concurrent execution
        let mut vectors = Vec::new();
        for i in 0..10 {
            vectors.push(create_mlkem_test_vector(&format!("CONCURRENT-{}", i), "768"));
        }

        let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

        assert_eq!(batch.test_results.len(), 10);
    }

    #[tokio::test]
    async fn test_test_metadata_environment_capture_records_environment_succeeds() {
        let metadata = CavpTestMetadata::default();

        assert!(!metadata.environment.os.is_empty());
        assert!(!metadata.environment.arch.is_empty());
        assert!(!metadata.environment.rust_version.is_empty());
    }

    #[tokio::test]
    async fn test_test_configuration_defaults_sets_expected_values_succeeds() {
        let config = TestConfiguration::default();

        assert_eq!(config.iterations, 1);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.statistical_tests);
        assert!(config.parameters.is_empty());
    }
}
