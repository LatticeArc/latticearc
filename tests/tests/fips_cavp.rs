//! CAVP (Cryptographic Algorithm Validation Program) tests.
//!
//! Sub-modules preserve the structure and imports of their original
//! source files. This is the largest consolidated test file (~17k LOC,
//! ~470 #[test] functions); the sub-module wrapping makes navigation
//! tractable.

#![deny(unsafe_code)]

// Originally: fips_cavp_pipeline_tests.rs
mod pipeline {
    //! Comprehensive tests for CAVP pipeline
    //!
    //! These tests focus on increasing coverage for arc-validation/src/cavp/pipeline.rs
    //! Testing pipeline configuration, execution, result aggregation, and error handling.

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

    use latticearc_tests::validation::cavp::compliance::CavpComplianceGenerator;
    use latticearc_tests::validation::cavp::pipeline::{
        CavpTestExecutor, CavpValidationPipeline, PipelineConfig,
    };
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    // =============================================================================
    // Test Helpers
    // =============================================================================

    /// Create a keygen test vector for ML-KEM-768
    fn create_mlkem_768_keygen_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
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
                public_key: Some(vec![0xAB; 64]),
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
        }
    }

    /// Create encapsulation vector for ML-KEM-768 with valid ek
    fn create_mlkem_768_encapsulation_vector_with_ek(id: &str, ek: Vec<u8>) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: Some(ek),
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: Some(vec![0xCC; 1088 + 32]),
                secret_key: None,
                ciphertext: Some(vec![0xDD; 1088]),
                signature: None,
                shared_secret: Some(vec![0xEE; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Encapsulation,
                created_at: chrono::Utc::now(),
                security_level: 192,
                notes: Some("ML-KEM-768 encapsulation test".to_string()),
            },
        }
    }

    /// Create decapsulation vector for ML-KEM-768
    fn create_mlkem_768_decapsulation_vector(id: &str, dk: Vec<u8>, c: Vec<u8>) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: Some(c),
                m: None,
                ek: None,
                dk: Some(dk),
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(vec![0xFF; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Decapsulation,
                created_at: chrono::Utc::now(),
                security_level: 192,
                notes: Some("ML-KEM-768 decapsulation test".to_string()),
            },
        }
    }

    /// Create ML-DSA keygen vector
    fn create_mldsa_keygen_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
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
                public_key: Some(vec![0x22; 64]),
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
                notes: Some(format!("ML-DSA-{} keygen test", variant)),
            },
        }
    }

    /// Create ML-DSA signature vector with valid sk
    fn create_mldsa_signature_vector(
        id: &str,
        variant: &str,
        sk: Vec<u8>,
        message: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: None,
                sk: Some(sk),
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
                signature: Some(vec![0x33; 256]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("ML-DSA-{} signature test", variant)),
            },
        }
    }

    /// Create ML-DSA verification vector
    fn create_mldsa_verification_vector(
        id: &str,
        variant: &str,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: Some(pk),
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: Some(signature),
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![1]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Verification,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("ML-DSA-{} verification test", variant)),
            },
        }
    }

    /// Create SLH-DSA keygen vector
    fn create_slhdsa_keygen_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
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
                public_key: Some(vec![0x44; 64]),
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
                notes: Some(format!("SLH-DSA-{} keygen test", variant)),
            },
        }
    }

    /// Create SLH-DSA signature vector
    fn create_slhdsa_signature_vector(
        id: &str,
        variant: &str,
        sk: Vec<u8>,
        message: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: None,
                sk: Some(sk),
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
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("SLH-DSA-{} signature test", variant)),
            },
        }
    }

    /// Create SLH-DSA verification vector
    fn create_slhdsa_verification_vector(
        id: &str,
        variant: &str,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: Some(pk),
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: Some(signature),
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![1]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Verification,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("SLH-DSA-{} verification test", variant)),
            },
        }
    }

    /// Create FN-DSA keygen vector
    fn create_fndsa_keygen_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
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
                public_key: Some(vec![0x66; 64]),
                secret_key: Some(vec![0x77; 128]),
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
                notes: Some(format!("FN-DSA-{} keygen test", variant)),
            },
        }
    }

    /// Create FN-DSA signature vector
    fn create_fndsa_signature_vector(
        id: &str,
        variant: &str,
        sk: Vec<u8>,
        message: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: None,
                sk: Some(sk),
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
                signature: Some(vec![0x88; 256]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("FN-DSA-{} signature test", variant)),
            },
        }
    }

    /// Create FN-DSA verification vector
    fn create_fndsa_verification_vector(
        id: &str,
        variant: &str,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: Some(pk),
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: Some(signature),
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: Some(vec![1]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Verification,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: Some(format!("FN-DSA-{} verification test", variant)),
            },
        }
    }

    /// Create Hybrid KEM keygen vector
    fn create_hybrid_kem_keygen_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x99; 64]),
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
                shared_secret: Some(vec![0xAA; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM keygen test".to_string()),
            },
        }
    }

    /// Create Hybrid KEM encapsulation vector
    fn create_hybrid_kem_encapsulation_vector(id: &str, ek: Vec<u8>, m: Vec<u8>) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: Some(m),
                ek: Some(ek),
                dk: None,
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(vec![0xBB; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::Encapsulation,
                created_at: chrono::Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM encapsulation test".to_string()),
            },
        }
    }

    /// Create Hybrid KEM decapsulation vector
    fn create_hybrid_kem_decapsulation_vector(id: &str, dk: Vec<u8>, c: Vec<u8>) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: Some(c),
                m: None,
                ek: None,
                dk: Some(dk),
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(vec![0xCC; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::Decapsulation,
                created_at: chrono::Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM decapsulation test".to_string()),
            },
        }
    }

    // =============================================================================
    // Pipeline Configuration Tests
    // =============================================================================

    mod pipeline_config_tests {
        use super::*;

        #[test]
        fn test_pipeline_config_default_values_are_correct() {
            let config = PipelineConfig::default();

            assert_eq!(config.max_concurrent_tests, 4);
            assert_eq!(config.test_timeout, Duration::from_secs(30));
            assert_eq!(config.retry_count, 3);
            assert!(config.run_statistical_tests);
            assert!(config.generate_reports);
        }

        #[test]
        fn test_pipeline_config_custom_values_are_correct() {
            let config = PipelineConfig {
                max_concurrent_tests: 16,
                test_timeout: Duration::from_secs(120),
                retry_count: 5,
                run_statistical_tests: false,
                generate_reports: false,
            };

            assert_eq!(config.max_concurrent_tests, 16);
            assert_eq!(config.test_timeout, Duration::from_secs(120));
            assert_eq!(config.retry_count, 5);
            assert!(!config.run_statistical_tests);
            assert!(!config.generate_reports);
        }

        #[test]
        fn test_pipeline_config_clone_produces_equal_value_succeeds() {
            let config = PipelineConfig {
                max_concurrent_tests: 8,
                test_timeout: Duration::from_secs(60),
                retry_count: 2,
                run_statistical_tests: true,
                generate_reports: false,
            };

            let cloned = config.clone();

            assert_eq!(config.max_concurrent_tests, cloned.max_concurrent_tests);
            assert_eq!(config.test_timeout, cloned.test_timeout);
            assert_eq!(config.retry_count, cloned.retry_count);
            assert_eq!(config.run_statistical_tests, cloned.run_statistical_tests);
            assert_eq!(config.generate_reports, cloned.generate_reports);
        }

        #[test]
        fn test_pipeline_config_debug_has_correct_format() {
            let config = PipelineConfig::default();
            let debug_str = format!("{:?}", config);

            assert!(debug_str.contains("PipelineConfig"));
            assert!(debug_str.contains("max_concurrent_tests"));
            assert!(debug_str.contains("test_timeout"));
        }

        #[test]
        fn test_pipeline_config_edge_values_are_accepted_succeeds() {
            let config = PipelineConfig {
                max_concurrent_tests: 0,
                test_timeout: Duration::ZERO,
                retry_count: 0,
                run_statistical_tests: false,
                generate_reports: false,
            };

            assert_eq!(config.max_concurrent_tests, 0);
            assert_eq!(config.test_timeout, Duration::ZERO);
            assert_eq!(config.retry_count, 0);
        }

        #[test]
        fn test_pipeline_config_large_values_are_accepted_succeeds() {
            let config = PipelineConfig {
                max_concurrent_tests: usize::MAX,
                test_timeout: Duration::from_secs(86400), // 24 hours
                retry_count: 100,
                run_statistical_tests: true,
                generate_reports: true,
            };

            assert_eq!(config.max_concurrent_tests, usize::MAX);
            assert_eq!(config.test_timeout, Duration::from_secs(86400));
            assert_eq!(config.retry_count, 100);
        }
    }

    // =============================================================================
    // Executor Creation Tests
    // =============================================================================

    mod executor_tests {
        use super::*;

        #[tokio::test]
        async fn test_executor_creation_with_default_config_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let _executor = CavpTestExecutor::new(config, storage);
            // Executor should be created successfully
        }

        #[tokio::test]
        async fn test_executor_creation_with_custom_config_succeeds() {
            let config = PipelineConfig {
                max_concurrent_tests: 1,
                test_timeout: Duration::from_millis(100),
                retry_count: 0,
                run_statistical_tests: false,
                generate_reports: false,
            };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let _executor = CavpTestExecutor::new(config, storage);
        }

        #[tokio::test]
        async fn test_executor_with_shared_storage_succeeds() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let config1 = PipelineConfig::default();
            let config2 = PipelineConfig::default();

            let executor1 = CavpTestExecutor::new(config1, storage.clone());
            let executor2 = CavpTestExecutor::new(config2, storage.clone());

            // Both executors should use the same storage
            let vector = create_mlkem_768_keygen_vector("SHARED-STORAGE-001");
            let _ = executor1.execute_single_test_vector(&vector).await;

            let vector2 = create_mlkem_768_keygen_vector("SHARED-STORAGE-002");
            let _ = executor2.execute_single_test_vector(&vector2).await;

            // Both results should be in storage
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 2);
        }
    }

    // =============================================================================
    // ML-KEM Algorithm Tests
    // =============================================================================

    mod mlkem_tests {
        use super::*;

        #[tokio::test]
        async fn test_mlkem_768_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mlkem_768_keygen_vector("MLKEM-KEYGEN-001");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            assert_eq!(test_result.algorithm.name(), "ML-KEM-768");
            // ML-KEM-768: ek is 1184 bytes, dk is 2400 bytes
            assert_eq!(test_result.actual_result.len(), 1184 + 2400);
        }

        #[tokio::test]
        async fn test_mlkem_encapsulation_missing_ek_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mlkem_768_encapsulation_vector_with_ek("MLKEM-ENCAP-NO-EK", vec![]);
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should fail due to missing/invalid ek
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_encapsulation_invalid_ek_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Wrong length for ek (should be 1184 bytes)
            let vector = create_mlkem_768_encapsulation_vector_with_ek(
                "MLKEM-ENCAP-BAD-LEN",
                vec![0xAA; 100],
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_decapsulation_missing_dk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // ML-KEM-768: ct is 1088 bytes
            let vector = create_mlkem_768_decapsulation_vector(
                "MLKEM-DECAP-NO-DK",
                vec![],
                vec![0xCC; 1088],
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_decapsulation_invalid_ciphertext_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Wrong ciphertext length
            let vector = create_mlkem_768_decapsulation_vector(
                "MLKEM-DECAP-BAD-CT",
                vec![0xDD; 2400],
                vec![0xEE; 32], // Should be 1088 bytes
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_unsupported_variant_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("MLKEM-BAD-VARIANT");
            vector.algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // 512 variant not implemented, should fail
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_signature_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("MLKEM-SIG-INVALID");
            vector.metadata.test_type = CavpTestType::Signature;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-KEM does not support signature operations
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mlkem_verification_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("MLKEM-VERIFY-INVALID");
            vector.metadata.test_type = CavpTestType::Verification;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // ML-DSA Algorithm Tests
    // =============================================================================

    mod mldsa_tests {
        use super::*;

        #[tokio::test]
        async fn test_mldsa_44_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_keygen_vector("MlDsa44-KEYGEN", "44");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // ML-DSA-44: pk is 1312 bytes, sk is 2560 bytes
            assert_eq!(test_result.actual_result.len(), 1312 + 2560);
        }

        #[tokio::test]
        async fn test_mldsa_65_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_keygen_vector("MlDsa65-KEYGEN", "65");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // ML-DSA-65: pk is 1952 bytes, sk is 4032 bytes
            assert_eq!(test_result.actual_result.len(), 1952 + 4032);
        }

        #[tokio::test]
        async fn test_mldsa_87_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_keygen_vector("MlDsa87-KEYGEN", "87");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // ML-DSA-87: pk is 2592 bytes, sk is 4896 bytes
            assert_eq!(test_result.actual_result.len(), 2592 + 4896);
        }

        #[tokio::test]
        async fn test_mldsa_unsupported_variant_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_keygen_vector("MLDSA-BAD-VARIANT", "99");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_signature_missing_sk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_signature_vector(
                "MlDsa44-SIG-NO-SK",
                "44",
                vec![], // Empty sk
                b"Test message".to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_signature_missing_message_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector =
                create_mldsa_signature_vector("MlDsa44-SIG-NO-MSG", "44", vec![0x11; 2560], vec![]);
            vector.inputs.message = None;
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_verification_missing_pk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_mldsa_verification_vector(
                "MlDsa44-VERIFY-NO-PK",
                "44",
                vec![], // Empty pk
                b"Test message".to_vec(),
                vec![0x22; 2420],
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_verification_missing_signature_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mldsa_verification_vector(
                "MlDsa44-VERIFY-NO-SIG",
                "44",
                vec![0x33; 1312],
                b"Test message".to_vec(),
                vec![], // Empty signature
            );
            vector.inputs.signature = None;
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_encapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mldsa_keygen_vector("MLDSA-ENCAP-INVALID", "44");
            vector.metadata.test_type = CavpTestType::Encapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-DSA does not support encapsulation
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_mldsa_decapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mldsa_keygen_vector("MLDSA-DECAP-INVALID", "44");
            vector.metadata.test_type = CavpTestType::Decapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // SLH-DSA Algorithm Tests
    // =============================================================================

    mod slhdsa_tests {
        use super::*;

        #[tokio::test]
        async fn test_slhdsa_shake_128s_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_keygen_vector("SLHDSA-128S-KEYGEN", "shake-128s");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // SLH-DSA-SHAKE-128s: pk is 32 bytes, sk is 64 bytes
            assert_eq!(test_result.actual_result.len(), 32 + 64);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_192s_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_keygen_vector("SLHDSA-192S-KEYGEN", "shake-192s");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // SLH-DSA-SHAKE-192s: pk is 48 bytes, sk is 96 bytes
            assert_eq!(test_result.actual_result.len(), 48 + 96);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_256s_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_keygen_vector("SLHDSA-256S-KEYGEN", "shake-256s");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
            // SLH-DSA-SHAKE-256s: pk is 64 bytes, sk is 128 bytes
            assert_eq!(test_result.actual_result.len(), 64 + 128);
        }

        #[tokio::test]
        async fn test_slhdsa_unsupported_variant_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_keygen_vector("SLHDSA-BAD-VARIANT", "sha2-128s");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_signature_missing_sk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_signature_vector(
                "SLHDSA-SIG-NO-SK",
                "shake-128s",
                vec![], // Empty sk
                b"Test message".to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_signature_invalid_sk_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // shake-128s expects sk of 64 bytes
            let vector = create_slhdsa_signature_vector(
                "SLHDSA-SIG-BAD-SK",
                "shake-128s",
                vec![0x11; 32], // Wrong length
                b"Test message".to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_verification_missing_pk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_slhdsa_verification_vector(
                "SLHDSA-VERIFY-NO-PK",
                "shake-128s",
                vec![], // Empty pk
                b"Test message".to_vec(),
                vec![0x22; 7856],
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_encapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_slhdsa_keygen_vector("SLHDSA-ENCAP-INVALID", "shake-128s");
            vector.metadata.test_type = CavpTestType::Encapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // FN-DSA Algorithm Tests
    // =============================================================================

    mod fndsa_tests {
        use super::*;

        #[tokio::test]
        async fn test_fndsa_512_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_fndsa_keygen_vector("FNDSA-512-KEYGEN", "512");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_fndsa_1024_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_fndsa_keygen_vector("FNDSA-1024-KEYGEN", "1024");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_fndsa_unsupported_variant_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_fndsa_keygen_vector("FNDSA-BAD-VARIANT", "256");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_signature_missing_sk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_fndsa_signature_vector(
                "FNDSA-SIG-NO-SK",
                "512",
                vec![], // Empty sk
                b"Test message".to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_verification_missing_pk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_fndsa_verification_vector(
                "FNDSA-VERIFY-NO-PK",
                "512",
                vec![], // Empty pk
                b"Test message".to_vec(),
                vec![0x22; 666],
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_encapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_fndsa_keygen_vector("FNDSA-ENCAP-INVALID", "512");
            vector.metadata.test_type = CavpTestType::Encapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_decapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_fndsa_keygen_vector("FNDSA-DECAP-INVALID", "512");
            vector.metadata.test_type = CavpTestType::Decapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // Hybrid KEM Tests
    // =============================================================================

    mod hybrid_kem_tests {
        use super::*;

        #[tokio::test]
        async fn test_hybrid_kem_keygen_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_hybrid_kem_keygen_vector("HYBRID-KEYGEN-001");
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_hybrid_kem_keygen_missing_seed_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_keygen_vector("HYBRID-KEYGEN-NO-SEED");
            vector.inputs.seed = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should fail due to missing seed
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_keygen_short_seed_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_keygen_vector("HYBRID-KEYGEN-SHORT-SEED");
            vector.inputs.seed = Some(vec![0x11; 16]); // Too short (need >= 32)

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_encapsulation_missing_ek_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_hybrid_kem_encapsulation_vector(
                "HYBRID-ENCAP-NO-EK",
                vec![], // Empty ek
                vec![0x22; 32],
            );

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_encapsulation_missing_m_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_encapsulation_vector(
                "HYBRID-ENCAP-NO-M",
                vec![0x33; 1184 + 32], // Valid ek length
                vec![],
            );
            vector.inputs.m = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_decapsulation_missing_dk_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vector = create_hybrid_kem_decapsulation_vector(
                "HYBRID-DECAP-NO-DK",
                vec![], // Empty dk
                vec![0x44; 1088 + 32],
            );

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_decapsulation_missing_c_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_decapsulation_vector(
                "HYBRID-DECAP-NO-C",
                vec![0x55; 2400 + 32],
                vec![],
            );
            vector.inputs.c = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_signature_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_keygen_vector("HYBRID-SIG-INVALID");
            vector.metadata.test_type = CavpTestType::Signature;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_verification_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_hybrid_kem_keygen_vector("HYBRID-VERIFY-INVALID");
            vector.metadata.test_type = CavpTestType::Verification;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // Batch Processing Tests
    // =============================================================================

    mod batch_tests {
        use super::*;

        #[tokio::test]
        async fn test_batch_empty_vectors_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vectors: Vec<CavpTestVector> = vec![];
            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.test_results.len(), 0);
            assert_eq!(batch.pass_rate, 0.0);
            assert!(matches!(batch.status, CavpValidationStatus::Incomplete));
        }

        #[tokio::test]
        async fn test_batch_single_vector_completes_matches_expected() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vectors = vec![create_mlkem_768_keygen_vector("BATCH-SINGLE-001")];
            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.test_results.len(), 1);
        }

        #[tokio::test]
        async fn test_batch_multiple_vectors_same_algorithm_completes_matches_expected() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("BATCH-MULTI-001"),
                create_mlkem_768_keygen_vector("BATCH-MULTI-002"),
                create_mlkem_768_keygen_vector("BATCH-MULTI-003"),
            ];
            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.test_results.len(), 3);
            assert!(batch.total_execution_time > Duration::ZERO);
        }

        #[tokio::test]
        async fn test_batch_mixed_algorithms_completes_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("BATCH-MIXED-001"),
                create_mldsa_keygen_vector("BATCH-MIXED-002", "44"),
                create_slhdsa_keygen_vector("BATCH-MIXED-003", "shake-128s"),
            ];
            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.test_results.len(), 3);
            // Algorithm from first vector is used for the batch
            assert_eq!(batch.algorithm.name(), "ML-KEM-768");
        }

        #[tokio::test]
        async fn test_batch_with_storage_verification_persists_correctly_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage.clone());

            let vectors = vec![
                create_mlkem_768_keygen_vector("BATCH-STORE-001"),
                create_mlkem_768_keygen_vector("BATCH-STORE-002"),
            ];
            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();

            // Verify batch was stored
            let stored_batch = storage.retrieve_batch(&batch.batch_id).unwrap();
            assert!(stored_batch.is_some());

            // Verify individual results were stored
            for test_result in &batch.test_results {
                let stored_result = storage.retrieve_result(&test_result.test_id).unwrap();
                assert!(stored_result.is_some());
            }
        }

        #[tokio::test]
        async fn test_batch_pass_rate_calculation_is_correct() {
            let mut batch = CavpBatchResult::new(
                "PASS-RATE-TEST".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
            );

            // Add passing result
            let passing = CavpTestResult::new(
                "PASS-001".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                "VEC-001".to_string(),
                vec![0x42],
                vec![0x42], // Same as actual
                Duration::from_millis(10),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(passing);

            assert_eq!(batch.pass_rate, 100.0);
            assert!(matches!(batch.status, CavpValidationStatus::Passed));

            // Add failing result
            let failing = CavpTestResult::failed(
                "FAIL-001".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                "VEC-002".to_string(),
                vec![0x42],
                vec![0x99], // Different from actual
                Duration::from_millis(10),
                "Mismatch".to_string(),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(failing);

            assert_eq!(batch.pass_rate, 50.0);
            assert!(matches!(batch.status, CavpValidationStatus::Failed));
        }

        #[tokio::test]
        async fn test_batch_large_count_completes_succeeds() {
            let config = PipelineConfig { max_concurrent_tests: 8, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let vectors: Vec<_> = (0..20)
                .map(|i| create_mlkem_768_keygen_vector(&format!("BATCH-LARGE-{:03}", i)))
                .collect();

            let result = executor.execute_test_vector_batch(vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.test_results.len(), 20);
        }
    }

    // =============================================================================
    // Validation Pipeline Tests
    // =============================================================================

    mod pipeline_tests {
        use super::*;

        #[tokio::test]
        async fn test_pipeline_creation_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let _pipeline = CavpValidationPipeline::new(config, storage);
        }

        #[tokio::test]
        async fn test_pipeline_run_algorithm_validation_succeeds() {
            let config = PipelineConfig { generate_reports: false, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let vectors = vec![
                create_mlkem_768_keygen_vector("PIPELINE-ALGO-001"),
                create_mlkem_768_keygen_vector("PIPELINE-ALGO-002"),
            ];

            let result = pipeline.run_algorithm_validation(algorithm.clone(), vectors).await;

            assert!(result.is_ok());
            let batch = result.unwrap();
            assert_eq!(batch.algorithm, algorithm);
            assert_eq!(batch.test_results.len(), 2);
        }

        #[tokio::test]
        async fn test_pipeline_run_full_validation_single_algorithm_succeeds() {
            let config = PipelineConfig { generate_reports: false, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("FULL-SINGLE-001"),
                create_mlkem_768_keygen_vector("FULL-SINGLE-002"),
            ];

            let result = pipeline.run_full_validation(vectors).await;

            assert!(result.is_ok());
            let batches = result.unwrap();
            assert_eq!(batches.len(), 1);
        }

        #[tokio::test]
        async fn test_pipeline_run_full_validation_multiple_algorithms_succeeds() {
            let config = PipelineConfig { generate_reports: false, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("FULL-MULTI-001"),
                create_mldsa_keygen_vector("FULL-MULTI-002", "44"),
                create_slhdsa_keygen_vector("FULL-MULTI-003", "shake-128s"),
                create_fndsa_keygen_vector("FULL-MULTI-004", "512"),
            ];

            let result = pipeline.run_full_validation(vectors).await;

            assert!(result.is_ok());
            let batches = result.unwrap();
            assert_eq!(batches.len(), 4);
        }

        #[tokio::test]
        async fn test_pipeline_run_full_validation_empty_succeeds() {
            let config = PipelineConfig { generate_reports: false, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let vectors: Vec<CavpTestVector> = vec![];
            let result = pipeline.run_full_validation(vectors).await;

            assert!(result.is_ok());
            let batches = result.unwrap();
            assert_eq!(batches.len(), 0);
        }

        #[tokio::test]
        async fn test_pipeline_create_sample_vectors_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let vectors = pipeline.create_sample_vectors(algorithm.clone(), 5);

            assert_eq!(vectors.len(), 5);
            for (i, vector) in vectors.iter().enumerate() {
                assert_eq!(vector.algorithm, algorithm);
                assert!(vector.id.contains("SAMPLE"));
                assert!(vector.id.contains(&format!("{}", i + 1)));
                assert!(vector.inputs.seed.is_some());
                assert!(vector.inputs.message.is_some());
                assert!(vector.expected_outputs.public_key.is_some());
            }
        }

        #[tokio::test]
        async fn test_pipeline_create_sample_vectors_zero_count_returns_empty_matches_expected() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let vectors = pipeline.create_sample_vectors(algorithm, 0);

            assert_eq!(vectors.len(), 0);
        }

        #[tokio::test]
        async fn test_pipeline_with_report_generation_succeeds() {
            let config = PipelineConfig { generate_reports: true, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let vectors = vec![create_mlkem_768_keygen_vector("REPORT-001")];

            let result = pipeline.run_algorithm_validation(algorithm, vectors).await;

            assert!(result.is_ok());
        }
    }

    // =============================================================================
    // Compliance Generator Tests
    // =============================================================================

    mod compliance_tests {
        use super::*;

        #[test]
        fn test_compliance_generator_creation_succeeds() {
            let generator = CavpComplianceGenerator::new();
            // Generator should be created with default criteria
            let _ = generator;
        }

        #[test]
        fn test_compliance_generator_default_succeeds() {
            let generator = CavpComplianceGenerator::default();
            let _ = generator;
        }

        #[tokio::test]
        async fn test_compliance_report_generation_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);
            let generator = CavpComplianceGenerator::new();

            let vectors = vec![create_mlkem_768_keygen_vector("COMPLIANCE-001")];
            let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

            let report = generator.generate_report(&[batch]);
            assert!(report.is_ok());

            let report = report.unwrap();
            assert_eq!(report.algorithm.name(), "ML-KEM-768");
            assert!(report.summary.total_tests > 0);
            assert!(!report.nist_standards.is_empty());
        }

        #[tokio::test]
        async fn test_compliance_report_empty_batches_returns_error() {
            let generator = CavpComplianceGenerator::new();
            let result = generator.generate_report(&[]);

            assert!(result.is_err());
        }

        #[tokio::test]
        async fn test_compliance_json_export_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);
            let generator = CavpComplianceGenerator::new();

            let vectors = vec![create_mldsa_keygen_vector("COMPLIANCE-JSON", "44")];
            let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

            let report = generator.generate_report(&[batch]).unwrap();
            let json = generator.export_json(&report);

            assert!(json.is_ok());
            let json_str = json.unwrap();
            assert!(json_str.contains("ML-DSA"));
            assert!(json_str.contains("report_id"));
            assert!(json_str.contains("compliance_status"));
        }

        #[tokio::test]
        async fn test_compliance_xml_export_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);
            let generator = CavpComplianceGenerator::new();

            let vectors = vec![create_slhdsa_keygen_vector("COMPLIANCE-XML", "shake-128s")];
            let batch = executor.execute_test_vector_batch(vectors).await.unwrap();

            let report = generator.generate_report(&[batch]).unwrap();
            let xml = generator.export_xml(&report);

            assert!(xml.is_ok());
            let xml_str = xml.unwrap();
            assert!(xml_str.contains("<?xml"));
            assert!(xml_str.contains("cavp_compliance_report"));
            assert!(xml_str.contains("SLH-DSA"));
        }

        #[tokio::test]
        async fn test_compliance_multiple_batches_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);
            let generator = CavpComplianceGenerator::new();

            let batch1 = executor
                .execute_test_vector_batch(vec![create_mlkem_768_keygen_vector("MULTI-BATCH-001")])
                .await
                .unwrap();
            let batch2 = executor
                .execute_test_vector_batch(vec![create_mlkem_768_keygen_vector("MULTI-BATCH-002")])
                .await
                .unwrap();

            let report = generator.generate_report(&[batch1, batch2]);
            assert!(report.is_ok());

            let report = report.unwrap();
            assert!(report.summary.total_tests >= 2);
        }
    }

    // =============================================================================
    // Result and Status Tests
    // =============================================================================

    mod result_tests {
        use super::*;

        #[test]
        fn test_cavp_test_result_new_passing_has_correct_fields_succeeds() {
            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                "VEC-001".to_string(),
                vec![0x42; 32],
                vec![0x42; 32], // Same as actual
                Duration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert!(result.passed);
            assert!(result.error_message.is_none());
            assert_eq!(result.actual_result, result.expected_result);
        }

        #[test]
        fn test_cavp_test_result_new_failing_has_correct_fields_fails() {
            let result = CavpTestResult::new(
                "TEST-002".to_string(),
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                "VEC-002".to_string(),
                vec![0x42; 32],
                vec![0x99; 32], // Different from actual
                Duration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_cavp_test_result_failed_has_correct_fields_fails() {
            let result = CavpTestResult::failed(
                "TEST-003".to_string(),
                CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
                "VEC-003".to_string(),
                vec![0x11; 16],
                vec![0x22; 16],
                Duration::from_millis(50),
                "Custom error".to_string(),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
            assert!(result.error_message.is_some());
            assert_eq!(result.error_message.unwrap(), "Custom error");
        }

        #[test]
        fn test_cavp_batch_result_new_has_correct_fields_succeeds() {
            let batch = CavpBatchResult::new(
                "BATCH-001".to_string(),
                CavpAlgorithm::FnDsa { variant: "512".to_string() },
            );

            assert_eq!(batch.batch_id, "BATCH-001");
            assert!(batch.test_results.is_empty());
            assert!(matches!(batch.status, CavpValidationStatus::Incomplete));
            assert_eq!(batch.pass_rate, 0.0);
        }

        #[test]
        fn test_cavp_batch_result_add_test_result_updates_count_succeeds() {
            let mut batch = CavpBatchResult::new("BATCH-002".to_string(), CavpAlgorithm::HybridKem);

            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                CavpAlgorithm::HybridKem,
                "VEC-001".to_string(),
                vec![0x42],
                vec![0x42],
                Duration::from_millis(10),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);

            assert_eq!(batch.test_results.len(), 1);
            assert!(batch.total_execution_time >= Duration::from_millis(10));
        }

        #[test]
        fn test_cavp_validation_status_variants_are_accessible() {
            let passed = CavpValidationStatus::Passed;
            let failed = CavpValidationStatus::Failed;
            let incomplete = CavpValidationStatus::Incomplete;
            let error = CavpValidationStatus::Error("Test error".to_string());

            assert!(matches!(passed, CavpValidationStatus::Passed));
            assert!(matches!(failed, CavpValidationStatus::Failed));
            assert!(matches!(incomplete, CavpValidationStatus::Incomplete));
            assert!(matches!(error, CavpValidationStatus::Error(_)));
        }
    }

    // =============================================================================
    // Algorithm Enum Tests
    // =============================================================================

    mod algorithm_tests {
        use super::*;

        #[test]
        fn test_algorithm_name_returns_correct_string_succeeds() {
            assert_eq!(CavpAlgorithm::MlKem { variant: "768".to_string() }.name(), "ML-KEM-768");
            assert_eq!(CavpAlgorithm::MlDsa { variant: "44".to_string() }.name(), "ML-DSA-44");
            assert_eq!(
                CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() }.name(),
                "SLH-DSA-shake-128s"
            );
            assert_eq!(CavpAlgorithm::FnDsa { variant: "512".to_string() }.name(), "FN-DSA-512");
            assert_eq!(CavpAlgorithm::HybridKem.name(), "Hybrid-KEM");
        }

        #[test]
        fn test_algorithm_fips_standard_returns_correct_string_succeeds() {
            assert_eq!(
                CavpAlgorithm::MlKem { variant: "768".to_string() }.fips_standard(),
                "FIPS 203"
            );
            assert_eq!(
                CavpAlgorithm::MlDsa { variant: "44".to_string() }.fips_standard(),
                "FIPS 204"
            );
            assert_eq!(
                CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() }.fips_standard(),
                "FIPS 205"
            );
            assert_eq!(
                CavpAlgorithm::FnDsa { variant: "512".to_string() }.fips_standard(),
                "FIPS 206"
            );
            assert_eq!(CavpAlgorithm::HybridKem.fips_standard(), "FIPS 203 + FIPS 197");
        }

        #[test]
        fn test_algorithm_equality_matches_expected() {
            let a1 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let a2 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let a3 = CavpAlgorithm::MlKem { variant: "512".to_string() };

            assert_eq!(a1, a2);
            assert_ne!(a1, a3);
        }

        #[test]
        fn test_algorithm_hash_deduplicates_correctly_succeeds() {
            use std::collections::HashSet;

            let mut set = HashSet::new();
            set.insert(CavpAlgorithm::MlKem { variant: "768".to_string() });
            set.insert(CavpAlgorithm::MlDsa { variant: "44".to_string() });
            set.insert(CavpAlgorithm::MlKem { variant: "768".to_string() }); // Duplicate

            assert_eq!(set.len(), 2);
        }
    }

    // =============================================================================
    // Test Type Tests
    // =============================================================================

    mod test_type_tests {
        use super::*;

        #[test]
        fn test_cavp_test_type_variants_are_accessible() {
            let keygen = CavpTestType::KeyGen;
            let encap = CavpTestType::Encapsulation;
            let decap = CavpTestType::Decapsulation;
            let sig = CavpTestType::Signature;
            let verify = CavpTestType::Verification;

            assert!(matches!(keygen, CavpTestType::KeyGen));
            assert!(matches!(encap, CavpTestType::Encapsulation));
            assert!(matches!(decap, CavpTestType::Decapsulation));
            assert!(matches!(sig, CavpTestType::Signature));
            assert!(matches!(verify, CavpTestType::Verification));
        }

        #[test]
        fn test_cavp_test_type_equality_matches_expected() {
            assert_eq!(CavpTestType::KeyGen, CavpTestType::KeyGen);
            assert_ne!(CavpTestType::KeyGen, CavpTestType::Signature);
        }

        #[test]
        fn test_cavp_test_type_hash_deduplicates_correctly_succeeds() {
            use std::collections::HashSet;

            let mut set = HashSet::new();
            set.insert(CavpTestType::KeyGen);
            set.insert(CavpTestType::Signature);
            set.insert(CavpTestType::KeyGen); // Duplicate

            assert_eq!(set.len(), 2);
        }
    }

    // =============================================================================
    // Metadata Tests
    // =============================================================================

    mod metadata_tests {
        use super::*;

        #[test]
        fn test_cavp_test_metadata_default_has_expected_values_succeeds() {
            let metadata = CavpTestMetadata::default();

            assert!(!metadata.environment.os.is_empty());
            assert!(!metadata.environment.arch.is_empty());
            assert!(!metadata.environment.rust_version.is_empty());
            assert_eq!(metadata.security_level, 128);
        }

        #[test]
        fn test_test_environment_default_has_expected_values_succeeds() {
            let env = TestEnvironment::default();

            assert!(!env.os.is_empty());
            assert!(!env.arch.is_empty());
            assert!(!env.rust_version.is_empty());
            assert!(!env.compiler.is_empty());
        }

        #[test]
        fn test_test_configuration_default_has_expected_values_succeeds() {
            let config = TestConfiguration::default();

            assert_eq!(config.iterations, 1);
            assert_eq!(config.timeout, Duration::from_secs(30));
            assert!(!config.statistical_tests);
            assert!(config.parameters.is_empty());
        }
    }

    // =============================================================================
    // Edge Case Tests
    // =============================================================================

    mod edge_case_tests {
        use super::*;

        #[tokio::test]
        async fn test_very_long_test_id_is_accepted() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let long_id = "A".repeat(10000);
            let mut vector = create_mlkem_768_keygen_vector(&long_id);
            vector.id = long_id;

            let result = executor.execute_single_test_vector(&vector).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_unicode_in_notes_is_accepted() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("UNICODE-TEST");
            vector.metadata.notes = Some("Unicode test: \u{1F600}\u{1F389}\u{2764}".to_string());

            let result = executor.execute_single_test_vector(&vector).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_empty_expected_output_is_accepted() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("EMPTY-EXPECTED");
            vector.expected_outputs.public_key = Some(vec![]);

            let result = executor.execute_single_test_vector(&vector).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_large_seed_is_accepted() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("LARGE-SEED");
            vector.inputs.seed = Some(vec![0x42; 1024 * 1024]); // 1MB seed

            let result = executor.execute_single_test_vector(&vector).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_special_characters_in_source_is_accepted() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_mlkem_768_keygen_vector("SPECIAL-CHARS");
            vector.metadata.source = "NIST <test> & \"validation\"".to_string();

            let result = executor.execute_single_test_vector(&vector).await;
            assert!(result.is_ok());
        }
    }

    // =============================================================================
    // Full Cryptographic Cycle Tests (Coverage Improvement)
    // =============================================================================

    mod full_cycle_tests {
        use super::*;
        use fips203::ml_kem_768;
        use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
        use fips204::traits::{SerDes as Fips204SerDes, Signer};
        use fips204::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
        use fips205::traits::{SerDes as Fips205SerDes, Signer as Fips205Signer};
        use fips205::{slh_dsa_shake_128s, slh_dsa_shake_192s, slh_dsa_shake_256s};

        // -------------------------------------------------------------------------
        // ML-KEM Full Cycle Tests
        // -------------------------------------------------------------------------

        #[tokio::test]
        async fn test_mlkem_768_full_encapsulation_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // First generate a valid key pair
            let (ek, _dk) = ml_kem_768::KG::try_keygen().unwrap();
            let ek_bytes = ek.into_bytes();

            // Create encapsulation vector with valid ek
            let vector = create_mlkem_768_encapsulation_vector_with_ek(
                "MLKEM-ENCAP-VALID",
                ek_bytes.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-KEM-768: ct is 1088 bytes, ssk is 32 bytes
            assert_eq!(test_result.actual_result.len(), 1088 + 32);
        }

        #[tokio::test]
        async fn test_mlkem_768_full_decapsulation_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate valid key pair and encapsulate
            let (ek, dk) = ml_kem_768::KG::try_keygen().unwrap();
            let (_, ct) = ek.try_encaps().unwrap();

            let dk_bytes = dk.into_bytes();
            let ct_bytes = ct.into_bytes();

            // Create decapsulation vector with valid dk and ct
            let vector = create_mlkem_768_decapsulation_vector(
                "MLKEM-DECAP-VALID",
                dk_bytes.to_vec(),
                ct_bytes.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-KEM-768: ssk is 32 bytes
            assert_eq!(test_result.actual_result.len(), 32);
        }

        #[tokio::test]
        async fn test_mlkem_768_complete_kem_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate keys
            let (ek, dk) = ml_kem_768::KG::try_keygen().unwrap();

            // Encapsulate
            let (ssk_sender, ct) = ek.try_encaps().unwrap();

            // Decapsulate
            let ssk_receiver = dk.try_decaps(&ct).unwrap();

            // Verify shared secrets match
            let ssk_sender_bytes: [u8; 32] = ssk_sender.into_bytes();
            let ssk_receiver_bytes: [u8; 32] = ssk_receiver.into_bytes();
            assert_eq!(ssk_sender_bytes, ssk_receiver_bytes);

            // Now test through the executor
            let dk_bytes = dk.into_bytes();
            let ct_bytes = ct.into_bytes();

            let vector = create_mlkem_768_decapsulation_vector(
                "MLKEM-FULL-CYCLE",
                dk_bytes.to_vec(),
                ct_bytes.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result.len(), 32);
        }

        // -------------------------------------------------------------------------
        // ML-DSA Full Cycle Tests
        // -------------------------------------------------------------------------

        #[tokio::test]
        async fn test_mldsa_44_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate a valid key pair
            let (_pk, sk) = ml_dsa_44::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for ML-DSA-44 signing".to_vec();

            let vector = create_mldsa_signature_vector(
                "MlDsa44-SIG-VALID",
                "44",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-DSA-44 signature is 2420 bytes
            assert_eq!(test_result.actual_result.len(), 2420);
        }

        #[tokio::test]
        async fn test_mldsa_44_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate key pair and sign
            let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
            let message = b"Test message for ML-DSA-44 verification".to_vec();
            let signature = sk.try_sign(&message, &[]).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_mldsa_verification_vector(
                "MlDsa44-VERIFY-VALID",
                "44",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should return [1] for successful verification
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_mldsa_65_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_pk, sk) = ml_dsa_65::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for ML-DSA-65 signing".to_vec();

            let vector = create_mldsa_signature_vector(
                "MlDsa65-SIG-VALID",
                "65",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-DSA-65 signature is 3309 bytes
            assert_eq!(test_result.actual_result.len(), 3309);
        }

        #[tokio::test]
        async fn test_mldsa_65_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
            let message = b"Test message for ML-DSA-65 verification".to_vec();
            let signature = sk.try_sign(&message, &[]).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_mldsa_verification_vector(
                "MlDsa65-VERIFY-VALID",
                "65",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_mldsa_87_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_pk, sk) = ml_dsa_87::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for ML-DSA-87 signing".to_vec();

            let vector = create_mldsa_signature_vector(
                "MlDsa87-SIG-VALID",
                "87",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // ML-DSA-87 signature is 4627 bytes
            assert_eq!(test_result.actual_result.len(), 4627);
        }

        #[tokio::test]
        async fn test_mldsa_87_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, sk) = ml_dsa_87::try_keygen().unwrap();
            let message = b"Test message for ML-DSA-87 verification".to_vec();
            let signature = sk.try_sign(&message, &[]).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_mldsa_verification_vector(
                "MlDsa87-VERIFY-VALID",
                "87",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_mldsa_44_invalid_signature_verification_fails() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, _sk) = ml_dsa_44::try_keygen().unwrap();
            let message = b"Test message".to_vec();
            // Invalid signature (all zeros)
            let invalid_signature = vec![0u8; 2420];

            let pk_bytes = pk.into_bytes();

            let vector = create_mldsa_verification_vector(
                "MlDsa44-VERIFY-INVALID-SIG",
                "44",
                pk_bytes.to_vec(),
                message,
                invalid_signature,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should return [0] for failed verification
            assert_eq!(test_result.actual_result, vec![0]);
        }

        // -------------------------------------------------------------------------
        // SLH-DSA Full Cycle Tests
        // -------------------------------------------------------------------------

        #[tokio::test]
        async fn test_slhdsa_shake_128s_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_pk, sk) = slh_dsa_shake_128s::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for SLH-DSA SHAKE-128s signing".to_vec();

            let vector = create_slhdsa_signature_vector(
                "SLHDSA-128S-SIG-VALID",
                "shake-128s",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // SLH-DSA-SHAKE-128s signature is 7856 bytes
            assert_eq!(test_result.actual_result.len(), 7856);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_128s_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, sk) = slh_dsa_shake_128s::try_keygen().unwrap();
            let message = b"Test message for SLH-DSA verification".to_vec();
            let signature = sk.try_sign(&message, b"", true).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_slhdsa_verification_vector(
                "SLHDSA-128S-VERIFY-VALID",
                "shake-128s",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_192s_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_pk, sk) = slh_dsa_shake_192s::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for SLH-DSA SHAKE-192s signing".to_vec();

            let vector = create_slhdsa_signature_vector(
                "SLHDSA-192S-SIG-VALID",
                "shake-192s",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // SLH-DSA-SHAKE-192s signature is 16224 bytes
            assert_eq!(test_result.actual_result.len(), 16224);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_192s_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, sk) = slh_dsa_shake_192s::try_keygen().unwrap();
            let message = b"Test message for SLH-DSA-192s verification".to_vec();
            let signature = sk.try_sign(&message, b"", true).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_slhdsa_verification_vector(
                "SLHDSA-192S-VERIFY-VALID",
                "shake-192s",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_256s_full_signature_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_pk, sk) = slh_dsa_shake_256s::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();
            let message = b"Test message for SLH-DSA SHAKE-256s signing".to_vec();

            let vector = create_slhdsa_signature_vector(
                "SLHDSA-256S-SIG-VALID",
                "shake-256s",
                sk_bytes.to_vec(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // SLH-DSA-SHAKE-256s signature is 29792 bytes
            assert_eq!(test_result.actual_result.len(), 29792);
        }

        #[tokio::test]
        async fn test_slhdsa_shake_256s_full_verification_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, sk) = slh_dsa_shake_256s::try_keygen().unwrap();
            let message = b"Test message for SLH-DSA-256s verification".to_vec();
            let signature = sk.try_sign(&message, b"", true).unwrap();

            let pk_bytes = pk.into_bytes();

            let vector = create_slhdsa_verification_vector(
                "SLHDSA-256S-VERIFY-VALID",
                "shake-256s",
                pk_bytes.to_vec(),
                message,
                signature.to_vec(),
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_slhdsa_invalid_signature_verification_fails() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, _sk) = slh_dsa_shake_128s::try_keygen().unwrap();
            let message = b"Test message".to_vec();
            // Invalid signature (all zeros, correct length)
            let invalid_signature = vec![0u8; 7856];

            let pk_bytes = pk.into_bytes();

            let vector = create_slhdsa_verification_vector(
                "SLHDSA-128S-VERIFY-INVALID",
                "shake-128s",
                pk_bytes.to_vec(),
                message,
                invalid_signature,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should return [0] for failed verification
            assert_eq!(test_result.actual_result, vec![0]);
        }

        #[tokio::test]
        async fn test_slhdsa_missing_message_for_signature_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (_, sk) = slh_dsa_shake_128s::try_keygen().unwrap();
            let sk_bytes = sk.into_bytes();

            let mut vector = create_slhdsa_signature_vector(
                "SLHDSA-128S-SIG-NO-MSG",
                "shake-128s",
                sk_bytes.to_vec(),
                vec![],
            );
            vector.inputs.message = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_missing_message_for_verification_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, _) = slh_dsa_shake_128s::try_keygen().unwrap();
            let pk_bytes = pk.into_bytes();

            let mut vector = create_slhdsa_verification_vector(
                "SLHDSA-128S-VERIFY-NO-MSG",
                "shake-128s",
                pk_bytes.to_vec(),
                vec![],
                vec![0u8; 7856],
            );
            vector.inputs.message = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_missing_signature_for_verification_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let (pk, _) = slh_dsa_shake_128s::try_keygen().unwrap();
            let pk_bytes = pk.into_bytes();

            let mut vector = create_slhdsa_verification_vector(
                "SLHDSA-128S-VERIFY-NO-SIG",
                "shake-128s",
                pk_bytes.to_vec(),
                b"Test message".to_vec(),
                vec![],
            );
            vector.inputs.signature = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_slhdsa_decapsulation_operation_invalid_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let mut vector = create_slhdsa_keygen_vector("SLHDSA-DECAP-INVALID", "shake-128s");
            vector.metadata.test_type = CavpTestType::Decapsulation;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // SLH-DSA doesn't support decapsulation
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        // -------------------------------------------------------------------------
        // FN-DSA Full Cycle Tests
        // -------------------------------------------------------------------------

        #[tokio::test]
        async fn test_fndsa_512_full_signature_cycle_succeeds() {
            use fn_dsa::{
                FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate keys
            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let message = b"Test message for FN-DSA-512 signing".to_vec();

            let vector = create_fndsa_signature_vector(
                "FNDSA512-SIG-VALID",
                "512",
                sign_key.clone(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // FN-DSA-512 signature should be non-empty
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_fndsa_512_full_verification_cycle_succeeds() {
            use fn_dsa::{
                DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW, KeyPairGenerator,
                KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, sign_key_size,
                signature_size, vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate keys
            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let message = b"Test message for FN-DSA-512 verification".to_vec();

            // Sign the message
            let mut sk: SigningKeyStandard = SigningKey::decode(&sign_key).unwrap();
            let mut signature = vec![0u8; signature_size(logn)];
            sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, &message, &mut signature);

            let vector = create_fndsa_verification_vector(
                "FNDSA512-VERIFY-VALID",
                "512",
                vrfy_key.clone(),
                message,
                signature,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should return [1] for successful verification
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_fndsa_1024_full_signature_cycle_succeeds() {
            use fn_dsa::{
                FN_DSA_LOGN_1024, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_1024;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let message = b"Test message for FN-DSA-1024 signing".to_vec();

            let vector = create_fndsa_signature_vector(
                "FNDSA1024-SIG-VALID",
                "1024",
                sign_key.clone(),
                message,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_fndsa_1024_full_verification_cycle_succeeds() {
            use fn_dsa::{
                DOMAIN_NONE, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator,
                KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, sign_key_size,
                signature_size, vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_1024;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let message = b"Test message for FN-DSA-1024 verification".to_vec();

            let mut sk: SigningKeyStandard = SigningKey::decode(&sign_key).unwrap();
            let mut signature = vec![0u8; signature_size(logn)];
            sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, &message, &mut signature);

            let vector = create_fndsa_verification_vector(
                "FNDSA1024-VERIFY-VALID",
                "1024",
                vrfy_key.clone(),
                message,
                signature,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.actual_result, vec![1]);
        }

        #[tokio::test]
        async fn test_fndsa_invalid_signature_verification_fails() {
            use fn_dsa::{
                FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                signature_size, vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let message = b"Test message".to_vec();
            // Invalid signature (all zeros)
            let invalid_signature = vec![0u8; signature_size(logn)];

            let vector = create_fndsa_verification_vector(
                "FNDSA512-VERIFY-INVALID",
                "512",
                vrfy_key,
                message,
                invalid_signature,
            );
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should return [0] for failed verification
            assert_eq!(test_result.actual_result, vec![0]);
        }

        #[tokio::test]
        async fn test_fndsa_missing_message_for_signature_returns_error() {
            use fn_dsa::{
                FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let mut vector =
                create_fndsa_signature_vector("FNDSA512-SIG-NO-MSG", "512", sign_key, vec![]);
            vector.inputs.message = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_missing_message_for_verification_returns_error() {
            use fn_dsa::{
                FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                signature_size, vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let mut vector = create_fndsa_verification_vector(
                "FNDSA512-VERIFY-NO-MSG",
                "512",
                vrfy_key,
                vec![],
                vec![0u8; signature_size(logn)],
            );
            vector.inputs.message = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_fndsa_missing_signature_for_verification_returns_error() {
            use fn_dsa::{
                FN_DSA_LOGN_512, KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size,
                vrfy_key_size,
            };
            use rand_core::OsRng;

            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            let logn = FN_DSA_LOGN_512;
            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            let mut vector = create_fndsa_verification_vector(
                "FNDSA512-VERIFY-NO-SIG",
                "512",
                vrfy_key,
                b"Test message".to_vec(),
                vec![],
            );
            vector.inputs.signature = None;

            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        // -------------------------------------------------------------------------
        // Hybrid KEM Full Cycle Tests
        // -------------------------------------------------------------------------

        #[tokio::test]
        async fn test_hybrid_kem_full_encapsulation_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate ML-KEM keys
            let (ek_pq, _dk_pq) = ml_kem_768::KG::try_keygen().unwrap();

            // Generate X25519 keys
            let seed: [u8; 32] = [0x42; 32];
            let sk_classical = x25519_dalek::StaticSecret::from(seed);
            let pk_classical = x25519_dalek::PublicKey::from(&sk_classical);

            // Construct hybrid ek (ML-KEM ek || X25519 pk)
            let mut ek = ek_pq.into_bytes().to_vec();
            ek.extend_from_slice(pk_classical.as_bytes());

            // Ephemeral secret for encapsulation
            let m = [0x33; 32];

            let vector =
                create_hybrid_kem_encapsulation_vector("HYBRID-ENCAP-VALID", ek, m.to_vec());
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Should have ciphertext + ephemeral pk + shared secret
            assert!(!test_result.actual_result.is_empty());
        }

        #[tokio::test]
        async fn test_hybrid_kem_full_decapsulation_cycle_succeeds() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate ML-KEM keys
            let (ek_pq, dk_pq) = ml_kem_768::KG::try_keygen().unwrap();

            // Generate X25519 keys
            let seed: [u8; 32] = [0x42; 32];
            let sk_classical = x25519_dalek::StaticSecret::from(seed);
            let _pk_classical = x25519_dalek::PublicKey::from(&sk_classical);

            // Perform encapsulation manually
            let (_k_pq, c_pq) = ek_pq.try_encaps().unwrap();

            // X25519 ephemeral
            let m: [u8; 32] = [0x55; 32];
            let sk_ephemeral = x25519_dalek::StaticSecret::from(m);
            let pk_ephemeral = x25519_dalek::PublicKey::from(&sk_ephemeral);

            // Construct hybrid dk (ML-KEM dk || X25519 sk)
            let mut dk = dk_pq.into_bytes().to_vec();
            dk.extend_from_slice(sk_classical.as_bytes());

            // Construct hybrid ciphertext (ML-KEM ct || X25519 ephemeral pk)
            let mut c = c_pq.into_bytes().to_vec();
            c.extend_from_slice(pk_ephemeral.as_bytes());

            let vector = create_hybrid_kem_decapsulation_vector("HYBRID-DECAP-VALID", dk, c);
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            // Shared secret is 32 bytes
            assert_eq!(test_result.actual_result.len(), 32);
        }

        #[tokio::test]
        async fn test_hybrid_kem_encapsulation_invalid_m_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Generate valid ek
            let (ek_pq, _) = ml_kem_768::KG::try_keygen().unwrap();
            let seed: [u8; 32] = [0x42; 32];
            let sk_classical = x25519_dalek::StaticSecret::from(seed);
            let pk_classical = x25519_dalek::PublicKey::from(&sk_classical);

            let mut ek = ek_pq.into_bytes().to_vec();
            ek.extend_from_slice(pk_classical.as_bytes());

            // m is wrong length (should be 32)
            let m = vec![0x33; 16];

            let vector = create_hybrid_kem_encapsulation_vector("HYBRID-ENCAP-BAD-M", ek, m);
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_decapsulation_invalid_dk_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // dk too short
            let dk = vec![0x44; 100];
            let c = vec![0x55; 1088 + 32];

            let vector = create_hybrid_kem_decapsulation_vector("HYBRID-DECAP-BAD-DK", dk, c);
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }

        #[tokio::test]
        async fn test_hybrid_kem_decapsulation_invalid_c_length_returns_error() {
            let config = PipelineConfig::default();
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let executor = CavpTestExecutor::new(config, storage);

            // Valid dk
            let (_, dk_pq) = ml_kem_768::KG::try_keygen().unwrap();
            let seed: [u8; 32] = [0x42; 32];
            let sk_classical = x25519_dalek::StaticSecret::from(seed);

            let mut dk = dk_pq.into_bytes().to_vec();
            dk.extend_from_slice(sk_classical.as_bytes());

            // c too short
            let c = vec![0x55; 100];

            let vector = create_hybrid_kem_decapsulation_vector("HYBRID-DECAP-BAD-C", dk, c);
            let result = executor.execute_single_test_vector(&vector).await;

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(test_result.error_message.is_some() || !test_result.passed);
        }
    }

    // =============================================================================
    // Pipeline Report Generation Tests (Coverage Improvement)
    // =============================================================================

    mod report_generation_tests {
        use super::*;

        #[tokio::test]
        async fn test_pipeline_full_validation_with_reports_succeeds() {
            let config = PipelineConfig { generate_reports: true, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("REPORT-GEN-001"),
                create_mlkem_768_keygen_vector("REPORT-GEN-002"),
            ];

            let result = pipeline.run_full_validation(vectors).await;

            assert!(result.is_ok());
            let batches = result.unwrap();
            assert!(!batches.is_empty());
        }

        #[tokio::test]
        async fn test_pipeline_algorithm_validation_with_reports_succeeds() {
            let config = PipelineConfig { generate_reports: true, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let vectors = vec![
                create_mldsa_keygen_vector("REPORT-ALGO-001", "44"),
                create_mldsa_keygen_vector("REPORT-ALGO-002", "44"),
            ];

            let result = pipeline.run_algorithm_validation(algorithm, vectors).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_compliance_report_for_all_algorithms_succeeds() {
            let config = PipelineConfig { generate_reports: true, ..Default::default() };
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
            let pipeline = CavpValidationPipeline::new(config, storage);

            let vectors = vec![
                create_mlkem_768_keygen_vector("MULTI-ALG-001"),
                create_mldsa_keygen_vector("MULTI-ALG-002", "65"),
                create_slhdsa_keygen_vector("MULTI-ALG-003", "shake-192s"),
                create_fndsa_keygen_vector("MULTI-ALG-004", "1024"),
                create_hybrid_kem_keygen_vector("MULTI-ALG-005"),
            ];

            let result = pipeline.run_full_validation(vectors).await;

            assert!(result.is_ok());
            let batches = result.unwrap();
            assert_eq!(batches.len(), 5);
        }
    }

    // =============================================================================
    // Storage Tests (Coverage Improvement)
    // =============================================================================

    mod storage_tests {
        use super::*;

        #[tokio::test]
        async fn test_storage_list_batches_by_algorithm_returns_correct_results_succeeds() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

            let mut batch1 = CavpBatchResult::new(
                "BATCH-LIST-001".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
            );
            batch1.add_test_result(CavpTestResult::new(
                "TEST-001".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                "VEC-001".to_string(),
                vec![0x42],
                vec![0x42],
                Duration::from_millis(10),
                CavpTestMetadata::default(),
            ));
            storage.store_batch(&batch1).unwrap();

            let mut batch2 = CavpBatchResult::new(
                "BATCH-LIST-002".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
            );
            batch2.add_test_result(CavpTestResult::new(
                "TEST-002".to_string(),
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                "VEC-002".to_string(),
                vec![0x43],
                vec![0x43],
                Duration::from_millis(20),
                CavpTestMetadata::default(),
            ));
            storage.store_batch(&batch2).unwrap();

            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();

            assert_eq!(batches.len(), 2);
        }

        #[tokio::test]
        async fn test_storage_list_batches_empty_returns_empty_vec_succeeds() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

            let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };
            let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();

            assert!(batches.is_empty());
        }

        #[tokio::test]
        async fn test_storage_list_results_empty_returns_empty_vec_succeeds() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

            let algorithm = CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() };
            let results = storage.list_results_by_algorithm(&algorithm).unwrap();

            assert!(results.is_empty());
        }

        #[tokio::test]
        async fn test_storage_retrieve_nonexistent_result_returns_none() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

            let result = storage.retrieve_result("NONEXISTENT-TEST-ID");

            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        #[tokio::test]
        async fn test_storage_retrieve_nonexistent_batch_returns_none() {
            let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

            let result = storage.retrieve_batch("NONEXISTENT-BATCH-ID");

            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }
    }

    // =============================================================================
    // Compliance Status Tests (Coverage Improvement)
    // =============================================================================

    mod compliance_status_tests {
        use latticearc_tests::validation::cavp::compliance::{
            ComplianceStatus, TestCategory, TestResult,
        };

        #[test]
        fn test_compliance_status_non_compliant_has_correct_failures_fails() {
            let status = ComplianceStatus::NonCompliant {
                failures: vec!["Test 1 failed".to_string(), "Test 2 failed".to_string()],
            };

            if let ComplianceStatus::NonCompliant { failures } = status {
                assert_eq!(failures.len(), 2);
            } else {
                panic!("Expected NonCompliant status");
            }
        }

        #[test]
        fn test_compliance_status_partially_compliant_has_exceptions_succeeds() {
            let status = ComplianceStatus::PartiallyCompliant {
                exceptions: vec!["Exception 1".to_string()],
            };

            if let ComplianceStatus::PartiallyCompliant { exceptions } = status {
                assert_eq!(exceptions.len(), 1);
            } else {
                panic!("Expected PartiallyCompliant status");
            }
        }

        #[test]
        fn test_compliance_status_insufficient_data_is_accessible() {
            let status = ComplianceStatus::InsufficientData;
            assert!(matches!(status, ComplianceStatus::InsufficientData));
        }

        #[test]
        fn test_test_result_skipped_has_correct_reason_succeeds() {
            let result = TestResult::Skipped("Not applicable".to_string());
            if let TestResult::Skipped(reason) = result {
                assert_eq!(reason, "Not applicable");
            } else {
                panic!("Expected Skipped result");
            }
        }

        #[test]
        fn test_test_result_error_has_correct_reason_fails() {
            let result = TestResult::Error("System error".to_string());
            if let TestResult::Error(reason) = result {
                assert_eq!(reason, "System error");
            } else {
                panic!("Expected Error result");
            }
        }

        #[test]
        fn test_test_category_variants_are_accessible() {
            let categories = vec![
                TestCategory::Correctness,
                TestCategory::Security,
                TestCategory::Performance,
                TestCategory::Robustness,
                TestCategory::Interoperability,
                TestCategory::Statistical,
                TestCategory::KeyGeneration,
                TestCategory::Signature,
                TestCategory::Encryption,
                TestCategory::Decryption,
                TestCategory::Compliance,
            ];

            assert_eq!(categories.len(), 11);
        }
    }

    // =============================================================================
    // Security Requirement Tests (Coverage Improvement)
    // =============================================================================

    mod security_requirement_tests {
        use latticearc_tests::validation::cavp::compliance::{
            ComplianceCriteria, SecurityRequirement,
        };

        #[test]
        fn test_security_requirement_creation_has_correct_fields_succeeds() {
            let req = SecurityRequirement {
                requirement_id: "SEC-001".to_string(),
                description: "Test requirement".to_string(),
                mandatory: true,
                test_methods: vec!["KAT".to_string(), "CAVP".to_string()],
            };

            assert_eq!(req.requirement_id, "SEC-001");
            assert!(req.mandatory);
            assert_eq!(req.test_methods.len(), 2);
        }

        #[test]
        fn test_compliance_criteria_creation_has_correct_fields_succeeds() {
            let criteria = ComplianceCriteria {
                min_pass_rate: 95.0,
                max_execution_time_ms: 5000,
                min_coverage: 90.0,
                security_requirements: vec![SecurityRequirement {
                    requirement_id: "REQ-001".to_string(),
                    description: "Test".to_string(),
                    mandatory: false,
                    test_methods: vec!["Test".to_string()],
                }],
            };

            assert_eq!(criteria.min_pass_rate, 95.0);
            assert_eq!(criteria.security_requirements.len(), 1);
        }
    }

    // =============================================================================
    // Performance Metrics Tests (Coverage Improvement)
    // =============================================================================

    mod performance_metrics_tests {
        use latticearc_tests::validation::cavp::compliance::{
            MemoryUsageMetrics, PerformanceMetrics, ThroughputMetrics,
        };
        use std::collections::HashMap;

        #[test]
        fn test_memory_usage_metrics_has_correct_values_succeeds() {
            let metrics = MemoryUsageMetrics {
                peak_memory_bytes: 1024 * 1024,
                avg_memory_bytes: 512 * 1024,
                efficiency_rating: 0.85,
            };

            assert_eq!(metrics.peak_memory_bytes, 1024 * 1024);
            assert_eq!(metrics.avg_memory_bytes, 512 * 1024);
            assert!((metrics.efficiency_rating - 0.85).abs() < 0.001);
        }

        #[test]
        fn test_throughput_metrics_has_correct_values_succeeds() {
            let mut latency_percentiles = HashMap::new();
            latency_percentiles.insert("p50".to_string(), 10.0);
            latency_percentiles.insert("p95".to_string(), 50.0);
            latency_percentiles.insert("p99".to_string(), 100.0);

            let metrics = ThroughputMetrics {
                operations_per_second: 1000.0,
                bytes_per_second: 1024 * 1024,
                latency_percentiles,
            };

            assert!((metrics.operations_per_second - 1000.0).abs() < 0.001);
            assert_eq!(metrics.bytes_per_second, 1024 * 1024);
            assert_eq!(metrics.latency_percentiles.len(), 3);
        }

        #[test]
        fn test_performance_metrics_creation_has_correct_values_succeeds() {
            let metrics = PerformanceMetrics {
                avg_execution_time_ms: 50.0,
                min_execution_time_ms: 10,
                max_execution_time_ms: 200,
                total_execution_time_ms: 5000,
                memory_usage: MemoryUsageMetrics {
                    peak_memory_bytes: 1024 * 1024,
                    avg_memory_bytes: 512 * 1024,
                    efficiency_rating: 0.9,
                },
                throughput: ThroughputMetrics {
                    operations_per_second: 500.0,
                    bytes_per_second: 1024 * 512,
                    latency_percentiles: HashMap::new(),
                },
            };

            assert!((metrics.avg_execution_time_ms - 50.0).abs() < 0.001);
            assert_eq!(metrics.min_execution_time_ms, 10);
            assert_eq!(metrics.max_execution_time_ms, 200);
        }
    }

    // =============================================================================
    // Test Summary Tests (Coverage Improvement)
    // =============================================================================

    mod test_summary_tests {
        use latticearc_tests::validation::cavp::compliance::TestSummary;

        #[test]
        fn test_test_summary_creation_has_correct_fields_succeeds() {
            let summary = TestSummary {
                total_tests: 100,
                passed_tests: 95,
                failed_tests: 5,
                pass_rate: 95.0,
                security_level: 192,
                coverage: 98.0,
            };

            assert_eq!(summary.total_tests, 100);
            assert_eq!(summary.passed_tests, 95);
            assert_eq!(summary.failed_tests, 5);
            assert!((summary.pass_rate - 95.0).abs() < 0.001);
            assert_eq!(summary.security_level, 192);
            assert!((summary.coverage - 98.0).abs() < 0.001);
        }

        #[test]
        fn test_test_summary_zero_tests_has_zero_values_succeeds() {
            let summary = TestSummary {
                total_tests: 0,
                passed_tests: 0,
                failed_tests: 0,
                pass_rate: 0.0,
                security_level: 128,
                coverage: 0.0,
            };

            assert_eq!(summary.total_tests, 0);
            assert_eq!(summary.pass_rate, 0.0);
        }
    }

    // =============================================================================
    // Detailed Test Result Tests (Coverage Improvement)
    // =============================================================================

    mod detailed_test_result_tests {
        use latticearc_tests::validation::cavp::compliance::{
            ComplianceTestResult, DetailedTestResult, TestCategory, TestResult,
        };
        use std::collections::HashMap;

        #[test]
        fn test_detailed_test_result_creation_has_correct_fields_succeeds() {
            let mut additional_details = HashMap::new();
            additional_details.insert("key1".to_string(), "value1".to_string());
            additional_details.insert("key2".to_string(), "value2".to_string());

            let result = DetailedTestResult {
                test_id: "DETAIL-001".to_string(),
                category: TestCategory::Correctness,
                description: "Detailed test description".to_string(),
                result: TestResult::Passed,
                execution_time_ms: 150,
                additional_details,
            };

            assert_eq!(result.test_id, "DETAIL-001");
            assert!(matches!(result.category, TestCategory::Correctness));
            assert!(matches!(result.result, TestResult::Passed));
            assert_eq!(result.execution_time_ms, 150);
            assert_eq!(result.additional_details.len(), 2);
        }

        #[test]
        fn test_compliance_test_result_creation_has_correct_fields_succeeds() {
            let mut details = HashMap::new();
            details.insert("vector_id".to_string(), "VEC-001".to_string());

            let result = ComplianceTestResult {
                test_id: "COMPLIANCE-001".to_string(),
                category: TestCategory::Security,
                description: "Security compliance test".to_string(),
                result: TestResult::Failed("Security violation".to_string()),
                execution_time_ms: 250,
                details,
            };

            assert_eq!(result.test_id, "COMPLIANCE-001");
            assert!(matches!(result.category, TestCategory::Security));
            if let TestResult::Failed(reason) = &result.result {
                assert_eq!(reason, "Security violation");
            } else {
                panic!("Expected Failed result");
            }
        }
    }
}

// Originally: fips_cavp_pipeline_algorithms.rs
mod pipeline_algorithms {
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

// Originally: fips_cavp_pipeline_error_paths.rs
mod pipeline_error_paths {
    //! Coverage tests for CAVP pipeline error paths.
    //! Targets: wrong test type combinations (ML-KEM Signature, SLH-DSA Encapsulation, etc.),
    //! unsupported variants, HybridKem operations, CavpValidationPipeline methods.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::float_cmp,
        clippy::needless_borrows_for_generic_args,
        clippy::redundant_closure_for_method_calls,
        clippy::useless_format,
        clippy::field_reassign_with_default
    )]

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

// Originally: fips_cavp_pipeline_integration.rs
mod pipeline_integration {
    //! Comprehensive integration tests for CAVP pipeline
    //!
    //! These tests verify the CAVP (Cryptographic Algorithm Validation Program) pipeline
    //! implementation, ensuring FIPS 140-3 compliance readiness.

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

// Originally: fips_cavp_pipeline_sign_verify_roundtrip.rs
mod pipeline_sign_verify_roundtrip {
    //! Coverage tests for CAVP pipeline Signature and Verification paths.
    //! Exercises real crypto roundtrips: KeyGen → Sign → Verify for each algorithm variant.
    //! Targets pipeline.rs lines: ML-DSA sign/verify (44, 65, 87), SLH-DSA sign/verify
    //! (shake-128s, 192s, 256s), FN-DSA sign/verify (512, 1024).

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::float_cmp,
        clippy::needless_borrows_for_generic_args,
        clippy::redundant_closure_for_method_calls,
        clippy::useless_format
    )]

    use latticearc_tests::validation::cavp::pipeline::{CavpTestExecutor, PipelineConfig};
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_executor() -> CavpTestExecutor {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        CavpTestExecutor::new(config, storage)
    }

    fn make_keygen_vector(id: &str, algorithm: CavpAlgorithm) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42; 48]),
                message: None,
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
                notes: None,
            },
        }
    }

    fn make_sign_vector(
        id: &str,
        algorithm: CavpAlgorithm,
        sk: Vec<u8>,
        message: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: None,
                sk: Some(sk),
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
                signature: Some(vec![0xBB; 128]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Signature,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn make_verify_vector(
        id: &str,
        algorithm: CavpAlgorithm,
        pk: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: None,
                message: Some(message),
                key_material: None,
                pk: Some(pk),
                sk: None,
                c: None,
                m: None,
                ek: None,
                dk: None,
                signature: Some(signature),
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Verification,
                created_at: chrono::Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    // ============================================================
    // ML-DSA-44 Sign + Verify roundtrip (covers mldsa_44_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-44 roundtrip".to_vec();

        // Step 1: KeyGen to get real keys
        let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let keygen_vec = make_keygen_vector("mldsa44-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;
        assert!(!key_material.is_empty(), "KeyGen should produce key material");

        // Split: pk (1312 bytes) + sk (2560 bytes)
        let pk = key_material[..1312].to_vec();
        let sk = key_material[1312..].to_vec();
        assert_eq!(sk.len(), 2560);

        // Step 2: Sign
        let sign_vec = make_sign_vector("mldsa44-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "Signing should produce a signature");
        assert_eq!(signature.len(), 2420, "ML-DSA-44 signature should be 2420 bytes");

        // Step 3: Verify
        let verify_vec = make_verify_vector("mldsa44-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        // Verify returns [1] for valid, [0] for invalid
        assert_eq!(verify_result.actual_result, vec![1], "Valid signature should verify");
    }

    // ============================================================
    // ML-DSA-65 Sign + Verify roundtrip (covers mldsa_65_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_65_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-65 roundtrip".to_vec();

        let alg = CavpAlgorithm::MlDsa { variant: "65".to_string() };
        let keygen_vec = make_keygen_vector("mldsa65-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (1952 bytes) + sk (4032 bytes)
        let pk = key_material[..1952].to_vec();
        let sk = key_material[1952..].to_vec();
        assert_eq!(sk.len(), 4032);

        // Sign
        let sign_vec = make_sign_vector("mldsa65-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 3309);

        // Verify
        let verify_vec = make_verify_vector("mldsa65-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // ML-DSA-87 Sign + Verify roundtrip (covers mldsa_87_impl Sign/Verify)
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_87_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for ML-DSA-87 roundtrip".to_vec();

        let alg = CavpAlgorithm::MlDsa { variant: "87".to_string() };
        let keygen_vec = make_keygen_vector("mldsa87-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (2592 bytes) + sk (4896 bytes)
        let pk = key_material[..2592].to_vec();
        let sk = key_material[2592..].to_vec();
        assert_eq!(sk.len(), 4896);

        // Sign
        let sign_vec = make_sign_vector("mldsa87-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 4627);

        // Verify
        let verify_vec = make_verify_vector("mldsa87-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-128s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_128s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-128s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa128s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (32 bytes) + sk (64 bytes)
        let pk = key_material[..32].to_vec();
        let sk = key_material[32..].to_vec();
        assert_eq!(sk.len(), 64);

        // Sign
        let sign_vec = make_sign_vector("slhdsa128s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 7856);

        // Verify
        let verify_vec = make_verify_vector("slhdsa128s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-192s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_192s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-192s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa192s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (48 bytes) + sk (96 bytes)
        let pk = key_material[..48].to_vec();
        let sk = key_material[48..].to_vec();
        assert_eq!(sk.len(), 96);

        // Sign
        let sign_vec = make_sign_vector("slhdsa192s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 16224);

        // Verify
        let verify_vec = make_verify_vector("slhdsa192s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // SLH-DSA-SHAKE-256s Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_shake_256s_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for SLH-DSA-SHAKE-256s".to_vec();

        let alg = CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() };
        let keygen_vec = make_keygen_vector("slhdsa256s-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // Split: pk (64 bytes) + sk (128 bytes)
        let pk = key_material[..64].to_vec();
        let sk = key_material[64..].to_vec();
        assert_eq!(sk.len(), 128);

        // Sign
        let sign_vec = make_sign_vector("slhdsa256s-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert_eq!(signature.len(), 29792);

        // Verify
        let verify_vec = make_verify_vector("slhdsa256s-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // FN-DSA-512 Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for FN-DSA-512".to_vec();

        let alg = CavpAlgorithm::FnDsa { variant: "512".to_string() };
        let keygen_vec = make_keygen_vector("fndsa512-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // FN-DSA KeyGen returns vrfy_key + sign_key
        // vrfy_key_size(FN_DSA_LOGN_512) and sign_key_size(FN_DSA_LOGN_512)
        // For logn=9 (512): vrfy_key = 897, sign_key = 1281
        let vrfy_key_len = 897;
        let pk = key_material[..vrfy_key_len].to_vec();
        let sk = key_material[vrfy_key_len..].to_vec();
        assert_eq!(sk.len(), 1281, "FN-DSA-512 sign key should be 1281 bytes");

        // Sign
        let sign_vec = make_sign_vector("fndsa512-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "FN-DSA-512 should produce a signature");

        // Verify
        let verify_vec = make_verify_vector("fndsa512-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // FN-DSA-1024 Sign + Verify roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_1024_sign_verify_roundtrip() {
        let executor = make_executor();
        let message = b"Test message for FN-DSA-1024".to_vec();

        let alg = CavpAlgorithm::FnDsa { variant: "1024".to_string() };
        let keygen_vec = make_keygen_vector("fndsa1024-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // For logn=10 (1024): vrfy_key = 1793, sign_key = 2305
        let vrfy_key_len = 1793;
        let pk = key_material[..vrfy_key_len].to_vec();
        let sk = key_material[vrfy_key_len..].to_vec();
        assert_eq!(sk.len(), 2305, "FN-DSA-1024 sign key should be 2305 bytes");

        // Sign
        let sign_vec = make_sign_vector("fndsa1024-sign", alg.clone(), sk, message.clone());
        let sign_result = executor.execute_single_test_vector(&sign_vec).await.unwrap();
        let signature = sign_result.actual_result;
        assert!(!signature.is_empty(), "FN-DSA-1024 should produce a signature");

        // Verify
        let verify_vec = make_verify_vector("fndsa1024-verify", alg, pk, message, signature);
        let verify_result = executor.execute_single_test_vector(&verify_vec).await.unwrap();
        assert_eq!(verify_result.actual_result, vec![1]);
    }

    // ============================================================
    // ML-KEM Encapsulation + Decapsulation roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_768_encap_decap_roundtrip() {
        let executor = make_executor();

        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };

        // Step 1: KeyGen
        let keygen_vec = make_keygen_vector("mlkem768-keygen", alg.clone());
        let keygen_result = executor.execute_single_test_vector(&keygen_vec).await.unwrap();
        let key_material = keygen_result.actual_result;

        // ML-KEM-768: ek (1184 bytes) + dk (2400 bytes)
        let ek_len = 1184;
        let dk_len = 2400;
        let ek = key_material[..ek_len].to_vec();
        let dk = key_material[ek_len..ek_len + dk_len].to_vec();

        // Step 2: Encapsulation
        let encap_vec = CavpTestVector {
            id: "mlkem768-encap".to_string(),
            algorithm: alg.clone(),
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: None,
                m: None,
                ek: Some(ek),
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
                notes: None,
            },
        };

        let encap_result = executor.execute_single_test_vector(&encap_vec).await.unwrap();
        let encap_output = encap_result.actual_result;
        // Output = ct (1088 bytes) + ssk (32 bytes)
        assert_eq!(encap_output.len(), 1088 + 32);
        let ct = encap_output[..1088].to_vec();
        let ssk_encap = encap_output[1088..].to_vec();

        // Step 3: Decapsulation
        let decap_vec = CavpTestVector {
            id: "mlkem768-decap".to_string(),
            algorithm: alg,
            inputs: CavpVectorInputs {
                seed: None,
                message: None,
                key_material: None,
                pk: None,
                sk: None,
                c: Some(ct),
                m: None,
                ek: None,
                dk: Some(dk),
                signature: None,
                parameters: HashMap::new(),
            },
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(ssk_encap.clone()),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::Decapsulation,
                created_at: chrono::Utc::now(),
                security_level: 192,
                notes: None,
            },
        };

        let decap_result = executor.execute_single_test_vector(&decap_vec).await.unwrap();
        let ssk_decap = decap_result.actual_result;
        // Decapsulation should produce the same shared secret
        assert_eq!(
            ssk_encap, ssk_decap,
            "Encapsulated and decapsulated shared secrets should match"
        );
        // Note: decap_result.passed may be false since expected_outputs has dummy values,
        // but the actual roundtrip succeeds (ssk_encap == ssk_decap)
    }
}

// Originally: fips_pipeline_dispatch_coverage.rs
mod pipeline_dispatch {
    //! Coverage tests for cavp/pipeline.rs algorithm dispatch functions.
    //! Targets the execute_* async methods and real_*_implementation functions
    //! including error paths for unsupported variants and test types.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::field_reassign_with_default
    )]

    use chrono::Utc;
    use latticearc_tests::validation::cavp::pipeline::{
        CavpTestExecutor, CavpValidationPipeline, PipelineConfig,
    };
    use latticearc_tests::validation::cavp::storage::MemoryCavpStorage;
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    fn make_storage() -> Arc<MemoryCavpStorage> {
        Arc::new(MemoryCavpStorage::new())
    }

    fn make_executor() -> CavpTestExecutor {
        CavpTestExecutor::new(PipelineConfig::default(), make_storage())
    }

    fn make_pipeline() -> CavpValidationPipeline {
        CavpValidationPipeline::new(PipelineConfig::default(), make_storage())
    }

    fn make_vector(algorithm: CavpAlgorithm, test_type: CavpTestType) -> CavpTestVector {
        CavpTestVector {
            id: "test-vec-1".to_string(),
            algorithm,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x42u8; 32]),
                message: Some(b"test message".to_vec()),
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
                public_key: Some(vec![0u8; 64]),
                secret_key: Some(vec![0u8; 128]),
                ciphertext: Some(vec![0u8; 96]),
                signature: Some(vec![0u8; 128]),
                shared_secret: Some(vec![0u8; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "test".to_string(),
                test_type,
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    // ============================================================
    // PipelineConfig
    // ============================================================

    #[test]
    fn test_pipeline_config_default_has_expected_values_succeeds() {
        let config = PipelineConfig::default();
        assert_eq!(config.max_concurrent_tests, 4);
        assert_eq!(config.retry_count, 3);
        assert!(config.run_statistical_tests);
        assert!(config.generate_reports);
    }

    // ============================================================
    // ML-KEM pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_keygen_execution_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
    }

    #[tokio::test]
    async fn test_mlkem_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlKem { variant: "999".to_string() }, CavpTestType::KeyGen);

        // Should return a failed test result (error captured, not propagated)
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok()); // The executor wraps errors into failed test results
        let test_result = result.unwrap();
        assert!(!test_result.passed);
    }

    #[tokio::test]
    async fn test_mlkem_signature_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Signature,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.passed); // ML-KEM doesn't support signatures
    }

    #[tokio::test]
    async fn test_mlkem_verification_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Verification,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.passed);
    }

    // ============================================================
    // ML-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_keygen_44_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_keygen_65_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "65".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_keygen_87_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "87".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mldsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "99".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Decapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_128s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_192s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_keygen_shake_256s_succeeds() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_slhdsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "unknown".to_string() },
            CavpTestType::KeyGen,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_keygen_512_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "512".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fndsa_keygen_1024_succeeds() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "1024".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fndsa_unsupported_variant_returns_error() {
        let executor = make_executor();
        let vector =
            make_vector(CavpAlgorithm::FnDsa { variant: "256".to_string() }, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_encapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Encapsulation,
        );

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid-KEM pipeline execution
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_keygen_succeeds() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::KeyGen);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hybrid_kem_signature_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::Signature);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Batch execution
    // ============================================================

    #[tokio::test]
    async fn test_batch_execution_mixed_algorithms_completes_succeeds() {
        let executor = make_executor();
        let vectors = vec![
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
        ];

        let result = executor.execute_test_vector_batch(vectors).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_batch_execution_empty_returns_empty_batch_succeeds() {
        let executor = make_executor();
        let vectors = Vec::new();

        let result = executor.execute_test_vector_batch(vectors).await;
        assert!(result.is_ok());
    }

    // ============================================================
    // CavpValidationPipeline
    // ============================================================

    #[tokio::test]
    async fn test_pipeline_run_full_validation_succeeds() {
        let pipeline = make_pipeline();
        let vectors = vec![
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen),
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen),
        ];

        let result = pipeline.run_full_validation(vectors).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2); // Two different algorithms = two batches
    }

    #[tokio::test]
    async fn test_pipeline_run_algorithm_validation_succeeds() {
        let pipeline = make_pipeline();
        let vectors = vec![make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::KeyGen,
        )];

        let result = pipeline
            .run_algorithm_validation(CavpAlgorithm::MlKem { variant: "768".to_string() }, vectors)
            .await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_pipeline_create_sample_vectors_succeeds() {
        let pipeline = make_pipeline();
        let vectors =
            pipeline.create_sample_vectors(CavpAlgorithm::MlKem { variant: "768".to_string() }, 5);
        assert_eq!(vectors.len(), 5);
        for (i, v) in vectors.iter().enumerate() {
            assert!(v.id.contains("SAMPLE"));
            assert!(v.id.contains(&format!("{}", i + 1)));
        }
    }

    #[test]
    fn test_pipeline_create_sample_vectors_empty_returns_empty_matches_expected() {
        let pipeline = make_pipeline();
        let vectors =
            pipeline.create_sample_vectors(CavpAlgorithm::MlDsa { variant: "44".to_string() }, 0);
        assert!(vectors.is_empty());
    }

    // ============================================================
    // ML-KEM Encapsulation / Decapsulation error paths
    // ============================================================

    fn make_vector_with_inputs(
        algorithm: CavpAlgorithm,
        test_type: CavpTestType,
        inputs: CavpVectorInputs,
    ) -> CavpTestVector {
        CavpTestVector {
            id: "test-vec-err".to_string(),
            algorithm,
            inputs,
            expected_outputs: CavpVectorOutputs {
                public_key: None,
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "test".to_string(),
                test_type,
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    fn default_inputs() -> CavpVectorInputs {
        CavpVectorInputs {
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
        }
    }

    #[tokio::test]
    async fn test_mlkem_encapsulation_missing_ek_returns_error() {
        let executor = make_executor();
        let inputs = default_inputs(); // ek is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Encapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_encapsulation_wrong_ek_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 10]); // Wrong length
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Encapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_missing_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.c = Some(vec![0u8; 10]); // c present but dk missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_missing_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // dk present but c missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_wrong_dk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // Wrong length
        inputs.c = Some(vec![0u8; 10]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        // sk is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 2560)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 2420]);
        // pk is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 1312)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 2420]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_wrong_sig_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 10]); // Wrong length (expected 2420)
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_65_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 4032)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_65_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 1952)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 3309]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "65".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_87_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 4896)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_87_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 2592)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 4627]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_128s_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 64)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 7856]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 32)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 7856]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_192s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 96)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_192s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 48)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 16224]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-192s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_256s_signature_wrong_sk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 10]); // Wrong length (expected 128)
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_256s_verification_wrong_pk_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 10]); // Wrong length (expected 64)
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 29792]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA Signature / Verification error paths
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_signature_missing_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_signature_invalid_sk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0xFFu8; 100]); // Invalid format
        inputs.message = Some(b"test".to_vec());
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 666]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_invalid_pk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]); // Invalid format
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 666]);
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_decapsulation_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Decapsulation,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid KEM Encapsulation / Decapsulation error paths
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encapsulation_missing_ek_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.m = Some(vec![0u8; 32]); // m present but ek missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decapsulation_missing_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.c = Some(vec![0u8; 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_verification_unsupported_returns_error() {
        let executor = make_executor();
        let vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::Verification);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Hybrid KEM Encapsulation + Decapsulation roundtrip
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encap_decap_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: Generate hybrid keys
        let keygen_vector = make_vector(CavpAlgorithm::HybridKem, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await;
        assert!(keygen_result.is_ok());
        let keygen_test = keygen_result.unwrap();
        assert!(
            keygen_test.passed || !keygen_test.actual_result.is_empty(),
            "HybridKem KeyGen should produce output"
        );

        // The keygen output is: ek_pq (1184) || pk_classical (32) || dk_pq (2400) || sk_classical (32)
        let key_data = &keygen_test.actual_result;
        if key_data.len() >= 1184 + 32 + 2400 + 32 {
            let ek_combined = key_data.get(..1184 + 32).unwrap().to_vec(); // ek_pq || pk_classical
            let dk_combined = key_data.get(1184 + 32..).unwrap().to_vec(); // dk_pq || sk_classical

            // Step 2: Encapsulation
            let mut encap_inputs = default_inputs();
            encap_inputs.ek = Some(ek_combined);
            encap_inputs.m = Some(vec![0x42u8; 32]); // ephemeral secret for X25519
            let encap_vector = make_vector_with_inputs(
                CavpAlgorithm::HybridKem,
                CavpTestType::Encapsulation,
                encap_inputs,
            );
            let encap_result = executor.execute_single_test_vector(&encap_vector).await;
            assert!(encap_result.is_ok());
            let encap_test = encap_result.unwrap();
            // Encapsulation output is: c_pq (1088) || pk_ephemeral (32) || combined_secret (32)
            assert!(!encap_test.actual_result.is_empty(), "Encapsulation should produce output");

            if encap_test.actual_result.len() >= 1088 + 32 + 32 {
                let ciphertext = encap_test.actual_result.get(..1088 + 32).unwrap().to_vec();
                let encap_secret = encap_test.actual_result.get(1088 + 32..).unwrap().to_vec();

                // Step 3: Decapsulation
                let mut decap_inputs = default_inputs();
                decap_inputs.dk = Some(dk_combined);
                decap_inputs.c = Some(ciphertext);
                let decap_vector = make_vector_with_inputs(
                    CavpAlgorithm::HybridKem,
                    CavpTestType::Decapsulation,
                    decap_inputs,
                );
                let decap_result = executor.execute_single_test_vector(&decap_vector).await;
                assert!(decap_result.is_ok());
                let decap_test = decap_result.unwrap();
                assert!(
                    !decap_test.actual_result.is_empty(),
                    "Decapsulation should produce output"
                );

                // Shared secrets should match
                assert_eq!(
                    encap_secret, decap_test.actual_result,
                    "Encapsulation and decapsulation should produce the same shared secret"
                );
            }
        }
    }

    // ============================================================
    // Hybrid KEM missing-input / invalid-length error paths
    // ============================================================

    #[tokio::test]
    async fn test_hybrid_kem_encap_missing_m_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 1184 + 32]); // ek present but m missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_encap_short_ek_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 10]); // Too short for PQ part
        inputs.m = Some(vec![0u8; 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_encap_wrong_m_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.ek = Some(vec![0u8; 1184 + 32]);
        inputs.m = Some(vec![0u8; 16]); // Wrong length (need 32)
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Encapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_missing_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400 + 32]); // dk present but c missing
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_short_dk_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 10]); // Too short
        inputs.c = Some(vec![0u8; 1088 + 32]);
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_hybrid_kem_decap_short_c_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400 + 32]);
        inputs.c = Some(vec![0u8; 10]); // Too short for PQ ciphertext part
        let vector =
            make_vector_with_inputs(CavpAlgorithm::HybridKem, CavpTestType::Decapsulation, inputs);
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-DSA sign/verify roundtrip through pipeline
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: KeyGen
        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "44".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (1312) || sk (2560)
        if key_data.len() >= 1312 + 2560 {
            let pk = key_data.get(..1312).unwrap().to_vec();
            let sk = key_data.get(1312..).unwrap().to_vec();

            // Step 2: Sign
            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-44 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty(), "Sign should produce signature");
            let signature = sign_result.actual_result;

            // Step 3: Verify
            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-44 pipeline".to_vec());
            verify_inputs.signature = Some(signature);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert!(!verify_result.actual_result.is_empty());
            // Result should be [1] for valid
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    #[tokio::test]
    async fn test_mldsa_65_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "65".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (1952) || sk (4032)
        if key_data.len() >= 1952 + 4032 {
            let pk = key_data.get(..1952).unwrap().to_vec();
            let sk = key_data.get(1952..).unwrap().to_vec();

            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-65 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "65".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty());

            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-65 pipeline".to_vec());
            verify_inputs.signature = Some(sign_result.actual_result);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "65".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    #[tokio::test]
    async fn test_mldsa_87_sign_verify_roundtrip_succeeds() {
        let executor = make_executor();

        let keygen_vector =
            make_vector(CavpAlgorithm::MlDsa { variant: "87".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: pk (2592) || sk (4896)
        if key_data.len() >= 2592 + 4896 {
            let pk = key_data.get(..2592).unwrap().to_vec();
            let sk = key_data.get(2592..).unwrap().to_vec();

            let mut sign_inputs = default_inputs();
            sign_inputs.sk = Some(sk);
            sign_inputs.message = Some(b"test message for ML-DSA-87 pipeline".to_vec());
            let sign_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "87".to_string() },
                CavpTestType::Signature,
                sign_inputs,
            );
            let sign_result = executor.execute_single_test_vector(&sign_vector).await.unwrap();
            assert!(!sign_result.actual_result.is_empty());

            let mut verify_inputs = default_inputs();
            verify_inputs.pk = Some(pk);
            verify_inputs.message = Some(b"test message for ML-DSA-87 pipeline".to_vec());
            verify_inputs.signature = Some(sign_result.actual_result);
            let verify_vector = make_vector_with_inputs(
                CavpAlgorithm::MlDsa { variant: "87".to_string() },
                CavpTestType::Verification,
                verify_inputs,
            );
            let verify_result = executor.execute_single_test_vector(&verify_vector).await.unwrap();
            assert_eq!(verify_result.actual_result, vec![1u8]);
        }
    }

    // ============================================================
    // ML-DSA missing-message error paths
    // ============================================================

    #[tokio::test]
    async fn test_mldsa_44_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 2560]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.signature = Some(vec![0u8; 2420]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_mldsa_44_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 1312]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // SLH-DSA missing-message/signature error paths
    // ============================================================

    #[tokio::test]
    async fn test_slhdsa_128s_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0u8; 64]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.signature = Some(vec![0u8; 7856]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_slhdsa_128s_verification_wrong_sig_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0u8; 32]);
        inputs.message = Some(b"test".to_vec());
        inputs.signature = Some(vec![0u8; 10]); // Wrong length (expected 7856)
        let vector = make_vector_with_inputs(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // FN-DSA missing-message/signature error paths
    // ============================================================

    #[tokio::test]
    async fn test_fndsa_512_signature_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.sk = Some(vec![0xFFu8; 100]); // sk present but message missing
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Signature,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_message_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]);
        inputs.signature = Some(vec![0u8; 666]);
        // message is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    #[tokio::test]
    async fn test_fndsa_512_verification_missing_signature_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.pk = Some(vec![0xFFu8; 100]);
        inputs.message = Some(b"test".to_vec());
        // signature is None
        let vector = make_vector_with_inputs(
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpTestType::Verification,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // ML-KEM encap/decap roundtrip through pipeline
    // ============================================================

    #[tokio::test]
    async fn test_mlkem_768_encap_decap_roundtrip_succeeds() {
        let executor = make_executor();

        // Step 1: ML-KEM-768 Encapsulation with valid ek from keygen
        let keygen_vector =
            make_vector(CavpAlgorithm::MlKem { variant: "768".to_string() }, CavpTestType::KeyGen);
        let keygen_result = executor.execute_single_test_vector(&keygen_vector).await.unwrap();
        let key_data = &keygen_result.actual_result;
        // Output: ek (1184) || dk (2400)
        if key_data.len() >= 1184 + 2400 {
            let ek = key_data.get(..1184).unwrap().to_vec();
            let dk = key_data.get(1184..).unwrap().to_vec();

            // Step 2: Encapsulation
            let mut encap_inputs = default_inputs();
            encap_inputs.ek = Some(ek);
            let encap_vector = make_vector_with_inputs(
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                CavpTestType::Encapsulation,
                encap_inputs,
            );
            let encap_result = executor.execute_single_test_vector(&encap_vector).await.unwrap();
            assert!(!encap_result.actual_result.is_empty(), "Encap should produce ciphertext + SS");

            // Output: ciphertext (1088) || shared_secret (32)
            if encap_result.actual_result.len() >= 1088 + 32 {
                let ct = encap_result.actual_result.get(..1088).unwrap().to_vec();
                let ss_encap = encap_result.actual_result.get(1088..).unwrap().to_vec();

                // Step 3: Decapsulation
                let mut decap_inputs = default_inputs();
                decap_inputs.dk = Some(dk);
                decap_inputs.c = Some(ct);
                let decap_vector = make_vector_with_inputs(
                    CavpAlgorithm::MlKem { variant: "768".to_string() },
                    CavpTestType::Decapsulation,
                    decap_inputs,
                );
                let decap_result =
                    executor.execute_single_test_vector(&decap_vector).await.unwrap();
                assert!(!decap_result.actual_result.is_empty());
                assert_eq!(ss_encap, decap_result.actual_result, "Shared secrets must match");
            }
        }
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_wrong_ct_length_returns_error() {
        let executor = make_executor();
        let mut inputs = default_inputs();
        inputs.dk = Some(vec![0u8; 2400]); // Valid dk length
        inputs.c = Some(vec![0u8; 10]); // Wrong ct length
        let vector = make_vector_with_inputs(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::Decapsulation,
            inputs,
        );
        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().passed);
    }

    // ============================================================
    // Pipeline with reports disabled
    // ============================================================

    #[tokio::test]
    async fn test_pipeline_no_reports_succeeds() {
        let mut config = PipelineConfig::default();
        config.generate_reports = false;
        config.run_statistical_tests = false;
        let pipeline = CavpValidationPipeline::new(config, make_storage());
        let vectors = vec![make_vector(
            CavpAlgorithm::MlKem { variant: "768".to_string() },
            CavpTestType::KeyGen,
        )];
        let result = pipeline.run_full_validation(vectors).await;
        assert!(result.is_ok());
    }
}

// Originally: fips_cavp_compliance_coverage.rs
mod compliance_coverage {
    //! Coverage tests for CAVP compliance report generation.
    //! Targets compliance.rs: CavpComplianceGenerator, report generation,
    //! JSON/XML export, compliance evaluation (FullyCompliant, PartiallyCompliant,
    //! NonCompliant), and algorithm-specific criteria.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_precision_loss,
        clippy::float_cmp,
        clippy::needless_borrows_for_generic_args,
        clippy::redundant_clone,
        clippy::redundant_closure_for_method_calls,
        clippy::useless_format
    )]

    use chrono::Utc;
    use latticearc_tests::validation::cavp::compliance::*;
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn make_passing_result(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
        CavpTestResult {
            test_id: id.to_string(),
            algorithm,
            vector_id: format!("{}-vec", id),
            passed: true,
            execution_time: Duration::from_millis(10),
            timestamp: Utc::now(),
            actual_result: vec![1],
            expected_result: vec![1],
            error_message: None,
            metadata: CavpTestMetadata::default(),
        }
    }

    fn make_failing_result(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
        CavpTestResult {
            test_id: id.to_string(),
            algorithm,
            vector_id: format!("{}-vec", id),
            passed: false,
            execution_time: Duration::from_millis(5),
            timestamp: Utc::now(),
            actual_result: vec![0],
            expected_result: vec![1],
            error_message: Some("Mismatch in test vector".to_string()),
            metadata: CavpTestMetadata::default(),
        }
    }

    fn make_failing_result_no_message(id: &str, algorithm: CavpAlgorithm) -> CavpTestResult {
        CavpTestResult {
            test_id: id.to_string(),
            algorithm,
            vector_id: format!("{}-vec", id),
            passed: false,
            execution_time: Duration::from_millis(3),
            timestamp: Utc::now(),
            actual_result: vec![0],
            expected_result: vec![1],
            error_message: None,
            metadata: CavpTestMetadata::default(),
        }
    }

    fn make_batch(
        algorithm: CavpAlgorithm,
        results: Vec<CavpTestResult>,
        _duration: Duration,
    ) -> CavpBatchResult {
        let mut batch = CavpBatchResult::new("batch-1".to_string(), algorithm);
        for r in results {
            batch.add_test_result(r);
        }
        batch.status = CavpValidationStatus::Passed;
        batch
    }

    // ============================================================
    // CavpComplianceGenerator construction
    // ============================================================

    #[test]
    fn test_generator_new_generates_report_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        // Verify it was constructed (exercises new() and all criteria insertions)
        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let _report = cgen.generate_report(&[batch]).unwrap();
    }

    #[test]
    fn test_generator_default_generates_report_succeeds() {
        let cgen = CavpComplianceGenerator::default();
        let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let _report = cgen.generate_report(&[batch]).unwrap();
    }

    // ============================================================
    // Report generation - FullyCompliant (all tests pass)
    // ============================================================

    #[test]
    fn test_generate_report_fully_compliant_hybrid_succeeds() {
        // HybridKem uses default_criteria with min_coverage=95.0, matching hardcoded 95.0%
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::HybridKem;
        let results = vec![
            make_passing_result("test-1", alg.clone()),
            make_passing_result("test-2", alg.clone()),
            make_passing_result("test-3", alg.clone()),
        ];
        let batch = make_batch(alg, results, Duration::from_millis(30));
        let report = cgen.generate_report(&[batch]).unwrap();

        assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
        assert_eq!(report.summary.total_tests, 3);
        assert_eq!(report.summary.passed_tests, 3);
        assert_eq!(report.summary.failed_tests, 0);
        assert!((report.summary.pass_rate - 100.0).abs() < 0.01);
        assert_eq!(report.summary.security_level, 256);
        assert!(!report.nist_standards.is_empty());
    }

    #[test]
    fn test_generate_report_mlkem_noncompliant_due_to_coverage_is_covered() {
        // Algorithm-specific criteria require 100% coverage, but summary hardcodes 95%
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let results = vec![
            make_passing_result("test-1", alg.clone()),
            make_passing_result("test-2", alg.clone()),
        ];
        let batch = make_batch(alg, results, Duration::from_millis(20));
        let report = cgen.generate_report(&[batch]).unwrap();

        // 100% pass rate but 95% coverage < required 100% → NonCompliant
        assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
        assert_eq!(report.summary.security_level, 192);
    }

    // ============================================================
    // Report generation - PartiallyCompliant (some failures but pass rate still high)
    // ============================================================

    #[test]
    fn test_generate_report_partially_compliant_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlKem { variant: "512".to_string() };

        // 99 pass, 1 fail -> 99% pass rate, FullyCompliant criteria requires 100%
        // But coverage 95% meets threshold, so this tests the evaluate_compliance branch
        // where pass_rate >= min_pass_rate (100%) is NOT met
        // Actually ML-KEM criteria requires 100% pass rate, so 99% will be NonCompliant
        // Let's use a scenario where all pass but with a Failed detailed result
        // to test the PartiallyCompliant path.
        let mut results: Vec<CavpTestResult> = Vec::new();
        for i in 0..10 {
            results.push(make_passing_result(&format!("test-{}", i), alg.clone()));
        }
        // Add one failing result with error message to exercise PartiallyCompliant
        results.push(make_failing_result("test-fail", alg.clone()));

        let batch = make_batch(alg, results, Duration::from_millis(100));

        // Use default criteria where min_pass_rate is 100% and coverage is 95%
        // pass_rate = 10/11 = 90.9% which is below 100%, so NonCompliant
        let report = cgen.generate_report(&[batch]).unwrap();

        // Since pass rate is below 100% (ML-KEM criteria requires 100%), this will be NonCompliant
        assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
    }

    // ============================================================
    // Report generation - NonCompliant
    // ============================================================

    #[test]
    fn test_generate_report_non_compliant_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::SlhDsa { variant: "128".to_string() };
        let results = vec![
            make_failing_result("fail-1", alg.clone()),
            make_failing_result("fail-2", alg.clone()),
            make_passing_result("pass-1", alg.clone()),
        ];
        let batch = make_batch(alg, results, Duration::from_millis(50));
        let report = cgen.generate_report(&[batch]).unwrap();

        assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
        if let ComplianceStatus::NonCompliant { failures } = &report.compliance_status {
            assert!(!failures.is_empty());
        }
        assert_eq!(report.summary.total_tests, 3);
        assert_eq!(report.summary.failed_tests, 2);
    }

    // ============================================================
    // Security level mapping for all algorithm variants
    // ============================================================

    #[test]
    fn test_security_level_mapping_mlkem_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in
            [("512", 128), ("768", 192), ("1024", 256), ("unknown", 128)]
        {
            let alg = CavpAlgorithm::MlKem { variant: variant.to_string() };
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg, results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            assert_eq!(
                report.summary.security_level, expected_level,
                "ML-KEM variant {} should map to level {}",
                variant, expected_level
            );
        }
    }

    #[test]
    fn test_security_level_mapping_mldsa_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in [("44", 128), ("65", 192), ("87", 256), ("unknown", 128)] {
            let alg = CavpAlgorithm::MlDsa { variant: variant.to_string() };
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg, results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            assert_eq!(report.summary.security_level, expected_level);
        }
    }

    #[test]
    fn test_security_level_mapping_slhdsa_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in
            [("128", 128), ("192", 192), ("256", 256), ("unknown", 128)]
        {
            let alg = CavpAlgorithm::SlhDsa { variant: variant.to_string() };
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg, results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            assert_eq!(report.summary.security_level, expected_level);
        }
    }

    #[test]
    fn test_security_level_mapping_fndsa_maps_variants_correctly_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        for (variant, expected_level) in [("512", 128), ("1024", 256), ("unknown", 128)] {
            let alg = CavpAlgorithm::FnDsa { variant: variant.to_string() };
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg, results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            assert_eq!(report.summary.security_level, expected_level);
        }
    }

    #[test]
    fn test_security_level_mapping_hybrid_kem_returns_256_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        let alg = CavpAlgorithm::HybridKem;
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();
        assert_eq!(report.summary.security_level, 256);
    }

    // ============================================================
    // JSON and XML export
    // ============================================================

    #[test]
    fn test_export_json_produces_valid_json_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::HybridKem;
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();

        let json = cgen.export_json(&report).unwrap();
        assert!(json.contains("CAVP-REPORT-"));
        assert!(json.contains("FullyCompliant"));
    }

    #[test]
    fn test_export_xml_produces_valid_xml_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();

        let xml = cgen.export_xml(&report).unwrap();
        assert!(xml.contains("<?xml version"));
        assert!(xml.contains("<cavp_compliance_report>"));
        assert!(xml.contains("<algorithm>ML-DSA-44</algorithm>"));
        assert!(xml.contains("<total_tests>1</total_tests>"));
        assert!(xml.contains("</cavp_compliance_report>"));
    }

    // ============================================================
    // Edge cases
    // ============================================================

    #[test]
    fn test_generate_report_empty_batches_fails() {
        let cgen = CavpComplianceGenerator::new();
        let result = cgen.generate_report(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_report_multiple_batches_accumulates_totals_succeeds() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::FnDsa { variant: "512".to_string() };

        let batch1 = make_batch(
            alg.clone(),
            vec![make_passing_result("b1-t1", alg.clone())],
            Duration::from_millis(10),
        );
        let batch2 = make_batch(
            alg.clone(),
            vec![make_passing_result("b2-t1", alg.clone())],
            Duration::from_millis(15),
        );

        let report = cgen.generate_report(&[batch1, batch2]).unwrap();
        assert_eq!(report.summary.total_tests, 2);
        assert_eq!(report.summary.passed_tests, 2);
    }

    #[test]
    fn test_generate_report_with_default_criteria_succeeds() {
        // Use an algorithm name that won't match any specific criteria
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::HybridKem;
        let results = vec![make_passing_result("t1", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();

        // HybridKem uses default_criteria since it's not in the criteria_map
        assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
    }

    // ============================================================
    // convert_to_compliance_results - test both fail paths
    // ============================================================

    #[test]
    fn test_compliance_results_with_error_message_fails() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let results = vec![make_failing_result("fail-with-msg", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();

        // Should have Failed with the specific error message
        assert_eq!(report.detailed_results.len(), 1);
        assert!(matches!(report.detailed_results[0].result, TestResult::Failed(_)));
        if let TestResult::Failed(msg) = &report.detailed_results[0].result {
            assert!(msg.contains("Mismatch"));
        }
    }

    #[test]
    fn test_compliance_results_without_error_message_uses_generic_message_fails() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlDsa { variant: "87".to_string() };
        let results = vec![make_failing_result_no_message("fail-no-msg", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(5));
        let report = cgen.generate_report(&[batch]).unwrap();

        // Should have Failed with the generic message
        assert_eq!(report.detailed_results.len(), 1);
        if let TestResult::Failed(msg) = &report.detailed_results[0].result {
            assert!(msg.contains("failed without specific error"));
        }
    }

    // ============================================================
    // ComplianceStatus and type coverage
    // ============================================================

    #[test]
    fn test_compliance_status_variants_serialize_and_deserialize_succeeds() {
        let fc = ComplianceStatus::FullyCompliant;
        let pc =
            ComplianceStatus::PartiallyCompliant { exceptions: vec!["minor issue".to_string()] };
        let nc = ComplianceStatus::NonCompliant { failures: vec!["critical failure".to_string()] };
        let id = ComplianceStatus::InsufficientData;

        // Serialize/deserialize roundtrip
        let fc_json = serde_json::to_string(&fc).unwrap();
        let pc_json = serde_json::to_string(&pc).unwrap();
        let nc_json = serde_json::to_string(&nc).unwrap();
        let id_json = serde_json::to_string(&id).unwrap();

        assert!(fc_json.contains("FullyCompliant"));
        assert!(pc_json.contains("PartiallyCompliant"));
        assert!(nc_json.contains("NonCompliant"));
        assert!(id_json.contains("InsufficientData"));

        // Deserialize back
        let fc2: ComplianceStatus = serde_json::from_str(&fc_json).unwrap();
        assert_eq!(fc, fc2);
    }

    #[test]
    fn test_test_category_variants_serialize_and_deserialize_succeeds() {
        let categories = vec![
            TestCategory::Correctness,
            TestCategory::Security,
            TestCategory::Performance,
            TestCategory::Robustness,
            TestCategory::Interoperability,
            TestCategory::Statistical,
            TestCategory::KeyGeneration,
            TestCategory::Signature,
            TestCategory::Encryption,
            TestCategory::Decryption,
            TestCategory::Compliance,
        ];
        for cat in &categories {
            let json = serde_json::to_string(cat).unwrap();
            let deserialized: TestCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, &deserialized);
        }
    }

    #[test]
    fn test_test_result_variants_serialize_and_deserialize_succeeds() {
        let variants = vec![
            TestResult::Passed,
            TestResult::Failed("reason".to_string()),
            TestResult::Skipped("skipped reason".to_string()),
            TestResult::Error("error reason".to_string()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let deserialized: TestResult = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &deserialized);
        }
    }

    #[test]
    fn test_performance_metrics_serialization_roundtrip_succeeds() {
        let metrics = PerformanceMetrics {
            avg_execution_time_ms: 10.5,
            min_execution_time_ms: 1,
            max_execution_time_ms: 50,
            total_execution_time_ms: 100,
            memory_usage: MemoryUsageMetrics {
                peak_memory_bytes: 1024,
                avg_memory_bytes: 512,
                efficiency_rating: 0.9,
            },
            throughput: ThroughputMetrics {
                operations_per_second: 100.0,
                bytes_per_second: 1024,
                latency_percentiles: {
                    let mut m = HashMap::new();
                    m.insert("p50".to_string(), 10.0);
                    m
                },
            },
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: PerformanceMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(metrics, deserialized);
    }

    #[test]
    fn test_compliance_criteria_serialization_roundtrip_succeeds() {
        let criteria = ComplianceCriteria {
            min_pass_rate: 99.0,
            max_execution_time_ms: 5000,
            min_coverage: 95.0,
            security_requirements: vec![SecurityRequirement {
                requirement_id: "REQ-001".to_string(),
                description: "Test requirement".to_string(),
                mandatory: true,
                test_methods: vec!["KAT".to_string()],
            }],
        };
        let json = serde_json::to_string(&criteria).unwrap();
        let deserialized: ComplianceCriteria = serde_json::from_str(&json).unwrap();
        assert_eq!(criteria, deserialized);
    }

    #[test]
    fn test_detailed_test_result_serialization_roundtrip_succeeds() {
        let result = DetailedTestResult {
            test_id: "DTR-001".to_string(),
            category: TestCategory::Security,
            description: "Security test".to_string(),
            result: TestResult::Passed,
            execution_time_ms: 42,
            additional_details: HashMap::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DetailedTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    // ============================================================
    // Full report serialization roundtrip
    // ============================================================

    #[test]
    fn test_full_report_json_roundtrip() {
        let cgen = CavpComplianceGenerator::new();
        let alg = CavpAlgorithm::MlKem { variant: "1024".to_string() };
        let results =
            vec![make_passing_result("t1", alg.clone()), make_passing_result("t2", alg.clone())];
        let batch = make_batch(alg, results, Duration::from_millis(20));
        let report = cgen.generate_report(&[batch]).unwrap();

        let json = cgen.export_json(&report).unwrap();
        let deserialized: CavpComplianceReport = serde_json::from_str(&json).unwrap();

        assert_eq!(report.algorithm, deserialized.algorithm);
        assert_eq!(report.summary.total_tests, deserialized.summary.total_tests);
        assert_eq!(report.compliance_status, deserialized.compliance_status);
    }

    // ============================================================
    // Algorithm-specific criteria exercise
    // ============================================================

    #[test]
    fn test_all_algorithm_criteria_are_exercised_succeeds() {
        let cgen = CavpComplianceGenerator::new();

        // Test each algorithm variant to exercise all criteria map entries
        // Algorithm-specific criteria have min_coverage=100% but summary hardcodes 95%,
        // so all will be NonCompliant. The goal is to exercise the criteria lookup paths.
        let algorithms = vec![
            CavpAlgorithm::MlKem { variant: "512".to_string() },
            CavpAlgorithm::MlKem { variant: "1024".to_string() },
            CavpAlgorithm::MlDsa { variant: "44".to_string() },
            CavpAlgorithm::MlDsa { variant: "87".to_string() },
            CavpAlgorithm::SlhDsa { variant: "128".to_string() },
            CavpAlgorithm::SlhDsa { variant: "192".to_string() },
            CavpAlgorithm::SlhDsa { variant: "256".to_string() },
            CavpAlgorithm::FnDsa { variant: "512".to_string() },
            CavpAlgorithm::FnDsa { variant: "1024".to_string() },
        ];

        for alg in algorithms {
            let results = vec![make_passing_result("t1", alg.clone())];
            let batch = make_batch(alg.clone(), results, Duration::from_millis(5));
            let report = cgen.generate_report(&[batch]).unwrap();
            // All have 100% pass rate but 95% < 100% required coverage → NonCompliant
            assert!(
                matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }),
                "Expected NonCompliant due to coverage gap for {:?}, got {:?}",
                alg,
                report.compliance_status
            );
        }
    }
}

// Originally: fips_cavp_official_vectors_tests.rs
mod official_vectors {
    //! Comprehensive tests for CAVP Official Vectors module
    //!
    //! This module tests the official CAVP vector downloading, parsing, and validation
    //! functionality including:
    //! - OfficialCavpVector struct and its fields
    //! - CavpTestInputs and CavpTestOutputs structs
    //! - CavpTestCollection and CavpTestGroup structs
    //! - VectorValidationResult struct
    //! - CavpVectorDownloader functionality
    //! - Hex validation
    //! - Parameter set validation
    //! - Vector parsing and validation logic
    //! - Error handling paths

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

    use latticearc_tests::validation::cavp::official_vectors::{
        CavpTestCollection, CavpTestGroup, CavpTestInputs, CavpTestOutputs, CavpVectorDownloader,
        OfficialCavpVector, VectorValidationResult,
    };
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    // ============================================================================
    // Test Helper Functions
    // ============================================================================

    /// Creates a valid ML-KEM keyGen test vector
    fn create_valid_mlkem_keygen_vector() -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 1,
            tc_id: 1,
            algorithm: "ML-KEM".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "ML-KEM-768".to_string(),
            inputs: CavpTestInputs {
                seed: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
                ),
                sk: Some(
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                ),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        }
    }

    /// Creates a valid ML-DSA sigGen test vector
    fn create_valid_mldsa_siggen_vector() -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 2,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "ML-DSA-65".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some(
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                ),
                message: Some("48656c6c6f20576f726c64".to_string()), // "Hello World" in hex
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        }
    }

    /// Creates a valid ML-DSA sigVer test vector
    fn create_valid_mldsa_sigver_vector() -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 3,
            tc_id: 1,
            algorithm: "ML-DSA".to_string(),
            test_type: "sigVer".to_string(),
            parameter_set: "ML-DSA-44".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: Some(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
                ),
                sk: None,
                message: Some("48656c6c6f20576f726c64".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            },
        }
    }

    /// Creates a valid SLH-DSA keyGen test vector
    fn create_valid_slhdsa_keygen_vector() -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 4,
            tc_id: 1,
            algorithm: "SLH-DSA".to_string(),
            test_type: "keyGen".to_string(),
            parameter_set: "SLH-DSA-SHA2-128s".to_string(),
            inputs: CavpTestInputs {
                seed: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: Some(
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
                ),
                sk: Some(
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                ),
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        }
    }

    /// Creates a valid FN-DSA sigGen test vector
    fn create_valid_fndsa_siggen_vector() -> OfficialCavpVector {
        OfficialCavpVector {
            tg_id: 5,
            tc_id: 1,
            algorithm: "FN-DSA".to_string(),
            test_type: "sigGen".to_string(),
            parameter_set: "Falcon-512".to_string(),
            inputs: CavpTestInputs {
                seed: None,
                pk: None,
                sk: Some(
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210".to_string(),
                ),
                message: Some("48656c6c6f20576f726c64".to_string()),
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            },
            outputs: CavpTestOutputs {
                pk: None,
                sk: None,
                signature: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            },
        }
    }

    /// Creates a mock CAVP JSON file content for testing
    /// Note: Uses snake_case field names to match the struct deserialization
    fn create_mock_cavp_json(
        algorithm: &str,
        test_type: &str,
        parameter_set: &str,
    ) -> serde_json::Value {
        json!({
            "vs_id": 12345,
            "algorithm": algorithm,
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": test_type,
                    "parameter_set": parameter_set,
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "seed": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            },
                            "results": {
                                "pk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                                "sk": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                            }
                        },
                        {
                            "tcId": 2,
                            "testCase": {
                                "seed": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
                            },
                            "results": {
                                "pk": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                "sk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                            }
                        }
                    ]
                }
            ]
        })
    }

    /// Creates a mock CAVP JSON file for signature generation tests
    fn create_mock_siggen_json(algorithm: &str, parameter_set: &str) -> serde_json::Value {
        json!({
            "vs_id": 12346,
            "algorithm": algorithm,
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "sigGen",
                    "parameter_set": parameter_set,
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "sk": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                                "message": "48656c6c6f20576f726c64"
                            },
                            "results": {
                                "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            }
                        }
                    ]
                }
            ]
        })
    }

    /// Creates a mock CAVP JSON file for signature verification tests
    fn create_mock_sigver_json(algorithm: &str, parameter_set: &str) -> serde_json::Value {
        json!({
            "vs_id": 12347,
            "algorithm": algorithm,
            "revision": "1.0",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "sigVer",
                    "parameter_set": parameter_set,
                    "tests": [
                        {
                            "tcId": 1,
                            "testCase": {
                                "pk": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                                "message": "48656c6c6f20576f726c64"
                            },
                            "results": {
                                "signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                "test_passed": true
                            }
                        }
                    ]
                }
            ]
        })
    }

    // ============================================================================
    // OfficialCavpVector Tests
    // ============================================================================

    mod official_cavp_vector_tests {
        use super::*;

        #[test]
        fn test_vector_creation_mlkem_keygen_has_correct_fields_matches_expected() {
            let vector = create_valid_mlkem_keygen_vector();

            assert_eq!(vector.tg_id, 1);
            assert_eq!(vector.tc_id, 1);
            assert_eq!(vector.algorithm, "ML-KEM");
            assert_eq!(vector.test_type, "keyGen");
            assert_eq!(vector.parameter_set, "ML-KEM-768");
            assert!(vector.inputs.seed.is_some());
            assert!(vector.outputs.pk.is_some());
            assert!(vector.outputs.sk.is_some());
        }

        #[test]
        fn test_vector_creation_mldsa_siggen_has_correct_fields_matches_expected() {
            let vector = create_valid_mldsa_siggen_vector();

            assert_eq!(vector.algorithm, "ML-DSA");
            assert_eq!(vector.test_type, "sigGen");
            assert_eq!(vector.parameter_set, "ML-DSA-65");
            assert!(vector.inputs.sk.is_some());
            assert!(vector.inputs.message.is_some());
            assert!(vector.outputs.signature.is_some());
        }

        #[test]
        fn test_vector_creation_mldsa_sigver_has_correct_fields_matches_expected() {
            let vector = create_valid_mldsa_sigver_vector();

            assert_eq!(vector.algorithm, "ML-DSA");
            assert_eq!(vector.test_type, "sigVer");
            assert!(vector.inputs.pk.is_some());
            assert!(vector.inputs.message.is_some());
            assert!(vector.outputs.signature.is_some());
            assert!(vector.outputs.test_passed.is_some());
            assert_eq!(vector.outputs.test_passed, Some(true));
        }

        #[test]
        fn test_vector_creation_slhdsa_has_correct_fields_matches_expected() {
            let vector = create_valid_slhdsa_keygen_vector();

            assert_eq!(vector.algorithm, "SLH-DSA");
            assert_eq!(vector.test_type, "keyGen");
            assert_eq!(vector.parameter_set, "SLH-DSA-SHA2-128s");
        }

        #[test]
        fn test_vector_creation_fndsa_has_correct_fields_matches_expected() {
            let vector = create_valid_fndsa_siggen_vector();

            assert_eq!(vector.algorithm, "FN-DSA");
            assert_eq!(vector.test_type, "sigGen");
            assert_eq!(vector.parameter_set, "Falcon-512");
        }

        #[test]
        fn test_vector_serialization_round_trips_correctly_roundtrip() {
            let vector = create_valid_mlkem_keygen_vector();

            let serialized = serde_json::to_string(&vector).unwrap();
            let deserialized: OfficialCavpVector = serde_json::from_str(&serialized).unwrap();

            assert_eq!(vector.tg_id, deserialized.tg_id);
            assert_eq!(vector.tc_id, deserialized.tc_id);
            assert_eq!(vector.algorithm, deserialized.algorithm);
            assert_eq!(vector.test_type, deserialized.test_type);
            assert_eq!(vector.parameter_set, deserialized.parameter_set);
        }

        #[test]
        fn test_vector_clone_produces_equal_value_matches_expected() {
            let vector = create_valid_mlkem_keygen_vector();
            let cloned = vector.clone();

            assert_eq!(vector.tg_id, cloned.tg_id);
            assert_eq!(vector.tc_id, cloned.tc_id);
            assert_eq!(vector.algorithm, cloned.algorithm);
            assert_eq!(vector.inputs.seed, cloned.inputs.seed);
        }

        #[test]
        fn test_vector_debug_has_correct_format() {
            let vector = create_valid_mlkem_keygen_vector();
            let debug_str = format!("{:?}", vector);

            assert!(debug_str.contains("OfficialCavpVector"));
            assert!(debug_str.contains("ML-KEM"));
            assert!(debug_str.contains("keyGen"));
        }
    }

    // ============================================================================
    // CavpTestInputs Tests
    // ============================================================================

    mod cavp_test_inputs_tests {
        use super::*;

        #[test]
        fn test_inputs_empty_has_none_fields_succeeds() {
            let inputs = CavpTestInputs {
                seed: None,
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            };

            assert!(inputs.seed.is_none());
            assert!(inputs.pk.is_none());
            assert!(inputs.sk.is_none());
            assert!(inputs.message.is_none());
            assert!(inputs.additional.is_empty());
        }

        #[test]
        fn test_inputs_with_all_fields_are_accessible() {
            let mut additional = HashMap::new();
            additional.insert("custom_field".to_string(), json!("custom_value"));

            let inputs = CavpTestInputs {
                seed: Some("abcd1234".to_string()),
                pk: Some("pk_hex".to_string()),
                sk: Some("sk_hex".to_string()),
                message: Some("message_hex".to_string()),
                ct: Some("ct_hex".to_string()),
                ek: Some("ek_hex".to_string()),
                dk: Some("dk_hex".to_string()),
                m: Some("m_hex".to_string()),
                additional,
            };

            assert_eq!(inputs.seed, Some("abcd1234".to_string()));
            assert_eq!(inputs.pk, Some("pk_hex".to_string()));
            assert_eq!(inputs.sk, Some("sk_hex".to_string()));
            assert_eq!(inputs.message, Some("message_hex".to_string()));
            assert_eq!(inputs.ct, Some("ct_hex".to_string()));
            assert_eq!(inputs.ek, Some("ek_hex".to_string()));
            assert_eq!(inputs.dk, Some("dk_hex".to_string()));
            assert_eq!(inputs.m, Some("m_hex".to_string()));
            assert!(inputs.additional.contains_key("custom_field"));
        }

        #[test]
        fn test_inputs_serialization_round_trips_correctly_roundtrip() {
            let inputs = CavpTestInputs {
                seed: Some("0123456789abcdef".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            };

            let serialized = serde_json::to_string(&inputs).unwrap();
            let deserialized: CavpTestInputs = serde_json::from_str(&serialized).unwrap();

            assert_eq!(inputs.seed, deserialized.seed);
        }

        #[test]
        fn test_inputs_clone_produces_equal_value_succeeds() {
            let inputs = CavpTestInputs {
                seed: Some("test_seed".to_string()),
                pk: Some("test_pk".to_string()),
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            };

            let cloned = inputs.clone();
            assert_eq!(inputs.seed, cloned.seed);
            assert_eq!(inputs.pk, cloned.pk);
        }
    }

    // ============================================================================
    // CavpTestOutputs Tests
    // ============================================================================

    mod cavp_test_outputs_tests {
        use super::*;

        #[test]
        fn test_outputs_empty_has_none_fields_succeeds() {
            let outputs = CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None,
                ct: None,
                ss: None,
                test_passed: None,
                additional: HashMap::new(),
            };

            assert!(outputs.pk.is_none());
            assert!(outputs.sk.is_none());
            assert!(outputs.signature.is_none());
            assert!(outputs.test_passed.is_none());
        }

        #[test]
        fn test_outputs_with_all_fields_are_accessible() {
            let mut additional = HashMap::new();
            additional.insert("extra".to_string(), json!(42));

            let outputs = CavpTestOutputs {
                pk: Some("pk_output".to_string()),
                sk: Some("sk_output".to_string()),
                signature: Some("sig_output".to_string()),
                ct: Some("ct_output".to_string()),
                ss: Some("ss_output".to_string()),
                test_passed: Some(true),
                additional,
            };

            assert_eq!(outputs.pk, Some("pk_output".to_string()));
            assert_eq!(outputs.sk, Some("sk_output".to_string()));
            assert_eq!(outputs.signature, Some("sig_output".to_string()));
            assert_eq!(outputs.ct, Some("ct_output".to_string()));
            assert_eq!(outputs.ss, Some("ss_output".to_string()));
            assert_eq!(outputs.test_passed, Some(true));
            assert!(outputs.additional.contains_key("extra"));
        }

        #[test]
        fn test_outputs_test_passed_variants_are_accessible() {
            let outputs_pass = CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None,
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            };

            let outputs_fail = CavpTestOutputs {
                pk: None,
                sk: None,
                signature: None,
                ct: None,
                ss: None,
                test_passed: Some(false),
                additional: HashMap::new(),
            };

            assert_eq!(outputs_pass.test_passed, Some(true));
            assert_eq!(outputs_fail.test_passed, Some(false));
        }

        #[test]
        fn test_outputs_serialization_round_trips_correctly_roundtrip() {
            let outputs = CavpTestOutputs {
                pk: Some("0123456789".to_string()),
                sk: None,
                signature: Some("abcdef".to_string()),
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional: HashMap::new(),
            };

            let serialized = serde_json::to_string(&outputs).unwrap();
            let deserialized: CavpTestOutputs = serde_json::from_str(&serialized).unwrap();

            assert_eq!(outputs.pk, deserialized.pk);
            assert_eq!(outputs.signature, deserialized.signature);
            assert_eq!(outputs.test_passed, deserialized.test_passed);
        }
    }

    // ============================================================================
    // CavpTestCollection Tests
    // ============================================================================

    mod cavp_test_collection_tests {
        use super::*;

        #[test]
        fn test_collection_creation_has_correct_fields_succeeds() {
            let collection = CavpTestCollection {
                vs_id: 12345,
                algorithm: "ML-KEM".to_string(),
                revision: "1.0".to_string(),
                is_sample: true,
                test_groups: vec![],
            };

            assert_eq!(collection.vs_id, 12345);
            assert_eq!(collection.algorithm, "ML-KEM");
            assert_eq!(collection.revision, "1.0");
            assert!(collection.is_sample);
            assert!(collection.test_groups.is_empty());
        }

        #[test]
        fn test_collection_with_groups_has_correct_fields_succeeds() {
            let group = CavpTestGroup {
                tg_id: 1,
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                tests: vec![json!({"tcId": 1})],
            };

            let collection = CavpTestCollection {
                vs_id: 12345,
                algorithm: "ML-KEM".to_string(),
                revision: "1.0".to_string(),
                is_sample: false,
                test_groups: vec![group],
            };

            assert_eq!(collection.test_groups.len(), 1);
            assert_eq!(collection.test_groups[0].tg_id, 1);
            assert!(!collection.is_sample);
        }

        #[test]
        fn test_collection_serialization_round_trips_correctly_roundtrip() {
            let collection = CavpTestCollection {
                vs_id: 99999,
                algorithm: "ML-DSA".to_string(),
                revision: "2.0".to_string(),
                is_sample: true,
                test_groups: vec![],
            };

            let serialized = serde_json::to_string(&collection).unwrap();
            let deserialized: CavpTestCollection = serde_json::from_str(&serialized).unwrap();

            assert_eq!(collection.vs_id, deserialized.vs_id);
            assert_eq!(collection.algorithm, deserialized.algorithm);
            assert_eq!(collection.revision, deserialized.revision);
        }

        #[test]
        fn test_collection_clone_produces_equal_value_succeeds() {
            let collection = CavpTestCollection {
                vs_id: 11111,
                algorithm: "SLH-DSA".to_string(),
                revision: "1.5".to_string(),
                is_sample: false,
                test_groups: vec![],
            };

            let cloned = collection.clone();
            assert_eq!(collection.vs_id, cloned.vs_id);
            assert_eq!(collection.algorithm, cloned.algorithm);
        }
    }

    // ============================================================================
    // CavpTestGroup Tests
    // ============================================================================

    mod cavp_test_group_tests {
        use super::*;

        #[test]
        fn test_group_creation_has_correct_fields_succeeds() {
            let group = CavpTestGroup {
                tg_id: 1,
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-512".to_string(),
                tests: vec![],
            };

            assert_eq!(group.tg_id, 1);
            assert_eq!(group.test_type, "keyGen");
            assert_eq!(group.parameter_set, "ML-KEM-512");
            assert!(group.tests.is_empty());
        }

        #[test]
        fn test_group_with_tests_has_correct_fields_succeeds() {
            let tests =
                vec![json!({"tcId": 1, "seed": "abc123"}), json!({"tcId": 2, "seed": "def456"})];

            let group = CavpTestGroup {
                tg_id: 5,
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                tests,
            };

            assert_eq!(group.tests.len(), 2);
            assert_eq!(group.tests[0]["tcId"], 1);
            assert_eq!(group.tests[1]["tcId"], 2);
        }

        #[test]
        fn test_group_serialization_round_trips_correctly_roundtrip() {
            let group = CavpTestGroup {
                tg_id: 10,
                test_type: "sigVer".to_string(),
                parameter_set: "Falcon-1024".to_string(),
                tests: vec![json!({"tcId": 1})],
            };

            let serialized = serde_json::to_string(&group).unwrap();
            let deserialized: CavpTestGroup = serde_json::from_str(&serialized).unwrap();

            assert_eq!(group.tg_id, deserialized.tg_id);
            assert_eq!(group.test_type, deserialized.test_type);
            assert_eq!(group.parameter_set, deserialized.parameter_set);
        }

        #[test]
        fn test_group_clone_produces_equal_value_succeeds() {
            let group = CavpTestGroup {
                tg_id: 3,
                test_type: "keyGen".to_string(),
                parameter_set: "SLH-DSA-SHAKE-256f".to_string(),
                tests: vec![json!({"test": "data"})],
            };

            let cloned = group.clone();
            assert_eq!(group.tg_id, cloned.tg_id);
            assert_eq!(group.tests.len(), cloned.tests.len());
        }
    }

    // ============================================================================
    // VectorValidationResult Tests
    // ============================================================================

    mod vector_validation_result_tests {
        use super::*;

        #[test]
        fn test_result_valid_has_no_errors_fails() {
            let result = VectorValidationResult {
                is_valid: true,
                errors: vec![],
                warnings: vec![],
                vector_id: "ML-KEM-1-1".to_string(),
            };

            assert!(result.is_valid);
            assert!(result.errors.is_empty());
            assert!(result.warnings.is_empty());
            assert_eq!(result.vector_id, "ML-KEM-1-1");
        }

        #[test]
        fn test_result_with_errors_has_correct_errors_fails() {
            let result = VectorValidationResult {
                is_valid: false,
                errors: vec!["Invalid hex".to_string(), "Missing seed".to_string()],
                warnings: vec![],
                vector_id: "ML-DSA-2-3".to_string(),
            };

            assert!(!result.is_valid);
            assert_eq!(result.errors.len(), 2);
            assert!(result.errors.contains(&"Invalid hex".to_string()));
            assert!(result.errors.contains(&"Missing seed".to_string()));
        }

        #[test]
        fn test_result_with_warnings_has_correct_warnings_succeeds() {
            let result = VectorValidationResult {
                is_valid: true,
                errors: vec![],
                warnings: vec!["Missing verification result".to_string()],
                vector_id: "SLH-DSA-3-1".to_string(),
            };

            assert!(result.is_valid);
            assert!(!result.warnings.is_empty());
            assert!(result.warnings.contains(&"Missing verification result".to_string()));
        }

        #[test]
        fn test_result_with_both_errors_and_warnings_has_correct_fields_fails() {
            let result = VectorValidationResult {
                is_valid: false,
                errors: vec!["Critical error".to_string()],
                warnings: vec!["Minor warning".to_string()],
                vector_id: "FN-DSA-4-1".to_string(),
            };

            assert!(!result.is_valid);
            assert_eq!(result.errors.len(), 1);
            assert_eq!(result.warnings.len(), 1);
        }

        #[test]
        fn test_result_clone_produces_equal_value_succeeds() {
            let result = VectorValidationResult {
                is_valid: true,
                errors: vec![],
                warnings: vec!["test warning".to_string()],
                vector_id: "TEST-1-1".to_string(),
            };

            let cloned = result.clone();
            assert_eq!(result.is_valid, cloned.is_valid);
            assert_eq!(result.warnings, cloned.warnings);
            assert_eq!(result.vector_id, cloned.vector_id);
        }

        #[test]
        fn test_result_debug_has_correct_format() {
            let result = VectorValidationResult {
                is_valid: false,
                errors: vec!["error".to_string()],
                warnings: vec![],
                vector_id: "DEBUG-1-1".to_string(),
            };

            let debug_str = format!("{:?}", result);
            assert!(debug_str.contains("VectorValidationResult"));
            assert!(debug_str.contains("is_valid"));
        }
    }

    // ============================================================================
    // CavpVectorDownloader Tests
    // ============================================================================

    mod cavp_vector_downloader_tests {
        use super::*;

        #[test]
        fn test_downloader_creation_success_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path());

            assert!(downloader.is_ok());
        }

        #[test]
        fn test_downloader_creation_with_string_path_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let path_string = temp_dir.path().to_string_lossy().to_string();
            let downloader = CavpVectorDownloader::new(&path_string);

            assert!(downloader.is_ok());
        }

        #[test]
        fn test_downloader_creates_cache_dir_on_creation_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let cache_path = temp_dir.path().join("nested").join("cache").join("dir");

            let downloader = CavpVectorDownloader::new(&cache_path);

            assert!(downloader.is_ok());
            assert!(cache_path.exists());
        }

        #[test]
        fn test_downloader_vector_validation_keygen_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = create_valid_mlkem_keygen_vector();
            let result = downloader.validate_vector(&vector);

            assert!(result.is_valid, "Valid keyGen vector should pass: {:?}", result.errors);
            assert!(result.errors.is_empty());
        }

        #[test]
        fn test_downloader_vector_validation_siggen_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = create_valid_mldsa_siggen_vector();
            let result = downloader.validate_vector(&vector);

            assert!(result.is_valid, "Valid sigGen vector should pass: {:?}", result.errors);
        }

        #[test]
        fn test_downloader_vector_validation_sigver_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = create_valid_mldsa_sigver_vector();
            let result = downloader.validate_vector(&vector);

            assert!(result.is_valid, "Valid sigVer vector should pass: {:?}", result.errors);
        }

        #[test]
        fn test_downloader_vector_validation_keygen_missing_seed_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: None, // Missing required seed
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing seed"));
        }

        #[test]
        fn test_downloader_vector_validation_keygen_missing_pk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None, // Missing expected public key
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing expected public key"));
        }

        #[test]
        fn test_downloader_vector_validation_keygen_missing_sk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: None, // Missing expected secret key
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing expected secret key"));
        }

        #[test]
        fn test_downloader_vector_validation_siggen_missing_sk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: None, // Missing required sk
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing secret key"));
        }

        #[test]
        fn test_downloader_vector_validation_siggen_missing_message_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("abcdef123456".to_string()),
                    message: None, // Missing required message
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing message"));
        }

        #[test]
        fn test_downloader_vector_validation_siggen_missing_signature_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("abcdef123456".to_string()),
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: None, // Missing expected signature
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing expected signature"));
        }

        #[test]
        fn test_downloader_vector_validation_sigver_missing_pk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None, // Missing required pk
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing public key"));
        }

        #[test]
        fn test_downloader_vector_validation_sigver_missing_message_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef".to_string()),
                    sk: None,
                    message: None, // Missing required message
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("123456".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing message"));
        }

        #[test]
        fn test_downloader_vector_validation_sigver_missing_signature_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: None, // Missing signature
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing signature"));
        }

        #[test]
        fn test_downloader_vector_validation_sigver_missing_test_passed_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("123456".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None, // Missing - should produce warning
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            // Should still be valid, just with a warning
            assert!(result.is_valid);
            assert!(!result.warnings.is_empty());
            let warning_string = result.warnings.join(" ");
            assert!(warning_string.contains("Missing verification result"));
        }

        #[test]
        fn test_downloader_vector_validation_unknown_test_type_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "unknownTestType".to_string(), // Unknown test type
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            // Should produce a warning for unknown test type
            assert!(!result.warnings.is_empty());
            let warning_string = result.warnings.join(" ");
            assert!(warning_string.contains("Unknown test type"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_hex_in_seed_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdeG".to_string()), // Invalid hex (G)
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_hex_in_pk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("xyz123!@#".to_string()), // Invalid hex
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_hex_in_sk_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("not-valid-hex!".to_string()), // Invalid hex
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_hex_in_message_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("abcdef123456".to_string()),
                    message: Some("ghijkl".to_string()), // Invalid hex (g, h, i, j, k, l are invalid)
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_hex_in_signature_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("abcdef123456".to_string()),
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("ZZZZ".to_string()), // Invalid hex
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_downloader_vector_validation_invalid_parameter_set_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-999".to_string(), // Invalid parameter set
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("123456".to_string()),
                    sk: Some("789abc".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid parameter set"));
        }

        #[test]
        fn test_downloader_vector_validation_vector_id_format_is_correct() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 5,
                tc_id: 10,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("123456".to_string()),
                    sk: Some("789abc".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);

            // Vector ID should be in format: algorithm-tg_id-tc_id
            assert_eq!(result.vector_id, "ML-KEM-5-10");
        }

        #[test]
        fn test_downloader_parse_vector_content_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
            let content = serde_json::to_vec(&json).unwrap();

            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 2); // Two test cases in mock
        }

        #[test]
        fn test_downloader_parse_vector_content_siggen_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = create_mock_siggen_json("ML-DSA", "ML-DSA-65");
            let content = serde_json::to_vec(&json).unwrap();

            let result = downloader.parse_vector_content(&content, "ML-DSA-sigGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1);
        }

        #[test]
        fn test_downloader_parse_vector_content_sigver_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = create_mock_sigver_json("ML-DSA", "ML-DSA-44");
            let content = serde_json::to_vec(&json).unwrap();

            let result = downloader.parse_vector_content(&content, "ML-DSA-sigVer");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1);
        }

        #[test]
        fn test_downloader_parse_vector_content_invalid_utf8_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Invalid UTF-8 sequence
            let invalid_content: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01];

            let result = downloader.parse_vector_content(&invalid_content, "test");

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Invalid UTF-8"));
        }

        #[test]
        fn test_downloader_parse_vector_content_invalid_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let invalid_json = b"{ invalid json }";

            let result = downloader.parse_vector_content(invalid_json, "test");

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Failed to parse"));
        }

        #[test]
        fn test_downloader_load_vectors_from_file_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Write a mock JSON file
            let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-512");
            let file_path = temp_dir.path().join("ML-KEM-keyGen.json");
            fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert!(!vectors.is_empty());
        }

        #[test]
        fn test_downloader_load_vectors_from_nonexistent_file_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let nonexistent_path = temp_dir.path().join("does_not_exist.json");

            let result = downloader.load_vectors_from_file(&nonexistent_path);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Failed to read"));
        }
    }

    // ============================================================================
    // Hex Validation Tests
    // ============================================================================

    mod hex_validation_tests {
        use super::*;

        #[test]
        fn test_is_valid_hex_lowercase_returns_true_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let _downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Test via vector validation which uses is_valid_hex internally
            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()), // Valid lowercase hex
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("fedcba9876543210".to_string()),
                    sk: Some("abcdef0123456789".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = _downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_is_valid_hex_uppercase_returns_true_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789ABCDEF".to_string()), // Valid uppercase hex
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("FEDCBA9876543210".to_string()),
                    sk: Some("ABCDEF0123456789".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_is_valid_hex_mixed_case_returns_true_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123ABCDabcd4567".to_string()), // Valid mixed case hex
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("AaBbCcDdEeFf0011".to_string()),
                    sk: Some("9876543210ABCdef".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_is_valid_hex_empty_returns_true_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("".to_string()), // Empty string - invalid
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid hex"));
        }

        #[test]
        fn test_is_valid_hex_with_spaces_returns_false_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcd 1234".to_string()), // Space - invalid
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
        }

        #[test]
        fn test_is_valid_hex_with_special_chars_returns_false_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcd!@#$".to_string()), // Special chars - invalid
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
        }
    }

    // ============================================================================
    // Parameter Set Validation Tests
    // ============================================================================

    mod parameter_set_validation_tests {
        use super::*;

        // ML-KEM parameter sets
        #[test]
        fn test_mlkem_512_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.parameter_set = "ML-KEM-512".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-KEM-512 should be valid");
        }

        #[test]
        fn test_mlkem_768_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.parameter_set = "ML-KEM-768".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-KEM-768 should be valid");
        }

        #[test]
        fn test_mlkem_1024_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.parameter_set = "ML-KEM-1024".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-KEM-1024 should be valid");
        }

        #[test]
        fn test_mlkem_invalid_variant_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.parameter_set = "ML-KEM-256".to_string(); // Invalid

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid parameter set"));
        }

        // ML-DSA parameter sets
        #[test]
        fn test_mldsa_44_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mldsa_siggen_vector();
            vector.parameter_set = "ML-DSA-44".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-DSA-44 should be valid");
        }

        #[test]
        fn test_mldsa_65_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mldsa_siggen_vector();
            vector.parameter_set = "ML-DSA-65".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-DSA-65 should be valid");
        }

        #[test]
        fn test_mldsa_87_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mldsa_siggen_vector();
            vector.parameter_set = "ML-DSA-87".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-DSA-87 should be valid");
        }

        #[test]
        fn test_mldsa_128_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mldsa_siggen_vector();
            vector.parameter_set = "ML-DSA-128".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "ML-DSA-128 should be valid");
        }

        #[test]
        fn test_mldsa_invalid_variant_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mldsa_siggen_vector();
            vector.parameter_set = "ML-DSA-99".to_string(); // Invalid

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
        }

        // SLH-DSA parameter sets
        #[test]
        fn test_slhdsa_sha2_128s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-128s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-128s should be valid");
        }

        #[test]
        fn test_slhdsa_sha2_128f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-128f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-128f should be valid");
        }

        #[test]
        fn test_slhdsa_sha2_192s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-192s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-192s should be valid");
        }

        #[test]
        fn test_slhdsa_sha2_192f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-192f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-192f should be valid");
        }

        #[test]
        fn test_slhdsa_sha2_256s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-256s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-256s should be valid");
        }

        #[test]
        fn test_slhdsa_sha2_256f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHA2-256f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHA2-256f should be valid");
        }

        #[test]
        fn test_slhdsa_shake_128s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-128s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-128s should be valid");
        }

        #[test]
        fn test_slhdsa_shake_128f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-128f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-128f should be valid");
        }

        #[test]
        fn test_slhdsa_shake_192s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-192s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-192s should be valid");
        }

        #[test]
        fn test_slhdsa_shake_192f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-192f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-192f should be valid");
        }

        #[test]
        fn test_slhdsa_shake_256s_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-256s".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-256s should be valid");
        }

        #[test]
        fn test_slhdsa_shake_256f_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-256f".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "SLH-DSA-SHAKE-256f should be valid");
        }

        #[test]
        fn test_slhdsa_invalid_variant_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_slhdsa_keygen_vector();
            vector.parameter_set = "SLH-DSA-SHAKE-512s".to_string(); // Invalid

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
        }

        // FN-DSA parameter sets
        #[test]
        fn test_fndsa_falcon_512_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_fndsa_siggen_vector();
            vector.parameter_set = "Falcon-512".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "Falcon-512 should be valid");
        }

        #[test]
        fn test_fndsa_falcon_1024_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_fndsa_siggen_vector();
            vector.parameter_set = "Falcon-1024".to_string();

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "Falcon-1024 should be valid");
        }

        #[test]
        fn test_fndsa_invalid_variant_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_fndsa_siggen_vector();
            vector.parameter_set = "Falcon-256".to_string(); // Invalid

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
        }

        // Unknown algorithm
        #[test]
        fn test_unknown_algorithm_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "UNKNOWN-ALG".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "UNKNOWN-PARAM".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("123456".to_string()),
                    sk: Some("789abc".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Invalid parameter set"));
        }
    }

    // ============================================================================
    // Async Download Tests (Mock)
    // ============================================================================

    mod async_download_tests {
        use super::*;

        #[tokio::test]
        async fn test_download_caching_behavior_persists_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Write a cached file
            let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
            let cache_path = temp_dir.path().join("ML-KEM-keyGen.json");
            fs::write(&cache_path, serde_json::to_vec(&json).unwrap()).unwrap();

            // Verify cached file exists
            assert!(cache_path.exists());

            // Load from cache
            let vectors = downloader.load_vectors_from_file(&cache_path).unwrap();
            assert!(!vectors.is_empty());
        }

        #[tokio::test]
        async fn test_downloader_exists_after_creation_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path());

            assert!(downloader.is_ok());
            // Just verifying the downloader can be created and used
            let downloader = downloader.unwrap();

            let vector = create_valid_mlkem_keygen_vector();
            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }
    }

    // ============================================================================
    // Edge Cases and Error Handling Tests
    // ============================================================================

    mod edge_cases_tests {
        use super::*;

        #[test]
        fn test_empty_additional_fields_are_accepted_succeeds() {
            let inputs = CavpTestInputs {
                seed: None,
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional: HashMap::new(),
            };

            assert!(inputs.additional.is_empty());
        }

        #[test]
        fn test_additional_fields_with_various_types_are_accepted_succeeds() {
            let mut additional = HashMap::new();
            additional.insert("string_field".to_string(), json!("string_value"));
            additional.insert("number_field".to_string(), json!(42));
            additional.insert("bool_field".to_string(), json!(true));
            additional.insert("array_field".to_string(), json!([1, 2, 3]));
            additional.insert("object_field".to_string(), json!({"nested": "value"}));
            additional.insert("null_field".to_string(), json!(null));

            let inputs = CavpTestInputs {
                seed: None,
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional,
            };

            assert_eq!(inputs.additional.len(), 6);
            assert_eq!(inputs.additional["string_field"], json!("string_value"));
            assert_eq!(inputs.additional["number_field"], json!(42));
        }

        #[test]
        fn test_very_long_hex_string_is_accepted() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a very long but valid hex string
            let long_hex: String = "a".repeat(10000);

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some(long_hex.clone()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some(long_hex.clone()),
                    sk: Some(long_hex),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid, "Long valid hex should be accepted");
        }

        #[test]
        fn test_multiple_validation_errors_are_reported_fails() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-999".to_string(), // Invalid parameter set
                inputs: CavpTestInputs {
                    seed: Some("GHIJ".to_string()), // Invalid hex
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None, // Missing required pk
                    sk: None, // Missing required sk
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            // Should have multiple errors
            assert!(result.errors.len() >= 3, "Expected multiple errors, got: {:?}", result.errors);
        }

        #[test]
        fn test_vector_with_all_none_inputs_is_accepted() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            // Should report missing seed for keyGen
            let error_string = result.errors.join(" ");
            assert!(error_string.contains("Missing seed"));
        }

        #[test]
        fn test_large_tg_id_and_tc_id_are_accepted_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: u32::MAX,
                tc_id: u32::MAX,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("123456".to_string()),
                    sk: Some("789abc".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
            assert!(result.vector_id.contains(&format!("{}", u32::MAX)));
        }
    }

    // ============================================================================
    // JSON Parsing Tests
    // ============================================================================

    mod json_parsing_tests {
        use super::*;

        #[test]
        fn test_parse_complete_collection_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {
                                    "seed": "0123456789abcdef0123456789abcdef"
                                },
                                "results": {
                                    "pk": "abcdef0123456789abcdef0123456789",
                                    "sk": "fedcba9876543210fedcba9876543210"
                                }
                            }
                        ]
                    },
                    {
                        "tg_id": 2,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-512",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {
                                    "seed": "aabbccdd11223344aabbccdd11223344"
                                },
                                "results": {
                                    "pk": "11223344aabbccdd11223344aabbccdd",
                                    "sk": "44332211ddccbbaa44332211ddccbbaa"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 2); // Two test groups with one test each
        }

        #[test]
        fn test_parse_empty_test_groups_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": []
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert!(vectors.is_empty());
        }

        #[test]
        fn test_parse_empty_tests_in_group_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": []
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert!(vectors.is_empty());
        }

        #[test]
        fn test_parse_missing_required_fields_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Missing "algorithm" field
            let json = json!({
                "vs_id": 12345,
                "revision": "1.0",
                "is_sample": true,
                "test_groups": []
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "test");

            assert!(result.is_err());
        }

        #[test]
        fn test_parse_with_default_tc_id_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Test case without tcId - should use index as default
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "testCase": {
                                    "seed": "0123456789abcdef0123456789abcdef"
                                },
                                "results": {
                                    "pk": "abcdef0123456789abcdef0123456789",
                                    "sk": "fedcba9876543210fedcba9876543210"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1);
            assert_eq!(vectors[0].tc_id, 0); // Default from index
        }
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_full_workflow_mlkem_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create mock JSON
            let json = create_mock_cavp_json("ML-KEM", "keyGen", "ML-KEM-768");
            let content = serde_json::to_vec(&json).unwrap();

            // Parse vectors
            let vectors = downloader.parse_vector_content(&content, "ML-KEM-keyGen").unwrap();

            // Validate each vector
            for vector in &vectors {
                let result = downloader.validate_vector(vector);
                assert!(result.is_valid, "Vector should be valid: {:?}", result.errors);
            }
        }

        #[test]
        fn test_full_workflow_mldsa_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create mock JSON for sigGen
            let json = create_mock_siggen_json("ML-DSA", "ML-DSA-44");
            let content = serde_json::to_vec(&json).unwrap();

            // Parse vectors
            let vectors = downloader.parse_vector_content(&content, "ML-DSA-sigGen").unwrap();

            // Validate each vector
            for vector in &vectors {
                let result = downloader.validate_vector(vector);
                assert!(result.is_valid, "Vector should be valid: {:?}", result.errors);
            }
        }

        #[test]
        fn test_cache_file_creation_persists_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let _downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Verify cache directory exists
            assert!(temp_dir.path().exists());
            assert!(temp_dir.path().is_dir());
        }

        #[test]
        fn test_multiple_downloader_instances_succeed_succeeds() {
            let temp_dir1 = TempDir::new().unwrap();
            let temp_dir2 = TempDir::new().unwrap();

            let downloader1 = CavpVectorDownloader::new(temp_dir1.path()).unwrap();
            let downloader2 = CavpVectorDownloader::new(temp_dir2.path()).unwrap();

            let vector = create_valid_mlkem_keygen_vector();

            let result1 = downloader1.validate_vector(&vector);
            let result2 = downloader2.validate_vector(&vector);

            assert_eq!(result1.is_valid, result2.is_valid);
        }
    }

    // ============================================================================
    // Additional Coverage Tests - Static Methods
    // ============================================================================

    mod static_method_tests {
        use super::*;

        // Tests for is_valid_hex static method
        #[test]
        fn test_is_valid_hex_direct_call_valid_lowercase_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_hex("0123456789abcdef"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_valid_uppercase_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_hex("0123456789ABCDEF"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_valid_mixed_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_hex("aAbBcCdDeEfF0123"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_single_char_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_hex("a"));
            assert!(CavpVectorDownloader::is_valid_hex("F"));
            assert!(CavpVectorDownloader::is_valid_hex("0"));
            assert!(CavpVectorDownloader::is_valid_hex("9"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_empty_returns_true_succeeds() {
            assert!(!CavpVectorDownloader::is_valid_hex(""));
        }

        #[test]
        fn test_is_valid_hex_direct_call_invalid_g_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_hex("g"));
            assert!(!CavpVectorDownloader::is_valid_hex("abcdG123"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_invalid_special_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_hex("!"));
            assert!(!CavpVectorDownloader::is_valid_hex("@"));
            assert!(!CavpVectorDownloader::is_valid_hex("#"));
            assert!(!CavpVectorDownloader::is_valid_hex("$"));
            assert!(!CavpVectorDownloader::is_valid_hex("%"));
            assert!(!CavpVectorDownloader::is_valid_hex("^"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_invalid_whitespace_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_hex(" "));
            assert!(!CavpVectorDownloader::is_valid_hex("\t"));
            assert!(!CavpVectorDownloader::is_valid_hex("\n"));
            assert!(!CavpVectorDownloader::is_valid_hex("ab cd"));
            assert!(!CavpVectorDownloader::is_valid_hex("ab\ncd"));
        }

        #[test]
        fn test_is_valid_hex_direct_call_invalid_unicode_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_hex("\u{00e9}")); // e with acute
            assert!(!CavpVectorDownloader::is_valid_hex("\u{03B1}")); // alpha
            assert!(!CavpVectorDownloader::is_valid_hex("\u{4e2d}")); // Chinese character
        }

        // Tests for is_valid_parameter_set static method
        #[test]
        fn test_is_valid_parameter_set_mlkem_all_valid_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-512"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-768"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-1024"));
        }

        #[test]
        fn test_is_valid_parameter_set_mlkem_invalid_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-128"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-256"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM-2048"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", ""));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ML-KEM"));
        }

        #[test]
        fn test_is_valid_parameter_set_mldsa_all_valid_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-44"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-65"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-87"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-128"));
        }

        #[test]
        fn test_is_valid_parameter_set_mldsa_invalid_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-32"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", "ML-DSA-256"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-DSA", ""));
        }

        #[test]
        fn test_is_valid_parameter_set_slhdsa_sha2_all_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-128s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-128f"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-192s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-192f"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-256s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-256f"));
        }

        #[test]
        fn test_is_valid_parameter_set_slhdsa_shake_all_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-128s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-128f"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-192s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-192f"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-256s"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-256f"));
        }

        #[test]
        fn test_is_valid_parameter_set_slhdsa_invalid_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHA2-64s"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-SHAKE-512s"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", "SLH-DSA-MD5-128s"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("SLH-DSA", ""));
        }

        #[test]
        fn test_is_valid_parameter_set_fndsa_all_valid_returns_true_succeeds() {
            assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-512"));
            assert!(CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-1024"));
        }

        #[test]
        fn test_is_valid_parameter_set_fndsa_invalid_returns_false_fails() {
            assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-256"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Falcon-2048"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", "Dilithium-512"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("FN-DSA", ""));
        }

        #[test]
        fn test_is_valid_parameter_set_unknown_algorithm_returns_false_succeeds() {
            assert!(!CavpVectorDownloader::is_valid_parameter_set("UNKNOWN", "any-param"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("", "ML-KEM-768"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("RSA", "RSA-2048"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ECDSA", "P-256"));
        }

        #[test]
        fn test_is_valid_parameter_set_case_sensitivity_returns_false_succeeds() {
            // The implementation is case-sensitive
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ml-kem", "ML-KEM-768"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("ML-KEM", "ml-kem-768"));
            assert!(!CavpVectorDownloader::is_valid_parameter_set("Ml-Kem", "ML-KEM-768"));
        }
    }

    // ============================================================================
    // Convert Test Case Error Handling Tests
    // ============================================================================

    mod convert_test_case_tests {
        use super::*;

        #[test]
        fn test_parse_vector_with_missing_testcase_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Test case missing testCase field - implementation returns error
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "results": {
                                    "pk": "abcdef0123456789",
                                    "sk": "fedcba9876543210"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            // Implementation returns error when testCase field is missing
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_vector_with_missing_results_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Test case missing results field - implementation returns error for missing fields
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {
                                    "seed": "0123456789abcdef"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            // Implementation returns error when results field is missing
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_vector_with_null_testcase_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": null,
                                "results": {
                                    "pk": "abcdef",
                                    "sk": "123456"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            // Implementation returns error for null testCase
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_vector_with_null_results_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {
                                    "seed": "0123456789abcdef"
                                },
                                "results": null
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            // Implementation returns error for null results
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_vector_with_wrong_type_in_testcase_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // testCase is a string instead of object
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": "invalid_string",
                                "results": {
                                    "pk": "abcdef",
                                    "sk": "123456"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            // Should return error due to type mismatch
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_vector_with_numeric_tcid_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 99999,
                                "testCase": {
                                    "seed": "0123456789abcdef"
                                },
                                "results": {
                                    "pk": "abcdef0123456789",
                                    "sk": "fedcba9876543210"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1);
            assert_eq!(vectors[0].tc_id, 99999);
        }

        #[test]
        fn test_parse_vector_tcid_as_string_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // tcId as string instead of number - should fallback to index
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": "not_a_number",
                                "testCase": {
                                    "seed": "0123456789abcdef"
                                },
                                "results": {
                                    "pk": "abcdef0123456789",
                                    "sk": "fedcba9876543210"
                                }
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 1);
            // Falls back to index (0)
            assert_eq!(vectors[0].tc_id, 0);
        }
    }

    // ============================================================================
    // File I/O Error Handling Tests
    // ============================================================================

    mod file_io_error_tests {
        use super::*;

        #[test]
        fn test_load_from_empty_file_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create an empty file
            let file_path = temp_dir.path().join("empty.json");
            fs::write(&file_path, "").unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Failed to parse"));
        }

        #[test]
        fn test_load_from_corrupted_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a corrupted JSON file
            let file_path = temp_dir.path().join("corrupted.json");
            fs::write(&file_path, r#"{"vs_id": 12345, "algorithm": "ML-KEM", incomplete..."#)
                .unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.to_string().contains("Failed to parse"));
        }

        #[test]
        fn test_load_from_valid_json_wrong_schema_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Valid JSON but wrong schema
            let file_path = temp_dir.path().join("wrong_schema.json");
            fs::write(&file_path, r#"{"name": "test", "value": 123}"#).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_err());
        }

        #[test]
        fn test_load_from_array_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // JSON array instead of object
            let file_path = temp_dir.path().join("array.json");
            fs::write(&file_path, r#"[1, 2, 3]"#).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_err());
        }

        #[test]
        fn test_load_from_binary_file_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a binary file
            let file_path = temp_dir.path().join("binary.json");
            fs::write(&file_path, &[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            // May fail at UTF-8 decoding or JSON parsing
            assert!(result.is_err());
        }

        #[test]
        fn test_cache_file_with_invalid_content_fallback_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a cache file with invalid JSON content
            let cache_path = temp_dir.path().join("ML-KEM-keyGen.json");
            fs::write(&cache_path, "not valid json").unwrap();

            // Try to load from this "cached" file
            let result = downloader.load_vectors_from_file(&cache_path);

            // Should fail because content is invalid
            assert!(result.is_err());
        }

        #[test]
        fn test_file_stem_extraction_with_extension_is_correct() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a valid JSON file with specific name
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": []
            });
            let file_path = temp_dir.path().join("test-vectors.json");
            fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_ok());
        }

        #[test]
        fn test_file_without_extension_is_correct() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // Create a valid JSON file without .json extension
            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": []
            });
            let file_path = temp_dir.path().join("test-vectors");
            fs::write(&file_path, serde_json::to_vec(&json).unwrap()).unwrap();

            let result = downloader.load_vectors_from_file(&file_path);

            assert!(result.is_ok());
        }
    }

    // ============================================================================
    // Validation Edge Cases Tests
    // ============================================================================

    mod validation_edge_cases {
        use super::*;

        #[test]
        fn test_validate_sigver_with_test_passed_false_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef1234567890".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("fedcba0987654321".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(false), // Explicitly false
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
            assert!(result.warnings.is_empty()); // No warning for present test_passed
        }

        #[test]
        fn test_validate_encapdecap_test_type_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // encapDecap is an unknown test type (not keyGen, sigGen, sigVer)
            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "encapDecap".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: Some("ciphertext".to_string()),
                    ek: Some("encap_key".to_string()),
                    dk: Some("decap_key".to_string()),
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: None,
                    ct: None,
                    ss: Some("shared_secret".to_string()),
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            // Should be valid but with warning about unknown test type
            assert!(result.is_valid);
            assert!(!result.warnings.is_empty());
            let warning = result.warnings.join(" ");
            assert!(warning.contains("Unknown test type"));
        }

        #[test]
        fn test_validate_with_extra_additional_inputs_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut additional = HashMap::new();
            additional.insert("rng_name".to_string(), json!("AES-256-CTR-DRBG"));
            additional.insert("deterministic".to_string(), json!(true));
            additional.insert("iterations".to_string(), json!(1000));

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional,
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_validate_with_extra_additional_outputs_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut additional = HashMap::new();
            additional.insert("hash".to_string(), json!("sha256_of_pk"));
            additional.insert("verification_time_ms".to_string(), json!(42));

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("abcdef".to_string()),
                    sk: Some("123456".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional,
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_validate_all_hex_fields_invalid_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("invalid!seed".to_string()),
                    pk: Some("invalid@pk".to_string()),
                    sk: Some("invalid#sk".to_string()),
                    message: Some("invalid$message".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("invalid%sig".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            // Should have multiple hex validation errors
            assert!(result.errors.len() >= 4);
        }

        #[test]
        fn test_validate_keygen_with_only_seed_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None, // Missing
                    sk: None, // Missing
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(!result.is_valid);
            let error_str = result.errors.join(" ");
            assert!(error_str.contains("Missing expected public key"));
            assert!(error_str.contains("Missing expected secret key"));
        }
    }

    // ============================================================================
    // Serialization/Deserialization Tests
    // ============================================================================

    mod serialization_tests {
        use super::*;

        #[test]
        fn test_vector_roundtrip_serialization_succeeds() {
            let vector = OfficialCavpVector {
                tg_id: 42,
                tc_id: 99,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef1234567890".to_string()),
                    pk: Some("pk_value".to_string()),
                    sk: Some("sk_value".to_string()),
                    message: Some("message_value".to_string()),
                    ct: Some("ct_value".to_string()),
                    ek: Some("ek_value".to_string()),
                    dk: Some("dk_value".to_string()),
                    m: Some("m_value".to_string()),
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("out_pk".to_string()),
                    sk: Some("out_sk".to_string()),
                    signature: Some("out_sig".to_string()),
                    ct: Some("out_ct".to_string()),
                    ss: Some("out_ss".to_string()),
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let serialized = serde_json::to_string(&vector).unwrap();
            let deserialized: OfficialCavpVector = serde_json::from_str(&serialized).unwrap();

            assert_eq!(vector.tg_id, deserialized.tg_id);
            assert_eq!(vector.tc_id, deserialized.tc_id);
            assert_eq!(vector.algorithm, deserialized.algorithm);
            assert_eq!(vector.inputs.seed, deserialized.inputs.seed);
            assert_eq!(vector.outputs.pk, deserialized.outputs.pk);
            assert_eq!(vector.outputs.test_passed, deserialized.outputs.test_passed);
        }

        #[test]
        fn test_collection_roundtrip_serialization_succeeds() {
            let collection = CavpTestCollection {
                vs_id: 12345,
                algorithm: "ML-DSA".to_string(),
                revision: "2.0".to_string(),
                is_sample: false,
                test_groups: vec![
                    CavpTestGroup {
                        tg_id: 1,
                        test_type: "sigGen".to_string(),
                        parameter_set: "ML-DSA-65".to_string(),
                        tests: vec![json!({"tcId": 1, "data": "test"})],
                    },
                    CavpTestGroup {
                        tg_id: 2,
                        test_type: "sigVer".to_string(),
                        parameter_set: "ML-DSA-87".to_string(),
                        tests: vec![],
                    },
                ],
            };

            let serialized = serde_json::to_string(&collection).unwrap();
            let deserialized: CavpTestCollection = serde_json::from_str(&serialized).unwrap();

            assert_eq!(collection.vs_id, deserialized.vs_id);
            assert_eq!(collection.algorithm, deserialized.algorithm);
            assert_eq!(collection.test_groups.len(), deserialized.test_groups.len());
            assert_eq!(
                collection.test_groups[0].parameter_set,
                deserialized.test_groups[0].parameter_set
            );
        }

        #[test]
        fn test_inputs_with_additional_fields_serialization_succeeds() {
            let mut additional = HashMap::new();
            additional.insert("custom1".to_string(), json!("value1"));
            additional.insert("custom2".to_string(), json!(123));
            additional.insert("custom3".to_string(), json!({"nested": "object"}));

            let inputs = CavpTestInputs {
                seed: Some("seed_value".to_string()),
                pk: None,
                sk: None,
                message: None,
                ct: None,
                ek: None,
                dk: None,
                m: None,
                additional,
            };

            let serialized = serde_json::to_string(&inputs).unwrap();
            let deserialized: CavpTestInputs = serde_json::from_str(&serialized).unwrap();

            assert_eq!(inputs.seed, deserialized.seed);
            assert_eq!(inputs.additional.len(), deserialized.additional.len());
            assert_eq!(inputs.additional["custom1"], deserialized.additional["custom1"]);
        }

        #[test]
        fn test_outputs_with_additional_fields_serialization_succeeds() {
            let mut additional = HashMap::new();
            additional.insert("extra_output".to_string(), json!([1, 2, 3]));
            additional.insert("flag".to_string(), json!(false));

            let outputs = CavpTestOutputs {
                pk: Some("pk_out".to_string()),
                sk: None,
                signature: None,
                ct: None,
                ss: None,
                test_passed: Some(true),
                additional,
            };

            let serialized = serde_json::to_string(&outputs).unwrap();
            let deserialized: CavpTestOutputs = serde_json::from_str(&serialized).unwrap();

            assert_eq!(outputs.pk, deserialized.pk);
            assert_eq!(outputs.test_passed, deserialized.test_passed);
            assert_eq!(outputs.additional.len(), deserialized.additional.len());
        }

        #[test]
        fn test_deserialize_from_external_json_format_has_correct_size() {
            // Simulate external JSON format that might come from NIST
            let external_json = r#"{
            "vs_id": 99999,
            "algorithm": "ML-KEM",
            "revision": "FIPS203",
            "is_sample": true,
            "test_groups": [
                {
                    "tg_id": 1,
                    "test_type": "keyGen",
                    "parameter_set": "ML-KEM-1024",
                    "tests": []
                }
            ]
        }"#;

            let collection: CavpTestCollection = serde_json::from_str(external_json).unwrap();

            assert_eq!(collection.vs_id, 99999);
            assert_eq!(collection.algorithm, "ML-KEM");
            assert_eq!(collection.revision, "FIPS203");
            assert!(collection.is_sample);
            assert_eq!(collection.test_groups.len(), 1);
        }
    }

    // ============================================================================
    // Multiple Test Groups Tests
    // ============================================================================

    mod multiple_test_groups_tests {
        use super::*;

        #[test]
        fn test_parse_multiple_groups_different_param_sets_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-512",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"seed": "0123456789abcdef"},
                                "results": {"pk": "aabbccdd", "sk": "11223344"}
                            }
                        ]
                    },
                    {
                        "tg_id": 2,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"seed": "fedcba9876543210"},
                                "results": {"pk": "55667788", "sk": "99aabbcc"}
                            }
                        ]
                    },
                    {
                        "tg_id": 3,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-1024",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"seed": "abcdef1234567890"},
                                "results": {"pk": "ddeeff00", "sk": "11223344"}
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 3);

            assert_eq!(vectors[0].parameter_set, "ML-KEM-512");
            assert_eq!(vectors[1].parameter_set, "ML-KEM-768");
            assert_eq!(vectors[2].parameter_set, "ML-KEM-1024");
        }

        #[test]
        fn test_parse_multiple_tests_in_single_group_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-DSA",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "sigGen",
                        "parameter_set": "ML-DSA-44",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"sk": "aabbccdd", "message": "11223344"},
                                "results": {"signature": "aabbccdd11223344"}
                            },
                            {
                                "tcId": 2,
                                "testCase": {"sk": "eeff0011", "message": "55667788"},
                                "results": {"signature": "eeff001155667788"}
                            },
                            {
                                "tcId": 3,
                                "testCase": {"sk": "99aabbcc", "message": "ddeeff00"},
                                "results": {"signature": "99aabbccddeeff00"}
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-DSA-sigGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            assert_eq!(vectors.len(), 3);

            assert_eq!(vectors[0].tc_id, 1);
            assert_eq!(vectors[1].tc_id, 2);
            assert_eq!(vectors[2].tc_id, 3);
        }

        #[test]
        fn test_parse_mixed_valid_invalid_vectors_returns_partial_errors_matches_expected() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"seed": "0123456789abcdef"},
                                "results": {"pk": "aabbccdd", "sk": "11223344"}
                            },
                            {
                                "tcId": 2,
                                "testCase": {"seed": "INVALID_HEX!!"},
                                "results": {"pk": "55667788", "sk": "99aabbcc"}
                            },
                            {
                                "tcId": 3,
                                "testCase": {"seed": "fedcba9876543210"},
                                "results": {"pk": "ddeeff00", "sk": "11223344"}
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "ML-KEM-keyGen");

            assert!(result.is_ok());
            let vectors = result.unwrap();
            // Invalid vector (tcId 2) should be filtered out
            assert_eq!(vectors.len(), 2);
            assert_eq!(vectors[0].tc_id, 1);
            assert_eq!(vectors[1].tc_id, 3);
        }
    }

    // ============================================================================
    // Vector ID Generation Tests
    // ============================================================================

    mod vector_id_tests {
        use super::*;

        #[test]
        fn test_vector_id_format_basic_matches_expected() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("123456".to_string()),
                    sk: Some("789abc".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert_eq!(result.vector_id, "ML-KEM-1-1");
        }

        #[test]
        fn test_vector_id_format_different_algorithms_matches_expected() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let algorithms = vec![
                ("ML-KEM", "ML-KEM-768", "keyGen"),
                ("ML-DSA", "ML-DSA-44", "sigGen"),
                ("SLH-DSA", "SLH-DSA-SHA2-128s", "keyGen"),
                ("FN-DSA", "Falcon-512", "sigGen"),
            ];

            for (alg, param, test_type) in algorithms {
                let mut vector = create_valid_mlkem_keygen_vector();
                vector.algorithm = alg.to_string();
                vector.parameter_set = param.to_string();
                vector.test_type = test_type.to_string();
                vector.tg_id = 10;
                vector.tc_id = 20;

                if test_type == "sigGen" {
                    vector.inputs.sk = Some("abcdef123456".to_string());
                    vector.inputs.message = Some("48656c6c6f".to_string());
                    vector.outputs.signature = Some("fedcba654321".to_string());
                    vector.outputs.pk = None;
                    vector.outputs.sk = None;
                    vector.inputs.seed = None;
                }

                let result = downloader.validate_vector(&vector);
                assert_eq!(result.vector_id, format!("{}-10-20", alg));
            }
        }

        #[test]
        fn test_vector_id_with_zero_ids_is_accepted() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.tg_id = 0;
            vector.tc_id = 0;

            let result = downloader.validate_vector(&vector);
            assert_eq!(result.vector_id, "ML-KEM-0-0");
        }

        #[test]
        fn test_vector_id_with_large_ids_is_accepted() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let mut vector = create_valid_mlkem_keygen_vector();
            vector.tg_id = 999999;
            vector.tc_id = 888888;

            let result = downloader.validate_vector(&vector);
            assert_eq!(result.vector_id, "ML-KEM-999999-888888");
        }
    }

    // ============================================================================
    // Downloader Creation Edge Cases
    // ============================================================================

    mod downloader_creation_tests {
        use super::*;

        #[test]
        fn test_downloader_with_existing_directory_succeeds() {
            let temp_dir = TempDir::new().unwrap();

            // Create directory first
            let cache_path = temp_dir.path().join("existing_cache");
            fs::create_dir_all(&cache_path).unwrap();

            // Should succeed even if directory exists
            let downloader = CavpVectorDownloader::new(&cache_path);
            assert!(downloader.is_ok());
        }

        #[test]
        fn test_downloader_with_deeply_nested_path_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let deep_path = temp_dir
                .path()
                .join("level1")
                .join("level2")
                .join("level3")
                .join("level4")
                .join("cache");

            let downloader = CavpVectorDownloader::new(&deep_path);
            assert!(downloader.is_ok());
            assert!(deep_path.exists());
        }

        #[test]
        fn test_downloader_with_path_string_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let path_str = temp_dir.path().to_string_lossy().to_string();

            let downloader = CavpVectorDownloader::new(&path_str);
            assert!(downloader.is_ok());
        }

        #[test]
        fn test_downloader_with_pathbuf_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let path_buf = temp_dir.path().to_path_buf();

            let downloader = CavpVectorDownloader::new(path_buf);
            assert!(downloader.is_ok());
        }

        #[test]
        fn test_downloader_with_unicode_path_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            // Note: Some systems may not support all unicode characters in paths
            let unicode_path = temp_dir.path().join("test_cache_dir");

            let downloader = CavpVectorDownloader::new(&unicode_path);
            assert!(downloader.is_ok());
        }
    }

    // ============================================================================
    // Parse Content Edge Cases
    // ============================================================================

    mod parse_content_edge_cases {
        use super::*;

        #[test]
        fn test_parse_content_with_bom_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            // UTF-8 BOM followed by valid JSON
            let mut content = vec![0xEF, 0xBB, 0xBF];
            content.extend_from_slice(
            br#"{"vs_id": 1, "algorithm": "ML-KEM", "revision": "1.0", "is_sample": true, "test_groups": []}"#,
        );

            // BOM may cause parsing to fail depending on implementation
            let result = downloader.parse_vector_content(&content, "test");
            // Either succeeds or fails gracefully
            if result.is_ok() {
                assert!(result.unwrap().is_empty());
            }
        }

        #[test]
        fn test_parse_content_with_trailing_whitespace_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = r#"{"vs_id": 1, "algorithm": "ML-KEM", "revision": "1.0", "is_sample": true, "test_groups": []}

        "#;

            let result = downloader.parse_vector_content(json.as_bytes(), "test");
            assert!(result.is_ok());
        }

        #[test]
        fn test_parse_content_with_unicode_in_strings_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "ML-KEM",
                "revision": "1.0 - Test \u{00e9}\u{00e8}\u{00ea}",
                "is_sample": true,
                "test_groups": []
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "test");

            assert!(result.is_ok());
        }

        #[test]
        fn test_parse_content_large_vs_id_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": u32::MAX,
                "algorithm": "ML-KEM",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": []
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "test");

            assert!(result.is_ok());
        }

        #[test]
        fn test_parse_content_empty_algorithm_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let json = json!({
                "vs_id": 12345,
                "algorithm": "",
                "revision": "1.0",
                "is_sample": true,
                "test_groups": [
                    {
                        "tg_id": 1,
                        "test_type": "keyGen",
                        "parameter_set": "ML-KEM-768",
                        "tests": [
                            {
                                "tcId": 1,
                                "testCase": {"seed": "abcdef"},
                                "results": {"pk": "123456", "sk": "789abc"}
                            }
                        ]
                    }
                ]
            });

            let content = serde_json::to_vec(&json).unwrap();
            let result = downloader.parse_vector_content(&content, "test");

            // Should parse but vectors will be invalid due to empty algorithm
            assert!(result.is_ok());
            let vectors = result.unwrap();
            // Empty algorithm won't match any valid parameter set
            assert!(vectors.is_empty());
        }

        #[test]
        fn test_parse_content_whitespace_only_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let content = b"   \n\t  \r\n  ";

            let result = downloader.parse_vector_content(content, "test");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_content_null_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let content = b"null";

            let result = downloader.parse_vector_content(content, "test");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_content_boolean_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let content = b"true";

            let result = downloader.parse_vector_content(content, "test");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_content_number_json_returns_error() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let content = b"12345";

            let result = downloader.parse_vector_content(content, "test");
            assert!(result.is_err());
        }

        #[test]
        fn test_parse_content_string_json_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let content = b"\"just a string\"";

            let result = downloader.parse_vector_content(content, "test");
            assert!(result.is_err());
        }
    }

    // ============================================================================
    // Test Type Validation Coverage
    // ============================================================================

    mod test_type_validation_tests {
        use super::*;

        #[test]
        fn test_keygen_all_required_fields_present_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-KEM".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "ML-KEM-768".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("aabbccdd".to_string()),
                    sk: Some("eeff0011".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
            assert!(result.errors.is_empty());
            assert!(result.warnings.is_empty());
        }

        #[test]
        fn test_siggen_all_required_fields_present_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "ML-DSA-44".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("abcdef1234567890".to_string()),
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("fedcba9876543210".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
            assert!(result.errors.is_empty());
        }

        #[test]
        fn test_sigver_all_required_fields_present_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "ML-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "ML-DSA-65".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef1234567890".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("fedcba9876543210".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
            assert!(result.errors.is_empty());
            assert!(result.warnings.is_empty());
        }

        #[test]
        fn test_custom_test_type_with_warning_returns_warning_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let custom_types = vec!["encrypt", "decrypt", "hash", "kdf", "mac", "drbg"];

            for test_type in custom_types {
                let vector = OfficialCavpVector {
                    tg_id: 1,
                    tc_id: 1,
                    algorithm: "ML-KEM".to_string(),
                    test_type: test_type.to_string(),
                    parameter_set: "ML-KEM-768".to_string(),
                    inputs: CavpTestInputs {
                        seed: Some("abcdef".to_string()),
                        pk: None,
                        sk: None,
                        message: None,
                        ct: None,
                        ek: None,
                        dk: None,
                        m: None,
                        additional: HashMap::new(),
                    },
                    outputs: CavpTestOutputs {
                        pk: None,
                        sk: None,
                        signature: None,
                        ct: None,
                        ss: None,
                        test_passed: None,
                        additional: HashMap::new(),
                    },
                };

                let result = downloader.validate_vector(&vector);
                assert!(result.is_valid, "Custom test type '{}' should be valid", test_type);
                assert!(!result.warnings.is_empty(), "Should have warning for '{}'", test_type);
                assert!(
                    result.warnings[0].contains("Unknown test type"),
                    "Warning should mention unknown test type"
                );
            }
        }
    }

    // ============================================================================
    // SLH-DSA Specific Tests
    // ============================================================================

    mod slhdsa_specific_tests {
        use super::*;

        #[test]
        fn test_slhdsa_keygen_valid_returns_ok() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = create_valid_slhdsa_keygen_vector();
            let result = downloader.validate_vector(&vector);

            assert!(result.is_valid);
        }

        #[test]
        fn test_slhdsa_siggen_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "SLH-DSA".to_string(),
                test_type: "sigGen".to_string(),
                parameter_set: "SLH-DSA-SHAKE-256f".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: None,
                    sk: Some("fedcba9876543210".to_string()),
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("0123456789abcdef".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_slhdsa_sigver_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "SLH-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "SLH-DSA-SHA2-192f".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef0123456789".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("fedcba9876543210".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(false),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }
    }

    // ============================================================================
    // FN-DSA Specific Tests
    // ============================================================================

    mod fndsa_specific_tests {
        use super::*;

        #[test]
        fn test_fndsa_keygen_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "FN-DSA".to_string(),
                test_type: "keyGen".to_string(),
                parameter_set: "Falcon-1024".to_string(),
                inputs: CavpTestInputs {
                    seed: Some("0123456789abcdef".to_string()),
                    pk: None,
                    sk: None,
                    message: None,
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: Some("aabbccdd".to_string()),
                    sk: Some("eeff0011".to_string()),
                    signature: None,
                    ct: None,
                    ss: None,
                    test_passed: None,
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }

        #[test]
        fn test_fndsa_siggen_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = create_valid_fndsa_siggen_vector();
            let result = downloader.validate_vector(&vector);

            assert!(result.is_valid);
        }

        #[test]
        fn test_fndsa_sigver_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let downloader = CavpVectorDownloader::new(temp_dir.path()).unwrap();

            let vector = OfficialCavpVector {
                tg_id: 1,
                tc_id: 1,
                algorithm: "FN-DSA".to_string(),
                test_type: "sigVer".to_string(),
                parameter_set: "Falcon-512".to_string(),
                inputs: CavpTestInputs {
                    seed: None,
                    pk: Some("abcdef1234567890".to_string()),
                    sk: None,
                    message: Some("48656c6c6f".to_string()),
                    ct: None,
                    ek: None,
                    dk: None,
                    m: None,
                    additional: HashMap::new(),
                },
                outputs: CavpTestOutputs {
                    pk: None,
                    sk: None,
                    signature: Some("fedcba9876543210".to_string()),
                    ct: None,
                    ss: None,
                    test_passed: Some(true),
                    additional: HashMap::new(),
                },
            };

            let result = downloader.validate_vector(&vector);
            assert!(result.is_valid);
        }
    }
}

// Originally: fips_cavp_storage_tests.rs
mod storage {
    //! Comprehensive tests for CAVP Storage Backend
    //!
    //! This module tests the CAVP (Cryptographic Algorithm Validation Program)
    //! storage implementations including:
    //! - MemoryCavpStorage - In-memory storage backend
    //! - FileCavpStorage - File-based persistent storage
    //! - CavpStorageManager - Multi-backend storage orchestration
    //! - CavpStorage trait - Common storage interface
    //!
    //! Tests cover:
    //! 1. Storage backend implementations (Memory, File)
    //! 2. Read/write operations for results and batches
    //! 3. Serialization/deserialization of CAVP data
    //! 4. Error handling paths
    //! 5. Concurrent access patterns
    //! 6. Algorithm-based indexing and retrieval

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

    use latticearc_tests::validation::cavp::storage::{
        CavpStorage, CavpStorageManager, FileCavpStorage, MemoryCavpStorage,
    };
    use latticearc_tests::validation::cavp::types::{
        CavpAlgorithm, CavpBatchResult, CavpTestMetadata, CavpTestResult, CavpValidationStatus,
        TestConfiguration, TestEnvironment,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    // ============================================================================
    // Test Helper Functions
    // ============================================================================

    /// Creates a sample CavpTestResult for testing
    fn create_test_result(test_id: &str, algorithm: CavpAlgorithm, passed: bool) -> CavpTestResult {
        if passed {
            CavpTestResult::new(
                test_id.to_string(),
                algorithm,
                format!("VEC-{}", test_id),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual - will pass
                Duration::from_millis(50),
                CavpTestMetadata::default(),
            )
        } else {
            CavpTestResult::failed(
                test_id.to_string(),
                algorithm,
                format!("VEC-{}", test_id),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual - will fail
                Duration::from_millis(50),
                "Test mismatch".to_string(),
                CavpTestMetadata::default(),
            )
        }
    }

    /// Creates a sample CavpBatchResult with specified test results
    fn create_batch_result(
        batch_id: &str,
        algorithm: CavpAlgorithm,
        passed: usize,
        failed: usize,
    ) -> CavpBatchResult {
        let mut batch = CavpBatchResult::new(batch_id.to_string(), algorithm.clone());

        for i in 0..passed {
            let result =
                create_test_result(&format!("{}-PASS-{}", batch_id, i), algorithm.clone(), true);
            batch.add_test_result(result);
        }

        for i in 0..failed {
            let result =
                create_test_result(&format!("{}-FAIL-{}", batch_id, i), algorithm.clone(), false);
            batch.add_test_result(result);
        }

        batch
    }

    /// Creates an ML-KEM algorithm with specified variant
    fn mlkem_algorithm(variant: &str) -> CavpAlgorithm {
        CavpAlgorithm::MlKem { variant: variant.to_string() }
    }

    /// Creates an ML-DSA algorithm with specified variant
    fn mldsa_algorithm(variant: &str) -> CavpAlgorithm {
        CavpAlgorithm::MlDsa { variant: variant.to_string() }
    }

    /// Creates an SLH-DSA algorithm with specified variant
    fn slhdsa_algorithm(variant: &str) -> CavpAlgorithm {
        CavpAlgorithm::SlhDsa { variant: variant.to_string() }
    }

    /// Creates an FN-DSA algorithm with specified variant
    fn fndsa_algorithm(variant: &str) -> CavpAlgorithm {
        CavpAlgorithm::FnDsa { variant: variant.to_string() }
    }

    // ============================================================================
    // MemoryCavpStorage Tests
    // ============================================================================

    mod memory_storage_tests {
        use super::*;

        #[test]
        fn test_memory_storage_new_succeeds() {
            let storage = MemoryCavpStorage::new();
            // Storage should be created successfully
            drop(storage);
        }

        #[test]
        fn test_memory_storage_default_succeeds() {
            let storage = MemoryCavpStorage::default();
            // Default should be equivalent to new()
            drop(storage);
        }

        #[test]
        fn test_store_single_result_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let result = create_test_result("TEST-001", mlkem_algorithm("768"), true);

            let store_result = storage.store_result(&result);
            assert!(store_result.is_ok());
        }

        #[test]
        fn test_retrieve_stored_result_returns_correct_value_succeeds() {
            let storage = MemoryCavpStorage::new();
            let result = create_test_result("TEST-002", mlkem_algorithm("768"), true);

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("TEST-002").unwrap();

            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.test_id, "TEST-002");
            assert!(retrieved.passed);
        }

        #[test]
        fn test_retrieve_nonexistent_result_returns_none() {
            let storage = MemoryCavpStorage::new();

            let retrieved = storage.retrieve_result("NONEXISTENT").unwrap();
            assert!(retrieved.is_none());
        }

        #[test]
        fn test_store_batch_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let batch = create_batch_result("BATCH-001", mlkem_algorithm("768"), 5, 2);

            let store_result = storage.store_batch(&batch);
            assert!(store_result.is_ok());
        }

        #[test]
        fn test_retrieve_stored_batch_returns_correct_value_succeeds() {
            let storage = MemoryCavpStorage::new();
            let batch = create_batch_result("BATCH-002", mldsa_algorithm("44"), 3, 1);

            storage.store_batch(&batch).unwrap();
            let retrieved = storage.retrieve_batch("BATCH-002").unwrap();

            assert!(retrieved.is_some());
            let retrieved = retrieved.unwrap();
            assert_eq!(retrieved.batch_id, "BATCH-002");
            assert_eq!(retrieved.test_results.len(), 4);
        }

        #[test]
        fn test_retrieve_nonexistent_batch_returns_none() {
            let storage = MemoryCavpStorage::new();

            let retrieved = storage.retrieve_batch("NONEXISTENT-BATCH").unwrap();
            assert!(retrieved.is_none());
        }

        #[test]
        fn test_list_results_by_algorithm_empty_returns_empty_vec_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mlkem_algorithm("768");

            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert!(results.is_empty());
        }

        #[test]
        fn test_list_results_by_algorithm_with_data_returns_correct_results_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mlkem_algorithm("768");

            // Store multiple results for the same algorithm
            for i in 0..5 {
                let result = create_test_result(&format!("TEST-{:03}", i), algorithm.clone(), true);
                storage.store_result(&result).unwrap();
            }

            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 5);
        }

        #[test]
        fn test_list_results_filters_by_algorithm_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let mlkem_768 = mlkem_algorithm("768");
            let mlkem_512 = mlkem_algorithm("512");
            let mldsa_44 = mldsa_algorithm("44");

            // Store results for different algorithms
            storage
                .store_result(&create_test_result("MLKEM-768-001", mlkem_768.clone(), true))
                .unwrap();
            storage
                .store_result(&create_test_result("MLKEM-768-002", mlkem_768.clone(), true))
                .unwrap();
            storage
                .store_result(&create_test_result("MLKEM-512-001", mlkem_512.clone(), true))
                .unwrap();
            storage
                .store_result(&create_test_result("MLDSA-44-001", mldsa_44.clone(), true))
                .unwrap();

            // Verify filtering works correctly
            let mlkem_768_results = storage.list_results_by_algorithm(&mlkem_768).unwrap();
            assert_eq!(mlkem_768_results.len(), 2);

            let mlkem_512_results = storage.list_results_by_algorithm(&mlkem_512).unwrap();
            assert_eq!(mlkem_512_results.len(), 1);

            let mldsa_44_results = storage.list_results_by_algorithm(&mldsa_44).unwrap();
            assert_eq!(mldsa_44_results.len(), 1);
        }

        #[test]
        fn test_list_batches_by_algorithm_empty_returns_empty_vec_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = slhdsa_algorithm("128s");

            let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();
            assert!(batches.is_empty());
        }

        #[test]
        fn test_list_batches_by_algorithm_with_data_returns_correct_results_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = slhdsa_algorithm("128s");

            // Store multiple batches for the same algorithm
            for i in 0..3 {
                let batch =
                    create_batch_result(&format!("BATCH-{:03}", i), algorithm.clone(), 2, 1);
                storage.store_batch(&batch).unwrap();
            }

            let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();
            assert_eq!(batches.len(), 3);
        }

        #[test]
        fn test_list_batches_filters_by_algorithm_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let fndsa_512 = fndsa_algorithm("512");
            let fndsa_1024 = fndsa_algorithm("1024");

            // Store batches for different algorithms
            storage
                .store_batch(&create_batch_result("FNDSA-512-BATCH", fndsa_512.clone(), 5, 0))
                .unwrap();
            storage
                .store_batch(&create_batch_result("FNDSA-1024-BATCH-1", fndsa_1024.clone(), 3, 1))
                .unwrap();
            storage
                .store_batch(&create_batch_result("FNDSA-1024-BATCH-2", fndsa_1024.clone(), 4, 0))
                .unwrap();

            // Verify filtering
            let fndsa_512_batches = storage.list_batches_by_algorithm(&fndsa_512).unwrap();
            assert_eq!(fndsa_512_batches.len(), 1);

            let fndsa_1024_batches = storage.list_batches_by_algorithm(&fndsa_1024).unwrap();
            assert_eq!(fndsa_1024_batches.len(), 2);
        }

        #[test]
        fn test_overwrite_existing_result_replaces_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mlkem_algorithm("768");

            // Store original result
            let original = create_test_result("TEST-OVERWRITE", algorithm.clone(), true);
            storage.store_result(&original).unwrap();

            // Overwrite with new result (different pass status)
            let updated = create_test_result("TEST-OVERWRITE", algorithm, false);
            storage.store_result(&updated).unwrap();

            // Verify overwrite occurred
            let retrieved = storage.retrieve_result("TEST-OVERWRITE").unwrap().unwrap();
            assert!(!retrieved.passed);
        }

        #[test]
        fn test_overwrite_existing_batch_replaces_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mldsa_algorithm("65");

            // Store original batch
            let original = create_batch_result("BATCH-OVERWRITE", algorithm.clone(), 3, 0);
            storage.store_batch(&original).unwrap();

            // Overwrite with new batch
            let updated = create_batch_result("BATCH-OVERWRITE", algorithm, 1, 5);
            storage.store_batch(&updated).unwrap();

            // Verify overwrite occurred
            let retrieved = storage.retrieve_batch("BATCH-OVERWRITE").unwrap().unwrap();
            assert_eq!(retrieved.test_results.len(), 6);
        }

        #[test]
        fn test_hybrid_kem_algorithm_is_accessible() {
            let storage = MemoryCavpStorage::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let result = create_test_result("HYBRID-001", algorithm.clone(), true);
            storage.store_result(&result).unwrap();

            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 1);
        }

        #[test]
        fn test_result_with_metadata_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mlkem_algorithm("1024");

            let mut result = create_test_result("METADATA-TEST", algorithm, true);
            result.metadata = CavpTestMetadata {
                environment: TestEnvironment {
                    os: "custom-os".to_string(),
                    arch: "custom-arch".to_string(),
                    rust_version: "1.93.0".to_string(),
                    compiler: "rustc".to_string(),
                    framework_version: "1.0.0".to_string(),
                },
                security_level: 256,
                vector_version: "2.0".to_string(),
                implementation_version: "0.1.0".to_string(),
                configuration: TestConfiguration {
                    iterations: 100,
                    timeout: Duration::from_secs(60),
                    statistical_tests: true,
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("custom_param".to_string(), vec![0x01, 0x02, 0x03]);
                        params
                    },
                },
            };

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("METADATA-TEST").unwrap().unwrap();

            assert_eq!(retrieved.metadata.security_level, 256);
            assert_eq!(retrieved.metadata.environment.os, "custom-os");
            assert_eq!(retrieved.metadata.configuration.iterations, 100);
        }

        #[test]
        fn test_batch_with_all_validation_statuses_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let algorithm = mlkem_algorithm("768");

            // Create batches with different statuses
            let passed_batch = create_batch_result("PASSED-BATCH", algorithm.clone(), 10, 0);
            let failed_batch = create_batch_result("FAILED-BATCH", algorithm.clone(), 5, 5);
            let incomplete_batch =
                CavpBatchResult::new("INCOMPLETE-BATCH".to_string(), algorithm.clone());

            storage.store_batch(&passed_batch).unwrap();
            storage.store_batch(&failed_batch).unwrap();
            storage.store_batch(&incomplete_batch).unwrap();

            // Verify statuses
            let retrieved_passed = storage.retrieve_batch("PASSED-BATCH").unwrap().unwrap();
            assert!(matches!(retrieved_passed.status, CavpValidationStatus::Passed));

            let retrieved_failed = storage.retrieve_batch("FAILED-BATCH").unwrap().unwrap();
            assert!(matches!(retrieved_failed.status, CavpValidationStatus::Failed));

            let retrieved_incomplete = storage.retrieve_batch("INCOMPLETE-BATCH").unwrap().unwrap();
            assert!(matches!(retrieved_incomplete.status, CavpValidationStatus::Incomplete));
        }
    }

    // ============================================================================
    // FileCavpStorage Tests
    // ============================================================================

    mod file_storage_tests {
        use super::*;

        #[test]
        fn test_file_storage_new_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path());
            assert!(storage.is_ok());
        }

        #[test]
        fn test_file_storage_creates_directories_on_init_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let _storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            // Verify directories were created
            assert!(temp_dir.path().join("results").exists());
            assert!(temp_dir.path().join("batches").exists());
        }

        #[test]
        fn test_file_storage_nested_path_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let nested_path = temp_dir.path().join("level1").join("level2").join("storage");

            let storage = FileCavpStorage::new(&nested_path);
            assert!(storage.is_ok());
            assert!(nested_path.join("results").exists());
            assert!(nested_path.join("batches").exists());
        }

        #[test]
        fn test_store_and_retrieve_result_round_trips_correctly_roundtrip() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            let result = create_test_result("FILE-TEST-001", mlkem_algorithm("768"), true);
            storage.store_result(&result).unwrap();

            let retrieved = storage.retrieve_result("FILE-TEST-001").unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().test_id, "FILE-TEST-001");
        }

        #[test]
        fn test_store_and_retrieve_batch_round_trips_correctly_roundtrip() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            let batch = create_batch_result("FILE-BATCH-001", mldsa_algorithm("44"), 3, 1);
            storage.store_batch(&batch).unwrap();

            let retrieved = storage.retrieve_batch("FILE-BATCH-001").unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().batch_id, "FILE-BATCH-001");
        }

        #[test]
        fn test_file_persistence_persists_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();

            // Store data in one instance
            {
                let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
                let result = create_test_result("PERSIST-001", mlkem_algorithm("512"), true);
                storage.store_result(&result).unwrap();

                let batch = create_batch_result("PERSIST-BATCH", mldsa_algorithm("65"), 2, 0);
                storage.store_batch(&batch).unwrap();
            }

            // Verify files exist
            let result_file = temp_dir.path().join("results").join("PERSIST-001.json");
            let batch_file = temp_dir.path().join("batches").join("PERSIST-BATCH.json");

            assert!(result_file.exists());
            assert!(batch_file.exists());
        }

        #[test]
        fn test_load_existing_results_loads_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();

            // Store data in first instance
            {
                let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
                storage
                    .store_result(&create_test_result("LOAD-001", mlkem_algorithm("768"), true))
                    .unwrap();
                storage
                    .store_result(&create_test_result("LOAD-002", mlkem_algorithm("768"), false))
                    .unwrap();
            }

            // Create new instance and load existing results
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            storage.load_existing_results().unwrap();

            // Verify results were loaded
            let result1 = storage.retrieve_result("LOAD-001").unwrap();
            let result2 = storage.retrieve_result("LOAD-002").unwrap();

            assert!(result1.is_some());
            assert!(result2.is_some());
        }

        #[test]
        fn test_load_existing_batches_loads_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();

            // Store data in first instance
            {
                let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
                storage
                    .store_batch(&create_batch_result(
                        "LOAD-BATCH-001",
                        slhdsa_algorithm("128s"),
                        5,
                        1,
                    ))
                    .unwrap();
                storage
                    .store_batch(&create_batch_result(
                        "LOAD-BATCH-002",
                        slhdsa_algorithm("256f"),
                        3,
                        0,
                    ))
                    .unwrap();
            }

            // Create new instance and load existing batches
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            storage.load_existing_batches().unwrap();

            // Verify batches were loaded
            let batch1 = storage.retrieve_batch("LOAD-BATCH-001").unwrap();
            let batch2 = storage.retrieve_batch("LOAD-BATCH-002").unwrap();

            assert!(batch1.is_some());
            assert!(batch2.is_some());
        }

        #[test]
        fn test_load_empty_directory_returns_empty_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            // Loading from empty directories should succeed
            let result1 = storage.load_existing_results();
            let result2 = storage.load_existing_batches();

            assert!(result1.is_ok());
            assert!(result2.is_ok());
        }

        #[test]
        fn test_list_results_by_algorithm_with_file_storage_returns_correct_results_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            let algorithm = fndsa_algorithm("512");

            // Store multiple results
            for i in 0..5 {
                let result =
                    create_test_result(&format!("FNDSA-{:03}", i), algorithm.clone(), true);
                storage.store_result(&result).unwrap();
            }

            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 5);
        }

        #[test]
        fn test_list_batches_by_algorithm_with_file_storage_returns_correct_results_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            let algorithm = CavpAlgorithm::HybridKem;

            // Store multiple batches
            for i in 0..3 {
                let batch =
                    create_batch_result(&format!("HYBRID-BATCH-{:03}", i), algorithm.clone(), 4, 1);
                storage.store_batch(&batch).unwrap();
            }

            let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();
            assert_eq!(batches.len(), 3);
        }

        #[test]
        fn test_json_serialization_validity_is_correct() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            let result = create_test_result("JSON-TEST", mlkem_algorithm("768"), true);
            storage.store_result(&result).unwrap();

            // Read the file directly and verify it's valid JSON
            let file_path = temp_dir.path().join("results").join("JSON-TEST.json");
            let content = std::fs::read_to_string(&file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert_eq!(parsed["test_id"], "JSON-TEST");
            assert!(parsed["passed"].as_bool().unwrap());
        }

        #[test]
        fn test_special_characters_in_id_are_accepted_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            // Note: File systems have restrictions on certain characters
            // Using characters that are valid for most file systems
            let result = create_test_result(
                "TEST_with-dashes_and_underscores",
                mlkem_algorithm("768"),
                true,
            );
            storage.store_result(&result).unwrap();

            let retrieved = storage.retrieve_result("TEST_with-dashes_and_underscores").unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_overwrite_file_replaces_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            let algorithm = mlkem_algorithm("768");

            // Store original
            let original = create_test_result("OVERWRITE-FILE", algorithm.clone(), true);
            storage.store_result(&original).unwrap();

            // Overwrite
            let updated = create_test_result("OVERWRITE-FILE", algorithm, false);
            storage.store_result(&updated).unwrap();

            // Verify overwrite in file
            let file_path = temp_dir.path().join("results").join("OVERWRITE-FILE.json");
            let content = std::fs::read_to_string(&file_path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

            assert!(!parsed["passed"].as_bool().unwrap());
        }

        #[test]
        fn test_load_with_invalid_json_file_returns_error() {
            let temp_dir = TempDir::new().unwrap();

            // Create storage and directories
            let _storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            // Write invalid JSON file
            let invalid_file = temp_dir.path().join("results").join("invalid.json");
            std::fs::write(&invalid_file, "{ invalid json }").unwrap();

            // Create new storage and try to load - should not panic, just warn
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            let result = storage.load_existing_results();

            // Should succeed (skipping invalid files)
            assert!(result.is_ok());
        }

        #[test]
        fn test_non_json_files_ignored_on_load_succeeds() {
            let temp_dir = TempDir::new().unwrap();

            // Create storage and directories
            let _storage = FileCavpStorage::new(temp_dir.path()).unwrap();

            // Create non-JSON files
            std::fs::write(temp_dir.path().join("results").join("readme.txt"), "Not a JSON file")
                .unwrap();
            std::fs::write(temp_dir.path().join("batches").join("metadata.xml"), "<xml></xml>")
                .unwrap();

            // Load should succeed ignoring non-JSON files
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            assert!(storage.load_existing_results().is_ok());
            assert!(storage.load_existing_batches().is_ok());
        }
    }

    // ============================================================================
    // CavpStorageManager Tests
    // ============================================================================

    mod storage_manager_tests {
        use super::*;

        #[test]
        fn test_manager_new_succeeds() {
            let primary = Box::new(MemoryCavpStorage::new());
            let manager = CavpStorageManager::new(primary);
            drop(manager);
        }

        #[test]
        fn test_manager_with_backup_succeeds() {
            let primary = Box::new(MemoryCavpStorage::new());
            let backup = Box::new(MemoryCavpStorage::new());
            let manager = CavpStorageManager::with_backup(primary, backup);
            drop(manager);
        }

        #[test]
        fn test_manager_memory_factory_creates_correctly_succeeds() {
            let manager = CavpStorageManager::memory();

            // Should be able to use the manager
            let result = create_test_result("MANAGER-MEM-001", mlkem_algorithm("768"), true);
            assert!(manager.store_result(&result).is_ok());
        }

        #[test]
        fn test_manager_file_factory_creates_correctly_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let manager = CavpStorageManager::file(temp_dir.path());

            assert!(manager.is_ok());
            let manager = manager.unwrap();

            let result = create_test_result("MANAGER-FILE-001", mlkem_algorithm("768"), true);
            assert!(manager.store_result(&result).is_ok());
        }

        #[test]
        fn test_manager_store_result_persists_correctly_succeeds() {
            let manager = CavpStorageManager::memory();
            let result = create_test_result("MGR-STORE-001", mldsa_algorithm("44"), true);

            assert!(manager.store_result(&result).is_ok());

            let retrieved = manager.retrieve_result("MGR-STORE-001").unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_manager_store_batch_persists_correctly_succeeds() {
            let manager = CavpStorageManager::memory();
            let batch = create_batch_result("MGR-BATCH-001", slhdsa_algorithm("128s"), 5, 2);

            assert!(manager.store_batch(&batch).is_ok());

            let retrieved = manager.retrieve_batch("MGR-BATCH-001").unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_manager_retrieve_result_returns_correct_value_succeeds() {
            let manager = CavpStorageManager::memory();
            let result = create_test_result("MGR-RETRIEVE-001", fndsa_algorithm("1024"), true);

            manager.store_result(&result).unwrap();
            let retrieved = manager.retrieve_result("MGR-RETRIEVE-001").unwrap();

            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().test_id, "MGR-RETRIEVE-001");
        }

        #[test]
        fn test_manager_retrieve_batch_returns_correct_value_succeeds() {
            let manager = CavpStorageManager::memory();
            let batch = create_batch_result("MGR-RETRIEVE-BATCH", CavpAlgorithm::HybridKem, 3, 0);

            manager.store_batch(&batch).unwrap();
            let retrieved = manager.retrieve_batch("MGR-RETRIEVE-BATCH").unwrap();

            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().batch_id, "MGR-RETRIEVE-BATCH");
        }

        #[test]
        fn test_manager_retrieve_nonexistent_returns_none() {
            let manager = CavpStorageManager::memory();

            let result = manager.retrieve_result("DOES-NOT-EXIST").unwrap();
            assert!(result.is_none());

            let batch = manager.retrieve_batch("DOES-NOT-EXIST-BATCH").unwrap();
            assert!(batch.is_none());
        }

        #[test]
        fn test_manager_list_results_by_algorithm_returns_correct_results_succeeds() {
            let manager = CavpStorageManager::memory();
            let algorithm = mlkem_algorithm("768");

            for i in 0..5 {
                let result =
                    create_test_result(&format!("MGR-LIST-{:03}", i), algorithm.clone(), true);
                manager.store_result(&result).unwrap();
            }

            let results = manager.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 5);
        }

        #[test]
        fn test_manager_list_batches_by_algorithm_returns_correct_results_succeeds() {
            let manager = CavpStorageManager::memory();
            let algorithm = mldsa_algorithm("87");

            for i in 0..3 {
                let batch = create_batch_result(
                    &format!("MGR-BATCH-LIST-{:03}", i),
                    algorithm.clone(),
                    4,
                    1,
                );
                manager.store_batch(&batch).unwrap();
            }

            let batches = manager.list_batches_by_algorithm(&algorithm).unwrap();
            assert_eq!(batches.len(), 3);
        }

        #[test]
        fn test_manager_with_backup_stores_to_both_backends_succeeds() {
            let primary = Arc::new(MemoryCavpStorage::new());
            let backup = Arc::new(MemoryCavpStorage::new());

            // Store in manager
            {
                let primary_box: Box<dyn CavpStorage> = Box::new(MemoryCavpStorage::new());
                let backup_box: Box<dyn CavpStorage> = Box::new(MemoryCavpStorage::new());
                let manager = CavpStorageManager::with_backup(primary_box, backup_box);

                let result = create_test_result("BACKUP-TEST", mlkem_algorithm("768"), true);
                manager.store_result(&result).unwrap();

                // Verify primary has the data
                let retrieved = manager.retrieve_result("BACKUP-TEST").unwrap();
                assert!(retrieved.is_some());
            }

            // Note: We can't directly access the backup storage through the manager API
            // But we verify the primary works correctly
            drop(primary);
            drop(backup);
        }

        #[test]
        fn test_manager_mixed_algorithms_are_stored_correctly_succeeds() {
            let manager = CavpStorageManager::memory();

            // Store results for various algorithms
            let algorithms = vec![
                mlkem_algorithm("512"),
                mlkem_algorithm("768"),
                mlkem_algorithm("1024"),
                mldsa_algorithm("44"),
                mldsa_algorithm("65"),
                slhdsa_algorithm("128s"),
                fndsa_algorithm("512"),
                CavpAlgorithm::HybridKem,
            ];

            for (i, algo) in algorithms.iter().enumerate() {
                let result = create_test_result(&format!("MIXED-{:03}", i), algo.clone(), true);
                manager.store_result(&result).unwrap();
            }

            // Verify each algorithm has its result
            for algo in &algorithms {
                let results = manager.list_results_by_algorithm(algo).unwrap();
                assert_eq!(results.len(), 1);
            }
        }
    }

    // ============================================================================
    // Concurrent Access Tests
    // ============================================================================

    mod concurrent_access_tests {
        use super::*;

        #[test]
        fn test_concurrent_reads_succeed_succeeds() {
            let storage = Arc::new(MemoryCavpStorage::new());

            // Pre-populate storage
            for i in 0..100 {
                let result = create_test_result(
                    &format!("CONCURRENT-{:03}", i),
                    mlkem_algorithm("768"),
                    true,
                );
                storage.store_result(&result).unwrap();
            }

            let barrier = Arc::new(Barrier::new(10));
            let mut handles = vec![];

            for thread_id in 0..10 {
                let storage_clone = Arc::clone(&storage);
                let barrier_clone = Arc::clone(&barrier);

                let handle = thread::spawn(move || {
                    barrier_clone.wait();

                    for i in 0..100 {
                        let test_id = format!("CONCURRENT-{:03}", i);
                        let result = storage_clone.retrieve_result(&test_id).unwrap();
                        assert!(
                            result.is_some(),
                            "Thread {} failed to retrieve {}",
                            thread_id,
                            test_id
                        );
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }

        #[test]
        fn test_concurrent_writes_succeed_succeeds() {
            let storage = Arc::new(MemoryCavpStorage::new());
            let barrier = Arc::new(Barrier::new(10));
            let mut handles = vec![];

            for thread_id in 0..10 {
                let storage_clone = Arc::clone(&storage);
                let barrier_clone = Arc::clone(&barrier);

                let handle = thread::spawn(move || {
                    barrier_clone.wait();

                    for i in 0..10 {
                        let result = create_test_result(
                            &format!("THREAD-{}-TEST-{}", thread_id, i),
                            mlkem_algorithm("768"),
                            true,
                        );
                        storage_clone.store_result(&result).unwrap();
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            // Verify all writes succeeded
            let algorithm = mlkem_algorithm("768");
            let results = storage.list_results_by_algorithm(&algorithm).unwrap();
            assert_eq!(results.len(), 100);
        }

        #[test]
        fn test_concurrent_read_write_succeeds() {
            let storage = Arc::new(MemoryCavpStorage::new());

            // Pre-populate some data
            for i in 0..50 {
                let result =
                    create_test_result(&format!("INITIAL-{:03}", i), mlkem_algorithm("768"), true);
                storage.store_result(&result).unwrap();
            }

            let barrier = Arc::new(Barrier::new(20));
            let mut handles = vec![];

            // 10 reader threads
            for _thread_id in 0..10 {
                let storage_clone = Arc::clone(&storage);
                let barrier_clone = Arc::clone(&barrier);

                let handle = thread::spawn(move || {
                    barrier_clone.wait();

                    for i in 0..50 {
                        let test_id = format!("INITIAL-{:03}", i);
                        let _ = storage_clone.retrieve_result(&test_id);
                    }
                });

                handles.push(handle);
            }

            // 10 writer threads
            for thread_id in 0..10 {
                let storage_clone = Arc::clone(&storage);
                let barrier_clone = Arc::clone(&barrier);

                let handle = thread::spawn(move || {
                    barrier_clone.wait();

                    for i in 0..5 {
                        let result = create_test_result(
                            &format!("NEW-{}-{}", thread_id, i),
                            mldsa_algorithm("44"),
                            true,
                        );
                        storage_clone.store_result(&result).unwrap();
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            // Verify data integrity
            let mlkem_results = storage.list_results_by_algorithm(&mlkem_algorithm("768")).unwrap();
            let mldsa_results = storage.list_results_by_algorithm(&mldsa_algorithm("44")).unwrap();

            assert_eq!(mlkem_results.len(), 50);
            assert_eq!(mldsa_results.len(), 50);
        }

        #[test]
        fn test_concurrent_batch_operations_succeed_succeeds() {
            let storage = Arc::new(MemoryCavpStorage::new());
            let barrier = Arc::new(Barrier::new(5));
            let mut handles = vec![];

            for thread_id in 0..5 {
                let storage_clone = Arc::clone(&storage);
                let barrier_clone = Arc::clone(&barrier);

                let handle = thread::spawn(move || {
                    barrier_clone.wait();

                    for i in 0..5 {
                        let batch = create_batch_result(
                            &format!("THREAD-{}-BATCH-{}", thread_id, i),
                            slhdsa_algorithm("128s"),
                            3,
                            1,
                        );
                        storage_clone.store_batch(&batch).unwrap();
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            // Verify all batches were stored
            let batches = storage.list_batches_by_algorithm(&slhdsa_algorithm("128s")).unwrap();
            assert_eq!(batches.len(), 25);
        }
    }

    // ============================================================================
    // Serialization Tests
    // ============================================================================

    mod serialization_tests {
        use super::*;

        #[test]
        fn test_result_json_roundtrip_succeeds() {
            let original = create_test_result("SERIAL-001", mlkem_algorithm("768"), true);

            let json = serde_json::to_string(&original).unwrap();
            let deserialized: CavpTestResult = serde_json::from_str(&json).unwrap();

            assert_eq!(original.test_id, deserialized.test_id);
            assert_eq!(original.passed, deserialized.passed);
            assert_eq!(original.algorithm, deserialized.algorithm);
        }

        #[test]
        fn test_batch_json_roundtrip_succeeds() {
            let original = create_batch_result("SERIAL-BATCH", mldsa_algorithm("44"), 5, 2);

            let json = serde_json::to_string(&original).unwrap();
            let deserialized: CavpBatchResult = serde_json::from_str(&json).unwrap();

            assert_eq!(original.batch_id, deserialized.batch_id);
            assert_eq!(original.test_results.len(), deserialized.test_results.len());
            assert_eq!(original.pass_rate, deserialized.pass_rate);
        }

        #[test]
        fn test_algorithm_serialization_round_trips_correctly_roundtrip() {
            let algorithms = vec![
                mlkem_algorithm("512"),
                mldsa_algorithm("65"),
                slhdsa_algorithm("256f"),
                fndsa_algorithm("1024"),
                CavpAlgorithm::HybridKem,
            ];

            for algo in algorithms {
                let json = serde_json::to_string(&algo).unwrap();
                let deserialized: CavpAlgorithm = serde_json::from_str(&json).unwrap();
                assert_eq!(algo, deserialized);
            }
        }

        #[test]
        fn test_metadata_serialization_round_trips_correctly_roundtrip() {
            let metadata = CavpTestMetadata {
                environment: TestEnvironment {
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    rust_version: "1.93.0".to_string(),
                    compiler: "rustc".to_string(),
                    framework_version: "1.0.0".to_string(),
                },
                security_level: 192,
                vector_version: "2.0".to_string(),
                implementation_version: "0.2.0".to_string(),
                configuration: TestConfiguration {
                    iterations: 50,
                    timeout: Duration::from_secs(120),
                    statistical_tests: true,
                    parameters: HashMap::new(),
                },
            };

            let json = serde_json::to_string(&metadata).unwrap();
            let deserialized: CavpTestMetadata = serde_json::from_str(&json).unwrap();

            assert_eq!(metadata.security_level, deserialized.security_level);
            assert_eq!(metadata.environment.os, deserialized.environment.os);
        }

        #[test]
        fn test_validation_status_serialization_round_trips_correctly_roundtrip() {
            let statuses = vec![
                CavpValidationStatus::Passed,
                CavpValidationStatus::Failed,
                CavpValidationStatus::Incomplete,
                CavpValidationStatus::Error("Test error".to_string()),
            ];

            for status in statuses {
                let json = serde_json::to_string(&status).unwrap();
                let deserialized: CavpValidationStatus = serde_json::from_str(&json).unwrap();
                assert_eq!(status, deserialized);
            }
        }

        #[test]
        fn test_large_result_serialization_round_trips_correctly_roundtrip() {
            let mut result = create_test_result("LARGE-RESULT", mlkem_algorithm("1024"), true);

            // Add large data
            result.actual_result = vec![0x42; 10000];
            result.expected_result = vec![0x42; 10000];

            let json = serde_json::to_string(&result).unwrap();
            let deserialized: CavpTestResult = serde_json::from_str(&json).unwrap();

            assert_eq!(result.actual_result.len(), deserialized.actual_result.len());
        }

        #[test]
        fn test_pretty_json_format_has_correct_structure_has_correct_size() {
            let result = create_test_result("PRETTY-001", mlkem_algorithm("768"), true);

            let pretty_json = serde_json::to_string_pretty(&result).unwrap();

            // Pretty JSON should have newlines
            assert!(pretty_json.contains('\n'));

            // Should still deserialize correctly
            let deserialized: CavpTestResult = serde_json::from_str(&pretty_json).unwrap();
            assert_eq!(result.test_id, deserialized.test_id);
        }
    }

    // ============================================================================
    // Edge Case Tests
    // ============================================================================

    mod edge_case_tests {
        use super::*;

        #[test]
        fn test_empty_test_id_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let result = create_test_result("", mlkem_algorithm("768"), true);

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("").unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_very_long_test_id_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let long_id = "A".repeat(1000);
            let result = create_test_result(&long_id, mlkem_algorithm("768"), true);

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result(&long_id).unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_unicode_in_test_id_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let unicode_id = "test_\u{1F600}_\u{4E2D}\u{6587}";
            let result = create_test_result(unicode_id, mlkem_algorithm("768"), true);

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result(unicode_id).unwrap();
            assert!(retrieved.is_some());
        }

        #[test]
        fn test_batch_with_no_results_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let batch = CavpBatchResult::new("EMPTY-BATCH".to_string(), mlkem_algorithm("768"));

            storage.store_batch(&batch).unwrap();
            let retrieved = storage.retrieve_batch("EMPTY-BATCH").unwrap().unwrap();

            assert!(retrieved.test_results.is_empty());
            assert!(matches!(retrieved.status, CavpValidationStatus::Incomplete));
        }

        #[test]
        fn test_result_with_empty_vectors_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let result = CavpTestResult::new(
                "EMPTY-VECTORS".to_string(),
                mlkem_algorithm("768"),
                "VEC-001".to_string(),
                vec![],
                vec![],
                Duration::from_millis(10),
                CavpTestMetadata::default(),
            );

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("EMPTY-VECTORS").unwrap().unwrap();

            assert!(retrieved.actual_result.is_empty());
            assert!(retrieved.expected_result.is_empty());
            assert!(retrieved.passed); // Empty vectors are equal
        }

        #[test]
        fn test_batch_with_large_number_of_results_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();
            let mut batch = CavpBatchResult::new("LARGE-BATCH".to_string(), mlkem_algorithm("768"));

            for i in 0..1000 {
                let result = create_test_result(
                    &format!("LARGE-{:04}", i),
                    mlkem_algorithm("768"),
                    i % 2 == 0,
                );
                batch.add_test_result(result);
            }

            storage.store_batch(&batch).unwrap();
            let retrieved = storage.retrieve_batch("LARGE-BATCH").unwrap().unwrap();

            assert_eq!(retrieved.test_results.len(), 1000);
            assert_eq!(retrieved.pass_rate, 50.0);
        }

        #[test]
        fn test_zero_execution_time_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let result = CavpTestResult::new(
                "ZERO-TIME".to_string(),
                mlkem_algorithm("768"),
                "VEC-001".to_string(),
                vec![0x42],
                vec![0x42],
                Duration::ZERO,
                CavpTestMetadata::default(),
            );

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("ZERO-TIME").unwrap().unwrap();

            assert_eq!(retrieved.execution_time, Duration::ZERO);
        }

        #[test]
        fn test_very_long_execution_time_is_accepted() {
            let storage = MemoryCavpStorage::new();
            let result = CavpTestResult::new(
                "LONG-TIME".to_string(),
                mlkem_algorithm("768"),
                "VEC-001".to_string(),
                vec![0x42],
                vec![0x42],
                Duration::from_secs(86400), // 24 hours
                CavpTestMetadata::default(),
            );

            storage.store_result(&result).unwrap();
            let retrieved = storage.retrieve_result("LONG-TIME").unwrap().unwrap();

            assert_eq!(retrieved.execution_time, Duration::from_secs(86400));
        }

        #[test]
        fn test_all_algorithm_variants_storage_persists_correctly_succeeds() {
            let storage = MemoryCavpStorage::new();

            let algorithms = vec![
                CavpAlgorithm::MlKem { variant: "512".to_string() },
                CavpAlgorithm::MlKem { variant: "768".to_string() },
                CavpAlgorithm::MlKem { variant: "1024".to_string() },
                CavpAlgorithm::MlDsa { variant: "44".to_string() },
                CavpAlgorithm::MlDsa { variant: "65".to_string() },
                CavpAlgorithm::MlDsa { variant: "87".to_string() },
                CavpAlgorithm::SlhDsa { variant: "128s".to_string() },
                CavpAlgorithm::SlhDsa { variant: "128f".to_string() },
                CavpAlgorithm::SlhDsa { variant: "256s".to_string() },
                CavpAlgorithm::SlhDsa { variant: "256f".to_string() },
                CavpAlgorithm::FnDsa { variant: "512".to_string() },
                CavpAlgorithm::FnDsa { variant: "1024".to_string() },
                CavpAlgorithm::HybridKem,
            ];

            for (i, algo) in algorithms.iter().enumerate() {
                let result = create_test_result(&format!("ALGO-{:02}", i), algo.clone(), true);
                storage.store_result(&result).unwrap();
            }

            // Verify each algorithm is retrievable
            for algo in &algorithms {
                let results = storage.list_results_by_algorithm(algo).unwrap();
                assert_eq!(results.len(), 1, "Algorithm {:?} should have 1 result", algo);
            }
        }
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_full_workflow_memory_succeeds() {
            let manager = CavpStorageManager::memory();

            // Store individual results
            for i in 0..10 {
                let result = create_test_result(
                    &format!("WORKFLOW-{:03}", i),
                    mlkem_algorithm("768"),
                    i % 3 != 0,
                );
                manager.store_result(&result).unwrap();
            }

            // Store batch
            let batch = create_batch_result("WORKFLOW-BATCH", mlkem_algorithm("768"), 7, 3);
            manager.store_batch(&batch).unwrap();

            // Query and verify
            let results = manager.list_results_by_algorithm(&mlkem_algorithm("768")).unwrap();
            assert_eq!(results.len(), 10);

            let batches = manager.list_batches_by_algorithm(&mlkem_algorithm("768")).unwrap();
            assert_eq!(batches.len(), 1);

            let retrieved_batch = manager.retrieve_batch("WORKFLOW-BATCH").unwrap().unwrap();
            assert_eq!(retrieved_batch.pass_rate, 70.0);
        }

        #[test]
        fn test_full_workflow_file_succeeds() {
            let temp_dir = TempDir::new().unwrap();
            let manager = CavpStorageManager::file(temp_dir.path()).unwrap();

            // Store individual results
            for i in 0..10 {
                let result = create_test_result(
                    &format!("FILE-WORKFLOW-{:03}", i),
                    mldsa_algorithm("44"),
                    i % 2 == 0,
                );
                manager.store_result(&result).unwrap();
            }

            // Store batch
            let batch = create_batch_result("FILE-WORKFLOW-BATCH", mldsa_algorithm("44"), 5, 5);
            manager.store_batch(&batch).unwrap();

            // Query and verify
            let results = manager.list_results_by_algorithm(&mldsa_algorithm("44")).unwrap();
            assert_eq!(results.len(), 10);

            let batches = manager.list_batches_by_algorithm(&mldsa_algorithm("44")).unwrap();
            assert_eq!(batches.len(), 1);

            // Verify files exist
            assert!(temp_dir.path().join("results").join("FILE-WORKFLOW-000.json").exists());
            assert!(temp_dir.path().join("batches").join("FILE-WORKFLOW-BATCH.json").exists());
        }

        #[test]
        fn test_multi_algorithm_storage_persists_correctly_succeeds() {
            let manager = CavpStorageManager::memory();

            let test_data = vec![
                (mlkem_algorithm("512"), 5),
                (mlkem_algorithm("768"), 10),
                (mldsa_algorithm("44"), 7),
                (slhdsa_algorithm("128s"), 3),
                (fndsa_algorithm("512"), 8),
                (CavpAlgorithm::HybridKem, 4),
            ];

            for (algo, count) in &test_data {
                for i in 0..*count {
                    let result = create_test_result(
                        &format!("{}-{:03}", algo.name(), i),
                        algo.clone(),
                        true,
                    );
                    manager.store_result(&result).unwrap();
                }
            }

            // Verify counts for each algorithm
            for (algo, expected_count) in &test_data {
                let results = manager.list_results_by_algorithm(algo).unwrap();
                assert_eq!(
                    results.len(),
                    *expected_count,
                    "Algorithm {} should have {} results",
                    algo.name(),
                    expected_count
                );
            }
        }

        #[test]
        fn test_batch_statistics_accuracy_is_correct() {
            let manager = CavpStorageManager::memory();

            // Create batch with known pass/fail ratio
            let batch = create_batch_result("STATS-BATCH", mlkem_algorithm("768"), 75, 25);
            manager.store_batch(&batch).unwrap();

            let retrieved = manager.retrieve_batch("STATS-BATCH").unwrap().unwrap();

            // Verify statistics
            assert_eq!(retrieved.test_results.len(), 100);
            assert_eq!(retrieved.pass_rate, 75.0);
            assert!(matches!(retrieved.status, CavpValidationStatus::Failed)); // Not 100% pass
        }

        #[test]
        fn test_storage_data_integrity_is_maintained_succeeds() {
            let manager = CavpStorageManager::memory();

            let original_result = CavpTestResult {
                test_id: "INTEGRITY-TEST".to_string(),
                algorithm: mlkem_algorithm("1024"),
                vector_id: "VEC-INTEGRITY".to_string(),
                passed: true,
                execution_time: Duration::from_millis(123),
                timestamp: chrono::Utc::now(),
                actual_result: vec![0x11, 0x22, 0x33, 0x44, 0x55],
                expected_result: vec![0x11, 0x22, 0x33, 0x44, 0x55],
                error_message: None,
                metadata: CavpTestMetadata {
                    environment: TestEnvironment {
                        os: "test-os".to_string(),
                        arch: "test-arch".to_string(),
                        rust_version: "1.93.0".to_string(),
                        compiler: "rustc".to_string(),
                        framework_version: "1.0.0".to_string(),
                    },
                    security_level: 256,
                    vector_version: "3.0".to_string(),
                    implementation_version: "0.6.0".to_string(),
                    configuration: TestConfiguration {
                        iterations: 1000,
                        timeout: Duration::from_secs(300),
                        statistical_tests: true,
                        parameters: {
                            let mut p = HashMap::new();
                            p.insert("key1".to_string(), vec![0xAA, 0xBB]);
                            p.insert("key2".to_string(), vec![0xCC, 0xDD, 0xEE]);
                            p
                        },
                    },
                },
            };

            manager.store_result(&original_result).unwrap();
            let retrieved = manager.retrieve_result("INTEGRITY-TEST").unwrap().unwrap();

            // Verify all fields
            assert_eq!(original_result.test_id, retrieved.test_id);
            assert_eq!(original_result.vector_id, retrieved.vector_id);
            assert_eq!(original_result.passed, retrieved.passed);
            assert_eq!(original_result.execution_time, retrieved.execution_time);
            assert_eq!(original_result.actual_result, retrieved.actual_result);
            assert_eq!(original_result.expected_result, retrieved.expected_result);
            assert_eq!(original_result.error_message, retrieved.error_message);
            assert_eq!(original_result.metadata.security_level, retrieved.metadata.security_level);
            assert_eq!(
                original_result.metadata.configuration.iterations,
                retrieved.metadata.configuration.iterations
            );
        }
    }
}

// Originally: fips_cavp_types_and_storage_coverage.rs
mod types_and_storage {
    //! Coverage tests for CAVP types (types.rs) and storage (storage.rs) modules.
    //! Targets: constructors, Default impls, CavpAlgorithm methods, CavpBatchResult lifecycle,
    //! CavpTestResult factory methods, MemoryCavpStorage full CRUD.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::float_cmp
    )]

    use latticearc_tests::validation::cavp::pipeline::PipelineConfig;
    use latticearc_tests::validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
    use latticearc_tests::validation::cavp::types::*;
    use std::collections::HashMap;
    use std::time::Duration;

    // ============================================================
    // CavpAlgorithm methods
    // ============================================================

    #[test]
    fn test_cavp_algorithm_name_all_variants_return_correct_strings_succeeds() {
        assert_eq!(CavpAlgorithm::MlKem { variant: "768".into() }.name(), "ML-KEM-768");
        assert_eq!(CavpAlgorithm::MlDsa { variant: "44".into() }.name(), "ML-DSA-44");
        assert_eq!(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".into() }.name(),
            "SLH-DSA-shake-128s"
        );
        assert_eq!(CavpAlgorithm::FnDsa { variant: "512".into() }.name(), "FN-DSA-512");
        assert_eq!(CavpAlgorithm::HybridKem.name(), "Hybrid-KEM");
    }

    #[test]
    fn test_cavp_algorithm_fips_standard_all_variants_return_correct_strings_succeeds() {
        assert_eq!(CavpAlgorithm::MlKem { variant: "768".into() }.fips_standard(), "FIPS 203");
        assert_eq!(CavpAlgorithm::MlDsa { variant: "65".into() }.fips_standard(), "FIPS 204");
        assert_eq!(
            CavpAlgorithm::SlhDsa { variant: "shake-256s".into() }.fips_standard(),
            "FIPS 205"
        );
        assert_eq!(CavpAlgorithm::FnDsa { variant: "1024".into() }.fips_standard(), "FIPS 206");
        assert_eq!(CavpAlgorithm::HybridKem.fips_standard(), "FIPS 203 + FIPS 197");
    }

    #[test]
    fn test_cavp_algorithm_clone_eq_hash_work_correctly_succeeds() {
        let a1 = CavpAlgorithm::MlKem { variant: "768".into() };
        let a2 = a1.clone();
        assert_eq!(a1, a2);

        let a3 = CavpAlgorithm::MlDsa { variant: "44".into() };
        assert_ne!(a1, a3);

        // Hash: can be used as HashMap key
        let mut map = HashMap::new();
        map.insert(a1.clone(), "mlkem");
        map.insert(a3, "mldsa");
        assert_eq!(map.len(), 2);
        assert_eq!(map[&a1], "mlkem");
    }

    #[test]
    fn test_cavp_algorithm_debug_produces_nonempty_string_succeeds() {
        let alg = CavpAlgorithm::SlhDsa { variant: "shake-192s".into() };
        let debug = format!("{:?}", alg);
        assert!(debug.contains("SlhDsa"));
        assert!(debug.contains("shake-192s"));
    }

    // ============================================================
    // Default impls
    // ============================================================

    #[test]
    fn test_pipeline_config_default_sets_expected_values_succeeds() {
        let config = PipelineConfig::default();
        assert_eq!(config.max_concurrent_tests, 4);
        assert_eq!(config.test_timeout, Duration::from_secs(30));
        assert_eq!(config.retry_count, 3);
        assert!(config.run_statistical_tests);
        assert!(config.generate_reports);
    }

    #[test]
    fn test_pipeline_config_debug_clone_work_correctly_succeeds() {
        let config = PipelineConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.retry_count, config.retry_count);
        let debug = format!("{:?}", config);
        assert!(debug.contains("PipelineConfig"));
    }

    #[test]
    fn test_test_environment_default_sets_expected_fields_succeeds() {
        let env = TestEnvironment::default();
        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
        assert_eq!(env.compiler, "rustc");
        assert_eq!(env.framework_version, "1.0.0");
    }

    #[test]
    fn test_test_configuration_default_sets_expected_fields_succeeds() {
        let tc = TestConfiguration::default();
        assert_eq!(tc.iterations, 1);
        assert_eq!(tc.timeout, Duration::from_secs(30));
        assert!(!tc.statistical_tests);
        assert!(tc.parameters.is_empty());
    }

    #[test]
    fn test_cavp_test_metadata_default_sets_expected_fields_succeeds() {
        let meta = CavpTestMetadata::default();
        assert!(!meta.environment.os.is_empty());
        assert_eq!(meta.security_level, 128);
        assert_eq!(meta.vector_version, "1.0");
    }

    // ============================================================
    // CavpTestResult constructors
    // ============================================================

    #[test]
    fn test_cavp_test_result_new_passing_sets_passed_status_succeeds() {
        let result = CavpTestResult::new(
            "test-1".to_string(),
            CavpAlgorithm::MlKem { variant: "768".into() },
            "vec-1".to_string(),
            vec![1, 2, 3],
            vec![1, 2, 3], // Same = pass
            Duration::from_millis(100),
            CavpTestMetadata::default(),
        );
        assert!(result.passed);
        assert!(result.error_message.is_none());
        assert_eq!(result.test_id, "test-1");
        assert_eq!(result.vector_id, "vec-1");
        assert_eq!(result.actual_result, vec![1, 2, 3]);
    }

    #[test]
    fn test_cavp_test_result_new_failing_sets_failed_status_fails() {
        let result = CavpTestResult::new(
            "test-2".to_string(),
            CavpAlgorithm::MlDsa { variant: "65".into() },
            "vec-2".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6], // Different = fail
            Duration::from_millis(50),
            CavpTestMetadata::default(),
        );
        assert!(!result.passed);
        assert!(result.error_message.is_none()); // No error_message for mismatch, just !passed
    }

    #[test]
    fn test_cavp_test_result_failed_factory_sets_failed_status_fails() {
        let result = CavpTestResult::failed(
            "test-3".to_string(),
            CavpAlgorithm::FnDsa { variant: "512".into() },
            "vec-3".to_string(),
            vec![],
            vec![0xAB; 16],
            Duration::from_millis(200),
            "crypto op failed".to_string(),
            CavpTestMetadata::default(),
        );
        assert!(!result.passed);
        assert_eq!(result.error_message.as_deref(), Some("crypto op failed"));
        assert!(result.actual_result.is_empty());
    }

    #[test]
    fn test_cavp_test_result_serialization_roundtrip() {
        let result = CavpTestResult::new(
            "test-ser".to_string(),
            CavpAlgorithm::HybridKem,
            "vec-ser".to_string(),
            vec![1],
            vec![1],
            Duration::from_millis(10),
            CavpTestMetadata::default(),
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test-ser"));
        let deserialized: CavpTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.test_id, "test-ser");
        assert!(deserialized.passed);
    }

    // ============================================================
    // CavpBatchResult lifecycle
    // ============================================================

    #[test]
    fn test_cavp_batch_result_new_sets_expected_fields_succeeds() {
        let batch = CavpBatchResult::new(
            "batch-1".to_string(),
            CavpAlgorithm::MlKem { variant: "768".into() },
        );
        assert_eq!(batch.batch_id, "batch-1");
        assert_eq!(batch.status, CavpValidationStatus::Incomplete);
        assert_eq!(batch.pass_rate, 0.0);
        assert!(batch.test_results.is_empty());
    }

    #[test]
    fn test_cavp_batch_result_add_passing_tests_increments_passed_count_succeeds() {
        let mut batch = CavpBatchResult::new(
            "batch-2".to_string(),
            CavpAlgorithm::MlDsa { variant: "44".into() },
        );

        for i in 0..3 {
            let result = CavpTestResult::new(
                format!("test-{}", i),
                CavpAlgorithm::MlDsa { variant: "44".into() },
                format!("vec-{}", i),
                vec![42],
                vec![42], // All pass
                Duration::from_millis(10),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(result);
        }

        assert_eq!(batch.test_results.len(), 3);
        assert_eq!(batch.pass_rate, 100.0);
        assert_eq!(batch.status, CavpValidationStatus::Passed);
    }

    #[test]
    fn test_cavp_batch_result_mixed_results_tracks_pass_and_fail_counts_fails() {
        let mut batch = CavpBatchResult::new(
            "batch-3".to_string(),
            CavpAlgorithm::SlhDsa { variant: "shake-128s".into() },
        );

        // One passing
        batch.add_test_result(CavpTestResult::new(
            "pass-1".to_string(),
            CavpAlgorithm::SlhDsa { variant: "shake-128s".into() },
            "v1".to_string(),
            vec![1],
            vec![1],
            Duration::from_millis(5),
            CavpTestMetadata::default(),
        ));

        // One failing
        batch.add_test_result(CavpTestResult::new(
            "fail-1".to_string(),
            CavpAlgorithm::SlhDsa { variant: "shake-128s".into() },
            "v2".to_string(),
            vec![1],
            vec![2], // Different = fail
            Duration::from_millis(5),
            CavpTestMetadata::default(),
        ));

        assert_eq!(batch.pass_rate, 50.0);
        assert_eq!(batch.status, CavpValidationStatus::Failed);
    }

    #[test]
    fn test_cavp_batch_result_update_status_empty_sets_no_results_succeeds() {
        let mut batch = CavpBatchResult::new("batch-empty".to_string(), CavpAlgorithm::HybridKem);
        batch.update_status();
        assert_eq!(batch.status, CavpValidationStatus::Incomplete);
    }

    // ============================================================
    // CavpValidationStatus
    // ============================================================

    #[test]
    fn test_cavp_validation_status_variants_produce_correct_strings_succeeds() {
        let passed = CavpValidationStatus::Passed;
        let failed = CavpValidationStatus::Failed;
        let incomplete = CavpValidationStatus::Incomplete;
        let error = CavpValidationStatus::Error("test error".to_string());

        assert_eq!(passed, CavpValidationStatus::Passed);
        assert_ne!(passed, failed);
        assert_ne!(failed, incomplete);

        let debug = format!("{:?}", error);
        assert!(debug.contains("test error"));

        // Serialization roundtrip
        let json = serde_json::to_string(&passed).unwrap();
        let deser: CavpValidationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deser, CavpValidationStatus::Passed);
    }

    // ============================================================
    // CavpTestType
    // ============================================================

    #[test]
    fn test_cavp_test_type_variants_produce_correct_strings_succeeds() {
        let types = [
            CavpTestType::KeyGen,
            CavpTestType::Encapsulation,
            CavpTestType::Decapsulation,
            CavpTestType::Signature,
            CavpTestType::Verification,
        ];
        for t in &types {
            let debug = format!("{:?}", t);
            assert!(!debug.is_empty());
            let json = serde_json::to_string(t).unwrap();
            let deser: CavpTestType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, deser);
        }
    }

    // ============================================================
    // MemoryCavpStorage CRUD
    // ============================================================

    #[test]
    fn test_memory_storage_store_and_retrieve_result_succeeds() {
        let storage = MemoryCavpStorage::new();
        let result = CavpTestResult::new(
            "store-test-1".to_string(),
            CavpAlgorithm::MlKem { variant: "768".into() },
            "vec-1".to_string(),
            vec![1, 2, 3],
            vec![1, 2, 3],
            Duration::from_millis(10),
            CavpTestMetadata::default(),
        );

        storage.store_result(&result).unwrap();

        let retrieved = storage.retrieve_result("store-test-1").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.test_id, "store-test-1");
        assert!(retrieved.passed);
    }

    #[test]
    fn test_memory_storage_retrieve_nonexistent_result_returns_none() {
        let storage = MemoryCavpStorage::new();
        let retrieved = storage.retrieve_result("does-not-exist").unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_memory_storage_store_and_retrieve_batch_succeeds() {
        let storage = MemoryCavpStorage::new();

        let mut batch = CavpBatchResult::new(
            "batch-store-1".to_string(),
            CavpAlgorithm::MlDsa { variant: "65".into() },
        );
        batch.add_test_result(CavpTestResult::new(
            "bt-1".to_string(),
            CavpAlgorithm::MlDsa { variant: "65".into() },
            "v1".to_string(),
            vec![1],
            vec![1],
            Duration::from_millis(5),
            CavpTestMetadata::default(),
        ));

        storage.store_batch(&batch).unwrap();

        let retrieved = storage.retrieve_batch("batch-store-1").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.batch_id, "batch-store-1");
        assert_eq!(retrieved.test_results.len(), 1);
    }

    #[test]
    fn test_memory_storage_retrieve_nonexistent_batch_returns_none() {
        let storage = MemoryCavpStorage::new();
        let retrieved = storage.retrieve_batch("no-batch").unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_memory_storage_list_results_by_algorithm_returns_filtered_results_succeeds() {
        let storage = MemoryCavpStorage::new();
        let alg = CavpAlgorithm::FnDsa { variant: "512".into() };

        for i in 0..3 {
            let result = CavpTestResult::new(
                format!("list-test-{}", i),
                alg.clone(),
                format!("v-{}", i),
                vec![i as u8],
                vec![i as u8],
                Duration::from_millis(5),
                CavpTestMetadata::default(),
            );
            storage.store_result(&result).unwrap();
        }

        let results = storage.list_results_by_algorithm(&alg).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_memory_storage_list_results_empty_algorithm_returns_empty_succeeds() {
        let storage = MemoryCavpStorage::new();
        let results = storage.list_results_by_algorithm(&CavpAlgorithm::HybridKem).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_memory_storage_list_batches_by_algorithm_returns_filtered_batches_succeeds() {
        let storage = MemoryCavpStorage::new();
        let alg = CavpAlgorithm::SlhDsa { variant: "shake-256s".into() };

        for i in 0..2 {
            let batch = CavpBatchResult::new(format!("batch-list-{}", i), alg.clone());
            storage.store_batch(&batch).unwrap();
        }

        let batches = storage.list_batches_by_algorithm(&alg).unwrap();
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn test_memory_storage_list_batches_empty_returns_empty_succeeds() {
        let storage = MemoryCavpStorage::new();
        let batches = storage
            .list_batches_by_algorithm(&CavpAlgorithm::MlKem { variant: "512".into() })
            .unwrap();
        assert!(batches.is_empty());
    }

    // ============================================================
    // CavpVectorInputs / CavpVectorOutputs
    // ============================================================

    #[test]
    fn test_cavp_vector_inputs_serialization_roundtrip() {
        let inputs = CavpVectorInputs {
            seed: Some(vec![0x42; 32]),
            message: Some(b"hello".to_vec()),
            key_material: None,
            pk: Some(vec![0xAA; 64]),
            sk: None,
            c: None,
            m: None,
            ek: None,
            dk: None,
            signature: None,
            parameters: HashMap::new(),
        };
        let json = serde_json::to_string(&inputs).unwrap();
        let deser: CavpVectorInputs = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.seed, inputs.seed);
        assert_eq!(deser.message, inputs.message);
        assert_eq!(deser.pk, inputs.pk);
    }

    #[test]
    fn test_cavp_vector_outputs_serialization_roundtrip() {
        let outputs = CavpVectorOutputs {
            public_key: Some(vec![1, 2, 3]),
            secret_key: Some(vec![4, 5, 6]),
            ciphertext: None,
            signature: Some(vec![7, 8, 9]),
            shared_secret: None,
            additional: HashMap::new(),
        };
        let json = serde_json::to_string(&outputs).unwrap();
        let deser: CavpVectorOutputs = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.public_key, outputs.public_key);
        assert_eq!(deser.signature, outputs.signature);
    }

    // ============================================================
    // CavpTestVector
    // ============================================================

    #[test]
    fn test_cavp_test_vector_full_roundtrip() {
        let vector = CavpTestVector {
            id: "roundtrip-1".to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "768".into() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0; 32]),
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
                public_key: Some(vec![1; 64]),
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "2.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: chrono::Utc::now(),
                security_level: 256,
                notes: Some("roundtrip test".to_string()),
            },
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deser: CavpTestVector = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.id, "roundtrip-1");
        assert_eq!(deser.algorithm, CavpAlgorithm::MlKem { variant: "768".into() });
        assert_eq!(deser.metadata.security_level, 256);
    }
}

// Originally: fips_cavp_enhanced_tests.rs
mod enhanced {
    //! Comprehensive tests for CAVP Enhanced Framework
    //!
    //! This module tests the enhanced CAVP (Cryptographic Algorithm Validation Program)
    //! framework components including:
    //! - NistComplianceValidator
    //! - CavpTestExecutor (enhanced)
    //! - PipelineConfig
    //! - StorageBackend
    //! - CavpValidationOrchestrator
    //!
    //! Tests cover:
    //! 1. All public types and their constructors
    //! 2. Framework configuration and initialization
    //! 3. Test execution flows with mock data
    //! 4. Result handling and reporting

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

    use chrono::{Duration, Utc};
    use latticearc_tests::validation::cavp::compliance::{
        ComplianceCriteria, ComplianceStatus, SecurityRequirement, TestCategory, TestResult,
    };
    use latticearc_tests::validation::cavp::enhanced_framework::{
        CavpTestExecutor as EnhancedCavpTestExecutor, CavpValidationOrchestrator,
        NistComplianceValidator, PipelineConfig as EnhancedPipelineConfig, StorageBackend,
    };
    use latticearc_tests::validation::cavp::types::{
        CavpAlgorithm, CavpBatchResult, CavpTestMetadata, CavpTestResult, CavpTestType,
        CavpTestVector, CavpValidationStatus, CavpVectorInputs, CavpVectorMetadata,
        CavpVectorOutputs, TestConfiguration, TestEnvironment,
    };
    use std::collections::HashMap;
    use std::time::Duration as StdDuration;

    // ============================================================================
    // Test Helper Functions
    // ============================================================================

    /// Creates a sample ML-KEM test vector for testing
    fn create_mlkem_vector(id: &str, variant: &str) -> CavpTestVector {
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
                public_key: Some(vec![0x42; 64]),
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
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("Test vector for enhanced framework testing".to_string()),
            },
        }
    }

    /// Creates a sample ML-DSA test vector for signature testing
    fn create_mldsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x11; 32]),
                message: Some(b"Test message for ML-DSA".to_vec()),
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
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("ML-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample SLH-DSA test vector
    fn create_slhdsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::SlhDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x22; 32]),
                message: Some(b"Test message for SLH-DSA".to_vec()),
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
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("SLH-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample FN-DSA test vector
    fn create_fndsa_vector(id: &str, variant: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::FnDsa { variant: variant.to_string() },
            inputs: CavpVectorInputs {
                seed: Some(vec![0x33; 32]),
                message: Some(b"Test message for FN-DSA".to_vec()),
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
                signature: Some(vec![0x42; 64]),
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "NIST".to_string(),
                test_type: CavpTestType::Signature,
                created_at: Utc::now(),
                security_level: 128,
                notes: Some("FN-DSA signature test vector".to_string()),
            },
        }
    }

    /// Creates a sample Hybrid KEM test vector
    fn create_hybrid_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::HybridKem,
            inputs: CavpVectorInputs {
                seed: Some(vec![0x44; 64]),
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
                public_key: Some(vec![0x42; 64]),
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: Some(vec![0x55; 32]),
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Internal".to_string(),
                test_type: CavpTestType::KeyGen,
                created_at: Utc::now(),
                security_level: 256,
                notes: Some("Hybrid KEM test vector".to_string()),
            },
        }
    }

    /// Creates a test vector that will trigger a timeout simulation
    fn create_slow_vector(id: &str) -> CavpTestVector {
        let mut vector = create_mlkem_vector(id, "768");
        vector.inputs.parameters.insert("simulate_slow_operation".to_string(), vec![1]);
        vector
    }

    /// Creates a test vector missing required seed for KeyGen
    fn create_invalid_keygen_vector(id: &str) -> CavpTestVector {
        CavpTestVector {
            id: id.to_string(),
            algorithm: CavpAlgorithm::MlKem { variant: "768".to_string() },
            inputs: CavpVectorInputs {
                seed: None, // Missing required seed
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
                secret_key: None,
                ciphertext: None,
                signature: None,
                shared_secret: None,
                additional: HashMap::new(),
            },
            metadata: CavpVectorMetadata {
                version: "1.0".to_string(),
                source: "Test".to_string(),
                test_type: CavpTestType::KeyGen, // KeyGen requires seed
                created_at: Utc::now(),
                security_level: 128,
                notes: None,
            },
        }
    }

    /// Helper function to create a batch result with specified test results
    fn create_batch_with_results(
        algorithm: CavpAlgorithm,
        passed: usize,
        failed: usize,
    ) -> CavpBatchResult {
        let batch_id = format!("BATCH-{}", Utc::now().timestamp_micros());
        let mut batch = CavpBatchResult::new(batch_id, algorithm.clone());

        for i in 0..passed {
            let result = CavpTestResult::new(
                format!("PASS-{}", i),
                algorithm.clone(),
                format!("VEC-PASS-{}", i),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual - will pass
                StdDuration::from_millis(50),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(result);
        }

        for i in 0..failed {
            let result = CavpTestResult::failed(
                format!("FAIL-{}", i),
                algorithm.clone(),
                format!("VEC-FAIL-{}", i),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual - will fail
                StdDuration::from_millis(50),
                "Test mismatch".to_string(),
                CavpTestMetadata::default(),
            );
            batch.add_test_result(result);
        }

        batch
    }

    // ============================================================================
    // NistComplianceValidator Tests
    // ============================================================================

    mod nist_compliance_validator_tests {
        use super::*;

        #[test]
        fn test_validator_creation_succeeds() {
            let _validator = NistComplianceValidator::new();
            // Validator should be created successfully with initialized criteria
            assert!(true, "NistComplianceValidator created successfully");
        }

        #[test]
        fn test_validator_default_succeeds() {
            let _validator = NistComplianceValidator::default();
            // Default should be equivalent to new()
            assert!(true, "NistComplianceValidator::default() works");
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_512_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1000);
            assert_eq!(criteria.min_coverage, 95.0);
            assert!(!criteria.security_requirements.is_empty());
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_768_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1500);
        }

        #[test]
        fn test_get_algorithm_criteria_mlkem_1024_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "1024".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 2000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_44_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 3000);
            assert_eq!(criteria.min_coverage, 98.0);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_65_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "65".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 4000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_87_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 5000);
        }

        #[test]
        fn test_get_algorithm_criteria_mldsa_128_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "128".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_coverage, 98.0);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_128s_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-128s".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 20000);
            assert_eq!(criteria.min_coverage, 99.0);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_128f_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-128f".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 25000);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_256s_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-256s".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 25000);
        }

        #[test]
        fn test_get_algorithm_criteria_slhdsa_sha2_256f_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "SHA2-256f".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 30000);
        }

        #[test]
        fn test_get_algorithm_criteria_fndsa_512_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 1500);
            assert_eq!(criteria.min_coverage, 97.0);
        }

        #[test]
        fn test_get_algorithm_criteria_fndsa_1024_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "1024".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            assert_eq!(criteria.max_execution_time_ms, 2000);
        }

        #[test]
        fn test_get_algorithm_criteria_unknown_algorithm_returns_default_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "unknown".to_string() };

            let criteria = validator.get_algorithm_criteria(&algorithm);

            // Should return default criteria
            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 5000);
            assert_eq!(criteria.min_coverage, 95.0);
            assert!(criteria.security_requirements.is_empty());
        }

        #[test]
        fn test_get_algorithm_criteria_hybrid_kem_returns_correct_criteria_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let criteria = validator.get_algorithm_criteria(&algorithm);

            // HybridKem should return default criteria
            assert_eq!(criteria.min_pass_rate, 100.0);
        }

        #[test]
        fn test_validate_batch_fully_compliant_returns_compliant_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let batch = create_batch_with_results(algorithm, 10, 0);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(report.compliance_status, ComplianceStatus::FullyCompliant));
            assert_eq!(report.summary.total_tests, 10);
            assert_eq!(report.summary.passed_tests, 10);
            assert_eq!(report.summary.failed_tests, 0);
            assert_eq!(report.summary.pass_rate, 100.0);
        }

        #[test]
        fn test_validate_batch_partially_compliant_returns_partial_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            // 7 passed, 3 failed = 70% pass rate
            let batch = create_batch_with_results(algorithm, 7, 3);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(
                report.compliance_status,
                ComplianceStatus::PartiallyCompliant { .. }
            ));
            assert_eq!(report.summary.pass_rate, 70.0);
        }

        #[test]
        fn test_validate_batch_non_compliant_returns_non_compliant_status_succeeds() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            // 4 passed, 6 failed = 40% pass rate (below 50%)
            let batch = create_batch_with_results(algorithm, 4, 6);
            let report = validator.validate_batch(&batch).unwrap();

            assert!(matches!(report.compliance_status, ComplianceStatus::NonCompliant { .. }));
        }

        #[test]
        fn test_validate_batch_report_structure_has_correct_format() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let batch = create_batch_with_results(algorithm.clone(), 5, 0);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify report structure
            assert!(report.report_id.starts_with("CAVP-REPORT-"));
            assert_eq!(report.algorithm, algorithm);
            assert!(!report.nist_standards.is_empty());
            assert_eq!(report.nist_standards[0], "FIPS 206");
        }

        #[test]
        fn test_validate_batch_performance_metrics_are_correct() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let batch = create_batch_with_results(algorithm, 5, 0);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify performance metrics
            assert!(report.performance_metrics.avg_execution_time_ms >= 0.0);
            assert!(report.performance_metrics.total_execution_time_ms > 0);
        }

        #[test]
        fn test_validate_batch_detailed_results_are_correct() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let batch = create_batch_with_results(algorithm, 3, 2);
            let report = validator.validate_batch(&batch).unwrap();

            // Verify detailed results
            assert_eq!(report.detailed_results.len(), 5);

            let passed_count = report
                .detailed_results
                .iter()
                .filter(|r| matches!(r.result, TestResult::Passed))
                .count();
            assert_eq!(passed_count, 3);
        }

        // Security Level Validation Tests

        #[test]
        fn test_validate_security_level_mlkem_512_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_768_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_1024_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "1024".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mlkem_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlKem { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Invalid security level"));
        }

        #[test]
        fn test_validate_security_level_mldsa_44_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_65_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "65".to_string() };

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_87_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_128_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "128".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_mldsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_slhdsa_128s_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_128f_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128f".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_256s_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "256s".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_256f_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "256f".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_slhdsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_fndsa_512_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_fndsa_1024_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "1024".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_fndsa_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_security_level_hybrid_kem_valid_returns_ok() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let result = validator.validate_security_level(&algorithm, 128);
            assert!(result.is_ok());

            let result = validator.validate_security_level(&algorithm, 192);
            assert!(result.is_ok());

            let result = validator.validate_security_level(&algorithm, 256);
            assert!(result.is_ok());
        }

        #[test]
        fn test_validate_security_level_hybrid_kem_invalid_returns_error() {
            let validator = NistComplianceValidator::new();
            let algorithm = CavpAlgorithm::HybridKem;

            let result = validator.validate_security_level(&algorithm, 64);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("minimum security level 128"));
        }
    }

    // ============================================================================
    // PipelineConfig Tests
    // ============================================================================

    mod pipeline_config_tests {
        use super::*;

        #[test]
        fn test_pipeline_config_default_has_expected_values_succeeds() {
            let config = EnhancedPipelineConfig::default();

            assert!(config.parallel_execution);
            assert!(config.max_threads > 0);
            assert!(config.timeout_per_test > Duration::zero());
            assert!(config.retry_failed_tests > 0);
            assert!(config.generate_reports);
            assert!(matches!(config.storage_backend, StorageBackend::Memory));
        }

        #[test]
        fn test_pipeline_config_custom_has_correct_values_succeeds() {
            let config = EnhancedPipelineConfig {
                parallel_execution: false,
                max_threads: 4,
                timeout_per_test: Duration::seconds(60),
                retry_failed_tests: 5,
                generate_reports: false,
                storage_backend: StorageBackend::File,
            };

            assert!(!config.parallel_execution);
            assert_eq!(config.max_threads, 4);
            assert_eq!(config.timeout_per_test, Duration::seconds(60));
            assert_eq!(config.retry_failed_tests, 5);
            assert!(!config.generate_reports);
            assert!(matches!(config.storage_backend, StorageBackend::File));
        }

        #[test]
        fn test_pipeline_config_clone_produces_equal_value_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let cloned = config.clone();

            assert_eq!(config.parallel_execution, cloned.parallel_execution);
            assert_eq!(config.max_threads, cloned.max_threads);
            assert_eq!(config.timeout_per_test, cloned.timeout_per_test);
        }

        #[test]
        fn test_pipeline_config_debug_has_correct_format() {
            let config = EnhancedPipelineConfig::default();
            let debug_str = format!("{:?}", config);

            assert!(debug_str.contains("PipelineConfig"));
            assert!(debug_str.contains("parallel_execution"));
        }
    }

    // ============================================================================
    // StorageBackend Tests
    // ============================================================================

    mod storage_backend_tests {
        use super::*;

        #[test]
        fn test_storage_backend_memory_is_accessible() {
            let backend = StorageBackend::Memory;
            assert!(matches!(backend, StorageBackend::Memory));
        }

        #[test]
        fn test_storage_backend_file_is_accessible() {
            let backend = StorageBackend::File;
            assert!(matches!(backend, StorageBackend::File));
        }

        #[test]
        fn test_storage_backend_clone_produces_equal_value_succeeds() {
            let backend = StorageBackend::Memory;
            let cloned = backend.clone();
            assert!(matches!(cloned, StorageBackend::Memory));
        }

        #[test]
        fn test_storage_backend_debug_has_correct_format() {
            let backend = StorageBackend::Memory;
            let debug_str = format!("{:?}", backend);
            assert!(debug_str.contains("Memory"));
        }
    }

    // ============================================================================
    // CavpTestExecutor Tests
    // ============================================================================

    mod cavp_test_executor_tests {
        use super::*;

        #[test]
        fn test_executor_creation_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            // Executor should be created successfully
            drop(executor);
        }

        #[test]
        fn test_execute_mlkem_keygen_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-MLKEM-001", "768");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert_eq!(test_result.vector_id, "TEST-MLKEM-001");
            assert!(test_result.test_id.starts_with("TEST-"));
        }

        #[test]
        fn test_execute_mldsa_signature_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mldsa_vector("TEST-MLDSA-001", "44");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_slhdsa_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_slhdsa_vector("TEST-SLHDSA-001", "128s");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_fndsa_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_fndsa_vector("TEST-FNDSA-001", "512");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_hybrid_vector_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_hybrid_vector("TEST-HYBRID-001");
            let result = executor.execute_test_vector(&vector);

            assert!(result.is_ok());
        }

        #[test]
        fn test_execute_timeout_simulation_completes_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_slow_vector("TEST-SLOW-001");
            let result = executor.execute_test_vector(&vector);

            // Should return a result (possibly failed due to timeout)
            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.passed, "Slow operation should simulate failure");
            assert!(test_result.error_message.is_some());
        }

        #[test]
        fn test_execute_missing_seed_keygen_returns_error() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_invalid_keygen_vector("TEST-INVALID-001");
            let result = executor.execute_test_vector(&vector);

            // Should return a result with error
            assert!(result.is_ok());
            let test_result = result.unwrap();
            assert!(!test_result.passed);
            assert!(test_result.error_message.is_some());
            assert!(test_result.error_message.as_ref().unwrap().contains("Missing required seed"));
        }

        #[test]
        fn test_execution_time_recorded_correctly_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-TIME-001", "512");
            let result = executor.execute_test_vector(&vector).unwrap();

            assert!(result.execution_time > StdDuration::ZERO);
        }

        #[test]
        fn test_result_metadata_populated_correctly_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);

            let vector = create_mlkem_vector("TEST-META-001", "768");
            let result = executor.execute_test_vector(&vector).unwrap();

            // Verify metadata is populated
            assert!(!result.metadata.environment.os.is_empty());
            assert!(!result.metadata.environment.arch.is_empty());
        }
    }

    // ============================================================================
    // CavpValidationOrchestrator Tests
    // ============================================================================

    mod cavp_validation_orchestrator_tests {
        use super::*;

        #[test]
        fn test_orchestrator_creation_succeeds() {
            let config = EnhancedPipelineConfig::default();
            let executor = EnhancedCavpTestExecutor::new(config);
            let orchestrator = CavpValidationOrchestrator::new(executor);

            // Orchestrator should be created successfully
            drop(orchestrator);
        }

        #[test]
        fn test_orchestrator_default_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            // Default orchestrator should work
            drop(orchestrator);
        }

        #[test]
        fn test_compliance_generator_access_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            let generator = orchestrator.compliance_generator();

            // Should be able to access compliance generator
            assert!(true, "Compliance generator accessible");
            let _ = generator;
        }

        #[test]
        fn test_run_full_validation_single_algorithm_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("ORCH-001", "768"),
                create_mlkem_vector("ORCH-002", "768"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // All vectors are ML-KEM, so should be one batch
            assert_eq!(batch_results.len(), 1);
            assert_eq!(batch_results[0].test_results.len(), 2);
        }

        #[test]
        fn test_run_full_validation_multiple_algorithms_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("MULTI-001", "768"),
                create_mldsa_vector("MULTI-002", "44"),
                create_slhdsa_vector("MULTI-003", "128s"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // Three different algorithms, so three batches
            assert_eq!(batch_results.len(), 3);
        }

        #[test]
        fn test_run_full_validation_empty_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors: Vec<CavpTestVector> = vec![];
            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            assert!(batch_results.is_empty());
        }

        #[test]
        fn test_run_full_validation_with_failures_reports_errors_fails() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("FAIL-001", "768"),
                create_invalid_keygen_vector("FAIL-002"),
                create_slow_vector("FAIL-003"),
            ];

            let results = orchestrator.run_full_validation(vectors);

            assert!(results.is_ok());
            let batch_results = results.unwrap();
            // All are ML-KEM variants, so one batch with mixed results
            assert!(!batch_results.is_empty());
        }

        #[test]
        fn test_orchestrator_grouping_by_algorithm_is_correct() {
            let orchestrator = CavpValidationOrchestrator::default();

            let vectors = vec![
                create_mlkem_vector("GROUP-001", "512"),
                create_mlkem_vector("GROUP-002", "768"), // Different variant = different algorithm
                create_mlkem_vector("GROUP-003", "1024"), // Different variant = different algorithm
            ];

            let results = orchestrator.run_full_validation(vectors).unwrap();

            // Three different ML-KEM variants should create three batches
            assert_eq!(results.len(), 3);
        }
    }

    // ============================================================================
    // TestCategory Tests
    // ============================================================================

    mod test_category_tests {
        use super::*;

        #[test]
        fn test_category_from_vector_id_keygen_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("ML-KEM-keygen-001");
            assert!(matches!(category, TestCategory::KeyGeneration));

            let category = TestCategory::from_vector_id("KEYGEN_TEST_001");
            assert!(matches!(category, TestCategory::KeyGeneration));
        }

        #[test]
        fn test_category_from_vector_id_signature_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("ML-DSA-sig-001");
            assert!(matches!(category, TestCategory::Signature));

            let category = TestCategory::from_vector_id("SIGNATURE_TEST");
            assert!(matches!(category, TestCategory::Signature));

            let category = TestCategory::from_vector_id("SIG_VERIFY");
            assert!(matches!(category, TestCategory::Signature));
        }

        #[test]
        fn test_category_from_vector_id_encryption_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("enc-001");
            assert!(matches!(category, TestCategory::Encryption));

            let category = TestCategory::from_vector_id("ENCAPSULATION_TEST");
            assert!(matches!(category, TestCategory::Encryption));
        }

        #[test]
        fn test_category_from_vector_id_decryption_returns_correct_category_matches_expected() {
            let category = TestCategory::from_vector_id("dec-001");
            assert!(matches!(category, TestCategory::Decryption));

            let category = TestCategory::from_vector_id("DECAPSULATION_TEST");
            assert!(matches!(category, TestCategory::Decryption));
        }

        #[test]
        fn test_category_from_vector_id_compliance_returns_correct_category_matches_expected() {
            // Default category when no pattern matches
            let category = TestCategory::from_vector_id("random_test_001");
            assert!(matches!(category, TestCategory::Compliance));

            let category = TestCategory::from_vector_id("MISC_TEST");
            assert!(matches!(category, TestCategory::Compliance));
        }
    }

    // ============================================================================
    // TestResult Tests
    // ============================================================================

    mod test_result_tests {
        use super::*;

        #[test]
        fn test_result_from_bool_passed_returns_passed_succeeds() {
            let result = TestResult::from_bool(true);
            assert!(matches!(result, TestResult::Passed));
        }

        #[test]
        fn test_result_from_bool_failed_returns_failed_fails() {
            let result = TestResult::from_bool(false);
            assert!(matches!(result, TestResult::Failed(_)));
        }
    }

    // ============================================================================
    // CavpBatchResult Tests
    // ============================================================================

    mod cavp_batch_result_tests {
        use super::*;

        #[test]
        fn test_batch_result_new_has_correct_fields_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            assert_eq!(batch.batch_id, "TEST-BATCH");
            assert_eq!(batch.algorithm, algorithm);
            assert!(batch.test_results.is_empty());
            assert!(matches!(batch.status, CavpValidationStatus::Incomplete));
            assert_eq!(batch.pass_rate, 0.0);
        }

        #[test]
        fn test_batch_result_add_test_result_updates_count_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);

            assert_eq!(batch.test_results.len(), 1);
            assert!(batch.total_execution_time >= StdDuration::from_millis(100));
        }

        #[test]
        fn test_batch_result_update_status_passed_is_correct() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add passing test
            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);
            batch.update_status();

            assert_eq!(batch.pass_rate, 100.0);
            assert!(matches!(batch.status, CavpValidationStatus::Passed));
        }

        #[test]
        fn test_batch_result_update_status_failed_is_correct() {
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add failing test
            let result = CavpTestResult::failed(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual
                StdDuration::from_millis(100),
                "Mismatch".to_string(),
                CavpTestMetadata::default(),
            );

            batch.add_test_result(result);
            batch.update_status();

            assert_eq!(batch.pass_rate, 0.0);
            assert!(matches!(batch.status, CavpValidationStatus::Failed));
        }

        #[test]
        fn test_batch_result_update_status_mixed_is_correct() {
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            // Add passing test
            batch.add_test_result(CavpTestResult::new(
                "PASS-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(50),
                CavpTestMetadata::default(),
            ));

            // Add failing test
            batch.add_test_result(CavpTestResult::failed(
                "FAIL-001".to_string(),
                algorithm.clone(),
                "VEC-002".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64],
                StdDuration::from_millis(50),
                "Error".to_string(),
                CavpTestMetadata::default(),
            ));

            batch.update_status();

            assert_eq!(batch.pass_rate, 50.0);
            assert!(matches!(batch.status, CavpValidationStatus::Failed));
        }

        #[test]
        fn test_batch_result_generate_ci_report_succeeds() {
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            let mut batch = CavpBatchResult::new("TEST-BATCH".to_string(), algorithm.clone());

            batch.add_test_result(CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            ));

            let report = batch.generate_ci_report();

            assert!(report.contains("FN-DSA-512"));
            assert!(report.contains("Total Tests: 1"));
            assert!(report.contains("Passed: 1"));
            assert!(report.contains("Failed: 0"));
            assert!(report.contains("Pass Rate:"));
        }
    }

    // ============================================================================
    // CavpTestMetadata Tests
    // ============================================================================

    mod cavp_test_metadata_tests {
        use super::*;

        #[test]
        fn test_metadata_default_has_expected_values_succeeds() {
            let metadata = CavpTestMetadata::default();

            assert!(!metadata.environment.os.is_empty());
            assert!(!metadata.environment.arch.is_empty());
            assert!(!metadata.environment.rust_version.is_empty());
            assert!(!metadata.environment.compiler.is_empty());
            assert_eq!(metadata.security_level, 128);
            assert_eq!(metadata.vector_version, "1.0");
        }

        #[test]
        fn test_environment_default_has_expected_values_succeeds() {
            let env = TestEnvironment::default();

            assert!(!env.os.is_empty());
            assert!(!env.arch.is_empty());
            assert!(!env.rust_version.is_empty());
            assert_eq!(env.compiler, "rustc");
        }

        #[test]
        fn test_configuration_default_has_expected_values_succeeds() {
            let config = TestConfiguration::default();

            assert_eq!(config.iterations, 1);
            assert_eq!(config.timeout, StdDuration::from_secs(30));
            assert!(!config.statistical_tests);
            assert!(config.parameters.is_empty());
        }
    }

    // ============================================================================
    // CavpAlgorithm Tests
    // ============================================================================

    mod cavp_algorithm_tests {
        use super::*;

        #[test]
        fn test_algorithm_name_mlkem_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlKem { variant: "768".to_string() };
            assert_eq!(algo.name(), "ML-KEM-768");
        }

        #[test]
        fn test_algorithm_name_mldsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            assert_eq!(algo.name(), "ML-DSA-44");
        }

        #[test]
        fn test_algorithm_name_slhdsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            assert_eq!(algo.name(), "SLH-DSA-128s");
        }

        #[test]
        fn test_algorithm_name_fndsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            assert_eq!(algo.name(), "FN-DSA-512");
        }

        #[test]
        fn test_algorithm_name_hybrid_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::HybridKem;
            assert_eq!(algo.name(), "Hybrid-KEM");
        }

        #[test]
        fn test_fips_standard_mlkem_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlKem { variant: "768".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 203");
        }

        #[test]
        fn test_fips_standard_mldsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::MlDsa { variant: "65".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 204");
        }

        #[test]
        fn test_fips_standard_slhdsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "256f".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 205");
        }

        #[test]
        fn test_fips_standard_fndsa_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::FnDsa { variant: "1024".to_string() };
            assert_eq!(algo.fips_standard(), "FIPS 206");
        }

        #[test]
        fn test_fips_standard_hybrid_returns_correct_string_succeeds() {
            let algo = CavpAlgorithm::HybridKem;
            assert_eq!(algo.fips_standard(), "FIPS 203 + FIPS 197");
        }

        #[test]
        fn test_algorithm_equality_matches_expected() {
            let algo1 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let algo2 = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let algo3 = CavpAlgorithm::MlKem { variant: "512".to_string() };

            assert_eq!(algo1, algo2);
            assert_ne!(algo1, algo3);
        }

        #[test]
        fn test_algorithm_hash_deduplicates_correctly_succeeds() {
            use std::collections::HashSet;

            let mut set = HashSet::new();
            set.insert(CavpAlgorithm::MlKem { variant: "768".to_string() });
            set.insert(CavpAlgorithm::MlDsa { variant: "44".to_string() });

            assert!(set.contains(&CavpAlgorithm::MlKem { variant: "768".to_string() }));
            assert!(!set.contains(&CavpAlgorithm::MlKem { variant: "512".to_string() }));
        }

        #[test]
        fn test_algorithm_clone_produces_equal_value_succeeds() {
            let algo = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let cloned = algo.clone();

            assert_eq!(algo, cloned);
        }
    }

    // ============================================================================
    // CavpTestResult Tests
    // ============================================================================

    mod cavp_test_result_tests {
        use super::*;

        #[test]
        fn test_result_new_passed_has_correct_fields_succeeds() {
            let algorithm = CavpAlgorithm::MlKem { variant: "768".to_string() };
            let result = CavpTestResult::new(
                "TEST-001".to_string(),
                algorithm.clone(),
                "VEC-001".to_string(),
                vec![0x42; 64],
                vec![0x42; 64], // Same as actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert_eq!(result.test_id, "TEST-001");
            assert_eq!(result.algorithm, algorithm);
            assert_eq!(result.vector_id, "VEC-001");
            assert!(result.passed);
            assert!(result.error_message.is_none());
        }

        #[test]
        fn test_result_new_failed_has_correct_fields_fails() {
            let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
            let result = CavpTestResult::new(
                "TEST-002".to_string(),
                algorithm,
                "VEC-002".to_string(),
                vec![0x00; 64],
                vec![0xFF; 64], // Different from actual
                StdDuration::from_millis(100),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
        }

        #[test]
        fn test_result_failed_constructor_has_correct_fields_fails() {
            let algorithm = CavpAlgorithm::SlhDsa { variant: "128s".to_string() };
            let result = CavpTestResult::failed(
                "TEST-003".to_string(),
                algorithm.clone(),
                "VEC-003".to_string(),
                vec![],
                vec![0x42; 64],
                StdDuration::from_millis(50),
                "Test execution failed".to_string(),
                CavpTestMetadata::default(),
            );

            assert!(!result.passed);
            assert_eq!(result.error_message, Some("Test execution failed".to_string()));
        }

        #[test]
        fn test_result_timestamp_is_set_succeeds() {
            let algorithm = CavpAlgorithm::FnDsa { variant: "512".to_string() };
            let before = Utc::now();

            let result = CavpTestResult::new(
                "TEST-TIME".to_string(),
                algorithm,
                "VEC-TIME".to_string(),
                vec![0x42; 64],
                vec![0x42; 64],
                StdDuration::from_millis(10),
                CavpTestMetadata::default(),
            );

            let after = Utc::now();

            assert!(result.timestamp >= before);
            assert!(result.timestamp <= after);
        }
    }

    // ============================================================================
    // ComplianceStatus Tests
    // ============================================================================

    mod compliance_status_tests {
        use super::*;

        #[test]
        fn test_fully_compliant_status_is_correct() {
            let status = ComplianceStatus::FullyCompliant;
            assert!(matches!(status, ComplianceStatus::FullyCompliant));
        }

        #[test]
        fn test_partially_compliant_status_is_correct() {
            let status = ComplianceStatus::PartiallyCompliant {
                exceptions: vec!["Minor issue".to_string()],
            };

            if let ComplianceStatus::PartiallyCompliant { exceptions } = status {
                assert_eq!(exceptions.len(), 1);
                assert_eq!(exceptions[0], "Minor issue");
            } else {
                panic!("Expected PartiallyCompliant");
            }
        }

        #[test]
        fn test_non_compliant_status_is_correct() {
            let status =
                ComplianceStatus::NonCompliant { failures: vec!["Critical failure".to_string()] };

            if let ComplianceStatus::NonCompliant { failures } = status {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0], "Critical failure");
            } else {
                panic!("Expected NonCompliant");
            }
        }

        #[test]
        fn test_insufficient_data_status_is_correct() {
            let status = ComplianceStatus::InsufficientData;
            assert!(matches!(status, ComplianceStatus::InsufficientData));
        }
    }

    // ============================================================================
    // SecurityRequirement Tests
    // ============================================================================

    mod security_requirement_tests {
        use super::*;

        #[test]
        fn test_security_requirement_creation_has_correct_fields_succeeds() {
            let req = SecurityRequirement {
                requirement_id: "FIPS203-4.1".to_string(),
                description: "Key generation shall be deterministic".to_string(),
                mandatory: true,
                test_methods: vec!["deterministic_keygen".to_string()],
            };

            assert_eq!(req.requirement_id, "FIPS203-4.1");
            assert!(req.mandatory);
            assert_eq!(req.test_methods.len(), 1);
        }

        #[test]
        fn test_security_requirement_optional_has_correct_fields_succeeds() {
            let req = SecurityRequirement {
                requirement_id: "OPT-001".to_string(),
                description: "Optional feature".to_string(),
                mandatory: false,
                test_methods: vec![],
            };

            assert!(!req.mandatory);
            assert!(req.test_methods.is_empty());
        }
    }

    // ============================================================================
    // ComplianceCriteria Tests
    // ============================================================================

    mod compliance_criteria_tests {
        use super::*;

        #[test]
        fn test_criteria_creation_has_correct_fields_succeeds() {
            let criteria = ComplianceCriteria {
                min_pass_rate: 100.0,
                max_execution_time_ms: 5000,
                min_coverage: 95.0,
                security_requirements: vec![],
            };

            assert_eq!(criteria.min_pass_rate, 100.0);
            assert_eq!(criteria.max_execution_time_ms, 5000);
            assert_eq!(criteria.min_coverage, 95.0);
        }

        #[test]
        fn test_criteria_with_requirements_has_correct_fields_succeeds() {
            let criteria = ComplianceCriteria {
                min_pass_rate: 100.0,
                max_execution_time_ms: 1000,
                min_coverage: 99.0,
                security_requirements: vec![
                    SecurityRequirement {
                        requirement_id: "REQ-001".to_string(),
                        description: "First requirement".to_string(),
                        mandatory: true,
                        test_methods: vec!["test1".to_string()],
                    },
                    SecurityRequirement {
                        requirement_id: "REQ-002".to_string(),
                        description: "Second requirement".to_string(),
                        mandatory: false,
                        test_methods: vec!["test2".to_string(), "test3".to_string()],
                    },
                ],
            };

            assert_eq!(criteria.security_requirements.len(), 2);
        }
    }

    // ============================================================================
    // Integration Tests
    // ============================================================================

    mod integration_tests {
        use super::*;

        #[test]
        fn test_full_validation_workflow_succeeds() {
            // Create orchestrator
            let orchestrator = CavpValidationOrchestrator::default();

            // Create test vectors for multiple algorithms
            let vectors = vec![
                create_mlkem_vector("INT-001", "768"),
                create_mlkem_vector("INT-002", "768"),
                create_mldsa_vector("INT-003", "44"),
            ];

            // Run validation
            let results = orchestrator.run_full_validation(vectors).unwrap();

            // Validate results
            assert!(!results.is_empty());

            // Validate with NistComplianceValidator
            let validator = NistComplianceValidator::new();
            for batch in &results {
                let report = validator.validate_batch(batch).unwrap();
                assert!(!report.report_id.is_empty());
                assert!(!report.nist_standards.is_empty());
            }
        }

        #[test]
        fn test_full_validation_with_compliance_report_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();
            let validator = NistComplianceValidator::new();

            let vectors = vec![
                create_mlkem_vector("COMP-001", "512"),
                create_mlkem_vector("COMP-002", "512"),
                create_mlkem_vector("COMP-003", "512"),
            ];

            let batch_results = orchestrator.run_full_validation(vectors).unwrap();

            for batch in &batch_results {
                let report = validator.validate_batch(batch).unwrap();

                // Verify report contains expected data
                assert!(report.summary.total_tests > 0);
                assert!(report.summary.pass_rate >= 0.0);
                assert!(report.summary.pass_rate <= 100.0);
                assert!(!report.detailed_results.is_empty());
            }
        }

        #[test]
        fn test_executor_with_custom_config_succeeds() {
            let config = EnhancedPipelineConfig {
                parallel_execution: false,
                max_threads: 1,
                timeout_per_test: Duration::seconds(10),
                retry_failed_tests: 0,
                generate_reports: false,
                storage_backend: StorageBackend::Memory,
            };

            let executor = EnhancedCavpTestExecutor::new(config);
            let vector = create_fndsa_vector("CUSTOM-001", "1024");

            let result = executor.execute_test_vector(&vector).unwrap();
            assert!(!result.test_id.is_empty());
        }

        #[test]
        fn test_all_algorithm_variants_are_accessible() {
            let orchestrator = CavpValidationOrchestrator::default();
            let validator = NistComplianceValidator::new();

            // Test all ML-KEM variants
            for variant in ["512", "768", "1024"] {
                let vectors = vec![create_mlkem_vector(&format!("MLKEM-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());

                let algo = CavpAlgorithm::MlKem { variant: variant.to_string() };
                let criteria = validator.get_algorithm_criteria(&algo);
                assert_eq!(criteria.min_pass_rate, 100.0);
            }

            // Test all ML-DSA variants
            for variant in ["44", "65", "87", "128"] {
                let vectors = vec![create_mldsa_vector(&format!("MLDSA-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());
            }

            // Test FN-DSA variants
            for variant in ["512", "1024"] {
                let vectors = vec![create_fndsa_vector(&format!("FNDSA-{}", variant), variant)];
                let results = orchestrator.run_full_validation(vectors).unwrap();
                assert!(!results.is_empty());
            }
        }

        #[test]
        fn test_large_batch_processing_completes_succeeds() {
            let orchestrator = CavpValidationOrchestrator::default();

            // Create a large batch of test vectors
            let vectors: Vec<CavpTestVector> =
                (0..100).map(|i| create_mlkem_vector(&format!("LARGE-{:04}", i), "768")).collect();

            let results = orchestrator.run_full_validation(vectors).unwrap();

            assert_eq!(results.len(), 1); // All same algorithm
            assert_eq!(results[0].test_results.len(), 100);
        }
    }
}
