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

use arc_validation::cavp::compliance::CavpComplianceGenerator;
use arc_validation::cavp::pipeline::{CavpTestExecutor, CavpValidationPipeline, PipelineConfig};
use arc_validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
use arc_validation::cavp::types::*;
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
    fn test_pipeline_config_default_values() {
        let config = PipelineConfig::default();

        assert_eq!(config.max_concurrent_tests, 4);
        assert_eq!(config.test_timeout, Duration::from_secs(30));
        assert_eq!(config.retry_count, 3);
        assert!(config.run_statistical_tests);
        assert!(config.generate_reports);
    }

    #[test]
    fn test_pipeline_config_custom_values() {
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
    fn test_pipeline_config_clone() {
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
    fn test_pipeline_config_debug() {
        let config = PipelineConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("PipelineConfig"));
        assert!(debug_str.contains("max_concurrent_tests"));
        assert!(debug_str.contains("test_timeout"));
    }

    #[test]
    fn test_pipeline_config_edge_values() {
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
    fn test_pipeline_config_large_values() {
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
    async fn test_executor_creation_with_default_config() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let _executor = CavpTestExecutor::new(config, storage);
        // Executor should be created successfully
    }

    #[tokio::test]
    async fn test_executor_creation_with_custom_config() {
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
    async fn test_executor_with_shared_storage() {
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
    async fn test_mlkem_768_keygen() {
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
    async fn test_mlkem_encapsulation_missing_ek() {
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
    async fn test_mlkem_encapsulation_invalid_ek_length() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Wrong length for ek (should be 1184 bytes)
        let vector =
            create_mlkem_768_encapsulation_vector_with_ek("MLKEM-ENCAP-BAD-LEN", vec![0xAA; 100]);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(test_result.error_message.is_some() || !test_result.passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_missing_dk() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // ML-KEM-768: ct is 1088 bytes
        let vector =
            create_mlkem_768_decapsulation_vector("MLKEM-DECAP-NO-DK", vec![], vec![0xCC; 1088]);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(test_result.error_message.is_some() || !test_result.passed);
    }

    #[tokio::test]
    async fn test_mlkem_decapsulation_invalid_ciphertext_length() {
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
    async fn test_mlkem_unsupported_variant() {
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
    async fn test_mlkem_signature_operation_invalid() {
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
    async fn test_mlkem_verification_operation_invalid() {
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
    async fn test_mldsa_44_keygen() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vector = create_mldsa_keygen_vector("MLDSA44-KEYGEN", "44");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
        // ML-DSA-44: pk is 1312 bytes, sk is 2560 bytes
        assert_eq!(test_result.actual_result.len(), 1312 + 2560);
    }

    #[tokio::test]
    async fn test_mldsa_65_keygen() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vector = create_mldsa_keygen_vector("MLDSA65-KEYGEN", "65");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
        // ML-DSA-65: pk is 1952 bytes, sk is 4032 bytes
        assert_eq!(test_result.actual_result.len(), 1952 + 4032);
    }

    #[tokio::test]
    async fn test_mldsa_87_keygen() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vector = create_mldsa_keygen_vector("MLDSA87-KEYGEN", "87");
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
        // ML-DSA-87: pk is 2592 bytes, sk is 4896 bytes
        assert_eq!(test_result.actual_result.len(), 2592 + 4896);
    }

    #[tokio::test]
    async fn test_mldsa_unsupported_variant() {
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
    async fn test_mldsa_signature_missing_sk() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vector = create_mldsa_signature_vector(
            "MLDSA44-SIG-NO-SK",
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
    async fn test_mldsa_signature_missing_message() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let mut vector =
            create_mldsa_signature_vector("MLDSA44-SIG-NO-MSG", "44", vec![0x11; 2560], vec![]);
        vector.inputs.message = None;
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(test_result.error_message.is_some() || !test_result.passed);
    }

    #[tokio::test]
    async fn test_mldsa_verification_missing_pk() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let vector = create_mldsa_verification_vector(
            "MLDSA44-VERIFY-NO-PK",
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
    async fn test_mldsa_verification_missing_signature() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let mut vector = create_mldsa_verification_vector(
            "MLDSA44-VERIFY-NO-SIG",
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
    async fn test_mldsa_encapsulation_operation_invalid() {
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
    async fn test_mldsa_decapsulation_operation_invalid() {
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
    async fn test_slhdsa_shake_128s_keygen() {
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
    async fn test_slhdsa_shake_192s_keygen() {
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
    async fn test_slhdsa_shake_256s_keygen() {
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
    async fn test_slhdsa_unsupported_variant() {
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
    async fn test_slhdsa_signature_missing_sk() {
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
    async fn test_slhdsa_signature_invalid_sk_length() {
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
    async fn test_slhdsa_verification_missing_pk() {
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
    async fn test_slhdsa_encapsulation_operation_invalid() {
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
    async fn test_fndsa_512_keygen() {
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
    async fn test_fndsa_1024_keygen() {
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
    async fn test_fndsa_unsupported_variant() {
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
    async fn test_fndsa_signature_missing_sk() {
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
    async fn test_fndsa_verification_missing_pk() {
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
    async fn test_fndsa_encapsulation_operation_invalid() {
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
    async fn test_fndsa_decapsulation_operation_invalid() {
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
    async fn test_hybrid_kem_keygen() {
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
    async fn test_hybrid_kem_keygen_missing_seed() {
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
    async fn test_hybrid_kem_keygen_short_seed() {
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
    async fn test_hybrid_kem_encapsulation_missing_ek() {
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
    async fn test_hybrid_kem_encapsulation_missing_m() {
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
    async fn test_hybrid_kem_decapsulation_missing_dk() {
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
    async fn test_hybrid_kem_decapsulation_missing_c() {
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
    async fn test_hybrid_kem_signature_operation_invalid() {
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
    async fn test_hybrid_kem_verification_operation_invalid() {
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
    async fn test_batch_empty_vectors() {
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
    async fn test_batch_single_vector() {
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
    async fn test_batch_multiple_vectors_same_algorithm() {
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
    async fn test_batch_mixed_algorithms() {
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
    async fn test_batch_with_storage_verification() {
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
    async fn test_batch_pass_rate_calculation() {
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
    async fn test_batch_large_count() {
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
    async fn test_pipeline_creation() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let _pipeline = CavpValidationPipeline::new(config, storage);
    }

    #[tokio::test]
    async fn test_pipeline_run_algorithm_validation() {
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
    async fn test_pipeline_run_full_validation_single_algorithm() {
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
    async fn test_pipeline_run_full_validation_multiple_algorithms() {
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
    async fn test_pipeline_run_full_validation_empty() {
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
    async fn test_pipeline_create_sample_vectors() {
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
    async fn test_pipeline_create_sample_vectors_zero_count() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let pipeline = CavpValidationPipeline::new(config, storage);

        let algorithm = CavpAlgorithm::MlDsa { variant: "44".to_string() };
        let vectors = pipeline.create_sample_vectors(algorithm, 0);

        assert_eq!(vectors.len(), 0);
    }

    #[tokio::test]
    async fn test_pipeline_with_report_generation() {
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
    fn test_compliance_generator_creation() {
        let generator = CavpComplianceGenerator::new();
        // Generator should be created with default criteria
        let _ = generator;
    }

    #[test]
    fn test_compliance_generator_default() {
        let generator = CavpComplianceGenerator::default();
        let _ = generator;
    }

    #[tokio::test]
    async fn test_compliance_report_generation() {
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
    async fn test_compliance_report_empty_batches() {
        let generator = CavpComplianceGenerator::new();
        let result = generator.generate_report(&[]);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_compliance_json_export() {
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
    async fn test_compliance_xml_export() {
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
    async fn test_compliance_multiple_batches() {
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
    fn test_cavp_test_result_new_passing() {
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
    fn test_cavp_test_result_new_failing() {
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
    fn test_cavp_test_result_failed() {
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
    fn test_cavp_batch_result_new() {
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
    fn test_cavp_batch_result_add_test_result() {
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
    fn test_cavp_validation_status_variants() {
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
    fn test_algorithm_name() {
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
    fn test_algorithm_fips_standard() {
        assert_eq!(CavpAlgorithm::MlKem { variant: "768".to_string() }.fips_standard(), "FIPS 203");
        assert_eq!(CavpAlgorithm::MlDsa { variant: "44".to_string() }.fips_standard(), "FIPS 204");
        assert_eq!(
            CavpAlgorithm::SlhDsa { variant: "shake-128s".to_string() }.fips_standard(),
            "FIPS 205"
        );
        assert_eq!(CavpAlgorithm::FnDsa { variant: "512".to_string() }.fips_standard(), "FIPS 206");
        assert_eq!(CavpAlgorithm::HybridKem.fips_standard(), "FIPS 203 + FIPS 197");
    }

    #[test]
    fn test_algorithm_equality() {
        let a1 = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let a2 = CavpAlgorithm::MlKem { variant: "768".to_string() };
        let a3 = CavpAlgorithm::MlKem { variant: "512".to_string() };

        assert_eq!(a1, a2);
        assert_ne!(a1, a3);
    }

    #[test]
    fn test_algorithm_hash() {
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
    fn test_cavp_test_type_variants() {
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
    fn test_cavp_test_type_equality() {
        assert_eq!(CavpTestType::KeyGen, CavpTestType::KeyGen);
        assert_ne!(CavpTestType::KeyGen, CavpTestType::Signature);
    }

    #[test]
    fn test_cavp_test_type_hash() {
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
    fn test_cavp_test_metadata_default() {
        let metadata = CavpTestMetadata::default();

        assert!(!metadata.environment.os.is_empty());
        assert!(!metadata.environment.arch.is_empty());
        assert!(!metadata.environment.rust_version.is_empty());
        assert_eq!(metadata.security_level, 128);
    }

    #[test]
    fn test_test_environment_default() {
        let env = TestEnvironment::default();

        assert!(!env.os.is_empty());
        assert!(!env.arch.is_empty());
        assert!(!env.rust_version.is_empty());
        assert!(!env.compiler.is_empty());
    }

    #[test]
    fn test_test_configuration_default() {
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
    async fn test_very_long_test_id() {
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
    async fn test_unicode_in_notes() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let mut vector = create_mlkem_768_keygen_vector("UNICODE-TEST");
        vector.metadata.notes = Some("Unicode test: \u{1F600}\u{1F389}\u{2764}".to_string());

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_expected_output() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let mut vector = create_mlkem_768_keygen_vector("EMPTY-EXPECTED");
        vector.expected_outputs.public_key = Some(vec![]);

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_large_seed() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let mut vector = create_mlkem_768_keygen_vector("LARGE-SEED");
        vector.inputs.seed = Some(vec![0x42; 1024 * 1024]); // 1MB seed

        let result = executor.execute_single_test_vector(&vector).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_special_characters_in_source() {
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
    async fn test_mlkem_768_full_encapsulation_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // First generate a valid key pair
        let (ek, _dk) = ml_kem_768::KG::try_keygen().unwrap();
        let ek_bytes = ek.into_bytes();

        // Create encapsulation vector with valid ek
        let vector =
            create_mlkem_768_encapsulation_vector_with_ek("MLKEM-ENCAP-VALID", ek_bytes.to_vec());
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // ML-KEM-768: ct is 1088 bytes, ssk is 32 bytes
        assert_eq!(test_result.actual_result.len(), 1088 + 32);
    }

    #[tokio::test]
    async fn test_mlkem_768_full_decapsulation_cycle() {
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
    async fn test_mlkem_768_complete_kem_cycle() {
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
    async fn test_mldsa_44_full_signature_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Generate a valid key pair
        let (_pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let sk_bytes = sk.into_bytes();
        let message = b"Test message for ML-DSA-44 signing".to_vec();

        let vector =
            create_mldsa_signature_vector("MLDSA44-SIG-VALID", "44", sk_bytes.to_vec(), message);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // ML-DSA-44 signature is 2420 bytes
        assert_eq!(test_result.actual_result.len(), 2420);
    }

    #[tokio::test]
    async fn test_mldsa_44_full_verification_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        // Generate key pair and sign
        let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
        let message = b"Test message for ML-DSA-44 verification".to_vec();
        let signature = sk.try_sign(&message, &[]).unwrap();

        let pk_bytes = pk.into_bytes();

        let vector = create_mldsa_verification_vector(
            "MLDSA44-VERIFY-VALID",
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
    async fn test_mldsa_65_full_signature_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let (_pk, sk) = ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = sk.into_bytes();
        let message = b"Test message for ML-DSA-65 signing".to_vec();

        let vector =
            create_mldsa_signature_vector("MLDSA65-SIG-VALID", "65", sk_bytes.to_vec(), message);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // ML-DSA-65 signature is 3309 bytes
        assert_eq!(test_result.actual_result.len(), 3309);
    }

    #[tokio::test]
    async fn test_mldsa_65_full_verification_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let (pk, sk) = ml_dsa_65::try_keygen().unwrap();
        let message = b"Test message for ML-DSA-65 verification".to_vec();
        let signature = sk.try_sign(&message, &[]).unwrap();

        let pk_bytes = pk.into_bytes();

        let vector = create_mldsa_verification_vector(
            "MLDSA65-VERIFY-VALID",
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
    async fn test_mldsa_87_full_signature_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let (_pk, sk) = ml_dsa_87::try_keygen().unwrap();
        let sk_bytes = sk.into_bytes();
        let message = b"Test message for ML-DSA-87 signing".to_vec();

        let vector =
            create_mldsa_signature_vector("MLDSA87-SIG-VALID", "87", sk_bytes.to_vec(), message);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // ML-DSA-87 signature is 4627 bytes
        assert_eq!(test_result.actual_result.len(), 4627);
    }

    #[tokio::test]
    async fn test_mldsa_87_full_verification_cycle() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let (pk, sk) = ml_dsa_87::try_keygen().unwrap();
        let message = b"Test message for ML-DSA-87 verification".to_vec();
        let signature = sk.try_sign(&message, &[]).unwrap();

        let pk_bytes = pk.into_bytes();

        let vector = create_mldsa_verification_vector(
            "MLDSA87-VERIFY-VALID",
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
    async fn test_mldsa_44_invalid_signature_verification() {
        let config = PipelineConfig::default();
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
        let executor = CavpTestExecutor::new(config, storage);

        let (pk, _sk) = ml_dsa_44::try_keygen().unwrap();
        let message = b"Test message".to_vec();
        // Invalid signature (all zeros)
        let invalid_signature = vec![0u8; 2420];

        let pk_bytes = pk.into_bytes();

        let vector = create_mldsa_verification_vector(
            "MLDSA44-VERIFY-INVALID-SIG",
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
    async fn test_slhdsa_shake_128s_full_signature_cycle() {
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
    async fn test_slhdsa_shake_128s_full_verification_cycle() {
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
    async fn test_slhdsa_shake_192s_full_signature_cycle() {
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
    async fn test_slhdsa_shake_192s_full_verification_cycle() {
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
    async fn test_slhdsa_shake_256s_full_signature_cycle() {
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
    async fn test_slhdsa_shake_256s_full_verification_cycle() {
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
    async fn test_slhdsa_invalid_signature_verification() {
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
    async fn test_slhdsa_missing_message_for_signature() {
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
    async fn test_slhdsa_missing_message_for_verification() {
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
    async fn test_slhdsa_missing_signature_for_verification() {
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
    async fn test_slhdsa_decapsulation_operation_invalid() {
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
    async fn test_fndsa_512_full_signature_cycle() {
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

        let vector =
            create_fndsa_signature_vector("FNDSA512-SIG-VALID", "512", sign_key.clone(), message);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // FN-DSA-512 signature should be non-empty
        assert!(!test_result.actual_result.is_empty());
    }

    #[tokio::test]
    async fn test_fndsa_512_full_verification_cycle() {
        use fn_dsa::{
            DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW, KeyPairGenerator, KeyPairGeneratorStandard,
            SigningKey, SigningKeyStandard, sign_key_size, signature_size, vrfy_key_size,
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
    async fn test_fndsa_1024_full_signature_cycle() {
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

        let vector =
            create_fndsa_signature_vector("FNDSA1024-SIG-VALID", "1024", sign_key.clone(), message);
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        assert!(!test_result.actual_result.is_empty());
    }

    #[tokio::test]
    async fn test_fndsa_1024_full_verification_cycle() {
        use fn_dsa::{
            DOMAIN_NONE, FN_DSA_LOGN_1024, HASH_ID_RAW, KeyPairGenerator, KeyPairGeneratorStandard,
            SigningKey, SigningKeyStandard, sign_key_size, signature_size, vrfy_key_size,
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
    async fn test_fndsa_invalid_signature_verification() {
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
    async fn test_fndsa_missing_message_for_signature() {
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
    async fn test_fndsa_missing_message_for_verification() {
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
    async fn test_fndsa_missing_signature_for_verification() {
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
    async fn test_hybrid_kem_full_encapsulation_cycle() {
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

        let vector = create_hybrid_kem_encapsulation_vector("HYBRID-ENCAP-VALID", ek, m.to_vec());
        let result = executor.execute_single_test_vector(&vector).await;

        assert!(result.is_ok());
        let test_result = result.unwrap();
        // Should have ciphertext + ephemeral pk + shared secret
        assert!(!test_result.actual_result.is_empty());
    }

    #[tokio::test]
    async fn test_hybrid_kem_full_decapsulation_cycle() {
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
    async fn test_hybrid_kem_encapsulation_invalid_m_length() {
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
    async fn test_hybrid_kem_decapsulation_invalid_dk_length() {
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
    async fn test_hybrid_kem_decapsulation_invalid_c_length() {
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
    async fn test_pipeline_full_validation_with_reports() {
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
    async fn test_pipeline_algorithm_validation_with_reports() {
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
    async fn test_compliance_report_for_all_algorithms() {
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
    async fn test_storage_list_batches_by_algorithm() {
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
    async fn test_storage_list_batches_empty() {
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

        let algorithm = CavpAlgorithm::MlDsa { variant: "87".to_string() };
        let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();

        assert!(batches.is_empty());
    }

    #[tokio::test]
    async fn test_storage_list_results_empty() {
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

        let algorithm = CavpAlgorithm::SlhDsa { variant: "shake-256s".to_string() };
        let results = storage.list_results_by_algorithm(&algorithm).unwrap();

        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_storage_retrieve_nonexistent_result() {
        let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());

        let result = storage.retrieve_result("NONEXISTENT-TEST-ID");

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_storage_retrieve_nonexistent_batch() {
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
    use arc_validation::cavp::compliance::{ComplianceStatus, TestCategory, TestResult};

    #[test]
    fn test_compliance_status_non_compliant() {
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
    fn test_compliance_status_partially_compliant() {
        let status =
            ComplianceStatus::PartiallyCompliant { exceptions: vec!["Exception 1".to_string()] };

        if let ComplianceStatus::PartiallyCompliant { exceptions } = status {
            assert_eq!(exceptions.len(), 1);
        } else {
            panic!("Expected PartiallyCompliant status");
        }
    }

    #[test]
    fn test_compliance_status_insufficient_data() {
        let status = ComplianceStatus::InsufficientData;
        assert!(matches!(status, ComplianceStatus::InsufficientData));
    }

    #[test]
    fn test_test_result_skipped() {
        let result = TestResult::Skipped("Not applicable".to_string());
        if let TestResult::Skipped(reason) = result {
            assert_eq!(reason, "Not applicable");
        } else {
            panic!("Expected Skipped result");
        }
    }

    #[test]
    fn test_test_result_error() {
        let result = TestResult::Error("System error".to_string());
        if let TestResult::Error(reason) = result {
            assert_eq!(reason, "System error");
        } else {
            panic!("Expected Error result");
        }
    }

    #[test]
    fn test_test_category_variants() {
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
    use arc_validation::cavp::compliance::{ComplianceCriteria, SecurityRequirement};

    #[test]
    fn test_security_requirement_creation() {
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
    fn test_compliance_criteria_creation() {
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
    use arc_validation::cavp::compliance::{
        MemoryUsageMetrics, PerformanceMetrics, ThroughputMetrics,
    };
    use std::collections::HashMap;

    #[test]
    fn test_memory_usage_metrics() {
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
    fn test_throughput_metrics() {
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
    fn test_performance_metrics_creation() {
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
    use arc_validation::cavp::compliance::TestSummary;

    #[test]
    fn test_test_summary_creation() {
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
    fn test_test_summary_zero_tests() {
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
    use arc_validation::cavp::compliance::{
        ComplianceTestResult, DetailedTestResult, TestCategory, TestResult,
    };
    use std::collections::HashMap;

    #[test]
    fn test_detailed_test_result_creation() {
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
    fn test_compliance_test_result_creation() {
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
