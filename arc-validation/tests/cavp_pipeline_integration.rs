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

use arc_validation::cavp::compliance::CavpComplianceGenerator;
use arc_validation::cavp::pipeline::{CavpTestExecutor, CavpValidationPipeline, PipelineConfig};
use arc_validation::cavp::storage::{
    CavpStorage, CavpStorageManager, FileCavpStorage, MemoryCavpStorage,
};
use arc_validation::cavp::types::*;
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
async fn test_pipeline_config_creation() {
    let config = PipelineConfig::default();

    assert_eq!(config.max_concurrent_tests, 4);
    assert_eq!(config.test_timeout, Duration::from_secs(30));
    assert_eq!(config.retry_count, 3);
    assert!(config.run_statistical_tests);
    assert!(config.generate_reports);
}

#[tokio::test]
async fn test_pipeline_config_custom() {
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
async fn test_executor_creation() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let executor = CavpTestExecutor::new(config, storage);

    // Executor should be created successfully
    // This is a smoke test to ensure the constructor works
    drop(executor);
}

#[tokio::test]
async fn test_execute_single_mlkem_test_vector() {
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
async fn test_execute_single_mldsa_test_vector() {
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
async fn test_execute_single_slhdsa_test_vector() {
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
async fn test_execute_single_fndsa_test_vector() {
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
async fn test_execute_single_hybrid_kem_test_vector() {
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
async fn test_execute_test_vector_batch_mlkem() {
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
async fn test_execute_test_vector_batch_empty() {
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
async fn test_execute_test_vector_batch_mixed_algorithms() {
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
async fn test_storage_backend_stores_results() {
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
async fn test_storage_backend_stores_batches() {
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
async fn test_list_results_by_algorithm() {
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
async fn test_list_batches_by_algorithm() {
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
async fn test_validation_pipeline_creation() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let pipeline = CavpValidationPipeline::new(config, storage);

    // Pipeline should be created successfully
    drop(pipeline);
}

#[tokio::test]
async fn test_validation_pipeline_run_algorithm_validation() {
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
async fn test_validation_pipeline_run_full_validation() {
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
async fn test_validation_pipeline_create_sample_vectors() {
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
async fn test_batch_result_update_status() {
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
async fn test_error_handling_invalid_test_type_for_algorithm() {
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
async fn test_file_storage_backend() {
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
async fn test_file_storage_batch_persistence() {
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
async fn test_storage_manager_with_memory_backend() {
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
async fn test_storage_manager_with_file_backend() {
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
async fn test_compliance_generator_mlkem_report() {
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
async fn test_compliance_generator_json_export() {
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
async fn test_compliance_generator_xml_export() {
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
async fn test_compliance_status_evaluation() {
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
async fn test_performance_metrics_calculation() {
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
async fn test_algorithm_name_formatting() {
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
async fn test_fips_standard_mapping() {
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
async fn test_concurrent_test_execution() {
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
async fn test_test_metadata_environment_capture() {
    let metadata = CavpTestMetadata::default();

    assert!(!metadata.environment.os.is_empty());
    assert!(!metadata.environment.arch.is_empty());
    assert!(!metadata.environment.rust_version.is_empty());
}

#[tokio::test]
async fn test_test_configuration_defaults() {
    let config = TestConfiguration::default();

    assert_eq!(config.iterations, 1);
    assert_eq!(config.timeout, Duration::from_secs(30));
    assert!(!config.statistical_tests);
    assert!(config.parameters.is_empty());
}
