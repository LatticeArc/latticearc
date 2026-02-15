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

use arc_validation::cavp::pipeline::{CavpTestExecutor, CavpValidationPipeline, PipelineConfig};
use arc_validation::cavp::storage::{CavpStorage, MemoryCavpStorage};
use arc_validation::cavp::types::*;
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
async fn test_mlkem_with_signature_type() {
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
async fn test_mlkem_with_verification_type() {
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
async fn test_slhdsa_128s_with_encapsulation_type() {
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
async fn test_slhdsa_128s_with_decapsulation_type() {
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
async fn test_slhdsa_192s_with_encapsulation_type() {
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
async fn test_slhdsa_256s_with_encapsulation_type() {
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
async fn test_slhdsa_unsupported_variant() {
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
async fn test_mldsa_44_with_encapsulation_type() {
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
async fn test_mldsa_65_with_decapsulation_type() {
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
async fn test_mldsa_87_with_encapsulation_type() {
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
async fn test_mldsa_unsupported_variant() {
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
async fn test_fndsa_512_with_encapsulation_type() {
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
async fn test_fndsa_1024_with_decapsulation_type() {
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
async fn test_fndsa_unsupported_variant() {
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
async fn test_hybrid_kem_with_signature_type() {
    let executor = make_executor();
    let vector = make_vector("hybrid-sig-err", CavpAlgorithm::HybridKem, CavpTestType::Signature);
    let result = executor.execute_single_test_vector(&vector).await.unwrap();
    assert!(result.error_message.is_some() || !result.passed);
}

#[tokio::test]
async fn test_hybrid_kem_with_verification_type() {
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
async fn test_hybrid_kem_keygen() {
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
fn test_create_sample_vectors_mlkem() {
    let config = PipelineConfig::default();
    let storage: Arc<dyn CavpStorage> = Arc::new(MemoryCavpStorage::new());
    let pipeline = CavpValidationPipeline::new(config, storage);

    let vectors = pipeline.create_sample_vectors(CavpAlgorithm::MlKem { variant: "768".into() }, 5);
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
fn test_create_sample_vectors_all_algorithms() {
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
fn test_create_sample_vectors_zero() {
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
async fn test_run_full_validation_mlkem_keygen() {
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
async fn test_run_full_validation_multiple_algorithms() {
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
        make_vector("multi-2", CavpAlgorithm::MlDsa { variant: "44".into() }, CavpTestType::KeyGen),
    ];

    let results = pipeline.run_full_validation(vectors).await.unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_run_full_validation_empty() {
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
async fn test_run_algorithm_validation() {
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
async fn test_run_algorithm_validation_no_reports() {
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
async fn test_batch_execution_stores_results() {
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
async fn test_full_validation_without_reports() {
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
