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
fn test_cavp_algorithm_name_all_variants() {
    assert_eq!(CavpAlgorithm::MlKem { variant: "768".into() }.name(), "ML-KEM-768");
    assert_eq!(CavpAlgorithm::MlDsa { variant: "44".into() }.name(), "ML-DSA-44");
    assert_eq!(CavpAlgorithm::SlhDsa { variant: "shake-128s".into() }.name(), "SLH-DSA-shake-128s");
    assert_eq!(CavpAlgorithm::FnDsa { variant: "512".into() }.name(), "FN-DSA-512");
    assert_eq!(CavpAlgorithm::HybridKem.name(), "Hybrid-KEM");
}

#[test]
fn test_cavp_algorithm_fips_standard_all_variants() {
    assert_eq!(CavpAlgorithm::MlKem { variant: "768".into() }.fips_standard(), "FIPS 203");
    assert_eq!(CavpAlgorithm::MlDsa { variant: "65".into() }.fips_standard(), "FIPS 204");
    assert_eq!(CavpAlgorithm::SlhDsa { variant: "shake-256s".into() }.fips_standard(), "FIPS 205");
    assert_eq!(CavpAlgorithm::FnDsa { variant: "1024".into() }.fips_standard(), "FIPS 206");
    assert_eq!(CavpAlgorithm::HybridKem.fips_standard(), "FIPS 203 + FIPS 197");
}

#[test]
fn test_cavp_algorithm_clone_eq_hash() {
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
fn test_cavp_algorithm_debug() {
    let alg = CavpAlgorithm::SlhDsa { variant: "shake-192s".into() };
    let debug = format!("{:?}", alg);
    assert!(debug.contains("SlhDsa"));
    assert!(debug.contains("shake-192s"));
}

// ============================================================
// Default impls
// ============================================================

#[test]
fn test_pipeline_config_default() {
    let config = PipelineConfig::default();
    assert_eq!(config.max_concurrent_tests, 4);
    assert_eq!(config.test_timeout, Duration::from_secs(30));
    assert_eq!(config.retry_count, 3);
    assert!(config.run_statistical_tests);
    assert!(config.generate_reports);
}

#[test]
fn test_pipeline_config_debug_clone() {
    let config = PipelineConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.retry_count, config.retry_count);
    let debug = format!("{:?}", config);
    assert!(debug.contains("PipelineConfig"));
}

#[test]
fn test_test_environment_default() {
    let env = TestEnvironment::default();
    assert!(!env.os.is_empty());
    assert!(!env.arch.is_empty());
    assert_eq!(env.compiler, "rustc");
    assert_eq!(env.framework_version, "1.0.0");
}

#[test]
fn test_test_configuration_default() {
    let tc = TestConfiguration::default();
    assert_eq!(tc.iterations, 1);
    assert_eq!(tc.timeout, Duration::from_secs(30));
    assert!(!tc.statistical_tests);
    assert!(tc.parameters.is_empty());
}

#[test]
fn test_cavp_test_metadata_default() {
    let meta = CavpTestMetadata::default();
    assert!(!meta.environment.os.is_empty());
    assert_eq!(meta.security_level, 128);
    assert_eq!(meta.vector_version, "1.0");
}

// ============================================================
// CavpTestResult constructors
// ============================================================

#[test]
fn test_cavp_test_result_new_passing() {
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
fn test_cavp_test_result_new_failing() {
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
fn test_cavp_test_result_failed_factory() {
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
fn test_cavp_test_result_serialization() {
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
fn test_cavp_batch_result_new() {
    let batch =
        CavpBatchResult::new("batch-1".to_string(), CavpAlgorithm::MlKem { variant: "768".into() });
    assert_eq!(batch.batch_id, "batch-1");
    assert_eq!(batch.status, CavpValidationStatus::Incomplete);
    assert_eq!(batch.pass_rate, 0.0);
    assert!(batch.test_results.is_empty());
}

#[test]
fn test_cavp_batch_result_add_passing_tests() {
    let mut batch =
        CavpBatchResult::new("batch-2".to_string(), CavpAlgorithm::MlDsa { variant: "44".into() });

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
fn test_cavp_batch_result_mixed_results() {
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
fn test_cavp_batch_result_update_status_empty() {
    let mut batch = CavpBatchResult::new("batch-empty".to_string(), CavpAlgorithm::HybridKem);
    batch.update_status();
    assert_eq!(batch.status, CavpValidationStatus::Incomplete);
}

// ============================================================
// CavpValidationStatus
// ============================================================

#[test]
fn test_cavp_validation_status_variants() {
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
fn test_cavp_test_type_variants() {
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
fn test_memory_storage_store_and_retrieve_result() {
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
fn test_memory_storage_retrieve_nonexistent_result() {
    let storage = MemoryCavpStorage::new();
    let retrieved = storage.retrieve_result("does-not-exist").unwrap();
    assert!(retrieved.is_none());
}

#[test]
fn test_memory_storage_store_and_retrieve_batch() {
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
fn test_memory_storage_retrieve_nonexistent_batch() {
    let storage = MemoryCavpStorage::new();
    let retrieved = storage.retrieve_batch("no-batch").unwrap();
    assert!(retrieved.is_none());
}

#[test]
fn test_memory_storage_list_results_by_algorithm() {
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
fn test_memory_storage_list_results_empty_algorithm() {
    let storage = MemoryCavpStorage::new();
    let results = storage.list_results_by_algorithm(&CavpAlgorithm::HybridKem).unwrap();
    assert!(results.is_empty());
}

#[test]
fn test_memory_storage_list_batches_by_algorithm() {
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
fn test_memory_storage_list_batches_empty() {
    let storage = MemoryCavpStorage::new();
    let batches =
        storage.list_batches_by_algorithm(&CavpAlgorithm::MlKem { variant: "512".into() }).unwrap();
    assert!(batches.is_empty());
}

// ============================================================
// CavpVectorInputs / CavpVectorOutputs
// ============================================================

#[test]
fn test_cavp_vector_inputs_serialization() {
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
fn test_cavp_vector_outputs_serialization() {
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
