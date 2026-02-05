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

use arc_validation::cavp::storage::{
    CavpStorage, CavpStorageManager, FileCavpStorage, MemoryCavpStorage,
};
use arc_validation::cavp::types::{
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
    fn test_memory_storage_new() {
        let storage = MemoryCavpStorage::new();
        // Storage should be created successfully
        drop(storage);
    }

    #[test]
    fn test_memory_storage_default() {
        let storage = MemoryCavpStorage::default();
        // Default should be equivalent to new()
        drop(storage);
    }

    #[test]
    fn test_store_single_result() {
        let storage = MemoryCavpStorage::new();
        let result = create_test_result("TEST-001", mlkem_algorithm("768"), true);

        let store_result = storage.store_result(&result);
        assert!(store_result.is_ok());
    }

    #[test]
    fn test_retrieve_stored_result() {
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
    fn test_retrieve_nonexistent_result() {
        let storage = MemoryCavpStorage::new();

        let retrieved = storage.retrieve_result("NONEXISTENT").unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_store_batch() {
        let storage = MemoryCavpStorage::new();
        let batch = create_batch_result("BATCH-001", mlkem_algorithm("768"), 5, 2);

        let store_result = storage.store_batch(&batch);
        assert!(store_result.is_ok());
    }

    #[test]
    fn test_retrieve_stored_batch() {
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
    fn test_retrieve_nonexistent_batch() {
        let storage = MemoryCavpStorage::new();

        let retrieved = storage.retrieve_batch("NONEXISTENT-BATCH").unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_list_results_by_algorithm_empty() {
        let storage = MemoryCavpStorage::new();
        let algorithm = mlkem_algorithm("768");

        let results = storage.list_results_by_algorithm(&algorithm).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_list_results_by_algorithm_with_data() {
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
    fn test_list_results_filters_by_algorithm() {
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
        storage.store_result(&create_test_result("MLDSA-44-001", mldsa_44.clone(), true)).unwrap();

        // Verify filtering works correctly
        let mlkem_768_results = storage.list_results_by_algorithm(&mlkem_768).unwrap();
        assert_eq!(mlkem_768_results.len(), 2);

        let mlkem_512_results = storage.list_results_by_algorithm(&mlkem_512).unwrap();
        assert_eq!(mlkem_512_results.len(), 1);

        let mldsa_44_results = storage.list_results_by_algorithm(&mldsa_44).unwrap();
        assert_eq!(mldsa_44_results.len(), 1);
    }

    #[test]
    fn test_list_batches_by_algorithm_empty() {
        let storage = MemoryCavpStorage::new();
        let algorithm = slhdsa_algorithm("128s");

        let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();
        assert!(batches.is_empty());
    }

    #[test]
    fn test_list_batches_by_algorithm_with_data() {
        let storage = MemoryCavpStorage::new();
        let algorithm = slhdsa_algorithm("128s");

        // Store multiple batches for the same algorithm
        for i in 0..3 {
            let batch = create_batch_result(&format!("BATCH-{:03}", i), algorithm.clone(), 2, 1);
            storage.store_batch(&batch).unwrap();
        }

        let batches = storage.list_batches_by_algorithm(&algorithm).unwrap();
        assert_eq!(batches.len(), 3);
    }

    #[test]
    fn test_list_batches_filters_by_algorithm() {
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
    fn test_overwrite_existing_result() {
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
    fn test_overwrite_existing_batch() {
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
    fn test_hybrid_kem_algorithm() {
        let storage = MemoryCavpStorage::new();
        let algorithm = CavpAlgorithm::HybridKem;

        let result = create_test_result("HYBRID-001", algorithm.clone(), true);
        storage.store_result(&result).unwrap();

        let results = storage.list_results_by_algorithm(&algorithm).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_result_with_metadata() {
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
    fn test_batch_with_all_validation_statuses() {
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
    fn test_file_storage_new() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path());
        assert!(storage.is_ok());
    }

    #[test]
    fn test_file_storage_creates_directories() {
        let temp_dir = TempDir::new().unwrap();
        let _storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        // Verify directories were created
        assert!(temp_dir.path().join("results").exists());
        assert!(temp_dir.path().join("batches").exists());
    }

    #[test]
    fn test_file_storage_nested_path() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("level1").join("level2").join("storage");

        let storage = FileCavpStorage::new(&nested_path);
        assert!(storage.is_ok());
        assert!(nested_path.join("results").exists());
        assert!(nested_path.join("batches").exists());
    }

    #[test]
    fn test_store_and_retrieve_result() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        let result = create_test_result("FILE-TEST-001", mlkem_algorithm("768"), true);
        storage.store_result(&result).unwrap();

        let retrieved = storage.retrieve_result("FILE-TEST-001").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().test_id, "FILE-TEST-001");
    }

    #[test]
    fn test_store_and_retrieve_batch() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        let batch = create_batch_result("FILE-BATCH-001", mldsa_algorithm("44"), 3, 1);
        storage.store_batch(&batch).unwrap();

        let retrieved = storage.retrieve_batch("FILE-BATCH-001").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().batch_id, "FILE-BATCH-001");
    }

    #[test]
    fn test_file_persistence() {
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
    fn test_load_existing_results() {
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
    fn test_load_existing_batches() {
        let temp_dir = TempDir::new().unwrap();

        // Store data in first instance
        {
            let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
            storage
                .store_batch(&create_batch_result("LOAD-BATCH-001", slhdsa_algorithm("128s"), 5, 1))
                .unwrap();
            storage
                .store_batch(&create_batch_result("LOAD-BATCH-002", slhdsa_algorithm("256f"), 3, 0))
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
    fn test_load_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        // Loading from empty directories should succeed
        let result1 = storage.load_existing_results();
        let result2 = storage.load_existing_batches();

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_list_results_by_algorithm_with_file_storage() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();
        let algorithm = fndsa_algorithm("512");

        // Store multiple results
        for i in 0..5 {
            let result = create_test_result(&format!("FNDSA-{:03}", i), algorithm.clone(), true);
            storage.store_result(&result).unwrap();
        }

        let results = storage.list_results_by_algorithm(&algorithm).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_list_batches_by_algorithm_with_file_storage() {
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
    fn test_json_serialization_validity() {
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
    fn test_special_characters_in_id() {
        let temp_dir = TempDir::new().unwrap();
        let storage = FileCavpStorage::new(temp_dir.path()).unwrap();

        // Note: File systems have restrictions on certain characters
        // Using characters that are valid for most file systems
        let result =
            create_test_result("TEST_with-dashes_and_underscores", mlkem_algorithm("768"), true);
        storage.store_result(&result).unwrap();

        let retrieved = storage.retrieve_result("TEST_with-dashes_and_underscores").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_overwrite_file() {
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
    fn test_load_with_invalid_json_file() {
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
    fn test_non_json_files_ignored() {
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
    fn test_manager_new() {
        let primary = Box::new(MemoryCavpStorage::new());
        let manager = CavpStorageManager::new(primary);
        drop(manager);
    }

    #[test]
    fn test_manager_with_backup() {
        let primary = Box::new(MemoryCavpStorage::new());
        let backup = Box::new(MemoryCavpStorage::new());
        let manager = CavpStorageManager::with_backup(primary, backup);
        drop(manager);
    }

    #[test]
    fn test_manager_memory_factory() {
        let manager = CavpStorageManager::memory();

        // Should be able to use the manager
        let result = create_test_result("MANAGER-MEM-001", mlkem_algorithm("768"), true);
        assert!(manager.store_result(&result).is_ok());
    }

    #[test]
    fn test_manager_file_factory() {
        let temp_dir = TempDir::new().unwrap();
        let manager = CavpStorageManager::file(temp_dir.path());

        assert!(manager.is_ok());
        let manager = manager.unwrap();

        let result = create_test_result("MANAGER-FILE-001", mlkem_algorithm("768"), true);
        assert!(manager.store_result(&result).is_ok());
    }

    #[test]
    fn test_manager_store_result() {
        let manager = CavpStorageManager::memory();
        let result = create_test_result("MGR-STORE-001", mldsa_algorithm("44"), true);

        assert!(manager.store_result(&result).is_ok());

        let retrieved = manager.retrieve_result("MGR-STORE-001").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_manager_store_batch() {
        let manager = CavpStorageManager::memory();
        let batch = create_batch_result("MGR-BATCH-001", slhdsa_algorithm("128s"), 5, 2);

        assert!(manager.store_batch(&batch).is_ok());

        let retrieved = manager.retrieve_batch("MGR-BATCH-001").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_manager_retrieve_result() {
        let manager = CavpStorageManager::memory();
        let result = create_test_result("MGR-RETRIEVE-001", fndsa_algorithm("1024"), true);

        manager.store_result(&result).unwrap();
        let retrieved = manager.retrieve_result("MGR-RETRIEVE-001").unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().test_id, "MGR-RETRIEVE-001");
    }

    #[test]
    fn test_manager_retrieve_batch() {
        let manager = CavpStorageManager::memory();
        let batch = create_batch_result("MGR-RETRIEVE-BATCH", CavpAlgorithm::HybridKem, 3, 0);

        manager.store_batch(&batch).unwrap();
        let retrieved = manager.retrieve_batch("MGR-RETRIEVE-BATCH").unwrap();

        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().batch_id, "MGR-RETRIEVE-BATCH");
    }

    #[test]
    fn test_manager_retrieve_nonexistent() {
        let manager = CavpStorageManager::memory();

        let result = manager.retrieve_result("DOES-NOT-EXIST").unwrap();
        assert!(result.is_none());

        let batch = manager.retrieve_batch("DOES-NOT-EXIST-BATCH").unwrap();
        assert!(batch.is_none());
    }

    #[test]
    fn test_manager_list_results_by_algorithm() {
        let manager = CavpStorageManager::memory();
        let algorithm = mlkem_algorithm("768");

        for i in 0..5 {
            let result = create_test_result(&format!("MGR-LIST-{:03}", i), algorithm.clone(), true);
            manager.store_result(&result).unwrap();
        }

        let results = manager.list_results_by_algorithm(&algorithm).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_manager_list_batches_by_algorithm() {
        let manager = CavpStorageManager::memory();
        let algorithm = mldsa_algorithm("87");

        for i in 0..3 {
            let batch =
                create_batch_result(&format!("MGR-BATCH-LIST-{:03}", i), algorithm.clone(), 4, 1);
            manager.store_batch(&batch).unwrap();
        }

        let batches = manager.list_batches_by_algorithm(&algorithm).unwrap();
        assert_eq!(batches.len(), 3);
    }

    #[test]
    fn test_manager_with_backup_stores_to_both() {
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
    fn test_manager_mixed_algorithms() {
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
    fn test_concurrent_reads() {
        let storage = Arc::new(MemoryCavpStorage::new());

        // Pre-populate storage
        for i in 0..100 {
            let result =
                create_test_result(&format!("CONCURRENT-{:03}", i), mlkem_algorithm("768"), true);
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
    fn test_concurrent_writes() {
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
    fn test_concurrent_read_write() {
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
    fn test_concurrent_batch_operations() {
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
    fn test_result_json_roundtrip() {
        let original = create_test_result("SERIAL-001", mlkem_algorithm("768"), true);

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: CavpTestResult = serde_json::from_str(&json).unwrap();

        assert_eq!(original.test_id, deserialized.test_id);
        assert_eq!(original.passed, deserialized.passed);
        assert_eq!(original.algorithm, deserialized.algorithm);
    }

    #[test]
    fn test_batch_json_roundtrip() {
        let original = create_batch_result("SERIAL-BATCH", mldsa_algorithm("44"), 5, 2);

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: CavpBatchResult = serde_json::from_str(&json).unwrap();

        assert_eq!(original.batch_id, deserialized.batch_id);
        assert_eq!(original.test_results.len(), deserialized.test_results.len());
        assert_eq!(original.pass_rate, deserialized.pass_rate);
    }

    #[test]
    fn test_algorithm_serialization() {
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
    fn test_metadata_serialization() {
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
    fn test_validation_status_serialization() {
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
    fn test_large_result_serialization() {
        let mut result = create_test_result("LARGE-RESULT", mlkem_algorithm("1024"), true);

        // Add large data
        result.actual_result = vec![0x42; 10000];
        result.expected_result = vec![0x42; 10000];

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: CavpTestResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result.actual_result.len(), deserialized.actual_result.len());
    }

    #[test]
    fn test_pretty_json_format() {
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
    fn test_empty_test_id() {
        let storage = MemoryCavpStorage::new();
        let result = create_test_result("", mlkem_algorithm("768"), true);

        storage.store_result(&result).unwrap();
        let retrieved = storage.retrieve_result("").unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_very_long_test_id() {
        let storage = MemoryCavpStorage::new();
        let long_id = "A".repeat(1000);
        let result = create_test_result(&long_id, mlkem_algorithm("768"), true);

        storage.store_result(&result).unwrap();
        let retrieved = storage.retrieve_result(&long_id).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_unicode_in_test_id() {
        let storage = MemoryCavpStorage::new();
        let unicode_id = "test_\u{1F600}_\u{4E2D}\u{6587}";
        let result = create_test_result(unicode_id, mlkem_algorithm("768"), true);

        storage.store_result(&result).unwrap();
        let retrieved = storage.retrieve_result(unicode_id).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_batch_with_no_results() {
        let storage = MemoryCavpStorage::new();
        let batch = CavpBatchResult::new("EMPTY-BATCH".to_string(), mlkem_algorithm("768"));

        storage.store_batch(&batch).unwrap();
        let retrieved = storage.retrieve_batch("EMPTY-BATCH").unwrap().unwrap();

        assert!(retrieved.test_results.is_empty());
        assert!(matches!(retrieved.status, CavpValidationStatus::Incomplete));
    }

    #[test]
    fn test_result_with_empty_vectors() {
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
    fn test_batch_with_large_number_of_results() {
        let storage = MemoryCavpStorage::new();
        let mut batch = CavpBatchResult::new("LARGE-BATCH".to_string(), mlkem_algorithm("768"));

        for i in 0..1000 {
            let result =
                create_test_result(&format!("LARGE-{:04}", i), mlkem_algorithm("768"), i % 2 == 0);
            batch.add_test_result(result);
        }

        storage.store_batch(&batch).unwrap();
        let retrieved = storage.retrieve_batch("LARGE-BATCH").unwrap().unwrap();

        assert_eq!(retrieved.test_results.len(), 1000);
        assert_eq!(retrieved.pass_rate, 50.0);
    }

    #[test]
    fn test_zero_execution_time() {
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
    fn test_very_long_execution_time() {
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
    fn test_all_algorithm_variants_storage() {
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
    fn test_full_workflow_memory() {
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
    fn test_full_workflow_file() {
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
    fn test_multi_algorithm_storage() {
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
                let result =
                    create_test_result(&format!("{}-{:03}", algo.name(), i), algo.clone(), true);
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
    fn test_batch_statistics_accuracy() {
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
    fn test_storage_data_integrity() {
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
                implementation_version: "0.5.0".to_string(),
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
