#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: CAVP test result storage backend.
// - Processes serialized test results with known structures
// - Statistics calculations for batch results
// - Test infrastructure prioritizes correctness verification
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]

use crate::cavp::types::*;
use anyhow::Result;
use serde_json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// CAVP result storage backend trait
pub trait CavpStorage: Send + Sync {
    /// Store a single CAVP test result.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to persist the result.
    fn store_result(&self, result: &CavpTestResult) -> Result<()>;

    /// Store a batch of CAVP test results.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to persist the batch.
    fn store_batch(&self, batch: &CavpBatchResult) -> Result<()>;

    /// Retrieve a single CAVP test result by ID.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to read the result.
    fn retrieve_result(&self, test_id: &str) -> Result<Option<CavpTestResult>>;

    /// Retrieve a batch of CAVP test results by batch ID.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to read the batch.
    fn retrieve_batch(&self, batch_id: &str) -> Result<Option<CavpBatchResult>>;

    /// List all results for a given algorithm.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to query results.
    fn list_results_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpTestResult>>;

    /// List all batches for a given algorithm.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to query batches.
    fn list_batches_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpBatchResult>>;
}

/// Internal state for CAVP storage
struct CavpStorageInternalState {
    results: HashMap<String, CavpTestResult>,
    batches: HashMap<String, CavpBatchResult>,
    algorithm_index: HashMap<String, Vec<String>>,
}

/// In-memory CAVP storage implementation
pub struct MemoryCavpStorage {
    internal_state: Arc<RwLock<CavpStorageInternalState>>,
}

impl MemoryCavpStorage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            internal_state: Arc::new(RwLock::new(CavpStorageInternalState {
                results: HashMap::new(),
                batches: HashMap::new(),
                algorithm_index: HashMap::new(),
            })),
        }
    }

    fn add_to_algorithm_index(&self, algorithm: &CavpAlgorithm, test_id: String) -> Result<()> {
        let algorithm_key = algorithm.name();
        let mut internal_state =
            self.internal_state.write().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        internal_state.algorithm_index.entry(algorithm_key).or_default().push(test_id);
        Ok(())
    }

    fn add_batch_to_algorithm_index(
        &self,
        algorithm: &CavpAlgorithm,
        batch_id: String,
    ) -> Result<()> {
        let algorithm_key = format!("batch_{}", algorithm.name());
        let mut internal_state =
            self.internal_state.write().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        internal_state.algorithm_index.entry(algorithm_key).or_default().push(batch_id);
        Ok(())
    }
}

impl Default for MemoryCavpStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl CavpStorage for MemoryCavpStorage {
    fn store_result(&self, result: &CavpTestResult) -> Result<()> {
        let test_id = result.test_id.clone();
        let algorithm = result.algorithm.clone();

        {
            let mut internal_state =
                self.internal_state.write().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            internal_state.results.insert(test_id.clone(), result.clone());
        }

        self.add_to_algorithm_index(&algorithm, test_id.clone())?;
        info!("Stored CAVP test result: {}", test_id);
        Ok(())
    }

    fn store_batch(&self, batch: &CavpBatchResult) -> Result<()> {
        let batch_id = batch.batch_id.clone();
        let algorithm = batch.algorithm.clone();

        {
            let mut internal_state =
                self.internal_state.write().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
            internal_state.batches.insert(batch_id.clone(), batch.clone());
        }

        self.add_batch_to_algorithm_index(&algorithm, batch_id.clone())?;
        info!("Stored CAVP batch result: {}", batch_id);
        Ok(())
    }

    fn retrieve_result(&self, test_id: &str) -> Result<Option<CavpTestResult>> {
        let internal_state =
            self.internal_state.read().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        Ok(internal_state.results.get(test_id).cloned())
    }

    fn retrieve_batch(&self, batch_id: &str) -> Result<Option<CavpBatchResult>> {
        let internal_state =
            self.internal_state.read().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        Ok(internal_state.batches.get(batch_id).cloned())
    }

    fn list_results_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpTestResult>> {
        let algorithm_key = algorithm.name();
        let internal_state =
            self.internal_state.read().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        if let Some(test_ids) = internal_state.algorithm_index.get(&algorithm_key) {
            let mut algorithm_results = Vec::new();

            for test_id in test_ids {
                if let Some(result) = internal_state.results.get(test_id) {
                    algorithm_results.push(result.clone());
                }
            }

            Ok(algorithm_results)
        } else {
            Ok(Vec::new())
        }
    }

    fn list_batches_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpBatchResult>> {
        let algorithm_key = format!("batch_{}", algorithm.name());
        let internal_state =
            self.internal_state.read().map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        if let Some(batch_ids) = internal_state.algorithm_index.get(&algorithm_key) {
            let mut algorithm_batches = Vec::new();

            for batch_id in batch_ids {
                if let Some(batch) = internal_state.batches.get(batch_id) {
                    algorithm_batches.push(batch.clone());
                }
            }

            Ok(algorithm_batches)
        } else {
            Ok(Vec::new())
        }
    }
}

/// File-based CAVP storage implementation
pub struct FileCavpStorage {
    base_path: std::path::PathBuf,
    memory_storage: MemoryCavpStorage,
}

impl FileCavpStorage {
    /// Create a new file-based CAVP storage at the given path.
    ///
    /// # Errors
    /// Returns an error if the directory structure cannot be created.
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        std::fs::create_dir_all(&base_path)?;
        std::fs::create_dir_all(base_path.join("results"))?;
        std::fs::create_dir_all(base_path.join("batches"))?;

        Ok(Self { base_path, memory_storage: MemoryCavpStorage::new() })
    }

    fn result_file_path(&self, test_id: &str) -> std::path::PathBuf {
        self.base_path.join("results").join(format!("{}.json", test_id))
    }

    fn batch_file_path(&self, batch_id: &str) -> std::path::PathBuf {
        self.base_path.join("batches").join(format!("{}.json", batch_id))
    }

    /// Load existing results from disk into memory storage.
    ///
    /// # Errors
    /// Returns an error if reading the directory or parsing JSON files fails.
    pub fn load_existing_results(&self) -> Result<()> {
        let results_dir = self.base_path.join("results");
        if results_dir.exists() {
            for entry in std::fs::read_dir(results_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let content = std::fs::read_to_string(&path)?;
                    if let Ok(result) = serde_json::from_str::<CavpTestResult>(&content) {
                        self.memory_storage.store_result(&result)?;
                    } else {
                        warn!("Failed to parse CAVP result file: {:?}", path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Load existing batches from disk into memory storage.
    ///
    /// # Errors
    /// Returns an error if reading the directory or parsing JSON files fails.
    pub fn load_existing_batches(&self) -> Result<()> {
        let batches_dir = self.base_path.join("batches");
        if batches_dir.exists() {
            for entry in std::fs::read_dir(batches_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let content = std::fs::read_to_string(&path)?;
                    if let Ok(batch) = serde_json::from_str::<CavpBatchResult>(&content) {
                        self.memory_storage.store_batch(&batch)?;
                    } else {
                        warn!("Failed to parse CAVP batch file: {:?}", path);
                    }
                }
            }
        }
        Ok(())
    }
}

impl CavpStorage for FileCavpStorage {
    fn store_result(&self, result: &CavpTestResult) -> Result<()> {
        let file_path = self.result_file_path(&result.test_id);
        let json_content = serde_json::to_string_pretty(result)?;
        std::fs::write(&file_path, json_content)?;

        self.memory_storage.store_result(result)
    }

    fn store_batch(&self, batch: &CavpBatchResult) -> Result<()> {
        let file_path = self.batch_file_path(&batch.batch_id);
        let json_content = serde_json::to_string_pretty(batch)?;
        std::fs::write(&file_path, json_content)?;

        self.memory_storage.store_batch(batch)
    }

    fn retrieve_result(&self, test_id: &str) -> Result<Option<CavpTestResult>> {
        self.memory_storage.retrieve_result(test_id)
    }

    fn retrieve_batch(&self, batch_id: &str) -> Result<Option<CavpBatchResult>> {
        self.memory_storage.retrieve_batch(batch_id)
    }

    fn list_results_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpTestResult>> {
        self.memory_storage.list_results_by_algorithm(algorithm)
    }

    fn list_batches_by_algorithm(&self, algorithm: &CavpAlgorithm) -> Result<Vec<CavpBatchResult>> {
        self.memory_storage.list_batches_by_algorithm(algorithm)
    }
}

/// CAVP storage manager with multiple backend support
pub struct CavpStorageManager {
    primary_storage: Box<dyn CavpStorage>,
    backup_storage: Option<Box<dyn CavpStorage>>,
}

impl CavpStorageManager {
    #[must_use]
    pub fn new(primary_storage: Box<dyn CavpStorage>) -> Self {
        Self { primary_storage, backup_storage: None }
    }

    #[must_use]
    pub fn with_backup(
        primary_storage: Box<dyn CavpStorage>,
        backup_storage: Box<dyn CavpStorage>,
    ) -> Self {
        Self { primary_storage, backup_storage: Some(backup_storage) }
    }

    #[must_use]
    pub fn memory() -> Self {
        Self::new(Box::new(MemoryCavpStorage::new()))
    }

    /// Create a file-based CAVP storage manager.
    ///
    /// # Errors
    /// Returns an error if the file storage directory cannot be created.
    pub fn file<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let storage = FileCavpStorage::new(base_path)?;
        Ok(Self::new(Box::new(storage)))
    }

    /// Store a single CAVP test result.
    ///
    /// # Errors
    /// Returns an error if the primary storage backend fails to persist the result.
    pub fn store_result(&self, result: &CavpTestResult) -> Result<()> {
        self.primary_storage.store_result(result)?;
        if let Some(backup) = &self.backup_storage
            && let Err(e) = backup.store_result(result)
        {
            warn!("Failed to store result in backup: {}", e);
        }
        Ok(())
    }

    /// Store a batch of CAVP test results.
    ///
    /// # Errors
    /// Returns an error if the primary storage backend fails to persist the batch.
    pub fn store_batch(&self, batch: &CavpBatchResult) -> Result<()> {
        self.primary_storage.store_batch(batch)?;
        if let Some(backup) = &self.backup_storage
            && let Err(e) = backup.store_batch(batch)
        {
            warn!("Failed to store batch in backup: {}", e);
        }
        Ok(())
    }

    /// Retrieve a stored test result by ID.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to read the result.
    pub fn retrieve_result(&self, test_id: &str) -> Result<Option<CavpTestResult>> {
        self.primary_storage.retrieve_result(test_id)
    }

    /// Retrieve a stored batch result by ID.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to read the batch.
    pub fn retrieve_batch(&self, batch_id: &str) -> Result<Option<CavpBatchResult>> {
        self.primary_storage.retrieve_batch(batch_id)
    }

    /// List all results for a specific algorithm.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to enumerate results.
    pub fn list_results_by_algorithm(
        &self,
        algorithm: &CavpAlgorithm,
    ) -> Result<Vec<CavpTestResult>> {
        self.primary_storage.list_results_by_algorithm(algorithm)
    }

    /// List all batches for a specific algorithm.
    ///
    /// # Errors
    /// Returns an error if the storage backend fails to enumerate batches.
    pub fn list_batches_by_algorithm(
        &self,
        algorithm: &CavpAlgorithm,
    ) -> Result<Vec<CavpBatchResult>> {
        self.primary_storage.list_batches_by_algorithm(algorithm)
    }
}
