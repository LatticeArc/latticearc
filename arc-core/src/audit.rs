//! # Persistent Audit Storage with Rotation
//!
//! Provides tamper-evident audit logging for cryptographic operations.
//! Events are persisted to disk in JSON Lines format with automatic rotation
//! based on file size and age.
//!
//! ## Security Features
//!
//! - **Integrity Verification**: SHA-256 hash chain for tamper detection
//! - **Automatic Rotation**: Files rotate based on size and age limits
//! - **Retention Policies**: Configurable retention periods for compliance
//! - **Thread-Safe**: All operations are safe for concurrent access
//!
//! ## Usage
//!
//! ```rust,ignore
//! use arc_core::audit::{AuditConfig, FileAuditStorage, AuditStorage, AuditEvent, AuditEventType, AuditOutcome};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! let config = AuditConfig {
//!     storage_path: PathBuf::from("/var/log/latticearc/audit"),
//!     max_file_size_bytes: 100 * 1024 * 1024, // 100MB
//!     max_file_age: Duration::from_secs(24 * 60 * 60), // 24 hours
//!     retention_days: 90,
//! };
//!
//! let storage = FileAuditStorage::new(config)?;
//!
//! // Create and write an audit event
//! let event = AuditEvent::new(
//!     AuditEventType::CryptoOperation,
//!     "encrypt_data",
//!     AuditOutcome::Success,
//! );
//! storage.write(&event)?;
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{CoreError, Result};

/// Audit event for persistent storage.
///
/// Each event captures a single auditable action with full context
/// for compliance and forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier for this event (UUID v4).
    pub id: String,
    /// Timestamp when the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Category of the audit event.
    pub event_type: AuditEventType,
    /// Identity of the actor performing the action (optional).
    pub actor: Option<String>,
    /// Resource being acted upon (optional).
    pub resource: Option<String>,
    /// Specific action performed.
    pub action: String,
    /// Outcome of the action.
    pub outcome: AuditOutcome,
    /// Additional key-value metadata.
    pub metadata: HashMap<String, String>,
    /// SHA-256 hash for tamper detection (includes previous event hash).
    pub integrity_hash: String,
}

impl AuditEvent {
    /// Create a new audit event with the given parameters.
    ///
    /// The integrity hash is initially empty and will be set when
    /// the event is written to storage.
    #[must_use]
    pub fn new(event_type: AuditEventType, action: &str, outcome: AuditOutcome) -> Self {
        Self {
            id: generate_uuid(),
            timestamp: Utc::now(),
            event_type,
            actor: None,
            resource: None,
            action: action.to_string(),
            outcome,
            metadata: HashMap::new(),
            integrity_hash: String::new(),
        }
    }

    /// Create a new audit event builder for fluent construction.
    #[must_use]
    pub fn builder(
        event_type: AuditEventType,
        action: &str,
        outcome: AuditOutcome,
    ) -> AuditEventBuilder {
        AuditEventBuilder::new(event_type, action, outcome)
    }

    /// Set the actor for this event.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Set the resource for this event.
    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Add metadata to this event.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the event ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the event timestamp.
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Get the event type.
    #[must_use]
    pub fn event_type(&self) -> &AuditEventType {
        &self.event_type
    }

    /// Get the actor.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// Get the resource.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// Get the action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Get the outcome.
    #[must_use]
    pub fn outcome(&self) -> &AuditOutcome {
        &self.outcome
    }

    /// Get the metadata.
    #[must_use]
    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    /// Get the integrity hash.
    #[must_use]
    pub fn integrity_hash(&self) -> &str {
        &self.integrity_hash
    }
}

/// Builder for constructing audit events with a fluent API.
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    /// Create a new builder with required fields.
    #[must_use]
    pub fn new(event_type: AuditEventType, action: &str, outcome: AuditOutcome) -> Self {
        Self { event: AuditEvent::new(event_type, action, outcome) }
    }

    /// Set the actor for this event.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.event.actor = Some(actor.into());
        self
    }

    /// Set the resource for this event.
    #[must_use]
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.event.resource = Some(resource.into());
        self
    }

    /// Add metadata to this event.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the audit event.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        self.event
    }
}

/// Categories of audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Authentication-related events (login, logout, session).
    Authentication,
    /// Key management operations (generation, rotation, destruction).
    KeyOperation,
    /// Cryptographic operations (encrypt, decrypt, sign, verify).
    CryptoOperation,
    /// Access control decisions (grant, deny, policy evaluation).
    AccessControl,
    /// Session lifecycle events (create, refresh, expire).
    SessionManagement,
    /// Security alerts and anomalies.
    SecurityAlert,
    /// Configuration changes.
    ConfigurationChange,
    /// System events (startup, shutdown, health checks).
    System,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication => write!(f, "authentication"),
            Self::KeyOperation => write!(f, "key_operation"),
            Self::CryptoOperation => write!(f, "crypto_operation"),
            Self::AccessControl => write!(f, "access_control"),
            Self::SessionManagement => write!(f, "session_management"),
            Self::SecurityAlert => write!(f, "security_alert"),
            Self::ConfigurationChange => write!(f, "configuration_change"),
            Self::System => write!(f, "system"),
        }
    }
}

/// Outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// Operation completed successfully.
    Success,
    /// Operation failed due to an error.
    Failure,
    /// Operation was denied by policy or access control.
    Denied,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
            Self::Denied => write!(f, "denied"),
        }
    }
}

/// Configuration for audit storage.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Directory path where audit files are stored.
    pub storage_path: PathBuf,
    /// Maximum size of a single audit file before rotation (default: 100MB).
    pub max_file_size_bytes: u64,
    /// Maximum age of a single audit file before rotation (default: 24 hours).
    pub max_file_age: Duration,
    /// Number of days to retain audit files (default: 90 days).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("audit_logs"),
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB
            max_file_age: Duration::from_secs(24 * 60 * 60), // 24 hours
            retention_days: 90,
        }
    }
}

impl AuditConfig {
    /// Create a new audit configuration with the specified storage path.
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path, ..Default::default() }
    }

    /// Set the maximum file size before rotation.
    #[must_use]
    pub fn with_max_file_size(mut self, max_bytes: u64) -> Self {
        self.max_file_size_bytes = max_bytes;
        self
    }

    /// Set the maximum file age before rotation.
    #[must_use]
    pub fn with_max_file_age(mut self, max_age: Duration) -> Self {
        self.max_file_age = max_age;
        self
    }

    /// Set the retention period in days.
    #[must_use]
    pub fn with_retention_days(mut self, days: u32) -> Self {
        self.retention_days = days;
        self
    }

    /// Get the storage path.
    #[must_use]
    pub fn storage_path(&self) -> &PathBuf {
        &self.storage_path
    }

    /// Get the maximum file size.
    #[must_use]
    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_bytes
    }

    /// Get the maximum file age.
    #[must_use]
    pub fn max_file_age(&self) -> Duration {
        self.max_file_age
    }

    /// Get the retention days.
    #[must_use]
    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }
}

/// Trait for audit storage implementations.
///
/// Implement this trait to create custom audit storage backends
/// (e.g., database, remote service, etc.).
pub trait AuditStorage: Send + Sync {
    /// Write an audit event to storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be written.
    fn write(&self, event: &AuditEvent) -> Result<()>;

    /// Flush any buffered events to persistent storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush operation fails.
    fn flush(&self) -> Result<()>;
}

/// Internal state for file rotation tracking.
struct FileState {
    /// Current file handle wrapped in a buffered writer.
    writer: BufWriter<File>,
    /// Path to the current file (used for logging during rotation).
    current_path: PathBuf,
    /// Size of the current file in bytes.
    current_size: u64,
    /// Timestamp when the current file was created.
    created_at: DateTime<Utc>,
}

/// File-based audit storage with automatic rotation.
///
/// Writes audit events as JSON Lines (one JSON object per line).
/// Files are rotated when they exceed the configured size or age limits.
pub struct FileAuditStorage {
    /// Configuration for this storage instance.
    config: AuditConfig,
    /// Current file state (protected by mutex for thread safety).
    file_state: Mutex<Option<FileState>>,
    /// Hash of the previous event for chain integrity.
    previous_hash: RwLock<String>,
}

impl FileAuditStorage {
    /// Create a new file-based audit storage.
    ///
    /// Creates the storage directory if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage directory cannot be created.
    pub fn new(config: AuditConfig) -> Result<Arc<Self>> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&config.storage_path).map_err(|e| {
            CoreError::AuditError(format!(
                "Failed to create audit directory '{}': {}",
                config.storage_path.display(),
                e
            ))
        })?;

        let storage = Arc::new(Self {
            config,
            file_state: Mutex::new(None),
            previous_hash: RwLock::new(String::new()),
        });

        // Clean up old files based on retention policy
        storage.cleanup_old_files()?;

        Ok(storage)
    }

    /// Get the configuration for this storage instance.
    #[must_use]
    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    /// Compute the integrity hash for an event.
    ///
    /// The hash includes the previous event's hash to create a chain,
    /// making tampering detectable.
    fn compute_integrity_hash(event: &AuditEvent, previous_hash: &str) -> String {
        let mut hasher = Sha256::new();

        // Include previous hash for chain integrity
        hasher.update(previous_hash.as_bytes());

        // Include all event fields (except the integrity_hash itself)
        hasher.update(event.id.as_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hasher.update(event.event_type.to_string().as_bytes());

        if let Some(ref actor) = event.actor {
            hasher.update(actor.as_bytes());
        }
        if let Some(ref resource) = event.resource {
            hasher.update(resource.as_bytes());
        }

        hasher.update(event.action.as_bytes());
        hasher.update(event.outcome.to_string().as_bytes());

        // Include metadata in sorted order for deterministic hashing
        let mut metadata_keys: Vec<&String> = event.metadata.keys().collect();
        metadata_keys.sort();
        for key in metadata_keys {
            hasher.update(key.as_bytes());
            if let Some(value) = event.metadata.get(key) {
                hasher.update(value.as_bytes());
            }
        }

        hex::encode(hasher.finalize())
    }

    /// Check if the current file needs rotation.
    fn needs_rotation(&self, state: &FileState) -> bool {
        // Check size limit
        if state.current_size >= self.config.max_file_size_bytes {
            return true;
        }

        // Check age limit
        let age =
            Utc::now().signed_duration_since(state.created_at).to_std().unwrap_or(Duration::ZERO);

        age >= self.config.max_file_age
    }

    /// Rotate the current file if needed.
    fn rotate_if_needed(&self, state: &mut Option<FileState>) -> Result<()> {
        let should_rotate = state.as_ref().is_some_and(|s| self.needs_rotation(s));

        if should_rotate {
            // Close current file and create new one
            if let Some(mut old_state) = state.take() {
                tracing::info!(
                    "Rotating audit file: {} (size: {} bytes)",
                    old_state.current_path.display(),
                    old_state.current_size
                );
                old_state.writer.flush().map_err(|e| {
                    CoreError::AuditError(format!("Failed to flush audit file: {}", e))
                })?;
            }
        }

        // Create new file if needed
        if state.is_none() {
            *state = Some(self.create_new_file()?);
        }

        Ok(())
    }

    /// Create a new audit file.
    fn create_new_file(&self) -> Result<FileState> {
        let now = Utc::now();
        let filename = format!("audit-{}.jsonl", now.format("%Y-%m-%dT%H-%M-%S"));
        let path = self.config.storage_path.join(&filename);

        let file = OpenOptions::new().create(true).append(true).open(&path).map_err(|e| {
            CoreError::AuditError(format!(
                "Failed to create audit file '{}': {}",
                path.display(),
                e
            ))
        })?;

        tracing::debug!("Created new audit file: {}", path.display());

        Ok(FileState {
            writer: BufWriter::new(file),
            current_path: path,
            current_size: 0,
            created_at: now,
        })
    }

    /// Clean up old audit files based on retention policy.
    fn cleanup_old_files(&self) -> Result<()> {
        let retention_duration = chrono::Duration::days(i64::from(self.config.retention_days));
        let cutoff = Utc::now().checked_sub_signed(retention_duration).unwrap_or_else(Utc::now);

        let entries = fs::read_dir(&self.config.storage_path).map_err(|e| {
            CoreError::AuditError(format!(
                "Failed to read audit directory '{}': {}",
                self.config.storage_path.display(),
                e
            ))
        })?;

        for entry in entries {
            let Ok(entry) = entry else { continue };

            let path = entry.path();

            // Only process .jsonl files
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }

            // Check file modification time
            let Ok(metadata) = fs::metadata(&path) else { continue };

            let modified = match metadata.modified() {
                Ok(t) => DateTime::<Utc>::from(t),
                Err(_) => continue,
            };

            if modified < cutoff {
                // Delete old file
                if let Err(e) = fs::remove_file(&path) {
                    tracing::warn!("Failed to remove old audit file '{}': {}", path.display(), e);
                } else {
                    tracing::info!("Removed old audit file: {}", path.display());
                }
            }
        }

        Ok(())
    }

    /// Write an audit event to the current file.
    fn write_event_to_file(&self, event: &mut AuditEvent) -> Result<()> {
        let mut file_state = self.file_state.lock();

        // Rotate if needed
        self.rotate_if_needed(&mut file_state)?;

        let state = file_state
            .as_mut()
            .ok_or_else(|| CoreError::AuditError("No active audit file".to_string()))?;

        // Compute integrity hash with chain
        let previous_hash = self.previous_hash.read().clone();
        event.integrity_hash = Self::compute_integrity_hash(event, &previous_hash);

        // Update previous hash for next event
        {
            let mut prev = self.previous_hash.write();
            prev.clone_from(&event.integrity_hash);
        }

        // Serialize event to JSON
        let json = serde_json::to_string(event).map_err(|e| {
            CoreError::AuditError(format!("Failed to serialize audit event: {}", e))
        })?;

        // Write JSON line
        let line = format!("{}\n", json);
        let line_bytes = line.as_bytes();

        state
            .writer
            .write_all(line_bytes)
            .map_err(|e| CoreError::AuditError(format!("Failed to write audit event: {}", e)))?;

        // Update size tracking
        state.current_size = state.current_size.saturating_add(line_bytes.len() as u64);

        Ok(())
    }
}

impl AuditStorage for FileAuditStorage {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        let mut event_copy = event.clone();
        self.write_event_to_file(&mut event_copy)
    }

    fn flush(&self) -> Result<()> {
        let mut file_state = self.file_state.lock();

        if let Some(ref mut state) = *file_state {
            state
                .writer
                .flush()
                .map_err(|e| CoreError::AuditError(format!("Failed to flush audit file: {}", e)))?;
        }

        Ok(())
    }
}

/// Generate a UUID v4 for event identification.
fn generate_uuid() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);

    // Set version (4) and variant (RFC 4122) bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_event_creation() {
        let event =
            AuditEvent::new(AuditEventType::CryptoOperation, "encrypt_data", AuditOutcome::Success);

        assert!(!event.id.is_empty());
        assert_eq!(event.action, "encrypt_data");
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert!(event.actor.is_none());
        assert!(event.resource.is_none());
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::builder(
            AuditEventType::KeyOperation,
            "generate_keypair",
            AuditOutcome::Success,
        )
        .actor("user@example.com")
        .resource("key-001")
        .metadata("algorithm", "ML-KEM-768")
        .build();

        assert_eq!(event.actor.as_deref(), Some("user@example.com"));
        assert_eq!(event.resource.as_deref(), Some("key-001"));
        assert_eq!(event.metadata.get("algorithm").map(|s| s.as_str()), Some("ML-KEM-768"));
    }

    #[test]
    fn test_audit_event_with_methods() {
        let event = AuditEvent::new(AuditEventType::Authentication, "login", AuditOutcome::Success)
            .with_actor("admin")
            .with_resource("system")
            .with_metadata("ip", "192.168.1.1");

        assert_eq!(event.actor(), Some("admin"));
        assert_eq!(event.resource(), Some("system"));
        assert_eq!(event.metadata().get("ip").map(|s| s.as_str()), Some("192.168.1.1"));
    }

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();

        assert_eq!(config.max_file_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_file_age, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.retention_days, 90);
    }

    #[test]
    fn test_audit_config_builder() {
        let config = AuditConfig::new(PathBuf::from("/tmp/audit"))
            .with_max_file_size(50 * 1024 * 1024)
            .with_max_file_age(Duration::from_secs(12 * 60 * 60))
            .with_retention_days(30);

        assert_eq!(config.max_file_size_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_file_age, Duration::from_secs(12 * 60 * 60));
        assert_eq!(config.retention_days, 30);
    }

    #[test]
    fn test_file_audit_storage_creation() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path);
            let storage = FileAuditStorage::new(config);
            assert!(storage.is_ok());
        }
    }

    #[test]
    fn test_file_audit_storage_write() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path.clone());

            if let Ok(storage) = FileAuditStorage::new(config) {
                let event = AuditEvent::new(
                    AuditEventType::CryptoOperation,
                    "test_operation",
                    AuditOutcome::Success,
                );

                let result = storage.write(&event);
                assert!(result.is_ok());

                let flush_result = storage.flush();
                assert!(flush_result.is_ok());

                // Verify file was created
                let entries: Vec<_> = fs::read_dir(&temp_path)
                    .map(|r| r.filter_map(|e| e.ok()).collect())
                    .unwrap_or_default();

                assert!(!entries.is_empty());
            }
        }
    }

    #[test]
    fn test_integrity_hash_chain() {
        let event1 =
            AuditEvent::new(AuditEventType::CryptoOperation, "operation1", AuditOutcome::Success);
        let event2 =
            AuditEvent::new(AuditEventType::CryptoOperation, "operation2", AuditOutcome::Success);

        let hash1 = FileAuditStorage::compute_integrity_hash(&event1, "");
        let hash2 = FileAuditStorage::compute_integrity_hash(&event2, &hash1);

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Same event with same previous hash should produce same result
        let hash2_again = FileAuditStorage::compute_integrity_hash(&event2, &hash1);
        assert_eq!(hash2, hash2_again);

        // Different previous hash should produce different result
        let hash2_different = FileAuditStorage::compute_integrity_hash(&event2, "different");
        assert_ne!(hash2, hash2_different);
    }

    #[test]
    fn test_uuid_generation() {
        let uuid1 = generate_uuid();
        let uuid2 = generate_uuid();

        // UUIDs should be valid format
        assert_eq!(uuid1.len(), 36);
        assert_eq!(uuid2.len(), 36);

        // UUIDs should be unique
        assert_ne!(uuid1, uuid2);

        // Check format (xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx)
        let parts: Vec<&str> = uuid1.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);

        // Version 4 marker
        assert!(parts[2].starts_with('4'));
    }

    #[test]
    fn test_audit_event_type_display() {
        assert_eq!(AuditEventType::Authentication.to_string(), "authentication");
        assert_eq!(AuditEventType::KeyOperation.to_string(), "key_operation");
        assert_eq!(AuditEventType::CryptoOperation.to_string(), "crypto_operation");
        assert_eq!(AuditEventType::AccessControl.to_string(), "access_control");
        assert_eq!(AuditEventType::SessionManagement.to_string(), "session_management");
        assert_eq!(AuditEventType::SecurityAlert.to_string(), "security_alert");
        assert_eq!(AuditEventType::ConfigurationChange.to_string(), "configuration_change");
        assert_eq!(AuditEventType::System.to_string(), "system");
    }

    #[test]
    fn test_audit_outcome_display() {
        assert_eq!(AuditOutcome::Success.to_string(), "success");
        assert_eq!(AuditOutcome::Failure.to_string(), "failure");
        assert_eq!(AuditOutcome::Denied.to_string(), "denied");
    }
}
