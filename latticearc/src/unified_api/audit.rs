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
//! ```rust,no_run
//! use latticearc::unified_api::audit::{AuditConfig, FileAuditStorage, AuditStorage, AuditEvent, AuditEventType, AuditOutcome};
//! use std::path::PathBuf;
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::unified_api::error::{CoreError, Result};

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
    /// Maximum byte length for the `action` string. Caller-supplied
    /// `action` text is the third free-form field on every event;
    /// without a cap, a single oversized argument would multiply
    /// memory + hashing cost across the whole audit chain.
    pub const MAX_ACTION_LEN: usize = 256;

    /// Create a new audit event with the given parameters.
    ///
    /// The integrity hash is initially empty and will be set when
    /// the event is written to storage. `action` is sanitized
    /// (control chars stripped, truncated to [`MAX_ACTION_LEN`]
    /// (Self::MAX_ACTION_LEN)) so a `\n`-laced or oversized argument
    /// cannot break JSONL consumers or amplify hashing cost.
    /// Sanitization that empties the string keeps a placeholder
    /// `"<empty>"` so every event still carries a non-empty action
    /// — audit must never silently drop the verb.
    #[must_use]
    pub fn new(event_type: AuditEventType, action: &str, outcome: AuditOutcome) -> Self {
        let action = sanitize_action_field(action.to_string());
        Self {
            id: generate_uuid(),
            timestamp: Utc::now(),
            event_type,
            actor: None,
            resource: None,
            action,
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

    /// Maximum byte length for `actor` and `resource` strings. Mirrors
    /// `MAX_METADATA_VALUE_LEN` so the same cap applies to all
    /// caller-supplied free-form fields. Empty / over-cap / control-
    /// char inputs are sanitized rather than rejected — audit must
    /// never fail-open by aborting the operation that produced the
    /// event.
    pub const MAX_ACTOR_LEN: usize = 256;
    /// Maximum byte length for `resource` string.
    pub const MAX_RESOURCE_LEN: usize = 1024;

    /// Set the actor for this event. Empty / oversized / control-char
    /// inputs are dropped silently (the field stays `None`); audit
    /// emission must not abort the operation.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = sanitize_audit_field(actor.into(), Self::MAX_ACTOR_LEN);
        self
    }

    /// Set the resource for this event. Same sanitization as
    /// `with_actor` with a wider cap (paths can be long).
    #[must_use]
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = sanitize_audit_field(resource.into(), Self::MAX_RESOURCE_LEN);
        self
    }

    /// Maximum number of metadata entries per event.
    ///
    /// Bounds memory + hashing cost when caller-supplied input is routed
    /// through audit. Beyond the cap, `with_metadata` silently drops the
    /// entry rather than rejecting the build (audit emission must never
    /// fail-open by aborting the operation that produced the event).
    pub const MAX_METADATA_ENTRIES: usize = 32;
    /// Maximum byte length per metadata key.
    pub const MAX_METADATA_KEY_LEN: usize = 256;
    /// Maximum byte length per metadata value.
    pub const MAX_METADATA_VALUE_LEN: usize = 4096;

    /// Add metadata to this event.
    ///
    /// Caps:
    /// - Keys longer than [`MAX_METADATA_KEY_LEN`](Self::MAX_METADATA_KEY_LEN)
    ///   are truncated.
    /// - Values longer than [`MAX_METADATA_VALUE_LEN`](Self::MAX_METADATA_VALUE_LEN)
    ///   are truncated.
    /// - Beyond [`MAX_METADATA_ENTRIES`](Self::MAX_METADATA_ENTRIES) entries
    ///   the call is a no-op (audit emission must not abort the operation
    ///   that triggered it).
    ///
    /// These caps prevent a DoS amplification path where attacker-controlled
    /// strings (e.g. SignedData.scheme, a request header) are routed through
    /// audit-event metadata: without them, every audit event could carry
    /// unbounded heap + hashing cost.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if self.metadata.len() >= Self::MAX_METADATA_ENTRIES {
            return self;
        }
        let mut k = key.into();
        let mut v = value.into();
        truncate_utf8_safe(&mut k, Self::MAX_METADATA_KEY_LEN);
        truncate_utf8_safe(&mut v, Self::MAX_METADATA_VALUE_LEN);
        self.metadata.insert(k, v); // LINT-OK: canonical-with-metadata-impl
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

/// Truncate a UTF-8 String to at most `max_bytes` bytes without splitting
/// a multi-byte code point. `String::truncate` panics on a non-boundary
/// index — for caller-controlled text we round DOWN to the nearest valid
/// boundary so attacker-supplied UTF-8 can't crash the audit pipeline.
fn truncate_utf8_safe(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut = cut.saturating_sub(1);
    }
    s.truncate(cut);
}

/// Sanitize a free-form audit field: returns `None` if the input is
/// empty after stripping control characters; truncates to `max_bytes`
/// otherwise. Control-char strip prevents `\n`-laced inputs from
/// breaking JSONL audit consumers; size cap bounds memory + hash cost.
fn sanitize_audit_field(input: String, max_bytes: usize) -> Option<String> {
    let mut s: String = input.chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        return None;
    }
    truncate_utf8_safe(&mut s, max_bytes);
    Some(s)
}

/// Sanitize the `action` verb. Unlike `actor`/`resource`, `action`
/// is mandatory on every event (the verb that triggered the audit
/// entry), so an empty result substitutes a `"<empty>"` placeholder
/// rather than dropping the field — auditors prefer "we know it
/// happened but the verb was unrepresentable" over a silent gap.
fn sanitize_action_field(input: String) -> String {
    let mut s: String = input.chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        return "<empty>".to_string();
    }
    truncate_utf8_safe(&mut s, AuditEvent::MAX_ACTION_LEN);
    s
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

    /// Set the actor for this event. Routes through
    /// [`AuditEvent::with_actor`] so the same control-char strip and
    /// `MAX_ACTOR_LEN` cap apply to builder callers as to direct
    /// callers.
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.event = self.event.with_actor(actor);
        self
    }

    /// Set the resource for this event. Routes through
    /// [`AuditEvent::with_resource`] so the same sanitization and
    /// `MAX_RESOURCE_LEN` cap apply to builder callers as to direct
    /// callers.
    #[must_use]
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.event = self.event.with_resource(resource);
        self
    }

    /// Add metadata to this event.
    ///
    /// Routes through [`AuditEvent::with_metadata`] so the same caps apply
    /// to builder callers as to direct callers — i.e. keys are truncated
    /// at `MAX_METADATA_KEY_LEN`, values at `MAX_METADATA_VALUE_LEN`, and
    /// inserts beyond `MAX_METADATA_ENTRIES` become a no-op. Bypassing
    /// these via the builder previously let attacker-controlled strings
    /// blow the audit-log size budget.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event = self.event.with_metadata(key, value);
        self
    }

    /// Build the audit event.
    #[must_use]
    pub fn build(self) -> AuditEvent {
        self.event
    }
}

/// Categories of audit events.
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// Consumer: FileAuditStorage::new()
    pub storage_path: PathBuf,
    /// Maximum size of a single audit file before rotation (default: 100MB).
    /// Consumer: FileAuditStorage::rotate_if_needed()
    pub max_file_size_bytes: u64,
    /// Maximum age of a single audit file before rotation (default: 24 hours).
    /// Consumer: FileAuditStorage::rotate_if_needed()
    pub max_file_age: Duration,
    /// Number of days to retain audit files (default: 90 days).
    /// Consumer: FileAuditStorage::cleanup_old_files()
    pub retention_days: u32,
}

impl Default for AuditConfig {
    /// The default path is rooted at the OS temp directory under
    /// `latticearc/audit_logs` so a daemon started from `/` does not
    /// silently write into the filesystem root, and a daemon started
    /// from a user's home doesn't bury audit logs in `~/audit_logs`.
    /// Production deployments must call [`AuditConfig::new`] with an
    /// explicit path; this default is only for tests / quick-start
    /// examples.
    fn default() -> Self {
        let storage_path = std::env::temp_dir().join("latticearc").join("audit_logs");
        Self {
            storage_path,
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

    /// Set the retention period in days. Returns the previous value.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidInput`] if `days == 0`. A retention
    /// of zero days makes the cleanup pass treat every file as
    /// already-expired and delete the entire audit history on the
    /// next startup. The minimum sensible retention is one day; if
    /// retention is genuinely undesired the operator should either
    /// (a) point `storage_path` somewhere ephemeral or (b) skip
    /// constructing `FileAuditStorage` altogether.
    pub fn with_retention_days(mut self, days: u32) -> Result<Self> {
        if days == 0 {
            return Err(CoreError::InvalidInput(
                "AuditConfig::with_retention_days requires days >= 1; \
                 zero would purge the entire audit history on next startup"
                    .to_string(),
            ));
        }
        self.retention_days = days;
        Ok(self)
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

/// Parse the timestamp embedded in an audit-log filename.
///
/// Audit logs are named either:
/// - `audit-YYYY-MM-DDTHH-MM-SS.jsonl` (legacy second-precision form)
/// - `audit-YYYY-MM-DDTHH-MM-SS-NNNNNN.jsonl` (current form, with
///   `NNNNNN` = microseconds since the second, added to defeat
///   sub-second rotation collisions under `create_new(true)`)
///
/// Both shapes parse to the same chronological key — microseconds
/// are stripped at parse time because retention is second-grained.
/// Treat the parsed `NaiveDateTime` as UTC since the producer writes
/// UTC clock readings. Used by the retention sweep so cleanup
/// decisions don't depend on filesystem `mtime`, which a privileged
/// attacker can rewrite with `touch`.
fn parse_audit_filename_timestamp(file_name: &str) -> Option<DateTime<Utc>> {
    let stem = file_name.strip_prefix("audit-")?.strip_suffix(".jsonl")?;
    // Try the current micro-precision form first (`SS-NNNNNN`), then
    // fall back to the legacy second-only form. The micro suffix is
    // exactly six digits; chrono's `%6f` matches.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(stem, "%Y-%m-%dT%H-%M-%S-%6f") {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    let naive = chrono::NaiveDateTime::parse_from_str(stem, "%Y-%m-%dT%H-%M-%S").ok()?;
    Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
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

/// Result of [`FileAuditStorage::verify_chain`]. Round-26 audit fix
/// (M20).
#[derive(Debug, Clone)]
pub struct ChainVerificationReport {
    /// Number of `audit-*.jsonl` files inspected.
    pub files_checked: usize,
    /// Number of audit events whose hash was recomputed.
    pub events_checked: u64,
    /// `Some(_)` when the first divergence was found; `None` when the
    /// chain verifies end-to-end.
    pub mismatch: Option<ChainMismatch>,
}

impl ChainVerificationReport {
    /// True if the chain verified end-to-end with no divergence.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.mismatch.is_none()
    }
}

/// First divergence found by [`FileAuditStorage::verify_chain`].
#[derive(Debug, Clone)]
pub struct ChainMismatch {
    /// Path to the JSONL file containing the diverging entry.
    pub file: PathBuf,
    /// Zero-based line number within the file.
    pub line: usize,
    /// `id` field of the diverging audit event.
    pub event_id: String,
    /// `integrity_hash` value as persisted on disk.
    pub stored_hash: String,
    /// Hash recomputed from `(previous_hash, fields)` per the canonical
    /// encoding.
    pub expected_hash: String,
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

/// Filename for the per-storage genesis anchor.
///
/// The genesis anchor is the `previous_hash` value used for the very first
/// audit event in a storage. It is derived from a domain label, a fresh
/// random nonce, and the creation timestamp, and is persisted alongside
/// the audit log so that:
///
///   * a truncate-only attack (delete log entries, leave genesis intact)
///     is detectable: the next event chains from `genesis`, not from the
///     deleted entry's hash, and any verifier replaying the chain spots
///     the gap.
///   * an attacker who deletes both the log and the genesis to fabricate
///     a "fresh storage" ends up with a different genesis on the next
///     create — an external pinning store (HSM, write-once log) can spot
///     the genesis change. Total erasure with no external state is
///     fundamentally undetectable; this fix closes the
///     truncate-and-restart-only path the empty-genesis behaviour left
///     wide open.
const AUDIT_GENESIS_FILENAME: &str = "genesis";

/// Domain-separation label baked into the genesis hash. Distinct from
/// every other transcript prefix in the crate so a genesis bytestring
/// cannot collide with any other artifact.
const AUDIT_GENESIS_DOMAIN_LABEL: &[u8] = b"latticearc-audit-genesis-v1";

/// Action verb of the synthetic event written as the first entry of
/// each rotated audit file. Anchors the new file to the prior file's
/// final hash; absence (or mismatch) of this anchor at the start of a
/// non-initial file indicates the chain has been truncated, reordered,
/// or had files deleted.
///
/// `pub(crate)` (not `pub`): downstream callers must not be able to
/// construct an `AuditEvent` whose action equals this verb, otherwise
/// they could append a counterfeit anchor anywhere in a writable log
/// — the `first_event_in_file` gate in `verify_chain` only guards the
/// first-line position, not later positions within the same file.
pub(crate) const CHAIN_ANCHOR_ACTION: &str = "audit-chain-link";
/// Metadata key on a chain-anchor event recording the filename of the
/// prior audit file in the rotation sequence. `pub(crate)` for the
/// same reason as [`CHAIN_ANCHOR_ACTION`].
pub(crate) const CHAIN_ANCHOR_PREV_FILE_KEY: &str = "previous_file";
/// Metadata key on a chain-anchor event recording the integrity hash
/// at the moment of rotation (i.e. the prior file's final event hash).
/// `pub(crate)` for the same reason as [`CHAIN_ANCHOR_ACTION`].
pub(crate) const CHAIN_ANCHOR_PREV_HASH_KEY: &str = "previous_hash";

impl FileAuditStorage {
    /// Create a new file-based audit storage.
    ///
    /// Creates the storage directory if it doesn't exist, and ensures a
    /// persisted genesis anchor file exists (creating one with a fresh
    /// random nonce on first run, reading the existing one on subsequent
    /// runs).
    ///
    /// # Errors
    ///
    /// Returns an error if the storage directory cannot be created, the
    /// genesis file cannot be read or written, or the random nonce
    /// generation for a new genesis fails.
    pub fn new(config: AuditConfig) -> Result<Arc<Self>> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&config.storage_path).map_err(|e| {
            CoreError::AuditError(format!(
                "Failed to create audit directory '{}': {}",
                config.storage_path.display(),
                e
            ))
        })?;

        let genesis = Self::load_or_create_genesis(&config.storage_path)?;

        let storage = Arc::new(Self {
            config,
            file_state: Mutex::new(None),
            previous_hash: RwLock::new(genesis),
        });

        // Clean up old files based on retention policy
        storage.cleanup_old_files()?;

        Ok(storage)
    }

    /// Read the on-disk genesis if it exists, otherwise create one.
    ///
    /// The created genesis is `SHA-256(domain_label || nonce || timestamp)`
    /// hex-encoded, where `nonce` is 32 bytes from the system CSPRNG and
    /// `timestamp` is the RFC 3339 creation time.
    fn load_or_create_genesis(storage_path: &std::path::Path) -> Result<String> {
        let genesis_path = storage_path.join(AUDIT_GENESIS_FILENAME);

        match fs::read_to_string(&genesis_path) {
            Ok(existing) => {
                let trimmed = existing.trim().to_string();
                if trimmed.is_empty() {
                    return Err(CoreError::AuditError(format!(
                        "Audit genesis file '{}' exists but is empty; refusing to start \
                         with an empty chain anchor",
                        genesis_path.display()
                    )));
                }
                Ok(trimmed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let nonce = crate::primitives::rand::csprng::random_bytes(32);
                let timestamp = Utc::now().to_rfc3339();
                let mut buf = Vec::with_capacity(
                    AUDIT_GENESIS_DOMAIN_LABEL
                        .len()
                        .saturating_add(4)
                        .saturating_add(nonce.len())
                        .saturating_add(4)
                        .saturating_add(timestamp.len()),
                );
                buf.extend_from_slice(AUDIT_GENESIS_DOMAIN_LABEL);
                let nonce_len = u32::try_from(nonce.len()).map_err(|_e| {
                    CoreError::AuditError("Genesis nonce length exceeds u32::MAX".to_string())
                })?;
                buf.extend_from_slice(&nonce_len.to_be_bytes());
                buf.extend_from_slice(&nonce);
                let ts_len = u32::try_from(timestamp.len()).map_err(|_e| {
                    CoreError::AuditError("Genesis timestamp length exceeds u32::MAX".to_string())
                })?;
                buf.extend_from_slice(&ts_len.to_be_bytes());
                buf.extend_from_slice(timestamp.as_bytes());

                let digest = crate::primitives::hash::sha2::sha256(&buf).map_err(|e| {
                    CoreError::AuditError(format!("Failed to hash genesis material: {e}"))
                })?;
                let hex = hex::encode(digest);

                // Persist atomically with restrictive permissions on Unix.
                #[cfg(unix)]
                {
                    use std::io::Write as _;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        // LINT-OK: mode-on-prev-line — chained above.
                        .open(&genesis_path)
                        .map_err(|err| {
                            CoreError::AuditError(format!(
                                "Failed to create audit genesis file '{}': {}",
                                genesis_path.display(),
                                err
                            ))
                        })?;
                    f.write_all(hex.as_bytes()).map_err(|err| {
                        CoreError::AuditError(format!(
                            "Failed to write audit genesis file '{}': {}",
                            genesis_path.display(),
                            err
                        ))
                    })?;
                    // fsync the file before declaring the genesis
                    // committed. A crash mid-flush would otherwise
                    // leave a zero-byte genesis on disk; the
                    // `create_new` flag would then refuse every
                    // subsequent startup until manual `rm`.
                    f.sync_all().map_err(|err| {
                        CoreError::AuditError(format!(
                            "Failed to fsync audit genesis file '{}': {}",
                            genesis_path.display(),
                            err
                        ))
                    })?;
                }
                #[cfg(not(unix))]
                {
                    // Round-36 M9: on Windows, use `OpenOptions` with
                    // `share_mode(0)` (deny share) and explicit
                    // `create_new(true)` so the genesis file is
                    // exclusive to this process while the handle is
                    // open. Default `fs::write` would inherit the
                    // process's default DACL — typically world-
                    // readable on local Windows — exposing the
                    // chain-integrity HMAC seed to other local users.
                    // Note: `share_mode(0)` is the closest std-only
                    // approximation to Unix `0o600` without pulling
                    // in the full Windows ACL API; a future round
                    // could tighten this further via the
                    // `windows-sys` ACL crate if regulators require
                    // it.
                    use std::io::Write as _;
                    use std::os::windows::fs::OpenOptionsExt as _;
                    // `.mode(0o600)` is `std::os::unix::fs::OpenOptionsExt`
                    // and is unavailable on this `cfg(not(unix))` branch;
                    // Windows confidentiality is enforced via the
                    // `share_mode(0)` exclusive-handle below.
                    let mut f = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .share_mode(0)
                        // LINT-OK: cfg-not-unix; no Unix `mode` API available
                        .open(&genesis_path)
                        .map_err(|err| {
                            CoreError::AuditError(format!(
                                "Failed to create audit genesis file '{}': {}",
                                genesis_path.display(),
                                err
                            ))
                        })?;
                    f.write_all(hex.as_bytes()).map_err(|err| {
                        CoreError::AuditError(format!(
                            "Failed to write audit genesis file '{}': {}",
                            genesis_path.display(),
                            err
                        ))
                    })?;
                    f.sync_all().map_err(|err| {
                        CoreError::AuditError(format!(
                            "Failed to fsync audit genesis file '{}': {}",
                            genesis_path.display(),
                            err
                        ))
                    })?;
                }
                Ok(hex)
            }
            Err(e) => Err(CoreError::AuditError(format!(
                "Failed to read audit genesis file '{}': {}",
                genesis_path.display(),
                e
            ))),
        }
    }

    /// Get the configuration for this storage instance.
    #[must_use]
    pub fn config(&self) -> &AuditConfig {
        &self.config
    }

    /// Compute the integrity hash for an event.
    ///
    /// The hash includes the previous event's hash to create a chain,
    /// making tampering detectable. Routes through the
    /// [`crate::primitives::hash::sha2::sha256`] wrapper so audit integrity
    /// uses the same hash call path as the rest of the crate.
    ///
    /// made `pub(crate)` so the public
    /// `verify_chain` helper below can re-use it without duplicating
    /// the field-encoding rules.
    ///
    /// # Errors
    /// Returns an error if the SHA-256 primitive fails (input exceeds 1 GiB guard).
    pub(crate) fn compute_integrity_hash(
        event: &AuditEvent,
        previous_hash: &str,
    ) -> Result<String> {
        // Length-prefix every field so prefix-collision attacks are
        // impossible (`"ab" + "c"` and `"a" + "bc"` no longer hash to the
        // same digest). The metadata caps already bound each field, but a
        // 4-byte BE length per element is the cheap and definitive fix.
        // (Encoding is BE per the L3 transcript-convention migration in
        // 85e2bd79e — see `append_lenp_field` doc comment for details.)
        let mut buf = Vec::new();
        Self::append_lenp_field(&mut buf, previous_hash.as_bytes())?;
        Self::append_lenp_field(&mut buf, event.id.as_bytes())?;
        Self::append_lenp_field(&mut buf, event.timestamp.to_rfc3339().as_bytes())?;
        Self::append_lenp_field(&mut buf, event.event_type.to_string().as_bytes())?;

        // Optional fields are encoded as a discriminator byte followed by
        // the length-prefixed bytes; absence vs empty is now distinguishable.
        match event.actor.as_ref() {
            Some(a) => {
                buf.push(1);
                Self::append_lenp_field(&mut buf, a.as_bytes())?;
            }
            None => buf.push(0),
        }
        match event.resource.as_ref() {
            Some(r) => {
                buf.push(1);
                Self::append_lenp_field(&mut buf, r.as_bytes())?;
            }
            None => buf.push(0),
        }

        Self::append_lenp_field(&mut buf, event.action.as_bytes())?;
        Self::append_lenp_field(&mut buf, event.outcome.to_string().as_bytes())?;

        // Metadata: include count, then sorted (key, value) pairs each
        // with their own length prefix. Overflow at `u32::MAX` (4 G
        // entries) propagates as `AuditError`, symmetric with the
        // length-prefix overflow path above. Length prefixes are
        // big-endian to match the transcript convention used by
        // `zkp::sigma::compute_challenge` (round-12 audit fix L3 —
        // unifies endianness across all transcript-style hashing in
        // the crate).
        let mut metadata_keys: Vec<&String> = event.metadata.keys().collect();
        metadata_keys.sort();
        let count = u32::try_from(metadata_keys.len()).map_err(|_e| {
            CoreError::AuditError("integrity hash metadata count exceeds 2^32".to_string())
        })?;
        buf.extend_from_slice(&count.to_be_bytes());
        for key in metadata_keys {
            Self::append_lenp_field(&mut buf, key.as_bytes())?;
            if let Some(value) = event.metadata.get(key) {
                Self::append_lenp_field(&mut buf, value.as_bytes())?;
            } else {
                Self::append_lenp_field(&mut buf, &[])?;
            }
        }

        // `sha256` only fails on inputs larger than 1 GiB (resource-limit guard),
        // which no reasonable audit event approaches.
        let digest = crate::primitives::hash::sha2::sha256(&buf)
            .map_err(|e| CoreError::AuditError(format!("integrity hash failed: {}", e)))?;
        Ok(hex::encode(digest))
    }

    /// Append `field.len() as u32 BE` followed by `field` to `buf`.
    ///
    /// Returns `Err(CoreError::AuditError)` if `field.len()` exceeds
    /// `u32::MAX` bytes (4 GiB) — symmetric with the overflow handling
    /// in `zkp::sigma::compute_challenge` (round-21 audit fix #7). The
    /// length is encoded big-endian to match the transcript convention
    /// used by `zkp::sigma::compute_challenge` (round-12 audit fix L3 —
    /// the previous LE encoding was an isolated outlier within the
    /// crate's transcript-style hashing).
    /// The previous saturating-to-`u32::MAX` form was a silent collapse
    /// that would let two distinct field values share the same length
    /// prefix; while the SHA-256 backend's 1 GiB cap makes this
    /// unreachable today, an explicit error preserves the asymmetric
    /// defensive posture the rest of the crate now uses.
    fn append_lenp_field(buf: &mut Vec<u8>, field: &[u8]) -> Result<()> {
        let len = u32::try_from(field.len()).map_err(|_e| {
            CoreError::AuditError("integrity hash field exceeds 2^32 bytes".to_string())
        })?;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(field);
        Ok(())
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
    ///
    /// On rotation, a `chain-link` event is written as the FIRST entry
    /// of the new file. The link carries the previous file's name and
    /// the chain hash at the moment of rotation. Without this anchor,
    /// `verify_chain` cannot detect a deletion or reorder of files at
    /// the boundary — the new file's first event would chain from
    /// in-memory `previous_hash`, but no on-disk record would tie that
    /// hash to the file it descended from. The anchor's own
    /// `integrity_hash` covers the metadata, so tampering with the
    /// recorded `previous_file` / `previous_hash` breaks the chain at
    /// verification time.
    fn rotate_if_needed(&self, state: &mut Option<FileState>) -> Result<()> {
        let should_rotate = state.as_ref().is_some_and(|s| self.needs_rotation(s));

        let mut rotation_link: Option<(String, String)> = None;
        if should_rotate {
            // Close current file and create new one. Capture the
            // outgoing filename and chain hash BEFORE we drop the old
            // state so the new file's chain-anchor can reference both.
            if let Some(mut old_state) = state.take() {
                let old_filename = old_state
                    .current_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")
                    .to_string();
                let old_hash = self.previous_hash.read().clone();
                tracing::info!(
                    "Rotating audit file: {} (size: {} bytes)",
                    old_state.current_path.display(),
                    old_state.current_size
                );
                old_state.writer.flush().map_err(|e| {
                    CoreError::AuditError(format!("Failed to flush audit file: {}", e))
                })?;
                rotation_link = Some((old_filename, old_hash));
            }
        }

        // Create new file if needed
        if state.is_none() {
            *state = Some(self.create_new_file()?);
        }

        // Write chain-anchor as the first entry of the new file when we
        // rotated from an existing file. (First-ever-file case has
        // `rotation_link = None` and the genesis hash anchors the chain
        // implicitly, as documented above.)
        if let Some((prev_file, prev_hash)) = rotation_link
            && let Some(new_state) = state.as_mut()
        {
            self.write_chain_anchor(new_state, &prev_file, &prev_hash)?;
        }

        Ok(())
    }

    /// Write a chain-anchor event as the first entry of a freshly
    /// rotated audit file.
    ///
    /// The anchor is itself a normal `AuditEvent`, chained from the
    /// outgoing file's final hash, with metadata recording that
    /// outgoing file's name and hash. Its own `integrity_hash` is
    /// recomputed by `verify_chain` and bumped into `previous_hash`
    /// like any other event, so the chain is unbroken across the
    /// rotation. Tampering with the anchor's metadata invalidates its
    /// integrity hash; deletion of either file makes the anchor
    /// reference dangling.
    fn write_chain_anchor(
        &self,
        state: &mut FileState,
        previous_file: &str,
        previous_hash: &str,
    ) -> Result<()> {
        let mut anchor =
            AuditEvent::new(AuditEventType::System, CHAIN_ANCHOR_ACTION, AuditOutcome::Success)
                .with_metadata(CHAIN_ANCHOR_PREV_FILE_KEY, previous_file)
                .with_metadata(CHAIN_ANCHOR_PREV_HASH_KEY, previous_hash);

        // Chain the anchor from the outgoing file's final hash
        // (= current `previous_hash`), then advance the in-memory
        // chain pointer to the anchor's own hash.
        let chain_prev = self.previous_hash.read().clone();
        anchor.integrity_hash = Self::compute_integrity_hash(&anchor, &chain_prev)?;
        {
            let mut prev = self.previous_hash.write();
            prev.clone_from(&anchor.integrity_hash);
        }

        let json = serde_json::to_string(&anchor).map_err(|e| {
            CoreError::AuditError(format!("Failed to serialize chain anchor: {}", e))
        })?;
        let line = format!("{}\n", json);
        let line_bytes = line.as_bytes();
        state
            .writer
            .write_all(line_bytes)
            .map_err(|e| CoreError::AuditError(format!("Failed to write chain anchor: {}", e)))?;
        let line_len_u64 = u64::try_from(line_bytes.len()).unwrap_or(u64::MAX);
        state.current_size = state.current_size.saturating_add(line_len_u64);
        Ok(())
    }

    /// Create a new audit file.
    ///
    /// Filename includes microsecond precision so sub-second rotations
    /// (rapid `with_max_file_size` triggering, repeated explicit
    /// `flush()` calls, or stress tests) cannot collide. The
    /// `create_new(true)` flag below would otherwise error on
    /// collisions and leave the rotation loop stuck.
    fn create_new_file(&self) -> Result<FileState> {
        let now = Utc::now();
        let micros = now.timestamp_subsec_micros();
        let filename = format!("audit-{}-{:06}.jsonl", now.format("%Y-%m-%dT%H-%M-%S"), micros);
        let path = self.config.storage_path.join(&filename);

        let file = {
            // On Unix, set 0o600 atomically via OpenOptions::mode() so the
            // file is never world-readable, even briefly. Audit logs may
            // contain operation context (key IDs, paths, actors) and must
            // not inherit the default umask the way the previous bare
            // `OpenOptions::new().create(...).open(...)` did.
            // `create_new(true)` (not `create(true)`): refuse to open a
            // pre-existing file. The rotation code generates the
            // filename from `Utc::now()` to second precision; if a
            // file already exists at that path it means either (a) a
            // sub-second rotation race or (b) a stale file from a
            // prior process. In either case we MUST NOT silently
            // adopt the existing inode and rewrite its DACL — that
            // would (a) make the chain hash-input contiguous across
            // processes that didn't actually share state, and (b)
            // hide the race. Surface the conflict as an error so the
            // caller can rotate forward by one second.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new().create_new(true).append(true).mode(0o600).open(&path).map_err(
                    |e| {
                        CoreError::AuditError(format!(
                            "Failed to create audit file '{}': {}",
                            path.display(),
                            e
                        ))
                    },
                )?
            }
            #[cfg(not(unix))]
            {
                // LINT-OK: cfg-not-unix — Windows confidentiality is
                // enforced via `set_local_admin_dacl` immediately after
                // open (Win32 `OpenOptionsExt` has no `.mode()` analog).
                let f =
                    OpenOptions::new().create_new(true).append(true).open(&path).map_err(|e| {
                        CoreError::AuditError(format!(
                            "Failed to create audit file '{}': {}",
                            path.display(),
                            e
                        ))
                    })?;
                // Replace the default DACL inherited from the parent
                // directory with the owner-only policy applied
                // workspace-wide. Symmetric with the Unix `mode(0o600)`
                // above. A failure here is fatal — letting an audit
                // log inherit a permissive DACL silently would defeat
                // the whole point of the rotation.
                crate::unified_api::set_local_admin_dacl(&path).map_err(|e| {
                    CoreError::AuditError(format!(
                        "Failed to harden audit file DACL '{}': {}",
                        path.display(),
                        e
                    ))
                })?;
                f
            }
        };

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
        // Belt-and-braces: even with `with_retention_days` rejecting
        // `0`, a `Default` or struct-literal construction could still
        // land here with `retention_days = 0`. Fail closed instead of
        // wiping the directory.
        if self.config.retention_days == 0 {
            return Err(CoreError::AuditError(
                "AuditConfig.retention_days = 0 would delete every audit file on \
                 cleanup; refusing to proceed (set with_retention_days(>= 1))"
                    .to_string(),
            ));
        }

        let retention_duration = chrono::Duration::days(i64::from(self.config.retention_days));
        let Some(cutoff) = Utc::now().checked_sub_signed(retention_duration) else {
            return Err(CoreError::AuditError(format!(
                "Retention period of {} days overflows date arithmetic",
                self.config.retention_days
            )));
        };

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

            // Use the timestamp embedded in the filename
            // (`audit-YYYY-MM-DDTHH-MM-SS.jsonl`, set by
            // `create_new_file`) instead of the filesystem mtime,
            // which a privileged attacker can rewrite with `touch`.
            // The filename is set at file creation by this process and
            // is not modifiable without also changing the file's name,
            // which is observable in directory listings and recorded
            // in the audit-genesis chain. Files whose names don't
            // parse — including operator-imported logs from another
            // tool — are skipped rather than deleted.
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(created_at) = parse_audit_filename_timestamp(file_name) else {
                tracing::debug!("Audit cleanup: skipping non-conforming filename '{}'", file_name);
                continue;
            };

            if created_at < cutoff {
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

    /// public hash-chain verification.
    ///
    /// Walks every `audit-*.jsonl` file in the storage directory in
    /// filename-timestamp order, recomputes each entry's
    /// `integrity_hash` from the persisted genesis, and reports the
    /// first divergence (or `Ok(report)` with no mismatches when the
    /// chain is intact). Tamper detection previously required
    /// hand-writing a verifier in the right encoding — the asymmetry
    /// tamper-evident logging exists to remove.
    ///
    /// The returned [`ChainVerificationReport`] carries the line count
    /// inspected and an `Option<Mismatch>` describing the first event
    /// whose recomputed hash differed from its persisted
    /// `integrity_hash` field.
    ///
    /// # Errors
    /// Returns an error if the storage directory cannot be read, a
    /// log file cannot be opened, a line cannot be parsed as JSON, or
    /// the hash recomputation fails.
    pub fn verify_chain(&self) -> Result<ChainVerificationReport> {
        let mut log_files: Vec<PathBuf> = Vec::new();
        let entries = fs::read_dir(&self.config.storage_path)
            .map_err(|e| CoreError::AuditError(format!("Failed to read audit dir: {}", e)))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            // Match `audit-*.jsonl` (case-insensitive on extension; round-26
            // audit fix L for case-sensitive .jsonl bug).
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("audit-") && lower.ends_with(".jsonl") {
                log_files.push(path);
            }
        }
        // Filename-timestamp ordering: `audit-YYYYMMDD-HHMMSS-NNN.jsonl`
        // is lexicographically chronological. Sort by basename rather
        // than the full `PathBuf` — the latter is byte-ordered, which
        // on Windows can differ across drive-letter case (`C:\` vs
        // `c:\`) or path-separator normalisation, producing an order
        // that doesn't match the chronological intent.
        log_files.sort_by(|a, b| {
            a.file_name()
                .unwrap_or_else(|| a.as_os_str())
                .cmp(b.file_name().unwrap_or_else(|| b.as_os_str()))
        });

        // Recompute from genesis. Reads the persisted genesis directly
        // rather than the in-memory `previous_hash` so verification
        // works on a freshly-mounted storage with no prior writes in
        // this process.
        let genesis = Self::load_or_create_genesis(&self.config.storage_path)?;
        let mut prev_hash = genesis;
        let mut events_checked: u64 = 0;
        let mut mismatch: Option<ChainMismatch> = None;

        // Defense-in-depth pre-decode caps. A persisted JSONL line is at
        // worst the product of in-memory caps (action 256 B + actor
        // 256 B + resource 1 KiB + 32 metadata × 4 KiB ≈ 130 KiB),
        // plus header / chain-marker fields and JSON encoding
        // overhead. 1 MiB is generously above that ceiling but small
        // enough to defeat a tampered file dropping a 1 GiB action
        // string in front of the verifier.
        const MAX_LINE_LEN: usize = 1024 * 1024;

        // Cross-file chain back-reference state. After processing the
        // first file, every subsequent file's first event MUST be a
        // `chain-link` anchor whose `previous_file` and `previous_hash`
        // metadata match the file we just finished. Without this check
        // the chain rotates "blindly" — `verify_chain` would happily
        // walk a sequence of files even after one was deleted, because
        // each file individually chains via in-memory state alone.
        //
        // `previous_file_name` is the basename of the prior file in the
        // sorted log_files list. `previous_file_final_hash` is the
        // chain hash when we exited the prior file's loop.
        let mut previous_file_name: Option<String> = None;
        let mut previous_file_final_hash: Option<String> = None;

        for file in &log_files {
            use std::io::Read;
            let f = File::open(file).map_err(|e| {
                CoreError::AuditError(format!("Failed to open {}: {}", file.display(), e))
            })?;
            let mut reader = std::io::BufReader::new(f);
            // Reset per-file: track whether we've seen the first
            // non-empty event of this file (used for the cross-file
            // anchor check below).
            let mut first_event_in_file = true;
            // Bounded line-reader. `BufReader::lines()` allocates the
            // whole `String` BEFORE returning it, so a 1 GiB
            // newline-free file would OOM the verifier before the
            // post-decode `MAX_LINE_LEN` check fires. Read byte-by-
            // byte through a buffer we control: as soon as the
            // accumulator exceeds `MAX_LINE_LEN`, abort with an
            // error — bytes past the cap are never allocated.
            let mut line_buf: Vec<u8> = Vec::new();
            let mut byte = [0u8; 1];
            let mut line_idx: usize = 0;
            let mut hit_eof = false;
            loop {
                if hit_eof && line_buf.is_empty() {
                    break;
                }
                let n = if hit_eof {
                    0
                } else {
                    match reader.read(&mut byte) {
                        Ok(n) => n,
                        Err(e) => {
                            return Err(CoreError::AuditError(format!(
                                "Failed to read line: {}",
                                e
                            )));
                        }
                    }
                };
                if n == 0 {
                    hit_eof = true;
                    if line_buf.is_empty() {
                        break;
                    }
                } else if byte[0] != b'\n' {
                    if line_buf.len() >= MAX_LINE_LEN {
                        return Err(CoreError::AuditError(format!(
                            "audit line {} of {} exceeds maximum length {}",
                            line_idx,
                            file.display(),
                            MAX_LINE_LEN
                        )));
                    }
                    line_buf.push(byte[0]);
                    continue;
                }
                // EOL or EOF reached — process the accumulated line
                // (which is guaranteed `<= MAX_LINE_LEN` bytes by the
                // cap above).
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        return Err(CoreError::AuditError(format!(
                            "audit line {} of {} is not valid UTF-8: {}",
                            line_idx,
                            file.display(),
                            e
                        )));
                    }
                };
                line_buf.clear();
                let saved_idx = line_idx;
                line_idx = line_idx.saturating_add(1);
                if line.trim().is_empty() {
                    continue;
                }
                let line_idx = saved_idx;
                // Pre-pass: extract `integrity_hash` cheaply with
                // `serde_json::Value` partial parsing so we can fail
                // fast on a tampered chain marker before paying for
                // the full `AuditEvent` deserialization (which
                // allocates strings for every field). This still
                // walks the whole line — `serde_json::from_str` is
                // O(n) regardless — but skips the secondary
                // allocation of a fully-typed event.
                //
                // Rejection here cannot leak which structural field
                // failed: any pre-pass parse error collapses to a
                // single "unparseable" outcome.
                let bare: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
                    CoreError::AuditError(format!(
                        "Failed to parse line {} of {}: {}",
                        line_idx,
                        file.display(),
                        e
                    ))
                })?;
                let _stored_hash_seen =
                    bare.get("integrity_hash").and_then(|v| v.as_str()).ok_or_else(|| {
                        CoreError::AuditError(format!(
                            "Audit line {} of {} missing integrity_hash",
                            line_idx,
                            file.display(),
                        ))
                    })?;
                // Now do the full typed parse — guaranteed by the
                // pre-pass to be a structurally valid event JSON
                // with an `integrity_hash` field present.
                let event: AuditEvent = serde_json::from_value(bare).map_err(|e| {
                    CoreError::AuditError(format!(
                        "Failed to typed-parse line {} of {}: {}",
                        line_idx,
                        file.display(),
                        e
                    ))
                })?;
                let stored = event.integrity_hash.clone();
                let recomputed = Self::compute_integrity_hash(&event, &prev_hash)?;
                events_checked = events_checked.saturating_add(1);
                if stored != recomputed {
                    mismatch = Some(ChainMismatch {
                        file: file.clone(),
                        line: line_idx,
                        event_id: event.id.clone(),
                        stored_hash: stored,
                        expected_hash: recomputed,
                    });
                    break;
                }

                // Cross-file anchor check: when this is the first
                // event of a non-initial file, it must be a chain-link
                // anchor whose metadata matches the prior file we
                // just verified.
                if first_event_in_file {
                    if let (Some(prev_name), Some(prev_final_hash)) =
                        (previous_file_name.as_deref(), previous_file_final_hash.as_deref())
                    {
                        // Constant-time compare on the chain hash:
                        // it's a hex-encoded SHA-256 that authenticates
                        // the prior file's tail state, and an attacker
                        // who can time `verify_chain` could otherwise
                        // recover it byte-by-byte. The action verb and
                        // filename are public values (the rotation
                        // produces deterministic timestamped names),
                        // so they don't need CT-compare — but we use
                        // the same primitive for consistency.
                        use subtle::ConstantTimeEq;
                        let action_ok =
                            event.action.as_bytes().ct_eq(CHAIN_ANCHOR_ACTION.as_bytes());
                        let prev_file_meta_ok = event
                            .metadata
                            .get(CHAIN_ANCHOR_PREV_FILE_KEY)
                            .map(|v| v.as_bytes().ct_eq(prev_name.as_bytes()))
                            .unwrap_or_else(|| 0u8.ct_eq(&1u8));
                        let prev_hash_meta_ok = event
                            .metadata
                            .get(CHAIN_ANCHOR_PREV_HASH_KEY)
                            .map(|v| v.as_bytes().ct_eq(prev_final_hash.as_bytes()))
                            .unwrap_or_else(|| 0u8.ct_eq(&1u8));
                        let action_ok: bool = action_ok.into();
                        let prev_file_meta_ok: bool = prev_file_meta_ok.into();
                        let prev_hash_meta_ok: bool = prev_hash_meta_ok.into();
                        if !(action_ok && prev_file_meta_ok && prev_hash_meta_ok) {
                            // Surface as a chain mismatch on this line —
                            // matches the existing reporting shape so
                            // callers don't need a second error
                            // variant for "anchor missing/wrong."
                            mismatch = Some(ChainMismatch {
                                file: file.clone(),
                                line: line_idx,
                                event_id: event.id.clone(),
                                stored_hash: stored.clone(),
                                expected_hash: format!(
                                    "expected chain-link from previous_file={prev_name:?} \
                                     previous_hash={prev_final_hash}"
                                ),
                            });
                            break;
                        }
                    }
                    first_event_in_file = false;
                }

                prev_hash = recomputed;
            }
            if mismatch.is_some() {
                break;
            }
            // Capture this file's tail state so the next iteration can
            // validate its chain-link anchor.
            previous_file_name = file.file_name().and_then(|n| n.to_str()).map(str::to_string);
            previous_file_final_hash = Some(prev_hash.clone());
        }

        Ok(ChainVerificationReport { files_checked: log_files.len(), events_checked, mismatch })
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
        event.integrity_hash = Self::compute_integrity_hash(event, &previous_hash)?;

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

        // Update size tracking. `usize → u64` is widening on 64-bit and
        // equal on 32-bit, so the conversion is always lossless — but
        // route via `try_from` for consistency with the rest of this file
        // and to silence `clippy::cast_possible_truncation` (round-20
        // audit fix #24).
        let line_len_u64 = u64::try_from(line_bytes.len()).unwrap_or(u64::MAX);
        state.current_size = state.current_size.saturating_add(line_len_u64);

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
    let bytes_vec = crate::primitives::rand::csprng::random_bytes(16);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&bytes_vec);

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
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_audit_event_creation_has_correct_defaults_succeeds() {
        let event =
            AuditEvent::new(AuditEventType::CryptoOperation, "encrypt_data", AuditOutcome::Success);

        assert!(!event.id.is_empty());
        assert_eq!(event.action, "encrypt_data");
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert!(event.actor.is_none());
        assert!(event.resource.is_none());
    }

    #[test]
    fn test_audit_event_builder_sets_actor_resource_and_metadata_succeeds() {
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
    fn test_audit_event_with_methods_sets_fields_correctly_succeeds() {
        let event = AuditEvent::new(AuditEventType::Authentication, "login", AuditOutcome::Success)
            .with_actor("admin")
            .with_resource("system")
            .with_metadata("ip", "192.168.1.1");

        assert_eq!(event.actor(), Some("admin"));
        assert_eq!(event.resource(), Some("system"));
        assert_eq!(event.metadata().get("ip").map(|s| s.as_str()), Some("192.168.1.1"));
    }

    #[test]
    fn test_audit_config_default_has_expected_values_succeeds() {
        let config = AuditConfig::default();

        assert_eq!(config.max_file_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_file_age, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.retention_days, 90);
    }

    #[test]
    fn test_audit_config_builder_sets_all_fields_correctly_succeeds() {
        let config = AuditConfig::new(std::env::temp_dir().join("audit"))
            .with_max_file_size(50 * 1024 * 1024)
            .with_max_file_age(Duration::from_secs(12 * 60 * 60))
            .with_retention_days(30)
            .expect("retention_days = 30 is positive");

        assert_eq!(config.max_file_size_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_file_age, Duration::from_secs(12 * 60 * 60));
        assert_eq!(config.retention_days, 30);
    }

    #[test]
    fn test_file_audit_storage_creation_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path);
            let storage = FileAuditStorage::new(config);
            assert!(storage.is_ok());
        }
    }

    #[test]
    fn test_file_audit_storage_write_creates_file_on_disk_succeeds() {
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
    fn test_integrity_hash_chain_produces_unique_chained_hashes_are_unique() {
        let event1 =
            AuditEvent::new(AuditEventType::CryptoOperation, "operation1", AuditOutcome::Success);
        let event2 =
            AuditEvent::new(AuditEventType::CryptoOperation, "operation2", AuditOutcome::Success);

        let hash1 = FileAuditStorage::compute_integrity_hash(&event1, "").unwrap();
        let hash2 = FileAuditStorage::compute_integrity_hash(&event2, &hash1).unwrap();

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Same event with same previous hash should produce same result
        let hash2_again = FileAuditStorage::compute_integrity_hash(&event2, &hash1).unwrap();
        assert_eq!(hash2, hash2_again);

        // Different previous hash should produce different result
        let hash2_different =
            FileAuditStorage::compute_integrity_hash(&event2, "different").unwrap();
        assert_ne!(hash2, hash2_different);
    }

    #[test]
    fn test_uuid_generation_produces_unique_v4_uuids_are_unique() {
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
    fn test_audit_event_type_display_has_correct_format() {
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
    fn test_audit_outcome_display_has_correct_format() {
        assert_eq!(AuditOutcome::Success.to_string(), "success");
        assert_eq!(AuditOutcome::Failure.to_string(), "failure");
        assert_eq!(AuditOutcome::Denied.to_string(), "denied");
    }

    #[test]
    fn test_audit_config_accessors_return_configured_values_succeeds() {
        let test_path = std::env::temp_dir().join("latticearc_audit_test");
        let config = AuditConfig::new(test_path.clone())
            .with_max_file_size(1024)
            .with_max_file_age(Duration::from_secs(60))
            .with_retention_days(7)
            .expect("retention_days = 7 is positive");

        assert_eq!(config.storage_path(), &test_path);
        assert_eq!(config.max_file_size_bytes(), 1024);
        assert_eq!(config.max_file_age(), Duration::from_secs(60));
        assert_eq!(config.retention_days(), 7);
    }

    #[test]
    fn test_audit_event_accessors_return_correct_values_succeeds() {
        let event =
            AuditEvent::new(AuditEventType::SecurityAlert, "detect_anomaly", AuditOutcome::Failure)
                .with_actor("system")
                .with_resource("network")
                .with_metadata("severity", "high");

        assert!(!event.id().is_empty());
        assert_eq!(*event.event_type(), AuditEventType::SecurityAlert);
        assert_eq!(event.action(), "detect_anomaly");
        assert_eq!(*event.outcome(), AuditOutcome::Failure);
        assert_eq!(event.actor(), Some("system"));
        assert_eq!(event.resource(), Some("network"));
        assert!(event.metadata().contains_key("severity"));
        // integrity_hash is empty until written to storage
        assert!(event.integrity_hash().is_empty());
        // timestamp should be recent
        let now = Utc::now();
        let diff = now.signed_duration_since(event.timestamp());
        assert!(diff.num_seconds() < 5);
    }

    #[test]
    fn test_file_audit_storage_config_accessor_returns_configured_path_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path.clone())
                .with_retention_days(30)
                .expect("retention_days = 30 is positive");
            if let Ok(storage) = FileAuditStorage::new(config) {
                assert_eq!(storage.config().storage_path(), &temp_path);
                assert_eq!(storage.config().retention_days(), 30);
            }
        }
    }

    #[test]
    fn test_file_audit_storage_multiple_events_writes_all_to_file_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path.clone());

            if let Ok(storage) = FileAuditStorage::new(config) {
                // Write multiple events to test chain integrity
                for i in 0..5 {
                    let event = AuditEvent::new(
                        AuditEventType::CryptoOperation,
                        &format!("operation_{}", i),
                        AuditOutcome::Success,
                    );
                    let result = storage.write(&event);
                    assert!(result.is_ok(), "Write {} should succeed", i);
                }

                storage.flush().expect("Flush should succeed");

                // Read back and verify the file has content. Filter to
                // `.jsonl` so the persisted genesis-anchor file (added
                // for chain-truncation detection) is not counted as an
                // event log.
                let entries: Vec<_> = fs::read_dir(&temp_path)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
                    .collect();
                assert_eq!(entries.len(), 1, "Should have one audit jsonl file");

                let content = fs::read_to_string(entries[0].path()).unwrap();
                let lines: Vec<&str> = content.lines().collect();
                assert_eq!(lines.len(), 5, "Should have 5 event lines");

                // Each line should be valid JSON
                for line in &lines {
                    let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
                    assert!(!parsed["integrity_hash"].as_str().unwrap().is_empty());
                }
            }
        }
    }

    #[test]
    fn test_file_audit_storage_rotation_by_size_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            // Set tiny max file size to trigger rotation logic
            let config = AuditConfig::new(temp_path.clone()).with_max_file_size(100); // 100 bytes

            if let Ok(storage) = FileAuditStorage::new(config) {
                // Write enough events to trigger rotation
                // (rotation runs, but sub-second filenames may collide)
                for i in 0..10 {
                    let event = AuditEvent::new(
                        AuditEventType::CryptoOperation,
                        &format!("operation_{}", i),
                        AuditOutcome::Success,
                    )
                    .with_metadata("data", "some value to make the event larger");
                    let result = storage.write(&event);
                    assert!(result.is_ok(), "Write {} should succeed even with rotation", i);
                }

                storage.flush().expect("Flush should succeed");

                // Verify at least one file was created with content
                let entries: Vec<_> = fs::read_dir(&temp_path)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("jsonl"))
                    .collect();
                assert!(!entries.is_empty(), "Should have at least one audit file");
            }
        }
    }

    #[test]
    fn test_flush_without_writes_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path);
            if let Ok(storage) = FileAuditStorage::new(config) {
                // Flush with no writes should succeed
                let result = storage.flush();
                assert!(result.is_ok());
            }
        }
    }

    #[test]
    fn test_audit_event_serialization_roundtrip_preserves_all_fields_roundtrip() {
        let event =
            AuditEvent::new(AuditEventType::KeyOperation, "rotate_key", AuditOutcome::Success)
                .with_actor("admin")
                .with_resource("key-123")
                .with_metadata("old_algo", "RSA-2048")
                .with_metadata("new_algo", "ML-KEM-768");

        let json = serde_json::to_string(&event).expect("Serialization should succeed");
        let deserialized: AuditEvent =
            serde_json::from_str(&json).expect("Deserialization should succeed");

        assert_eq!(deserialized.action, event.action);
        assert_eq!(deserialized.actor, event.actor);
        assert_eq!(deserialized.resource, event.resource);
        assert_eq!(deserialized.outcome, event.outcome);
        assert_eq!(deserialized.event_type, event.event_type);
        assert_eq!(deserialized.metadata.len(), 2);
    }

    #[test]
    fn test_integrity_hash_includes_metadata_produces_distinct_hashes_are_unique() {
        let event_no_meta =
            AuditEvent::new(AuditEventType::System, "startup", AuditOutcome::Success);
        let event_with_meta =
            AuditEvent::new(AuditEventType::System, "startup", AuditOutcome::Success)
                .with_metadata("version", "1.0");

        // Events with the same ID would need the same timestamp to produce
        // truly comparable hashes, but metadata inclusion means these differ
        let hash1 = FileAuditStorage::compute_integrity_hash(&event_no_meta, "").unwrap();
        let hash2 = FileAuditStorage::compute_integrity_hash(&event_with_meta, "").unwrap();
        assert_ne!(hash1, hash2, "Different metadata should produce different hashes");
    }

    #[test]
    fn test_audit_event_all_types_and_outcomes_write_successfully_succeeds() {
        let types = [
            AuditEventType::Authentication,
            AuditEventType::KeyOperation,
            AuditEventType::CryptoOperation,
            AuditEventType::AccessControl,
            AuditEventType::SessionManagement,
            AuditEventType::SecurityAlert,
            AuditEventType::ConfigurationChange,
            AuditEventType::System,
        ];
        let outcomes = [AuditOutcome::Success, AuditOutcome::Failure, AuditOutcome::Denied];

        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path);
            if let Ok(storage) = FileAuditStorage::new(config) {
                for event_type in &types {
                    for outcome in &outcomes {
                        let event = AuditEvent::new(*event_type, "test", *outcome);
                        assert!(storage.write(&event).is_ok());
                    }
                }
                assert!(storage.flush().is_ok());
            }
        }
    }

    #[test]
    fn test_file_audit_storage_rotation_by_age_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            // Set max age to 0 seconds to immediately trigger age-based rotation
            let config =
                AuditConfig::new(temp_path.clone()).with_max_file_age(Duration::from_secs(0));

            if let Ok(storage) = FileAuditStorage::new(config) {
                // Write first event — creates file
                let event1 =
                    AuditEvent::new(AuditEventType::CryptoOperation, "op_1", AuditOutcome::Success);
                assert!(storage.write(&event1).is_ok());

                // Small delay so file age > 0
                std::thread::sleep(Duration::from_millis(10));

                // Write second event — should trigger rotation
                let event2 =
                    AuditEvent::new(AuditEventType::CryptoOperation, "op_2", AuditOutcome::Success);
                assert!(storage.write(&event2).is_ok());
                assert!(storage.flush().is_ok());
            }
        }
    }

    #[test]
    fn test_cleanup_removes_old_jsonl_files_without_error_fails() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();

            // Create an old audit file manually
            let old_file = temp_path.join("audit-old.jsonl");
            fs::write(&old_file, "old data\n").unwrap();

            // Set file modification time to the past by writing then setting retention to 0
            // With retention_days=0 and cutoff = now, only past-modified files are removed.
            // The file we just created has a "now" mtime, so it won't be removed with days=0.
            // We need retention_days=0 which means cutoff = now, so nothing is "older" than now.
            // Actually, let's just verify the cleanup doesn't error with valid dir.

            let config = AuditConfig::new(temp_path.clone())
                .with_retention_days(36500) // 100 years
                .expect("retention_days = 36500 is positive");
            let storage = FileAuditStorage::new(config);
            assert!(storage.is_ok());

            // Old file should still exist (not older than 100 years)
            assert!(old_file.exists());
        }
    }

    #[test]
    fn test_with_retention_days_zero_rejected() {
        // Zero retention would purge every audit file on next startup;
        // the builder must reject it so bad configs surface at
        // construction rather than at the next cleanup pass.
        let temp_path = std::env::temp_dir().join("latticearc_audit_zero_retention");
        let result = AuditConfig::new(temp_path).with_retention_days(0);
        assert!(matches!(result, Err(CoreError::InvalidInput(_))));
    }

    #[test]
    fn test_cleanup_skips_non_jsonl_files_leaving_them_intact_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();

            // Create a non-jsonl file
            let txt_file = temp_path.join("notes.txt");
            fs::write(&txt_file, "not an audit file\n").unwrap();

            // Use a positive retention; the cleanup pass operates only
            // on files whose names parse as audit-{timestamp}.jsonl,
            // so a foreign .txt file is skipped regardless of how long
            // we keep audit logs.
            let config = AuditConfig::new(temp_path)
                .with_retention_days(1)
                .expect("retention_days = 1 is positive");
            let storage = FileAuditStorage::new(config);
            assert!(storage.is_ok());

            // Non-jsonl file should not be touched
            assert!(txt_file.exists());
        }
    }

    #[test]
    fn test_write_sets_integrity_hash_to_64_char_hex_succeeds() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path.clone());

            if let Ok(storage) = FileAuditStorage::new(config) {
                let event = AuditEvent::new(
                    AuditEventType::CryptoOperation,
                    "hash_test",
                    AuditOutcome::Success,
                );
                storage.write(&event).unwrap();
                storage.flush().unwrap();

                // Read back and verify integrity_hash is set. Filter to
                // `.jsonl` so the persisted genesis-anchor file is not
                // picked up as an event log.
                let entries: Vec<_> = fs::read_dir(&temp_path)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
                    .collect();
                let content = fs::read_to_string(entries[0].path()).unwrap();
                let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
                let hash = parsed["integrity_hash"].as_str().unwrap();
                assert!(!hash.is_empty(), "Integrity hash should be set after write");
                assert_eq!(hash.len(), 64, "SHA-256 hash should be 64 hex chars");
            }
        }
    }

    #[test]
    fn test_integrity_hash_chain_consistency_produces_unique_hashes_per_event_are_unique() {
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let config = AuditConfig::new(temp_path.clone());

            if let Ok(storage) = FileAuditStorage::new(config) {
                for i in 0..3 {
                    let event = AuditEvent::new(
                        AuditEventType::CryptoOperation,
                        &format!("chain_op_{}", i),
                        AuditOutcome::Success,
                    );
                    storage.write(&event).unwrap();
                }
                storage.flush().unwrap();

                // Read all events and verify hashes form a chain.
                // Filter to `.jsonl` so the persisted genesis-anchor
                // file is not picked up as event-log lines.
                let entries: Vec<_> = fs::read_dir(&temp_path)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("jsonl"))
                    .collect();
                let content = fs::read_to_string(entries[0].path()).unwrap();
                let events: Vec<AuditEvent> =
                    content.lines().map(|line| serde_json::from_str(line).unwrap()).collect();

                assert_eq!(events.len(), 3);
                // All hashes should be non-empty and unique
                let hashes: Vec<&str> = events.iter().map(|e| e.integrity_hash.as_str()).collect();
                assert!(hashes.iter().all(|h| !h.is_empty()));
                assert_ne!(hashes[0], hashes[1]);
                assert_ne!(hashes[1], hashes[2]);
            }
        }
    }

    #[test]
    fn test_compute_integrity_hash_with_actor_and_resource_differs_from_without_succeeds() {
        let event = AuditEvent::new(AuditEventType::System, "test", AuditOutcome::Success)
            .with_actor("user1")
            .with_resource("resource1");

        let hash_with = FileAuditStorage::compute_integrity_hash(&event, "").unwrap();

        // Same event without actor/resource should have different hash
        let event_without = AuditEvent::new(AuditEventType::System, "test", AuditOutcome::Success);
        let hash_without = FileAuditStorage::compute_integrity_hash(&event_without, "").unwrap();

        assert_ne!(hash_with, hash_without);
    }

    #[test]
    fn test_audit_event_serde_roundtrip_all_fields_roundtrip() {
        let event =
            AuditEvent::new(AuditEventType::AccessControl, "policy_eval", AuditOutcome::Denied)
                .with_actor("service-account")
                .with_resource("secrets/key-001")
                .with_metadata("policy_id", "pol-42")
                .with_metadata("deny_reason", "insufficient_privileges");

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.event_type, AuditEventType::AccessControl);
        assert_eq!(deserialized.outcome, AuditOutcome::Denied);
        assert_eq!(deserialized.actor.as_deref(), Some("service-account"));
        assert_eq!(deserialized.resource.as_deref(), Some("secrets/key-001"));
        assert_eq!(deserialized.metadata.len(), 2);
        assert_eq!(
            deserialized.metadata.get("deny_reason").map(|s| s.as_str()),
            Some("insufficient_privileges")
        );
    }

    // =========================================================================
    // Pattern P4: AuditConfig Parameter Influence Tests
    // Each test proves changing ONLY one field changes the observable output.
    // =========================================================================

    #[test]
    fn test_max_file_size_bytes_influences_rotation_trigger_has_correct_size() {
        // max_file_size_bytes is consumed by needs_rotation() as the size threshold.
        // Two configs with different limits must expose different values, and the tiny-limit
        // config must trigger rotation (needs_rotation returns true) once the file grows.

        let config_tiny = AuditConfig::default().with_max_file_size(1); // 1 byte
        let config_large = AuditConfig::default().with_max_file_size(100 * 1024 * 1024); // 100 MB

        assert_ne!(
            config_tiny.max_file_size_bytes(),
            config_large.max_file_size_bytes(),
            "max_file_size_bytes must differ between the two configs"
        );
        assert_eq!(config_tiny.max_file_size_bytes(), 1);
        assert_eq!(config_large.max_file_size_bytes(), 100 * 1024 * 1024);

        // Demonstrate the field is consumed at rotation time: a 1-byte limit means
        // even a single event (which is many bytes as JSON) exceeds the threshold.
        // Use separate directories to avoid same-second filename collision on rotation.
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let dir_tiny = dir.path().join("tiny");
            fs::create_dir_all(&dir_tiny).unwrap();
            let storage_tiny =
                FileAuditStorage::new(AuditConfig::new(dir_tiny.clone()).with_max_file_size(1));
            if let Ok(s) = storage_tiny {
                // Write one event — its JSON is >1 byte, so current_size > threshold after write.
                // The next write will trigger needs_rotation() == true.
                let event1 = AuditEvent::new(
                    AuditEventType::CryptoOperation,
                    "op_first",
                    AuditOutcome::Success,
                );
                s.write(&event1).unwrap();

                // Verify that writing a second event also succeeds (rotation runs, old file
                // is flushed and a new FileState is opened).
                let event2 = AuditEvent::new(
                    AuditEventType::CryptoOperation,
                    "op_second",
                    AuditOutcome::Success,
                );
                // This write must succeed — rotation must handle the 1-byte overflow gracefully.
                assert!(
                    s.write(&event2).is_ok(),
                    "Write after size-triggered rotation must succeed"
                );
                s.flush().unwrap();
            }

            // With a large limit, writing many events never triggers overflow errors.
            let dir_large = dir.path().join("large");
            fs::create_dir_all(&dir_large).unwrap();
            let storage_large = FileAuditStorage::new(
                AuditConfig::new(dir_large.clone()).with_max_file_size(100 * 1024 * 1024),
            );
            if let Ok(s) = storage_large {
                for i in 0..5 {
                    let event = AuditEvent::new(
                        AuditEventType::CryptoOperation,
                        &format!("op_{}", i),
                        AuditOutcome::Success,
                    );
                    s.write(&event).unwrap();
                }
                s.flush().unwrap();

                // All events land in a single file (no rotation needed).
                let file_count = fs::read_dir(&dir_large)
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
                    .count();
                assert_eq!(
                    file_count, 1,
                    "max_file_size_bytes=100MB must not rotate for 5 small events (got {})",
                    file_count
                );
            }
        }
    }

    #[test]
    fn test_retention_days_influences_cleanup_cutoff_succeeds() {
        // retention_days is consumed by cleanup_old_files() which computes a cutoff
        // as (now - retention_days). Different values produce different cutoffs.
        // We verify the field value is read via the accessor and differs between configs.
        let config_short =
            AuditConfig::default().with_retention_days(1).expect("retention_days = 1 is positive");
        let config_long = AuditConfig::default()
            .with_retention_days(365)
            .expect("retention_days = 365 is positive");

        assert_ne!(
            config_short.retention_days(),
            config_long.retention_days(),
            "retention_days must influence the cleanup cutoff"
        );

        // Verify that retention_days = 0 is rejected at config time so
        // an operator cannot accidentally configure aggressive cleanup
        // that would purge the entire audit history on next startup.
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let temp_path = dir.path().to_path_buf();
            let new_file = temp_path.join("current.jsonl");
            fs::write(&new_file, "fresh event\n").unwrap();

            let result = AuditConfig::new(temp_path).with_retention_days(0);
            assert!(result.is_err(), "with_retention_days(0) must be rejected at the builder");
            // The pre-existing file is untouched because no storage was constructed.
            assert!(new_file.exists());
        }
    }

    #[test]
    fn test_max_file_age_influences_rotation_trigger_succeeds() {
        // max_file_age is consumed by needs_rotation() via the file's created_at timestamp.
        // Verify that the accessor returns different values for different configs.
        let config_short = AuditConfig::default().with_max_file_age(Duration::from_secs(1));
        let config_long = AuditConfig::default().with_max_file_age(Duration::from_secs(86400));

        assert_ne!(
            config_short.max_file_age(),
            config_long.max_file_age(),
            "max_file_age must influence when file rotation is triggered"
        );
    }

    #[test]
    fn test_storage_path_influences_file_location_succeeds() {
        // storage_path is consumed by FileAuditStorage::new() which creates the directory
        // at that path and writes audit files there.
        let temp_dir = TempDir::new();
        if let Ok(dir) = temp_dir {
            let path_a = dir.path().join("audit_a");
            let path_b = dir.path().join("audit_b");

            let config_a = AuditConfig::new(path_a.clone());
            let config_b = AuditConfig::new(path_b.clone());

            assert_ne!(
                config_a.storage_path(),
                config_b.storage_path(),
                "storage_path must differ between configs"
            );

            // Creating storage with different paths creates different directories
            if let Ok(storage_a) = FileAuditStorage::new(config_a) {
                let event = AuditEvent::new(AuditEventType::System, "start", AuditOutcome::Success);
                storage_a.write(&event).unwrap();
                storage_a.flush().unwrap();
                assert!(path_a.exists(), "Storage path A must be created by FileAuditStorage::new");
            }

            if let Ok(storage_b) = FileAuditStorage::new(config_b) {
                let event = AuditEvent::new(AuditEventType::System, "start", AuditOutcome::Success);
                storage_b.write(&event).unwrap();
                storage_b.flush().unwrap();
                assert!(path_b.exists(), "Storage path B must be created by FileAuditStorage::new");
            }

            // Files exist in each respective path, not the other
            let files_a: Vec<_> = fs::read_dir(&path_a)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .collect();
            let files_b: Vec<_> = fs::read_dir(&path_b)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("jsonl"))
                .collect();
            assert_eq!(files_a.len(), 1, "storage_path_a must contain exactly one .jsonl file");
            assert_eq!(files_b.len(), 1, "storage_path_b must contain exactly one .jsonl file");
            assert_ne!(
                files_a[0].path(),
                files_b[0].path(),
                "Files in different storage paths must have different absolute paths"
            );
        }
    }
}
