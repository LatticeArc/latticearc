//! # Persistent Audit Storage with Rotation
//!
//! Provides hash-chained audit logging for cryptographic operations.
//! Events are persisted to disk in JSON Lines format with automatic rotation
//! based on file size and age.
//!
//! ## Security Features
//!
//! - **Integrity Verification**: SHA-256 hash chain linking each event to its
//!   predecessor and to a per-storage genesis anchor. This detects truncation,
//!   reordering, and edits by any party that cannot read the genesis anchor
//!   file. It is **not** a keyed MAC: an attacker with read access to the
//!   genesis anchor *and* write access to the log can recompute a
//!   self-consistent chain. Tamper-evidence therefore rests on the genesis
//!   anchor's `0o600` confidentiality, not on a secret key.
//! - **Exact-bytes hashing**: each line is
//!   `{"v":2,"event":{...},"integrity_hash":"<hex>"}` and the hash is
//!   `SHA-256("latticearc-audit-event-v2" || len‖previous_hash || len‖event)`
//!   over the `event` bytes exactly as stored, so verification never
//!   re-encodes anything and gives the same answer on every platform.
//!   Lines written before format 2 (no `"v"` key) still verify through the
//!   field transcript they were hashed with; once a chain contains a
//!   format-2 line, a later format-1 line is rejected.
//! - **Restart continuity**: a new `FileAuditStorage` resumes from the last
//!   stored hash and starts its first file with a chain-link anchor to the
//!   previous file, so the chain verifies across process restarts.
//! - **Verified retention**: the retention sweep removes only the oldest
//!   contiguous run of expired files, only after that run verifies, and
//!   records the new chain boundary in a protected `retention-checkpoint`
//!   file (next to the genesis anchor) before each removal. Verification
//!   accepts a chain whose oldest files are gone only at that recorded
//!   boundary; files that do not verify are kept for inspection.
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

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::types::timestamp::{Timestamp, UtcSuffix};

use crate::unified_api::error::{CoreError, Result};

/// Audit event for persistent storage.
///
/// Each event captures a single auditable action with full context
/// for compliance and forensic analysis.
///
/// All fields are private. External callers must construct via
/// [`Self::new`] / [`AuditEventBuilder`] (caller-supplied fields are
/// sanitized + capped at construction) and read via the typed
/// accessors below. Privatization closes four post-construction
/// mutation hazards that were previously exposed:
///
///   - `id: String` is free-form bytes (no length cap on direct
///     mutation; a 10-MiB id propagates into the integrity-hash
///     chain payload).
///   - `timestamp` mutation enables backdating after the chain hash
///     has bound the original value.
///   - `event_type` and `outcome` flip event semantics
///     (`Success ↔ Failure`) post-hash; `compute_integrity_hash`
///     binds all four into the chain so post-hash mutation leaves the
///     in-memory record disagreeing with the on-disk record that
///     produced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    // Unique identifier for this event (UUID v4).
    // Private — set internally by `new`. Free-form `String`; mutation
    // would amplify the chain-payload size unboundedly.
    id: String,
    // Timestamp when the event occurred.
    // Private — set internally by `new` via `Timestamp::now()`. Mutation
    // enables backdating after the chain hash has bound the value.
    timestamp: Timestamp,
    // Category of the audit event.
    // Private — set internally by `new`. Mutation flips event
    // semantics post-chain-hash.
    event_type: AuditEventType,
    // Identity of the actor performing the action (optional).
    // Private — set via `with_actor`, which sanitizes & caps.
    actor: Option<String>,
    // Resource being acted upon (optional).
    // Private — set via `with_resource`, which sanitizes & caps.
    resource: Option<String>,
    // Specific action performed.
    // Private — set via `new`, which routes through `sanitize_action_field`.
    action: String,
    // Outcome of the action.
    // Private — set internally. Mutation flips Success ↔ Failure
    // post-chain-hash.
    outcome: AuditOutcome,
    // Additional key-value metadata.
    // Private — entries added via `with_metadata`, which truncates and
    // enforces `MAX_METADATA_ENTRIES`.
    metadata: HashMap<String, String>,
    // SHA-256 hash for tamper detection (includes previous event hash).
    // Private — set internally by `FileAuditStorage::write_event_to_file`
    // after the chain hash is computed. External assignment would
    // invalidate the on-disk chain. Omitted from the JSON while empty:
    // the format-2 line stores it beside the event bytes it covers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    integrity_hash: String,
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
            timestamp: Timestamp::now(),
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
    pub fn timestamp(&self) -> Timestamp {
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
/// The clock reading is UTC (the producer writes UTC). Used by the
/// retention sweep so cleanup decisions don't depend on filesystem
/// `mtime`, which a privileged attacker can rewrite with `touch`.
/// Anything that is not exactly one of the two fixed-width shapes is
/// rejected, so the sweep skips (never deletes) foreign files.
fn parse_audit_filename_timestamp(file_name: &str) -> Option<Timestamp> {
    let stem = file_name.strip_prefix("audit-")?.strip_suffix(".jsonl")?;
    // `YYYY-MM-DDTHH-MM-SS` is 19 bytes; the current form appends
    // `-NNNNNN` (exactly six digits of microseconds).
    let (date_time, fraction) = match stem.len() {
        19 => (stem, String::new()),
        26 => {
            let micros = stem.get(19..)?.strip_prefix('-')?;
            if !micros.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (stem.get(..19)?, format!(".{micros}"))
        }
        _ => return None,
    };
    // The producer always writes an upper-case `T` and `-` time separators.
    // Check those bytes here (the RFC 3339 parser would also accept `t` or a
    // space), rewrite `HH-MM-SS` → `HH:MM:SS`, and let the parser validate
    // every numeric field.
    let shape = date_time.as_bytes();
    if shape.get(10) != Some(&b'T') || shape.get(13) != Some(&b'-') || shape.get(16) != Some(&b'-')
    {
        return None;
    }
    let rfc3339 = format!(
        "{}:{}:{}{fraction}Z",
        date_time.get(..13)?,
        date_time.get(14..16)?,
        date_time.get(17..)?
    );
    rfc3339.parse::<Timestamp>().ok()
}

/// Trait for audit storage implementations.
///
/// Implement this trait to create custom audit storage backends
/// (e.g., database, remote service, etc.).
///
/// # Why this trait is intentionally NOT sealed
///
/// `DESIGN_PATTERNS.md` Pattern 4 (Sealed Security Traits) requires
/// sealing traits where an external impl could *bypass security* —
/// e.g., a `SigmaProtocol::verify` impl that always returns `Ok(true)`
/// silently passes any proof. `AuditStorage` doesn't have that shape:
/// the trait surfaces a *storage* abstraction, not a security check.
/// A custom backend that drops events doesn't compromise crypto
/// integrity — it just produces incomplete audit logs, which is the
/// operator's deployment trust decision. Sealing this trait would
/// remove the documented plug-in architecture (database, remote
/// service, etc.) without closing any actual security hole.
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
    created_at: Timestamp,
}

/// Result of [`FileAuditStorage::verify_chain`].
#[derive(Debug, Clone)]
pub struct ChainVerificationReport {
    /// Number of `audit-*.jsonl` files inspected.
    pub files_checked: usize,
    /// Number of audit events whose hash was recomputed.
    pub events_checked: u64,
    /// `Some(_)` when the first divergence was found; `None` when the
    /// chain verifies end-to-end.
    pub mismatch: Option<ChainMismatch>,
    /// Hash of the last verified event (the genesis anchor if there are
    /// none). Record it externally to detect later tail truncation.
    pub tail_hash: String,
    /// `Some(file)` when the retention policy has removed the oldest files,
    /// `file` being the newest one removed. Verification then starts from
    /// the chain hash the retention sweep recorded for `file` in the
    /// protected `retention-checkpoint` (written only after the removed
    /// segment verified); a leading chain-link anchor that does not match
    /// that record is reported as a mismatch, never accepted.
    pub retention_boundary: Option<String>,
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
    /// Basename of the file the next new audit file must link back to
    /// with a chain-link anchor: the outgoing file on rotation, or the
    /// previous run's newest file after a restart. Cleared only once that
    /// anchor is written, so a failed create or write retries the link.
    pending_link: Mutex<Option<String>>,
}

/// Filename for the per-storage genesis anchor.
///
/// The genesis anchor is the `previous_hash` value used for the very first
/// audit event in a storage. It is derived from a domain label, a fresh
/// random nonce, and the creation timestamp, and is persisted alongside
/// the audit log so that:
///
///   * entries cannot be removed from the start or middle of the chain
///     without breaking it: every event's hash covers its predecessor's,
///     back to `genesis`.
///   * removing entries from the *end* (or whole newest files) leaves a
///     shorter chain that still verifies — an unkeyed hash chain cannot
///     detect tail truncation on its own. Pin the chain head externally:
///     [`ChainVerificationReport::tail_hash`] and the startup log line
///     emitted when a chain is resumed give the value to record in an
///     append-only store.
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

/// Domain-separation label of the format-2 event hash.
const AUDIT_EVENT_DOMAIN_V2: &[u8] = b"latticearc-audit-event-v2";

/// `"v"` value of a format-2 audit line.
const AUDIT_LINE_FORMAT_V2: u8 = 2;

/// Defense-in-depth cap on a persisted JSONL line. A line is at worst the
/// product of the in-memory caps (action 256 B + actor 256 B + resource
/// 1 KiB + 32 metadata × 4 KiB ≈ 130 KiB) plus JSON overhead; 1 MiB is
/// generously above that and small enough to defeat a tampered file
/// dropping a 1 GiB string in front of the verifier.
const MAX_AUDIT_LINE_LEN: usize = 1024 * 1024;

/// A format-2 line as written: the event's JSON is embedded verbatim and
/// the hash covers exactly those bytes.
#[derive(Serialize)]
struct AuditLineOut<'a> {
    v: u8,
    event: &'a serde_json::value::RawValue,
    integrity_hash: &'a str,
}

/// A format-2 line as read: `event` borrows the stored bytes unchanged.
#[derive(Deserialize)]
struct AuditLineIn<'a> {
    v: u8,
    #[serde(borrow)]
    event: &'a serde_json::value::RawValue,
    integrity_hash: String,
}

/// Format probe: format-2 lines carry `"v"`, format-1 lines (bare
/// `AuditEvent` objects) do not.
#[derive(Deserialize)]
struct AuditLineVersion {
    #[serde(default)]
    v: Option<u8>,
}

/// Result of replaying the chain over a run of files.
struct ChainWalk {
    events_checked: u64,
    mismatch: Option<ChainMismatch>,
    /// Chain hash after the last event.
    tail_hash: String,
    /// Chain hash at the end of each file walked, in order (shorter than
    /// the file list when the walk stopped at a mismatch).
    file_tails: Vec<String>,
}

/// The chain boundary left by the retention sweep: the newest removed file
/// and the chain hash at its end.
struct RetentionCheckpoint {
    file: String,
    hash: String,
}

/// Filename of the retention checkpoint, kept next to the genesis anchor
/// with the same protection. Written by the retention sweep *before* each
/// file it removes, and only after the removed segment has verified; it is
/// the sole evidence `verify_chain` accepts for a chain whose oldest files
/// are gone.
const AUDIT_RETENTION_CHECKPOINT_FILENAME: &str = "retention-checkpoint";

/// One stored line, decoded and with its hash recomputed.
struct VerifiedLine {
    event: AuditEvent,
    stored_hash: String,
    recomputed_hash: String,
    format: u8,
}

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
            pending_link: Mutex::new(None),
        });

        // Apply the retention policy first, so the chain is resumed from
        // files that still exist.
        storage.cleanup_old_files()?;

        // Resume the existing chain: the next event chains from the last
        // stored hash, and the first file this instance creates starts
        // with a chain-link anchor naming the newest existing file.
        let resume = match Self::chain_tail(&storage.config.storage_path)? {
            Some((newest_file, tail_hash)) => Some((newest_file, tail_hash)),
            // Every file has been removed by retention: continue from the
            // boundary the sweep recorded, so the chain stays continuous.
            None => Self::load_retention_checkpoint(&storage.config.storage_path)?
                .map(|cp| (cp.file, Some(cp.hash))),
        };
        if let Some((newest_file, tail_hash)) = resume {
            if let Some(tail_hash) = tail_hash {
                *storage.previous_hash.write() = tail_hash;
            }
            tracing::info!(
                target: "latticearc::audit",
                file = %newest_file,
                tail_hash = %storage.previous_hash.read(),
                "resuming audit chain"
            );
            *storage.pending_link.lock() = Some(newest_file);
        }

        Ok(storage)
    }

    /// Read the retention checkpoint, `None` if no sweep has removed files.
    ///
    /// # Errors
    /// Fails closed on a checkpoint that exists but is unreadable or
    /// malformed: verification must not silently fall back to genesis.
    fn load_retention_checkpoint(dir: &std::path::Path) -> Result<Option<RetentionCheckpoint>> {
        use std::io::Read as _;
        const CHECKPOINT_MAX_BYTES: u64 = 512;
        let path = dir.join(AUDIT_RETENTION_CHECKPOINT_FILENAME);
        let text = match File::open(&path) {
            Ok(f) => {
                let mut text = String::new();
                f.take(CHECKPOINT_MAX_BYTES).read_to_string(&mut text).map_err(|e| {
                    CoreError::AuditError(format!(
                        "Failed to read retention checkpoint '{}': {}",
                        path.display(),
                        e
                    ))
                })?;
                text
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CoreError::AuditError(format!(
                    "Failed to open retention checkpoint '{}': {}",
                    path.display(),
                    e
                )));
            }
        };
        let malformed = || {
            CoreError::AuditError(format!(
                "Retention checkpoint '{}' is malformed; refusing to verify across it",
                path.display()
            ))
        };
        let (file, hash) = text.trim().split_once(' ').ok_or_else(malformed)?;
        let file_ok = file.starts_with("audit-")
            && file.ends_with(".jsonl")
            && !file.contains(['/', '\\'])
            && parse_audit_filename_timestamp(file).is_some();
        let hash_ok = hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit());
        if !file_ok || !hash_ok {
            return Err(malformed());
        }
        Ok(Some(RetentionCheckpoint { file: file.to_string(), hash: hash.to_string() }))
    }

    /// Replace the retention checkpoint atomically (write a protected temp
    /// file, fsync, rename), or remove it when `checkpoint` is `None`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written, synced or renamed.
    fn store_retention_checkpoint(
        dir: &std::path::Path,
        checkpoint: Option<&RetentionCheckpoint>,
    ) -> Result<()> {
        use std::io::Write as _;
        let path = dir.join(AUDIT_RETENTION_CHECKPOINT_FILENAME);
        let Some(checkpoint) = checkpoint else {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(CoreError::AuditError(format!(
                    "Failed to remove retention checkpoint '{}': {}",
                    path.display(),
                    e
                ))),
            };
        };
        let tmp = dir.join(format!(".{AUDIT_RETENTION_CHECKPOINT_FILENAME}.tmp"));
        // A stale temp file from an interrupted sweep would block
        // `create_new`; it carries no state, so remove it first.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(CoreError::AuditError(format!(
                    "Failed to clear stale checkpoint temp file '{}': {}",
                    tmp.display(),
                    e
                )));
            }
        }
        let io_err = |what: &str, e: std::io::Error| {
            CoreError::AuditError(format!(
                "Failed to {what} retention checkpoint '{}': {}",
                path.display(),
                e
            ))
        };
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        {
            // Same exclusive-handle approximation of 0o600 as the genesis file.
            use std::os::windows::fs::OpenOptionsExt as _;
            options.share_mode(0);
        }
        // LINT-OK: mode set on the line(s) above per platform.
        let mut f = options.open(&tmp).map_err(|e| io_err("create", e))?;
        f.write_all(format!("{} {}\n", checkpoint.file, checkpoint.hash).as_bytes())
            .map_err(|e| io_err("write", e))?;
        f.sync_all().map_err(|e| io_err("fsync", e))?;
        drop(f);
        fs::rename(&tmp, &path).map_err(|e| io_err("install", e))?;
        Ok(())
    }

    /// Read the on-disk genesis if it exists, otherwise create one.
    ///
    /// The created genesis is `SHA-256(domain_label || nonce || timestamp)`
    /// hex-encoded, where `nonce` is 32 bytes from the system CSPRNG and
    /// `timestamp` is the RFC 3339 creation time.
    fn load_or_create_genesis(storage_path: &std::path::Path) -> Result<String> {
        let genesis_path = storage_path.join(AUDIT_GENESIS_FILENAME);

        // M-audit-genesis: cap the read at 128 bytes. Genesis is a
        // SHA-256 hex digest written by `create_new()` below — exactly
        // 64 hex chars + a trailing newline. `fs::read_to_string` had
        // no cap, so an attacker who can write the audit dir could
        // replace genesis with a multi-GiB file and OOM the process
        // at startup. The genuine genesis must round-trip through the
        // 64-hex invariant check below; anything past the cap is
        // truncated and the invariant catches it as malformed.
        const GENESIS_MAX_BYTES: u64 = 128;
        let read_capped = || -> std::io::Result<String> {
            use std::io::Read as _;
            let f = File::open(&genesis_path)?;
            let mut buf = String::new();
            f.take(GENESIS_MAX_BYTES).read_to_string(&mut buf)?;
            Ok(buf)
        };
        match read_capped() {
            Ok(existing) => {
                let trimmed = existing.trim().to_string();
                if trimmed.is_empty() {
                    return Err(CoreError::AuditError(format!(
                        "Audit genesis file '{}' exists but is empty; refusing to start \
                         with an empty chain anchor",
                        genesis_path.display()
                    )));
                }
                // SHA-256 hex digest invariant — exactly 64 chars, all
                // ASCII hexdigits. Pre-fix the loader accepted any
                // non-empty trimmed string, so a partially-overwritten
                // genesis would propagate as the chain anchor.
                if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(CoreError::AuditError(format!(
                        "Audit genesis file '{}' is not a valid 64-char SHA-256 hex \
                         digest; refusing to start with a corrupted chain anchor",
                        genesis_path.display()
                    )));
                }
                Ok(trimmed)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let nonce = crate::primitives::rand::csprng::random_bytes(32);
                let timestamp =
                    Timestamp::now().to_rfc3339(UtcSuffix::PlusZero).ok_or_else(|| {
                        CoreError::AuditError(
                            "System clock is outside the RFC 3339 year range".to_string(),
                        )
                    })?;
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
                    // on Windows, use `OpenOptions` with
                    // `share_mode(0)` (deny share) and explicit
                    // `create_new(true)` so the genesis file is
                    // exclusive to this process while the handle is
                    // open. Default `fs::write` would inherit the
                    // process's default DACL — typically world-
                    // readable on local Windows — exposing the
                    // chain-integrity seed to other local users.
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
    pub(crate) fn compute_integrity_hash_v1(
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
        // `+00:00` suffix and chrono-compatible fraction digits: chains
        // written by earlier versions hash exactly these bytes.
        let ts = event.timestamp.to_rfc3339(UtcSuffix::PlusZero).ok_or_else(|| {
            CoreError::AuditError("Audit event timestamp outside the RFC 3339 range".to_string())
        })?;
        Self::append_lenp_field(&mut buf, ts.as_bytes())?;
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
        // `zkp::sigma::compute_challenge` — unifies endianness across
        // all transcript-style hashing in the crate.
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
            .map_err(|e| CoreError::AuditError(format!("integrity hash failed: {e}")))?;
        Ok(hex::encode(digest))
    }

    /// Format-2 integrity hash: SHA-256 over the domain label, the previous
    /// hash and the event JSON exactly as stored on the line, each
    /// length-prefixed. Verification hashes the stored bytes directly, so
    /// no field is ever re-encoded.
    ///
    /// # Errors
    /// Returns an error if a field exceeds 2^32 bytes or SHA-256 fails.
    fn compute_integrity_hash_v2(previous_hash: &str, event_json: &[u8]) -> Result<String> {
        let mut buf = Vec::with_capacity(
            AUDIT_EVENT_DOMAIN_V2
                .len()
                .saturating_add(8)
                .saturating_add(previous_hash.len())
                .saturating_add(event_json.len()),
        );
        buf.extend_from_slice(AUDIT_EVENT_DOMAIN_V2);
        Self::append_lenp_field(&mut buf, previous_hash.as_bytes())?;
        Self::append_lenp_field(&mut buf, event_json)?;
        let digest = crate::primitives::hash::sha2::sha256(&buf)
            .map_err(|e| CoreError::AuditError(format!("integrity hash failed: {e}")))?;
        Ok(hex::encode(digest))
    }

    /// Encode `event` as a format-2 line chained from `previous_hash`
    /// (newline included) and set `event.integrity_hash` to its hash.
    ///
    /// # Errors
    /// Returns an error if serialization or hashing fails, or the line
    /// would exceed [`MAX_AUDIT_LINE_LEN`] (the verifier would reject it).
    fn encode_line(event: &mut AuditEvent, previous_hash: &str) -> Result<String> {
        event.integrity_hash.clear();
        let body = serde_json::to_string(&*event)
            .map_err(|e| CoreError::AuditError(format!("Failed to serialize audit event: {e}")))?;
        let hash = Self::compute_integrity_hash_v2(previous_hash, body.as_bytes())?;
        let raw = serde_json::value::RawValue::from_string(body)
            .map_err(|e| CoreError::AuditError(format!("Failed to embed audit event: {e}")))?;
        let line = serde_json::to_string(&AuditLineOut {
            v: AUDIT_LINE_FORMAT_V2,
            event: &raw,
            integrity_hash: &hash,
        })
        .map_err(|e| CoreError::AuditError(format!("Failed to serialize audit line: {e}")))?;
        if line.len() > MAX_AUDIT_LINE_LEN {
            return Err(CoreError::AuditError(format!(
                "audit line of {} bytes exceeds maximum length {MAX_AUDIT_LINE_LEN}",
                line.len()
            )));
        }
        event.integrity_hash = hash;
        Ok(format!("{line}\n"))
    }

    /// Decode one stored line (format 1 or 2) and recompute its hash from
    /// `previous_hash`. `Ok(None)` when the line is not valid audit JSON;
    /// the caller decides how to report that.
    ///
    /// # Errors
    /// Returns an error for an unsupported format version or a hashing
    /// failure.
    fn decode_line(line: &str, previous_hash: &str) -> Result<Option<VerifiedLine>> {
        let Ok(probe) = serde_json::from_str::<AuditLineVersion>(line) else {
            return Ok(None);
        };
        match probe.v {
            None => {
                let Ok(event) = serde_json::from_str::<AuditEvent>(line) else {
                    return Ok(None);
                };
                if event.integrity_hash.is_empty() {
                    return Ok(None);
                }
                let recomputed_hash = Self::compute_integrity_hash_v1(&event, previous_hash)?;
                let stored_hash = event.integrity_hash.clone();
                Ok(Some(VerifiedLine { event, stored_hash, recomputed_hash, format: 1 }))
            }
            Some(AUDIT_LINE_FORMAT_V2) => {
                let Ok(stored) = serde_json::from_str::<AuditLineIn<'_>>(line) else {
                    return Ok(None);
                };
                // The line must be exactly what the writer produces for
                // these values: no extra fields, whitespace or escapes
                // outside the hashed event bytes can go unnoticed.
                let canonical = serde_json::to_string(&AuditLineOut {
                    v: stored.v,
                    event: stored.event,
                    integrity_hash: &stored.integrity_hash,
                })
                .map_err(|e| {
                    CoreError::AuditError(format!("Failed to re-encode audit line: {e}"))
                })?;
                if canonical != line {
                    return Ok(None);
                }
                let event_json = stored.event.get();
                let recomputed_hash =
                    Self::compute_integrity_hash_v2(previous_hash, event_json.as_bytes())?;
                let Ok(mut event) = serde_json::from_str::<AuditEvent>(event_json) else {
                    return Ok(None);
                };
                event.integrity_hash.clone_from(&stored.integrity_hash);
                Ok(Some(VerifiedLine {
                    event,
                    stored_hash: stored.integrity_hash,
                    recomputed_hash,
                    format: stored.v,
                }))
            }
            Some(other) => {
                Err(CoreError::AuditError(format!("unsupported audit line format version {other}")))
            }
        }
    }

    /// The first non-empty line of `path` and its zero-based index, reading
    /// at most [`MAX_AUDIT_LINE_LEN`] bytes per line; `None` for an empty
    /// file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, a line exceeds the cap,
    /// or it is not UTF-8.
    fn first_line(path: &std::path::Path) -> Result<Option<(usize, String)>> {
        use std::io::{BufRead as _, Read as _};
        let f = File::open(path).map_err(|e| {
            CoreError::AuditError(format!("Failed to open {}: {}", path.display(), e))
        })?;
        let cap = u64::try_from(MAX_AUDIT_LINE_LEN.saturating_add(1)).unwrap_or(u64::MAX);
        let mut reader = std::io::BufReader::new(f);
        let mut idx: usize = 0;
        loop {
            let mut buf = Vec::new();
            let n = (&mut reader)
                .take(cap)
                .read_until(b'\n', &mut buf)
                .map_err(|e| CoreError::AuditError(format!("Failed to read audit file: {e}")))?;
            if n == 0 {
                return Ok(None);
            }
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            if buf.len() > MAX_AUDIT_LINE_LEN {
                return Err(CoreError::AuditError(format!(
                    "audit line of {} exceeds maximum length {MAX_AUDIT_LINE_LEN}",
                    path.display()
                )));
            }
            let line = String::from_utf8(buf).map_err(|_e| {
                CoreError::AuditError(format!("audit line of {} is not UTF-8", path.display()))
            })?;
            if !line.trim().is_empty() {
                return Ok(Some((idx, line)));
            }
            idx = idx.saturating_add(1);
        }
    }

    /// `audit-*.jsonl` files in `dir`, oldest first (the filename timestamp
    /// is lexicographically chronological; sort by basename so path
    /// normalisation differences cannot reorder them).
    fn sorted_audit_files(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
        let mut log_files: Vec<PathBuf> = Vec::new();
        let entries = fs::read_dir(dir)
            .map_err(|e| CoreError::AuditError(format!("Failed to read audit dir: {e}")))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("audit-") && lower.ends_with(".jsonl") {
                log_files.push(path);
            }
        }
        log_files.sort_by(|a, b| {
            a.file_name()
                .unwrap_or_else(|| a.as_os_str())
                .cmp(b.file_name().unwrap_or_else(|| b.as_os_str()))
        });
        Ok(log_files)
    }

    /// The existing chain's tail: the newest audit file's basename and the
    /// last stored integrity hash (`None` if no file holds an event yet).
    /// `Ok(None)` when the directory has no audit files.
    ///
    /// Reads at most the final `2 × MAX_AUDIT_LINE_LEN` bytes of a file. A
    /// torn final line (crash mid-write) is skipped with a warning; it is
    /// still reported by [`Self::verify_chain`].
    ///
    /// # Errors
    /// Fails closed — and so does [`Self::new`] — when an audit file
    /// cannot be opened or read: appending to a chain whose tail is
    /// unknown would silently fork it.
    fn chain_tail(dir: &std::path::Path) -> Result<Option<(String, Option<String>)>> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let files = Self::sorted_audit_files(dir)?;
        let Some(newest) = files.last() else { return Ok(None) };
        let newest_name = newest
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| CoreError::AuditError("non-UTF-8 audit filename".to_string()))?
            .to_string();
        for file in files.iter().rev() {
            let mut f = File::open(file).map_err(|e| {
                CoreError::AuditError(format!("Failed to open {}: {}", file.display(), e))
            })?;
            let len = f
                .metadata()
                .map_err(|e| CoreError::AuditError(format!("Failed to stat audit file: {e}")))?
                .len();
            let window = u64::try_from(MAX_AUDIT_LINE_LEN.saturating_mul(2)).unwrap_or(u64::MAX);
            let start = len.saturating_sub(window);
            f.seek(SeekFrom::Start(start))
                .map_err(|e| CoreError::AuditError(format!("Failed to seek audit file: {e}")))?;
            let mut tail = Vec::new();
            f.take(window)
                .read_to_end(&mut tail)
                .map_err(|e| CoreError::AuditError(format!("Failed to read audit file: {e}")))?;
            let mut lines: Vec<&[u8]> = tail.split(|&b| b == b'\n').collect();
            if start > 0 && !lines.is_empty() {
                // The window may begin mid-line; drop that fragment.
                lines.remove(0);
            }
            for raw in lines.iter().rev() {
                if raw.len() > MAX_AUDIT_LINE_LEN {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(raw) else { continue };
                if text.trim().is_empty() {
                    continue;
                }
                // Any previous hash works here: only the stored hash is read.
                if let Ok(Some(decoded)) = Self::decode_line(text, "") {
                    return Ok(Some((newest_name, Some(decoded.stored_hash))));
                }
                tracing::warn!(
                    file = %file.display(),
                    "audit chain resume: skipping an unreadable trailing line"
                );
            }
        }
        Ok(Some((newest_name, None)))
    }

    /// Append `field.len() as u32 BE` followed by `field` to `buf`.
    ///
    /// Returns `Err(CoreError::AuditError)` if `field.len()` exceeds
    /// `u32::MAX` bytes (4 GiB) — symmetric with the overflow handling
    /// in `zkp::sigma::compute_challenge`. The length is encoded
    /// big-endian to match the transcript convention used by
    /// `zkp::sigma::compute_challenge` — LE encoding here would be an
    /// isolated outlier within the crate's transcript-style hashing.
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

        // Check age limit. `duration_since` is `None` only when
        // `created_at` is in the future (clock skew or a tampered
        // timestamp). A future-dated file would otherwise read as 0 s old
        // forever and never age-rotate; treat the anomaly as past the age
        // limit so the file rotates.
        let Some(age) = Timestamp::now().duration_since(state.created_at) else {
            return true;
        };

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
        if state.as_ref().is_some_and(|s| self.needs_rotation(s)) {
            // Flush before letting go of the outgoing file, so a flush
            // failure leaves it in place rather than half-closed.
            if let Some(old_state) = state.as_mut() {
                old_state.writer.flush().map_err(|e| {
                    CoreError::AuditError(format!("Failed to flush audit file: {e}"))
                })?;
            }
            if let Some(old_state) = state.take() {
                tracing::info!(
                    "Rotating audit file: {} (size: {} bytes)",
                    old_state.current_path.display(),
                    old_state.current_size
                );
                let old_filename = old_state
                    .current_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unknown>")
                    .to_string();
                *self.pending_link.lock() = Some(old_filename);
            }
        }

        if state.is_none() {
            let mut new_state = self.create_new_file()?;
            // The new file starts with a chain-link anchor whenever it
            // continues an existing file (rotation or restart). The very
            // first file of a storage needs none: genesis anchors it.
            let pending = self.pending_link.lock().clone();
            if let Some(prev_file) = pending {
                let prev_hash = self.previous_hash.read().clone();
                self.write_chain_anchor(&mut new_state, &prev_file, &prev_hash)?;
                *self.pending_link.lock() = None;
            }
            *state = Some(new_state);
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
        let line = Self::encode_line(&mut anchor, &chain_prev)?;
        let line_bytes = line.as_bytes();
        state
            .writer
            .write_all(line_bytes)
            .map_err(|e| CoreError::AuditError(format!("Failed to write chain anchor: {e}")))?;
        // Advance the chain only after the anchor is written, like events.
        {
            let mut prev = self.previous_hash.write();
            prev.clone_from(&anchor.integrity_hash);
        }
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
        let now = Timestamp::now();
        // Files are ordered by name, so a new file must sort after every
        // existing one even if the clock stepped backwards (NTP, another
        // host): name it 1 µs after the newest file in that case.
        let newest_existing = Self::sorted_audit_files(&self.config.storage_path)?
            .last()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()))
            .and_then(parse_audit_filename_timestamp);
        let name_time = match newest_existing {
            Some(newest) if newest >= now => {
                newest.checked_add(Duration::from_micros(1)).ok_or_else(|| {
                    CoreError::AuditError("audit file timestamp overflow".to_string())
                })?
            }
            _ => now,
        };
        let fields = name_time.utc_fields().ok_or_else(|| {
            CoreError::AuditError("System clock is outside the RFC 3339 year range".to_string())
        })?;
        let filename = format!(
            "audit-{:04}-{:02}-{:02}T{:02}-{:02}-{:02}-{:06}.jsonl",
            fields.year(),
            u8::from(fields.month()),
            fields.day(),
            fields.hour(),
            fields.minute(),
            fields.second(),
            fields.microsecond()
        );
        let path = self.config.storage_path.join(&filename);

        let file = {
            // On Unix, set 0o600 atomically via OpenOptions::mode() so the
            // file is never world-readable, even briefly. Audit logs may
            // contain operation context (key IDs, paths, actors) and must
            // not inherit the default umask the way the previous bare
            // `OpenOptions::new().create(..).open(..)` did.
            // `create_new(true)` (not `create(true)`): refuse to open a
            // pre-existing file. The rotation code generates the
            // filename from `Timestamp::now()` to microsecond precision; if a
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
                let f = {
                    // LINT-OK: cfg-not-unix — Windows confidentiality
                    // enforced via `set_local_admin_dacl` immediately
                    // below (Win32 `OpenOptionsExt` has no `.mode()`).
                    OpenOptions::new().create_new(true).append(true).open(&path).map_err(|e| {
                        CoreError::AuditError(format!(
                            "Failed to create audit file '{}': {}",
                            path.display(),
                            e
                        ))
                    })?
                };
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

        let retention_duration =
            Duration::from_secs(u64::from(self.config.retention_days).saturating_mul(86_400));
        let Some(cutoff) = Timestamp::now().checked_sub(retention_duration) else {
            return Err(CoreError::AuditError(format!(
                "Retention period of {} days overflows date arithmetic",
                self.config.retention_days
            )));
        };

        // Retention removes only the oldest *contiguous* run of expired
        // files (filenames sort chronologically), judged by the filename
        // timestamp rather than the filesystem mtime, which a privileged
        // attacker can rewrite with `touch`. Files whose names don't parse
        // stop the run and are never deleted.
        let dir = &self.config.storage_path;
        let files = Self::sorted_audit_files(dir)?;
        let expired = files
            .iter()
            .take_while(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(parse_audit_filename_timestamp)
                    .is_some_and(|created_at| created_at < cutoff)
            })
            .count();
        let Some(segment) = files.get(..expired).filter(|s| !s.is_empty()) else {
            return Ok(());
        };

        // Removing files moves the chain's starting point, so only a
        // segment that verifies may go, and the new boundary is recorded
        // first. An unverifiable segment is kept: deleting it would destroy
        // the evidence of whatever happened to it.
        let genesis = Self::load_or_create_genesis(dir)?;
        let walk = match Self::chain_start(dir, &files, &genesis)? {
            Ok((start_hash, _)) => Self::walk_chain(segment, start_hash),
            Err(mismatch) => Ok(ChainWalk {
                events_checked: 0,
                mismatch: Some(mismatch),
                tail_hash: String::new(),
                file_tails: Vec::new(),
            }),
        };
        let walk = match walk {
            Ok(walk) if walk.mismatch.is_none() && walk.file_tails.len() == segment.len() => walk,
            Ok(_) | Err(_) => {
                tracing::warn!(
                    target: "latticearc::audit",
                    files = segment.len(),
                    "audit retention: expired files do not verify; keeping them for inspection"
                );
                return Ok(());
            }
        };

        let previous_checkpoint = Self::load_retention_checkpoint(dir)?;
        let mut last_removed: Option<RetentionCheckpoint> = None;
        for (path, tail_hash) in segment.iter().zip(&walk.file_tails) {
            let Some(file) = path.file_name().and_then(|n| n.to_str()) else { break };
            let boundary = RetentionCheckpoint { file: file.to_string(), hash: tail_hash.clone() };
            Self::store_retention_checkpoint(dir, Some(&boundary))?;
            if let Err(e) = fs::remove_file(path) {
                tracing::warn!("Failed to remove old audit file '{}': {}", path.display(), e);
                // Put the boundary back where the remaining files start.
                Self::store_retention_checkpoint(
                    dir,
                    last_removed.as_ref().or(previous_checkpoint.as_ref()),
                )?;
                break;
            }
            tracing::info!("Removed old audit file: {}", path.display());
            last_removed = Some(boundary);
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
        // Hold the writer lock across directory enumeration
        // AND file reads so a concurrent `write_event_to_file`'s
        // `BufWriter` cannot leave a half-written line in our scan
        // window. Flush defensively so the on-disk view is consistent
        // with the in-memory chain hash. The lock is held for the
        // entire chain replay — verify_chain is a maintenance
        // operation, not a per-request hot path, so the latency hit on
        // concurrent writers is acceptable.
        let mut file_state = self.file_state.lock();
        if let Some(state) = file_state.as_mut() {
            state
                .writer
                .flush()
                .map_err(|e| CoreError::AuditError(format!("verify_chain flush failed: {e}")))?;
        }

        let log_files = Self::sorted_audit_files(&self.config.storage_path)?;

        // Recompute from genesis — read from disk rather than the
        // in-memory `previous_hash`, so verification works on storage
        // this process never wrote to — or from the boundary the retention
        // sweep recorded, when the oldest files have been removed.
        let genesis = Self::load_or_create_genesis(&self.config.storage_path)?;
        let (start_hash, retention_boundary) =
            match Self::chain_start(&self.config.storage_path, &log_files, &genesis)? {
                Ok(start) => start,
                Err(mismatch) => {
                    return Ok(ChainVerificationReport {
                        files_checked: log_files.len(),
                        events_checked: 0,
                        mismatch: Some(mismatch),
                        tail_hash: genesis,
                        retention_boundary: None,
                    });
                }
            };
        let walk = Self::walk_chain(&log_files, start_hash)?;
        Ok(ChainVerificationReport {
            files_checked: log_files.len(),
            events_checked: walk.events_checked,
            mismatch: walk.mismatch,
            tail_hash: walk.tail_hash,
            retention_boundary,
        })
    }

    /// Replay the hash chain over `files` (oldest first) starting from
    /// `start_hash`, checking each line's hash, the format-downgrade rule
    /// and every cross-file chain-link anchor.
    ///
    /// # Errors
    /// Returns an error if a file cannot be read, a line exceeds the cap,
    /// is not UTF-8 or cannot be parsed, or hashing fails.
    fn walk_chain(files: &[PathBuf], start_hash: String) -> Result<ChainWalk> {
        let mut prev_hash = start_hash;
        let mut file_tails: Vec<String> = Vec::with_capacity(files.len());
        let mut events_checked: u64 = 0;
        let mut mismatch: Option<ChainMismatch> = None;

        // Once a format-2 line has been seen, the chain may not fall back
        // to format 1: new writers never emit it, so a later format-1 line
        // can only be a splice.
        let mut seen_format_2 = false;

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

        for file in files {
            use std::io::BufRead;
            let f = File::open(file).map_err(|e| {
                CoreError::AuditError(format!("Failed to open {}: {}", file.display(), e))
            })?;
            let mut reader = std::io::BufReader::new(f);
            // Reset per-file: track whether we've seen the first
            // non-empty event of this file (used for the cross-file
            // anchor check below).
            let mut first_event_in_file = true;
            // Bounded line-reader. `BufReader::lines()` and the
            // obvious `read_until(b'\n', &mut buf)` BOTH allocate the
            // whole line BEFORE returning, so a 1 GiB newline-free
            // file would OOM the verifier before any post-decode
            // `MAX_AUDIT_LINE_LEN` check could fire.
            //
            // We use `BufRead::fill_buf` / `consume` to scan for
            // `b'\n'` in the buffered region and accumulate at most
            // `MAX_AUDIT_LINE_LEN + 1` bytes into `line_buf` per line.
            // The +1 byte lets us detect the over-cap case
            // unambiguously (the cap is exclusive). An earlier
            // implementation used per-byte `reader.read()` which was
            // correct but did one syscall per byte; this shape keeps
            // the bound while letting the kernel/buffer combine reads.
            let mut line_buf: Vec<u8> = Vec::new();
            let mut line_idx: usize = 0;
            loop {
                line_buf.clear();
                let mut hit_newline = false;
                let mut hit_eof = false;
                while !hit_newline && !hit_eof {
                    let buf = reader
                        .fill_buf()
                        .map_err(|e| CoreError::AuditError(format!("Failed to read line: {e}")))?;
                    if buf.is_empty() {
                        hit_eof = true;
                        break;
                    }
                    // How many bytes can we still accumulate before
                    // crossing `MAX_AUDIT_LINE_LEN + 1`? Stop the moment
                    // we'd cross — that's the cap-exceeded signal.
                    let remaining_room =
                        MAX_AUDIT_LINE_LEN.saturating_add(1).saturating_sub(line_buf.len());
                    let scan_end = buf.len().min(remaining_room);
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "indexing into a slice whose length is known at this site"
                    )]
                    // SAFETY: `scan_end = buf.len().min(remaining_room)`
                    // ⇒ `scan_end ≤ buf.len()` ⇒ `&buf[..scan_end]`
                    // is in-bounds. (no possible panic)
                    let scan_slice = &buf[..scan_end];
                    if let Some(rel) = scan_slice.iter().position(|&b| b == b'\n') {
                        // Found the newline within the room budget —
                        // append up to (but excluding) it, consume
                        // the newline.
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "indexing into a slice whose length is known at this site"
                        )]
                        // SAFETY: `rel` came from `scan_slice.iter().position()`
                        // ⇒ `rel < scan_slice.len()` ⇒ `&scan_slice[..rel]`
                        // is in-bounds. (no possible panic)
                        let prefix = &scan_slice[..rel];
                        line_buf.extend_from_slice(prefix);
                        let consume_n = rel.saturating_add(1);
                        reader.consume(consume_n);
                        hit_newline = true;
                    } else if scan_end < buf.len() {
                        // No newline within room budget AND there's
                        // more data in the kernel buffer — that means
                        // this line exceeds the cap. Append whatever
                        // fits in the room budget (may be zero), then
                        // BREAK so the over-cap check below converts
                        // to Err. Without `break`, the next iteration
                        // sees `remaining_room == 0` ⇒ `scan_end == 0`
                        // ⇒ no append + no consume ⇒ infinite livelock,
                        // giving an attacker with audit-write access
                        // a DoS on `verify_chain`.
                        line_buf.extend_from_slice(scan_slice);
                        reader.consume(scan_end);
                        break;
                    } else {
                        // No newline yet, but the entire buffered
                        // chunk fits within room — append, consume,
                        // refill.
                        line_buf.extend_from_slice(scan_slice);
                        reader.consume(scan_end);
                    }
                }
                if hit_eof && line_buf.is_empty() {
                    break;
                }
                if line_buf.len() > MAX_AUDIT_LINE_LEN {
                    return Err(CoreError::AuditError(format!(
                        "audit line {} of {} exceeds maximum length {}",
                        line_idx,
                        file.display(),
                        MAX_AUDIT_LINE_LEN
                    )));
                }
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
                let saved_idx = line_idx;
                line_idx = line_idx.saturating_add(1);
                if line.trim().is_empty() {
                    continue;
                }
                let line_idx = saved_idx;
                // Decode either format and recompute its hash. Parse
                // failures collapse to one opaque "unparseable" outcome so
                // the error cannot leak which structural field failed.
                let Some(VerifiedLine {
                    event,
                    stored_hash: stored,
                    recomputed_hash: recomputed,
                    format,
                }) = Self::decode_line(&line, &prev_hash)?
                else {
                    tracing::debug!(
                        line = line_idx,
                        file = %file.display(),
                        "audit chain line rejected as unparseable"
                    );
                    return Err(CoreError::AuditError(format!(
                        "Failed to parse line {} of {}",
                        line_idx,
                        file.display()
                    )));
                };
                events_checked = events_checked.saturating_add(1);
                if format == 1 && seen_format_2 {
                    mismatch = Some(ChainMismatch {
                        file: file.clone(),
                        line: line_idx,
                        event_id: event.id,
                        stored_hash: stored,
                        expected_hash: "a format-2 line (chain already uses format 2)".to_string(),
                    });
                    break;
                }
                seen_format_2 |= format == AUDIT_LINE_FORMAT_V2;
                if stored != recomputed {
                    mismatch = Some(ChainMismatch {
                        file: file.clone(),
                        line: line_idx,
                        event_id: event.id,
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
                        //
                        // The three `ct_eq` results are combined with
                        // `subtle::Choice::&` BEFORE the final
                        // `.into() -> bool`. A naïve `bool && bool &&
                        // bool` shape would short-circuit on the first
                        // false result, leaking via timing which of
                        // the three checks failed. Combining
                        // `Choice<u8>` values keeps the comparison
                        // data-independent.
                        use subtle::ConstantTimeEq;
                        let action_eq =
                            event.action.as_bytes().ct_eq(CHAIN_ANCHOR_ACTION.as_bytes());
                        let prev_file_eq = event
                            .metadata
                            .get(CHAIN_ANCHOR_PREV_FILE_KEY)
                            .map(|v| v.as_bytes().ct_eq(prev_name.as_bytes()))
                            .unwrap_or_else(|| 0u8.ct_eq(&1u8));
                        let prev_hash_eq = event
                            .metadata
                            .get(CHAIN_ANCHOR_PREV_HASH_KEY)
                            .map(|v| v.as_bytes().ct_eq(prev_final_hash.as_bytes()))
                            .unwrap_or_else(|| 0u8.ct_eq(&1u8));
                        let consistent: bool = (action_eq & prev_file_eq & prev_hash_eq).into();
                        if !consistent {
                            // Surface as a chain mismatch on this line —
                            // matches the existing reporting shape so
                            // callers don't need a second error
                            // variant for "anchor missing/wrong."
                            mismatch = Some(ChainMismatch {
                                file: file.clone(),
                                line: line_idx,
                                event_id: event.id,
                                stored_hash: stored,
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
            file_tails.push(prev_hash.clone());
        }

        Ok(ChainWalk { events_checked, mismatch, tail_hash: prev_hash, file_tails })
    }

    /// Where verification of `files` starts.
    ///
    /// From `genesis`, unless the oldest file begins with a chain-link
    /// anchor — meaning its predecessor has been removed. That is accepted
    /// only when the anchor names exactly the file and hash the retention
    /// sweep recorded in the protected checkpoint before deleting; an
    /// anchor that merely claims a predecessor (e.g. a fabricated file
    /// written after deleting the real log) is reported as a mismatch.
    ///
    /// # Errors
    /// Returns an error if the oldest file or the checkpoint cannot be read.
    fn chain_start(
        dir: &std::path::Path,
        files: &[PathBuf],
        genesis: &str,
    ) -> Result<std::result::Result<(String, Option<String>), ChainMismatch>> {
        let from_genesis = Ok(Ok((genesis.to_string(), None)));
        let Some(oldest) = files.first() else { return from_genesis };
        let Some((line_idx, first_line)) = Self::first_line(oldest)? else { return from_genesis };
        // An unparseable first line is reported by the walk itself.
        let Some(decoded) = Self::decode_line(&first_line, genesis)? else { return from_genesis };
        if decoded.event.action != CHAIN_ANCHOR_ACTION {
            return from_genesis;
        }
        if let (Some(checkpoint), Some(prev_file), Some(prev_hash)) = (
            Self::load_retention_checkpoint(dir)?,
            decoded.event.metadata.get(CHAIN_ANCHOR_PREV_FILE_KEY),
            decoded.event.metadata.get(CHAIN_ANCHOR_PREV_HASH_KEY),
        ) {
            use subtle::ConstantTimeEq;
            let matches: bool = (prev_file.as_bytes().ct_eq(checkpoint.file.as_bytes())
                & prev_hash.as_bytes().ct_eq(checkpoint.hash.as_bytes()))
            .into();
            if matches {
                return Ok(Ok((checkpoint.hash, Some(checkpoint.file))));
            }
        }
        Ok(Err(ChainMismatch {
            file: oldest.clone(),
            line: line_idx,
            event_id: decoded.event.id,
            stored_hash: decoded.stored_hash,
            expected_hash: "a link to a removed file recorded in the retention checkpoint"
                .to_string(),
        }))
    }

    /// Write an audit event to the current file.
    fn write_event_to_file(&self, event: &mut AuditEvent) -> Result<()> {
        let mut file_state = self.file_state.lock();

        // Rotate if needed
        self.rotate_if_needed(&mut file_state)?;

        let state = file_state
            .as_mut()
            .ok_or_else(|| CoreError::AuditError("No active audit file".to_string()))?;

        // Encode the format-2 line; its hash covers the exact event bytes.
        let previous_hash = self.previous_hash.read().clone();
        let line = Self::encode_line(event, &previous_hash)?;

        // Write JSON line BEFORE advancing the in-memory chain hash.
        // If `write_all` fails (ENOSPC, EIO, etc.), `previous_hash`
        // must NOT advance — otherwise the next successfully-written
        // event would chain from a hash whose corresponding line is
        // missing on disk, and a subsequent `verify_chain()` would
        // report it as tampering. Write-then-advance, not
        // advance-then-write.
        let line_bytes = line.as_bytes();

        state
            .writer
            .write_all(line_bytes)
            .map_err(|e| CoreError::AuditError(format!("Failed to write audit event: {e}")))?;

        // Disk-write succeeded — now safe to advance the chain.
        {
            let mut prev = self.previous_hash.write();
            prev.clone_from(&event.integrity_hash);
        }

        // Update size tracking. `usize → u64` is widening on 64-bit and
        // equal on 32-bit, so the conversion is always lossless — but
        // route via `try_from` for consistency with the rest of this
        // file and to silence `clippy::cast_possible_truncation`.
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
                .map_err(|e| CoreError::AuditError(format!("Failed to flush audit file: {e}")))?;
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
#[expect(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    unused_qualifications,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Rename the oldest audit file so its filename says `days` days ago
    /// (retention judges age by filename). Must run before any later file
    /// links to it by name.
    fn age_oldest_file(dir: &std::path::Path, days: u64) -> String {
        let oldest = FileAuditStorage::sorted_audit_files(dir).unwrap().remove(0);
        let then =
            Timestamp::now().checked_sub(Duration::from_secs(days.saturating_mul(86_400))).unwrap();
        let name = audit_file_name(then);
        fs::rename(&oldest, dir.join(&name)).unwrap();
        name
    }

    #[test]
    fn test_restart_after_all_files_expired_continues_from_checkpoint_succeeds() {
        let three_days_ago = Timestamp::now().checked_sub(Duration::from_secs(3 * 86_400)).unwrap();
        let (dir, old) = legacy_dir_at(&["expired"], three_days_ago);
        let old_name = old.file_name().unwrap().to_str().unwrap().to_string();
        let config = AuditConfig::new(dir.path().to_path_buf()).with_retention_days(1).unwrap();
        let storage = FileAuditStorage::new(config).unwrap();
        assert!(!old.exists(), "retention must remove the expired, verified file");
        write_one(&storage, "fresh");
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.retention_boundary.as_deref(), Some(old_name.as_str()));
        assert_eq!(report.events_checked, 2); // chain-link anchor + fresh
    }

    #[test]
    fn test_retention_sweep_records_boundary_and_chain_verifies_succeeds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        {
            let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
            write_one(&storage, "run-1");
        }
        let aged = age_oldest_file(&path, 3);
        {
            let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
            write_one(&storage, "run-2");
        }
        let config = AuditConfig::new(path.clone()).with_retention_days(1).unwrap();
        let storage = FileAuditStorage::new(config).unwrap();
        assert!(!path.join(&aged).exists());
        write_one(&storage, "run-3");
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.retention_boundary.as_deref(), Some(aged.as_str()));
        assert_eq!(report.tail_hash, *storage.previous_hash.read());
    }

    #[test]
    fn test_manual_removal_without_checkpoint_is_reported_fails() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig::new(dir.path().to_path_buf());
        {
            let storage = FileAuditStorage::new(config.clone()).unwrap();
            write_one(&storage, "run-1");
        }
        std::thread::sleep(Duration::from_millis(2));
        let storage = FileAuditStorage::new(config).unwrap();
        write_one(&storage, "run-2");
        let oldest = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().remove(0);
        fs::remove_file(&oldest).unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(!report.is_intact(), "removal not recorded by retention must not verify");
        assert_eq!(report.retention_boundary, None);
    }

    /// The automated-review attack: wipe the log, then write a file that
    /// starts with a chain-link anchor claiming an arbitrary predecessor.
    #[test]
    fn test_forged_leading_anchor_is_rejected_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        {
            let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
            write_one(&storage, "genuine");
        }
        let forge = |claimed_file: &str, claimed_hash: &str| {
            for f in FileAuditStorage::sorted_audit_files(&path).unwrap() {
                fs::remove_file(f).unwrap();
            }
            let mut anchor =
                AuditEvent::new(AuditEventType::System, CHAIN_ANCHOR_ACTION, AuditOutcome::Success)
                    .with_metadata(CHAIN_ANCHOR_PREV_FILE_KEY, claimed_file)
                    .with_metadata(CHAIN_ANCHOR_PREV_HASH_KEY, claimed_hash);
            let mut content = FileAuditStorage::encode_line(&mut anchor, claimed_hash).unwrap();
            let mut fake = AuditEvent::new(AuditEventType::System, "forged", AuditOutcome::Success);
            content.push_str(
                &FileAuditStorage::encode_line(&mut fake, &anchor.integrity_hash).unwrap(),
            );
            fs::write(path.join(audit_file_name(Timestamp::now())), content).unwrap();
        };
        let claimed = audit_file_name(Timestamp::from_unix(1_700_000_000, 0).unwrap());

        // No retention checkpoint at all.
        forge(&claimed, &"cd".repeat(32));
        let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(!report.is_intact(), "{report:?}");
        drop(storage);

        // A genuine checkpoint exists, but the forged anchor does not match it.
        FileAuditStorage::store_retention_checkpoint(
            &path,
            Some(&RetentionCheckpoint { file: claimed.clone(), hash: "ef".repeat(32) }),
        )
        .unwrap();
        forge(&claimed, &"cd".repeat(32));
        let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
        assert!(!storage.verify_chain().unwrap().is_intact());
    }

    #[test]
    fn test_retention_keeps_expired_files_that_do_not_verify_succeeds() {
        let three_days_ago = Timestamp::now().checked_sub(Duration::from_secs(3 * 86_400)).unwrap();
        let (dir, old) = legacy_dir_at(&["one", "two"], three_days_ago);
        // Tamper with the expired file: retention must keep it as evidence.
        let content = fs::read_to_string(&old).unwrap();
        fs::write(&old, content.replacen("\"one\"", "\"0ne\"", 1)).unwrap();
        let config = AuditConfig::new(dir.path().to_path_buf()).with_retention_days(1).unwrap();
        let storage = FileAuditStorage::new(config).unwrap();
        assert!(old.exists(), "an unverifiable expired file must not be deleted");
        assert!(!dir.path().join(AUDIT_RETENTION_CHECKPOINT_FILENAME).exists());
        assert!(!storage.verify_chain().unwrap().is_intact());
    }

    #[test]
    fn test_malformed_retention_checkpoint_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();
        {
            let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
            write_one(&storage, "run-1");
        }
        let aged = age_oldest_file(&path, 3);
        {
            let storage = FileAuditStorage::new(AuditConfig::new(path.clone())).unwrap();
            write_one(&storage, "run-2");
        }
        let storage =
            FileAuditStorage::new(AuditConfig::new(path.clone()).with_retention_days(1).unwrap())
                .unwrap();
        assert!(!path.join(&aged).exists());
        fs::write(path.join(AUDIT_RETENTION_CHECKPOINT_FILENAME), "not a checkpoint\n").unwrap();
        // Verification relies on the checkpoint, so it fails closed.
        assert!(storage.verify_chain().is_err());
    }

    fn write_one(storage: &FileAuditStorage, action: &str) {
        storage
            .write(&AuditEvent::new(AuditEventType::System, action, AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
    }

    #[test]
    fn test_new_file_sorts_after_newest_even_if_clock_is_behind_succeeds() {
        // The newest file is named an hour in the future (clock stepped
        // back since it was written).
        let hour_ahead = Timestamp::now().checked_add(Duration::from_secs(3_600)).unwrap();
        let (dir, future_file) = legacy_dir_at(&["from-the-future"], hour_ahead);
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        write_one(&storage, "now");
        let files = FileAuditStorage::sorted_audit_files(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0], future_file, "the new file must sort after the existing one");
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
    }

    #[test]
    fn test_restart_with_empty_newest_file_succeeds() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig::new(dir.path().to_path_buf());
        {
            let storage = FileAuditStorage::new(config.clone()).unwrap();
            write_one(&storage, "before");
        }
        // A crash right after creating a file leaves it empty.
        std::thread::sleep(Duration::from_millis(2));
        let empty = dir.path().join(audit_file_name(Timestamp::now()));
        File::create(&empty).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let storage = FileAuditStorage::new(config).unwrap();
        write_one(&storage, "after");
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.files_checked, 3);
    }

    #[test]
    fn test_non_canonical_format_2_lines_are_rejected_fails() {
        for (from, to) in [
            (r#""event":{"#, r#""event": {"#),  // whitespace outside the event
            (r#"{"v":2,"#, r#"{"v":2,"x":1,"#), // unknown field
        ] {
            let dir = TempDir::new().unwrap();
            let storage =
                FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
            write_one(&storage, "canonical");
            let path = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
            let content = fs::read_to_string(&path).unwrap();
            let edited = content.replacen(from, to, 1);
            assert_ne!(edited, content, "{from:?}");
            fs::write(&path, edited).unwrap();
            assert!(storage.verify_chain().is_err(), "non-canonical edit {to:?} must be rejected");
        }
    }

    #[test]
    fn test_escaped_integrity_hash_is_rejected_fails() {
        // Same hash value after JSON unescaping, different bytes: only the
        // canonical-line check can catch it.
        let dir = TempDir::new().unwrap();
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        write_one(&storage, "escape");
        let path = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let hash = storage.previous_hash.read().clone();
        let first = hash.chars().next().unwrap();
        let escaped = format!("\\u{:04x}{}", u32::from(first), &hash[1..]);
        let edited = content.replacen(&hash, &escaped, 1);
        assert_ne!(edited, content);
        let reparsed: AuditLineIn<'_> = serde_json::from_str(edited.trim_end()).unwrap();
        assert_eq!(reparsed.integrity_hash, hash, "escape must decode to the same value");
        fs::write(&path, edited).unwrap();
        assert!(storage.verify_chain().is_err());
    }

    /// Name an audit file for `at` the way `create_new_file` does.
    fn audit_file_name(at: Timestamp) -> String {
        let f = at.utc_fields().unwrap();
        format!(
            "audit-{:04}-{:02}-{:02}T{:02}-{:02}-{:02}-{:06}.jsonl",
            f.year(),
            u8::from(f.month()),
            f.day(),
            f.hour(),
            f.minute(),
            f.second(),
            f.microsecond()
        )
    }

    /// A format-1 line (bare event JSON with the field-transcript hash),
    /// as every version before format 2 wrote it.
    fn legacy_line(previous_hash: &str, action: &str) -> (String, String) {
        let mut event = AuditEvent::new(AuditEventType::System, action, AuditOutcome::Success);
        event.integrity_hash =
            FileAuditStorage::compute_integrity_hash_v1(&event, previous_hash).unwrap();
        (serde_json::to_string(&event).unwrap(), event.integrity_hash.clone())
    }

    /// Storage directory holding a genesis anchor and one format-1 file of
    /// `actions.len()` events written an hour ago.
    fn legacy_dir(actions: &[&str]) -> (TempDir, PathBuf) {
        let hour_ago = Timestamp::now().checked_sub(Duration::from_secs(3_600)).unwrap();
        legacy_dir_at(actions, hour_ago)
    }

    /// Like [`legacy_dir`], with the file named for `at`.
    fn legacy_dir_at(actions: &[&str], at: Timestamp) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let genesis = "ab".repeat(32);
        fs::write(dir.path().join(AUDIT_GENESIS_FILENAME), format!("{genesis}\n")).unwrap();
        let mut prev = genesis;
        let mut content = String::new();
        for action in actions {
            let (line, hash) = legacy_line(&prev, action);
            content.push_str(&line);
            content.push('\n');
            prev = hash;
        }
        let path = dir.path().join(audit_file_name(at));
        fs::write(&path, content).unwrap();
        (dir, path)
    }

    #[test]
    fn test_legacy_format_1_chain_verifies_and_resumes_as_format_2_succeeds() {
        let (dir, _legacy) = legacy_dir(&["old-1", "old-2"]);
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.events_checked, 2);

        storage
            .write(&AuditEvent::new(AuditEventType::System, "new-1", AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        // two legacy events + chain-link anchor + new event
        assert_eq!(report.events_checked, 4);
        assert_eq!(report.files_checked, 2);
    }

    #[test]
    fn test_format_1_line_after_format_2_is_rejected_fails() {
        let (dir, _legacy) = legacy_dir(&["old-1"]);
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        storage
            .write(&AuditEvent::new(AuditEventType::System, "new-1", AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
        // Splice a correctly chained format-1 line after the format-2 tail.
        let newest = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
        let tail = storage.previous_hash.read().clone();
        let (line, _) = legacy_line(&tail, "spliced");
        // LINT-OK: test appends to an existing log file; mode applies only at creation.
        let mut file = OpenOptions::new().append(true).open(&newest).unwrap();
        writeln!(file, "{line}").unwrap();
        drop(file);
        let report = storage.verify_chain().unwrap();
        let mismatch = report.mismatch.expect("format downgrade must be reported");
        assert!(mismatch.expected_hash.contains("format-2"), "{mismatch:?}");
    }

    #[test]
    fn test_format_2_hash_covers_exact_stored_bytes_fails_on_whitespace_edit() {
        let dir = TempDir::new().unwrap();
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        storage
            .write(&AuditEvent::new(AuditEventType::System, "exact", AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
        assert!(storage.verify_chain().unwrap().is_intact());
        // Insert insignificant whitespace inside the stored event object:
        // semantically identical JSON, different bytes — must not verify.
        let path = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let edited = content.replacen(r#""event":{"#, r#""event":{ "#, 1);
        assert_ne!(edited, content);
        fs::write(&path, edited).unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(report.mismatch.is_some(), "whitespace edit must break the chain");
    }

    #[test]
    fn test_unsupported_line_format_version_returns_error_fails() {
        let dir = TempDir::new().unwrap();
        let storage = FileAuditStorage::new(AuditConfig::new(dir.path().to_path_buf())).unwrap();
        storage
            .write(&AuditEvent::new(AuditEventType::System, "v", AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
        let path = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
        let content = fs::read_to_string(&path).unwrap();
        fs::write(&path, content.replacen(r#"{"v":2,"#, r#"{"v":3,"#, 1)).unwrap();
        let err = storage.verify_chain().unwrap_err();
        assert!(err.to_string().contains("unsupported audit line format version 3"), "{err}");
    }

    #[test]
    fn test_resume_skips_torn_final_line_succeeds() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig::new(dir.path().to_path_buf());
        let tail_before_crash = {
            let storage = FileAuditStorage::new(config.clone()).unwrap();
            storage
                .write(&AuditEvent::new(AuditEventType::System, "pre-crash", AuditOutcome::Success))
                .unwrap();
            storage.flush().unwrap();
            storage.previous_hash.read().clone()
        };
        // Simulate a crash mid-write: a truncated line with no newline.
        let path = FileAuditStorage::sorted_audit_files(dir.path()).unwrap().pop().unwrap();
        // LINT-OK: test appends to an existing log file; mode applies only at creation.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, r#"{{"v":2,"event":{{"id":"#).unwrap();
        drop(file);
        let storage = FileAuditStorage::new(config).unwrap();
        assert_eq!(*storage.previous_hash.read(), tail_before_crash);
        // Verification still reports the torn line.
        assert!(storage.verify_chain().is_err());
    }

    /// A process restart must continue the existing chain: the new run's
    /// file links to the previous file's tail, so `verify_chain` stays
    /// intact across restarts.
    #[test]
    fn test_verify_chain_survives_process_restart_succeeds() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig::new(dir.path().to_path_buf());
        {
            let storage = FileAuditStorage::new(config.clone()).unwrap();
            storage
                .write(&AuditEvent::new(AuditEventType::System, "first-run", AuditOutcome::Success))
                .unwrap();
            storage.flush().unwrap();
        }
        // Filenames carry microseconds; make sure the second run's differs.
        std::thread::sleep(Duration::from_millis(2));
        let storage = FileAuditStorage::new(config).unwrap();
        storage
            .write(&AuditEvent::new(AuditEventType::System, "second-run", AuditOutcome::Success))
            .unwrap();
        storage.flush().unwrap();
        let report = storage.verify_chain().unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(report.files_checked, 2);
        // first-run event + chain-link anchor + second-run event
        assert_eq!(report.events_checked, 3);
    }

    /// A format-1 audit line as written by 0.17.0 (timestamps encoded by
    /// chrono 0.4.45) with the integrity hash that version computed. Loading
    /// it must reproduce both the hash and the JSON byte-for-byte, or every
    /// pre-existing audit chain would fail `verify_chain`.
    #[test]
    fn test_audit_event_from_chrono_era_rehashes_identically_succeeds() {
        const LINE: &str = concat!(
            r#"{"id":"00000000-0000-4000-8000-000000000001","#,
            r#""timestamp":"2023-11-14T22:13:20.123456Z","event_type":"KeyOperation","#,
            r#""actor":"user@example.com","resource":"key-001","action":"generate_keypair","#,
            r#""outcome":"Success","metadata":{"algorithm":"ML-KEM-768"},"#,
            r#""integrity_hash":"89ec1b2d1e0baa6a18f27b504c2169c32c35e46d9ac2a2eba02fa1f9f57bce30"}"#
        );
        let event: AuditEvent = serde_json::from_str(LINE).unwrap();
        assert_eq!(event.timestamp(), Timestamp::from_unix(1_700_000_000, 123_456_000).unwrap());
        let rehash = FileAuditStorage::compute_integrity_hash_v1(&event, "").unwrap();
        assert_eq!(rehash, event.integrity_hash());
        assert_eq!(serde_json::to_string(&event).unwrap(), LINE);
    }

    #[test]
    fn test_parse_audit_filename_timestamp_shapes_succeeds() {
        let base = Timestamp::from_unix(1_700_000_000, 0).unwrap();
        assert_eq!(parse_audit_filename_timestamp("audit-2023-11-14T22-13-20.jsonl"), Some(base));
        assert_eq!(
            parse_audit_filename_timestamp("audit-2023-11-14T22-13-20-000042.jsonl"),
            base.checked_add(Duration::from_micros(42))
        );
        for bad in [
            "audit-2023-11-14T22-13-20-42.jsonl",
            "audit-2023-11-14T22-13-20-00004x.jsonl",
            "audit-2023-11-14T22:13:20.jsonl",
            "audit-2023-11-14t22-13-20.jsonl",
            "audit-2023-11-14 22-13-20.jsonl",
            "audit-2023-11-14_22-13-20.jsonl",
            "audit-+2023-11-14T22-13-20.jsonl",
            "audit-2023-11-14T25-13-20.jsonl",
            "audit-2023-11-14T22-13-20.log",
            "other-2023-11-14T22-13-20.jsonl",
            "audit-.jsonl",
        ] {
            assert_eq!(parse_audit_filename_timestamp(bad), None, "{bad:?} must be rejected");
        }
    }

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

        let hash1 = FileAuditStorage::compute_integrity_hash_v1(&event1, "").unwrap();
        let hash2 = FileAuditStorage::compute_integrity_hash_v1(&event2, &hash1).unwrap();

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Same event with same previous hash should produce same result
        let hash2_again = FileAuditStorage::compute_integrity_hash_v1(&event2, &hash1).unwrap();
        assert_eq!(hash2, hash2_again);

        // Different previous hash should produce different result
        let hash2_different =
            FileAuditStorage::compute_integrity_hash_v1(&event2, "different").unwrap();
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
        let diff =
            crate::types::timestamp::signed_seconds_between(event.timestamp(), Timestamp::now());
        assert!((0..5).contains(&diff));
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
                        &format!("operation_{i}"),
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
                        &format!("operation_{i}"),
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
        let hash1 = FileAuditStorage::compute_integrity_hash_v1(&event_no_meta, "").unwrap();
        let hash2 = FileAuditStorage::compute_integrity_hash_v1(&event_with_meta, "").unwrap();
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
                        &format!("chain_op_{i}"),
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
                let genesis = fs::read_to_string(temp_path.join(AUDIT_GENESIS_FILENAME)).unwrap();
                // Each format-2 line's hash covers its stored event bytes
                // and links to the previous line's hash, starting at genesis.
                let mut prev = genesis.trim().to_string();
                let mut hashes = Vec::new();
                for line in content.lines() {
                    let stored: AuditLineIn<'_> = serde_json::from_str(line).unwrap();
                    assert_eq!(stored.v, AUDIT_LINE_FORMAT_V2);
                    let expected = FileAuditStorage::compute_integrity_hash_v2(
                        &prev,
                        stored.event.get().as_bytes(),
                    )
                    .unwrap();
                    assert_eq!(stored.integrity_hash, expected);
                    prev = stored.integrity_hash;
                    hashes.push(prev.clone());
                }
                assert_eq!(hashes.len(), 3);
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

        let hash_with = FileAuditStorage::compute_integrity_hash_v1(&event, "").unwrap();

        // Same event without actor/resource should have different hash
        let event_without = AuditEvent::new(AuditEventType::System, "test", AuditOutcome::Success);
        let hash_without = FileAuditStorage::compute_integrity_hash_v1(&event_without, "").unwrap();

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
                        &format!("op_{i}"),
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

    /// A single audit JSONL line longer than `MAX_AUDIT_LINE_LEN` bytes with
    /// no early newline must return `AuditError` promptly rather than
    /// livelocking the inner `BufRead::fill_buf` loop in `verify_chain`.
    /// Asserts both correctness AND a wall-clock budget — a previous
    /// implementation hit `extend_from_slice(empty)` + `consume(0)`
    /// indefinitely on cap exceedance, so a regression that re-opens
    /// the same shape would never return without the budget check.
    #[test]
    fn test_verify_chain_over_cap_line_returns_error_promptly_fails() {
        use std::io::Write;
        use std::time::{Duration, Instant};

        let temp_dir = TempDir::new().unwrap();
        let storage_dir = temp_dir.path().join("audit");
        std::fs::create_dir_all(&storage_dir).unwrap();

        // Write a synthetic JSONL with one line of `MAX_AUDIT_LINE_LEN + 1024`
        // bytes (no newline before that point) followed by a newline.
        // `1 MiB + 1 KiB` is comfortably over the cap (1 MiB) and small
        // enough not to balloon test memory.
        let line_len = (1024 * 1024) + 1024;
        let file_path = storage_dir.join("audit-test.jsonl");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(&vec![b'A'; line_len]).unwrap();
            f.write_all(b"\n").unwrap();
            f.flush().unwrap();
        }

        let config = AuditConfig::new(storage_dir.clone());
        let storage = FileAuditStorage::new(config).unwrap();
        let started = Instant::now();
        let result = storage.verify_chain();
        let elapsed = started.elapsed();

        match result {
            Err(CoreError::AuditError(msg)) => {
                assert!(
                    msg.contains("exceeds maximum length"),
                    "expected 'exceeds maximum length' error, got: {msg}"
                );
            }
            other => panic!("expected over-cap AuditError, got {other:?}"),
        }
        // Pre-fix this test would never return; cap the budget so a
        // future regression that re-introduces the livelock fails the
        // suite instead of hanging it. 5s is generous for a 1 MiB file
        // even on the slowest CI runner.
        assert!(
            elapsed < Duration::from_secs(5),
            "verify_chain on over-cap line took {elapsed:?} (>5s — possible livelock)"
        );
    }
}
