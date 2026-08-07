//! `PortableKey` JSON / CBOR serialization, file I/O (atomic writes with
//! per-key-type Unix permissions), and the legacy CLI v1 key-file format.

use super::{KeyAlgorithm, KeyData, KeyType, PortableKey};
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::serialization::{decode_cbor_opaque, decode_json_opaque};
use serde::Deserialize;

impl PortableKey {
    // --- JSON serialization ---

    /// Serialize to JSON string (human-readable format).
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| CoreError::SerializationError(format!("JSON serialization failed: {e}")))
    }

    /// Serialize to pretty-printed JSON.
    ///
    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CoreError::SerializationError(format!("JSON serialization failed: {e}")))
    }

    /// Maximum accepted size for a JSON-serialized key (1 MiB).
    ///
    /// Inputs larger than this are rejected before parsing to prevent
    /// memory exhaustion from maliciously crafted payloads.
    pub const MAX_KEY_JSON_SIZE: usize = 1024 * 1024; // 1 MiB

    /// Maximum accepted size for a CBOR-serialized key (1 MiB).
    ///
    /// Inputs larger than this are rejected before parsing to prevent
    /// memory exhaustion from maliciously crafted payloads.
    pub const MAX_KEY_CBOR_SIZE: usize = 1024 * 1024; // 1 MiB

    /// Maximum number of entries the open `metadata` map may carry.
    /// `serde_json::Value` is recursive, so a 1 MiB JSON document can
    /// expand into a much larger heap tree; the entry cap and the
    /// per-value byte cap below bound that amplification.
    pub const MAX_METADATA_ENTRIES: usize = 64;
    /// Maximum byte length of a single metadata key.
    pub const MAX_METADATA_KEY_LEN: usize = 256;
    /// Maximum byte length of any single metadata value's serialized
    /// JSON representation. AAD includes serialized metadata on every
    /// encrypted-key decrypt; without this cap one oversized value
    /// would amplify hashing cost across every load of the same key.
    pub const MAX_METADATA_VALUE_JSON_LEN: usize = 4 * 1024;

    /// Deserialize from JSON string.
    ///
    /// # Errors
    /// Returns an error if the input exceeds [`MAX_KEY_JSON_SIZE`](Self::MAX_KEY_JSON_SIZE),
    /// JSON parsing fails, or validation fails.
    pub fn from_json(json: &str) -> Result<Self> {
        if json.len() > Self::MAX_KEY_JSON_SIZE {
            return Err(CoreError::ResourceExceeded(format!(
                "Key JSON size {} exceeds limit {}",
                json.len(),
                Self::MAX_KEY_JSON_SIZE
            )));
        }
        let key: Self = decode_json_opaque(json, "key.json")?;
        key.validate()?;
        key.check_use_case_or_security_level_invariant()?;
        Ok(key)
    }

    // --- CBOR serialization ---

    /// Serialize to CBOR bytes (compact binary format, RFC 8949).
    ///
    /// CBOR is the primary wire/storage format. Key material is stored as
    /// native CBOR byte strings — no base64 encoding overhead.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| {
            CoreError::SerializationError(format!("CBOR serialization failed: {e}"))
        })?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes.
    ///
    /// # Errors
    /// Returns an error if the input exceeds [`MAX_KEY_CBOR_SIZE`](Self::MAX_KEY_CBOR_SIZE),
    /// CBOR parsing fails, or validation fails.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        if data.len() > Self::MAX_KEY_CBOR_SIZE {
            return Err(CoreError::ResourceExceeded(format!(
                "Key CBOR size {} exceeds limit {}",
                data.len(),
                Self::MAX_KEY_CBOR_SIZE
            )));
        }
        let key: Self = decode_cbor_opaque(data, "key.cbor")?;
        key.validate()?;
        key.check_use_case_or_security_level_invariant()?;
        Ok(key)
    }

    /// Enforce the documented invariant that at least one of `use_case`
    /// or `security_level` is present. Applied only at the
    /// deserialization boundary; locally-constructed keys always have
    /// `security_level` set by the constructors, so the invariant cannot
    /// be violated internally — only by hand-crafted wire payloads.
    fn check_use_case_or_security_level_invariant(&self) -> Result<()> {
        if self.use_case.is_none() && self.security_level.is_none() {
            return Err(CoreError::InvalidKey(
                "PortableKey requires at least one of `use_case` or `security_level`".to_string(),
            ));
        }
        Ok(())
    }

    // --- File I/O ---

    /// Write to a file as pretty JSON. Creates the file with 0600 permissions atomically on Unix
    /// for secret/symmetric keys, preventing a window where the file is world-readable.
    ///
    /// # Errors
    /// Returns an error if file writing or permission setting fails.
    pub fn write_to_file(&self, path: &std::path::Path) -> Result<()> {
        self.write_to_file_with_overwrite(path, false)
    }

    /// Like [`Self::write_to_file`] but with explicit overwrite control.
    ///
    /// `overwrite = false` (the recommended default) refuses to clobber
    /// an existing file at `path` and returns
    /// `CoreError::ConfigurationError` — caller should map this to a
    /// `--force`-equivalent prompt or abort.
    ///
    /// `overwrite = true` replaces any existing file via atomic rename
    /// (no truncate-then-write window where a crash leaves zero bytes
    /// on disk + the prior key destroyed).
    ///
    /// On Unix, secret/symmetric files are written with mode `0o600`
    /// applied BEFORE the rename. On Windows the tempfile inherits the
    /// parent dir's ACL via `tempfile`'s NTFS path; further hardening
    /// requires `windows-sys` and is left to the consumer.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` on overwrite-refused or
    /// tempfile creation failure, or `CoreError::Internal` on I/O.
    pub fn write_to_file_with_overwrite(
        &self,
        path: &std::path::Path,
        overwrite: bool,
    ) -> Result<()> {
        let json = self.to_json_pretty()?;
        self.make_atomic_writer(json.as_bytes(), overwrite).write(path)
    }

    /// Build an `AtomicWrite` with the project's mode policy for this
    /// key type pre-applied.
    ///
    /// Mode policy:
    ///   Secret / Symmetric → 0o600 (owner read+write only)
    ///   Public             → 0o644 (owner rw, others r) — public
    ///                        keys are MEANT to be readable; without
    ///                        this an explicit 0o644, tempfile's
    ///                        default 0o600 would lock pub keys to
    ///                        the creator and break key-distribution
    ///                        flows.
    ///
    /// lifted out of `write_to_file_with_overwrite`
    /// so the JSON and CBOR write paths share one source of truth for
    /// mode selection. Drift between the two would silently regress the
    /// secret-key threat model.
    fn make_atomic_writer<'a>(
        &self,
        bytes: &'a [u8],
        overwrite: bool,
    ) -> crate::unified_api::atomic_write::AtomicWrite<'a> {
        let writer =
            crate::unified_api::atomic_write::AtomicWrite::new(bytes).overwrite_existing(overwrite);
        if self.key_type == KeyType::Secret || self.key_type == KeyType::Symmetric {
            writer.secret_mode()
        } else {
            writer.unix_mode(0o644)
        }
    }

    /// Write to a file as CBOR. Creates the file with 0600 permissions atomically on Unix
    /// for secret/symmetric keys, preventing a window where the file is world-readable.
    ///
    /// # Errors
    /// Returns an error if CBOR serialization or file writing fails.
    pub fn write_cbor_to_file(&self, path: &std::path::Path) -> Result<()> {
        self.write_cbor_to_file_with_overwrite(path, false)
    }

    /// Like [`Self::write_cbor_to_file`] but with explicit overwrite control.
    ///
    /// Same contract as [`Self::write_to_file_with_overwrite`] — the JSON
    /// and CBOR paths now both go through `AtomicWrite` instead of
    /// the original truncate-then-write pattern that would destroy
    /// prior key material on crash mid-write.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` on overwrite-refused or
    /// tempfile creation failure, or `CoreError::Internal` on I/O.
    pub fn write_cbor_to_file_with_overwrite(
        &self,
        path: &std::path::Path,
        overwrite: bool,
    ) -> Result<()> {
        let cbor = self.to_cbor()?;
        self.make_atomic_writer(&cbor, overwrite).write(path)
    }

    /// Read from a JSON file with a bounded read.
    ///
    /// Reads at most [`Self::MAX_KEY_JSON_SIZE`] + 1 bytes via a
    /// `Read::take` adapter so a symlink to `/dev/zero`, a pathological
    /// attacker file, or any path whose `metadata().len()` is unreliable
    /// (FIFOs, `/proc/*`) cannot OOM the process before the size cap
    /// fires inside [`Self::from_json`].
    ///
    /// # Errors
    /// Returns an error if file reading, the size cap, or JSON parsing fails.
    pub fn read_from_file(path: &std::path::Path) -> Result<Self> {
        use std::io::Read;
        // +1 so anything longer than the cap reads as MAX+1 and is
        // rejected by `from_json`'s length check rather than silently
        // truncating to MAX.
        const READ_CAP: u64 = (PortableKey::MAX_KEY_JSON_SIZE as u64).saturating_add(1);
        let file = std::fs::File::open(path)?;
        let mut buf = String::new();
        file.take(READ_CAP).read_to_string(&mut buf).map_err(|e| {
            tracing::debug!(error = %e, "key JSON file read rejected");
            CoreError::SerializationError("key JSON file read failed".to_string())
        })?;
        Self::from_json(&buf)
    }

    /// Read from a CBOR file with a bounded read.
    ///
    /// Reads at most [`Self::MAX_KEY_CBOR_SIZE`] + 1 bytes — see
    /// [`Self::read_from_file`] for the OOM-resistance rationale.
    ///
    /// # Errors
    /// Returns an error if file reading, the size cap, or CBOR parsing fails.
    pub fn read_cbor_from_file(path: &std::path::Path) -> Result<Self> {
        use std::io::Read;
        const READ_CAP: u64 = (PortableKey::MAX_KEY_CBOR_SIZE as u64).saturating_add(1);
        let file = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        file.take(READ_CAP).read_to_end(&mut buf).map_err(|e| {
            tracing::debug!(error = %e, "key CBOR file read rejected");
            CoreError::SerializationError("key CBOR file read failed".to_string())
        })?;
        Self::from_cbor(&buf)
    }

    // --- Legacy CLI format ---

    /// Parse a legacy CLI v1 key file format.
    ///
    /// The CLI v1 format uses `"key"` for raw key bytes and `"algorithm"` as a string.
    ///
    /// ```json
    /// {
    ///   "algorithm": "ML-DSA-65",
    ///   "key_type": "public",
    ///   "key": "Base64..."
    /// }
    /// ```
    ///
    /// # Errors
    /// Returns an error if the JSON is invalid or the algorithm is unrecognized.
    pub fn from_legacy_json(json: &str) -> Result<Self> {
        // parallel `from_json` enforces a 1 MiB size
        // guard before parsing to prevent memory exhaustion from
        // maliciously crafted payloads. The legacy path was missing this
        // check, leaving a DoS vector when migrating older keyfiles.
        if json.len() > Self::MAX_KEY_JSON_SIZE {
            return Err(CoreError::ResourceExceeded(format!(
                "Legacy key JSON size {} exceeds limit {}",
                json.len(),
                Self::MAX_KEY_JSON_SIZE
            )));
        }

        #[derive(Deserialize)]
        struct LegacyKeyFile {
            algorithm: String,
            key_type: String,
            key: String,
            #[serde(default)]
            label: Option<String>,
        }

        let legacy: LegacyKeyFile = decode_json_opaque(json, "key.legacy_json")?;

        let algorithm = parse_legacy_algorithm(&legacy.algorithm)?;
        // The legacy schema carries a single flat `key` field, so it
        // physically cannot represent a hybrid key's separate post-quantum
        // and classical components. Reject hybrid algorithms here with the
        // real reason: otherwise the key is built as `KeyData::Single` and
        // `validate()` rejects it with the misleading "must use composite
        // key data" message, which reads as a caller error rather than a
        // format limitation.
        if algorithm.is_hybrid() {
            return Err(CoreError::InvalidKey(format!(
                "Legacy key format cannot represent hybrid algorithm {algorithm:?}: \
                 the legacy schema has a single `key` field and no way to encode \
                 the separate post-quantum and classical components a hybrid key \
                 requires. Re-export this key in the current (non-legacy) format."
            )));
        }
        let key_type = match legacy.key_type.to_lowercase().as_str() {
            "public" | "pub" => KeyType::Public,
            "secret" | "private" | "sk" => KeyType::Secret,
            "symmetric" | "sym" => KeyType::Symmetric,
            other => {
                return Err(CoreError::InvalidKey(format!(
                    "Unrecognized legacy key_type: '{other}'"
                )));
            }
        };

        let key_data = KeyData::Single { raw: legacy.key };

        let mut key = Self::new(algorithm, key_type, key_data);
        if let Some(label) = legacy.label {
            key.set_label(label)?;
        }
        key.validate()?;
        Ok(key)
    }
}

/// Parse legacy algorithm strings to [`KeyAlgorithm`].
///
/// Thin wrapper over [`KeyAlgorithm::from_canonical_name`] that maps
/// `None` to a [`CoreError::InvalidKey`] for the `from_legacy_json`
/// path.
fn parse_legacy_algorithm(s: &str) -> Result<KeyAlgorithm> {
    KeyAlgorithm::from_canonical_name(s)
        .ok_or_else(|| CoreError::InvalidKey(format!("Unrecognized algorithm: '{s}'")))
}
