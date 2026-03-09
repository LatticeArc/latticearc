//! Key file format for LatticeArc CLI.
//!
//! Keys are stored as JSON files with algorithm metadata, Base64-encoded key
//! material, and creation timestamps. Secret key files are written with
//! restricted permissions (0600 on Unix) and key material is zeroized on drop.

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Key type discriminant stored in the JSON file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyType {
    /// Symmetric key (e.g., AES-256).
    Symmetric,
    /// Asymmetric public key.
    Public,
    /// Asymmetric secret key.
    Secret,
}

/// JSON key file format.
///
/// Uses a manual `Debug` implementation that redacts key material for
/// secret and symmetric keys (FIPS 140-3 key protection).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct KeyFile {
    /// File format version.
    pub version: u8,
    /// Algorithm identifier (e.g., "ml-kem-768", "ml-dsa-65", "aes-256").
    pub algorithm: String,
    /// Key type.
    pub key_type: KeyType,
    /// Base64-encoded key material.
    pub key: String,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// Optional human-readable label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("KeyFile");
        s.field("version", &self.version)
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type);

        // Redact key material for secret and symmetric keys
        if matches!(self.key_type, KeyType::Secret | KeyType::Symmetric) {
            s.field("key", &"[REDACTED]");
        } else {
            s.field("key", &self.key);
        }

        s.field("created", &self.created).field("label", &self.label).finish()
    }
}

impl KeyFile {
    /// Create a new key file with the given parameters.
    pub fn new(
        algorithm: impl Into<String>,
        key_type: KeyType,
        key_bytes: &[u8],
        label: Option<String>,
    ) -> Self {
        Self {
            version: 1,
            algorithm: algorithm.into(),
            key_type,
            key: B64.encode(key_bytes),
            created: chrono::Utc::now().to_rfc3339(),
            label,
        }
    }

    /// Decode the Base64 key material.
    ///
    /// Returns `Zeroizing<Vec<u8>>` so secret key bytes are automatically
    /// wiped from memory when dropped (FIPS 140-3 key zeroization).
    pub fn key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let bytes = B64.decode(&self.key).context("Invalid Base64 in key file")?;
        Ok(zeroize::Zeroizing::new(bytes))
    }

    /// Write this key file to disk as pretty-printed JSON.
    ///
    /// Secret and symmetric key files are written with restricted
    /// permissions (owner read/write only, 0600 on Unix).
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("Failed to serialize key file")?;
        std::fs::write(path, &json)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        // Restrict permissions on secret/symmetric key files
        if matches!(self.key_type, KeyType::Secret | KeyType::Symmetric) {
            restrict_file_permissions(path)?;
        }

        Ok(())
    }

    /// Read a key file from disk.
    pub fn read_from(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        serde_json::from_str(&data)
            .with_context(|| format!("Invalid key file format in {}", path.display()))
    }

    /// Validate that the key file algorithm matches the expected algorithm.
    pub fn validate_algorithm(&self, expected: &str) -> Result<()> {
        if self.algorithm != expected {
            bail!(
                "Key algorithm mismatch: key file is '{}', expected '{expected}'",
                self.algorithm
            );
        }
        Ok(())
    }
}

/// Zeroize the base64-encoded key material when the key file is dropped,
/// regardless of key type. Prevents secret key material from lingering
/// in memory after the `KeyFile` is no longer needed.
impl Drop for KeyFile {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// Set owner-only read/write permissions on secret key files (Unix).
#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to restrict permissions on {}", path.display()))
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
