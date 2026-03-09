//! Persistent key storage with password-protected key wrapping.
//!
//! Keys are encrypted at rest using AES-256-GCM with a key encryption key (KEK)
//! derived from a master password via PBKDF2-HMAC-SHA256 (600K iterations).
//! Each key's associated data (AAD) is the SHA-256 hash of its metadata,
//! preventing key/metadata substitution attacks.
//!
//! ## File layout
//!
//! ```text
//! ~/.latticearc/keys/
//!   keystore.json          # Index + wrapped keys
//! ```
//!
//! ## Security properties
//!
//! - KEK derived from password with PBKDF2 (600K iterations, 16-byte random salt)
//! - Each key wrapped individually with AES-256-GCM + per-key random nonce
//! - AAD = SHA-256(key_id || algorithm || key_type || created) — binds ciphertext to metadata
//! - Password verification via encrypted sentinel (no password hash stored)
//! - All secret material zeroized on drop
//! - File permissions restricted to owner (0600 on Unix)

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ============================================================================
// Constants
// ============================================================================

/// PBKDF2 iteration count (OWASP 2023 recommendation for HMAC-SHA256).
const PBKDF2_ITERATIONS: u32 = 600_000;

/// PBKDF2 salt length in bytes.
const PBKDF2_SALT_LEN: usize = 16;

/// KEK length in bytes (AES-256).
const KEK_LEN: usize = 32;

/// Sentinel plaintext for password verification.
/// Encrypted with the KEK on creation; decrypted on open to verify password.
const SENTINEL_PLAINTEXT: &[u8] = b"latticearc-keystore-v1-sentinel";

/// Sentinel AAD — domain-separated from key wrapping AAD.
const SENTINEL_AAD: &[u8] = b"latticearc-keystore-sentinel-aad";

/// Default keystore directory name under home.
const KEYSTORE_DIR: &str = ".latticearc/keys";

/// Keystore index filename.
const KEYSTORE_FILE: &str = "keystore.json";

// ============================================================================
// Types
// ============================================================================

/// Key type stored in the keystore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredKeyType {
    /// Symmetric key (e.g., AES-256).
    Symmetric,
    /// Asymmetric keypair (public + secret stored together).
    Keypair,
    /// Public key only (exported from a keypair).
    Public,
}

/// Persisted keystore file format (JSON on disk).
#[derive(Serialize, Deserialize)]
pub(crate) struct KeyStoreFile {
    /// Format version.
    pub version: u8,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// Base64-encoded PBKDF2 salt.
    pub salt: String,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Base64-encoded encrypted sentinel (password verification).
    pub sentinel: String,
    /// Wrapped key entries keyed by user-chosen label.
    pub entries: BTreeMap<String, WrappedEntry>,
}

/// A single wrapped key entry on disk.
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct WrappedEntry {
    /// Unique key identifier (hex-encoded random bytes).
    pub id: String,
    /// Algorithm identifier (e.g., "ml-kem-768", "aes-256").
    pub algorithm: String,
    /// Key type.
    pub key_type: StoredKeyType,
    /// ISO 8601 creation timestamp.
    pub created: String,
    /// Base64-encoded AES-256-GCM wrapped key material (nonce || ciphertext || tag).
    pub wrapped_key: String,
    /// Base64-encoded public key (only for keypair entries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Number of times this key has been rotated.
    pub rotation_count: u32,
    /// ISO 8601 timestamp of last rotation (None if never rotated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rotated: Option<String>,
}

impl std::fmt::Debug for WrappedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedEntry")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type)
            .field("created", &self.created)
            .field("wrapped_key", &"[ENCRYPTED]")
            .field("public_key", &self.public_key.as_ref().map(|_| "[PRESENT]"))
            .field("rotation_count", &self.rotation_count)
            .field("last_rotated", &self.last_rotated)
            .finish()
    }
}

/// In-memory keystore with unlocked KEK.
///
/// The KEK is held in `Zeroizing<Vec<u8>>` and is wiped when the `KeyStore`
/// is dropped. All key material loaded from entries is also zeroized.
pub(crate) struct KeyStore {
    /// Path to the keystore.json file.
    path: PathBuf,
    /// Deserialized file contents.
    file: KeyStoreFile,
    /// Derived key encryption key (zeroized on drop).
    kek: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore")
            .field("path", &self.path)
            .field("entries", &self.file.entries.len())
            .field("kek", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// KeyStore Implementation
// ============================================================================

impl KeyStore {
    /// Create a new keystore protected by the given master password.
    ///
    /// Creates the directory structure and writes the initial keystore.json.
    pub fn create(password: &[u8], store_dir: Option<&Path>) -> Result<Self> {
        let dir = match store_dir {
            Some(d) => d.to_path_buf(),
            None => default_keystore_dir()?,
        };

        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create keystore directory: {}", dir.display()))?;

        let path = dir.join(KEYSTORE_FILE);
        if path.exists() {
            bail!("Keystore already exists at {}", path.display());
        }

        // Derive KEK from password
        let params = latticearc::primitives::kdf::pbkdf2::Pbkdf2Params::new(PBKDF2_SALT_LEN)?
            .iterations(PBKDF2_ITERATIONS)
            .key_length(KEK_LEN);

        let kek_result = latticearc::primitives::kdf::pbkdf2::pbkdf2(password, &params)
            .map_err(|e| anyhow::anyhow!("PBKDF2 key derivation failed: {e}"))?;

        let kek = Zeroizing::new(kek_result.key().to_vec());

        // Encrypt sentinel for password verification
        let sentinel_encrypted =
            latticearc::encrypt_aes_gcm_with_aad_unverified(SENTINEL_PLAINTEXT, &kek, SENTINEL_AAD)
                .map_err(|e| anyhow::anyhow!("Sentinel encryption failed: {e}"))?;

        let file = KeyStoreFile {
            version: 1,
            created: chrono::Utc::now().to_rfc3339(),
            salt: B64.encode(&params.salt),
            iterations: params.iterations,
            sentinel: B64.encode(&sentinel_encrypted),
            entries: BTreeMap::new(),
        };

        let store = Self { path, file, kek };
        store.save()?;

        Ok(store)
    }

    /// Open an existing keystore with the given master password.
    pub fn open(password: &[u8], store_dir: Option<&Path>) -> Result<Self> {
        let dir = match store_dir {
            Some(d) => d.to_path_buf(),
            None => default_keystore_dir()?,
        };

        let path = dir.join(KEYSTORE_FILE);
        if !path.exists() {
            bail!("No keystore found at {}", path.display());
        }

        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read keystore: {}", path.display()))?;
        let file: KeyStoreFile = serde_json::from_str(&data).context("Invalid keystore format")?;

        if file.version != 1 {
            bail!("Unsupported keystore version: {}", file.version);
        }

        // Derive KEK from password using stored salt + iterations
        let salt = B64.decode(&file.salt).context("Invalid salt encoding")?;
        let params = latticearc::primitives::kdf::pbkdf2::Pbkdf2Params::with_salt(&salt)
            .iterations(file.iterations)
            .key_length(KEK_LEN);

        let kek_result = latticearc::primitives::kdf::pbkdf2::pbkdf2(password, &params)
            .map_err(|e| anyhow::anyhow!("PBKDF2 key derivation failed: {e}"))?;

        let kek = Zeroizing::new(kek_result.key().to_vec());

        // Verify password by decrypting sentinel
        let sentinel_bytes = B64.decode(&file.sentinel).context("Invalid sentinel encoding")?;
        let decrypted =
            latticearc::decrypt_aes_gcm_with_aad_unverified(&sentinel_bytes, &kek, SENTINEL_AAD)
                .map_err(|_err| anyhow::anyhow!("Wrong password or corrupted keystore"))?;

        if decrypted != SENTINEL_PLAINTEXT {
            bail!("Sentinel mismatch — keystore may be corrupted");
        }

        Ok(Self { path, file, kek })
    }

    /// Store a key in the keystore.
    ///
    /// For asymmetric keys, pass the secret key as `key_bytes` and optionally
    /// provide the public key via `public_key_bytes`.
    pub fn store(
        &mut self,
        label: &str,
        algorithm: &str,
        key_type: StoredKeyType,
        key_bytes: &[u8],
        public_key_bytes: Option<&[u8]>,
    ) -> Result<String> {
        if self.file.entries.contains_key(label) {
            bail!("Key with label '{label}' already exists. Use rotate or delete first.");
        }

        let id = generate_key_id();
        let created = chrono::Utc::now().to_rfc3339();

        // Compute AAD = SHA-256(id || algorithm || key_type || created)
        let aad = compute_entry_aad(&id, algorithm, &key_type, &created);

        // Wrap key with KEK + AAD
        let wrapped = latticearc::encrypt_aes_gcm_with_aad_unverified(key_bytes, &self.kek, &aad)
            .map_err(|e| anyhow::anyhow!("Key wrapping failed: {e}"))?;

        let entry = WrappedEntry {
            id: id.clone(),
            algorithm: algorithm.to_string(),
            key_type,
            created,
            wrapped_key: B64.encode(&wrapped),
            public_key: public_key_bytes.map(|pk| B64.encode(pk)),
            rotation_count: 0,
            last_rotated: None,
        };

        self.file.entries.insert(label.to_string(), entry);
        self.save()?;

        Ok(id)
    }

    /// Load (unwrap) a key from the keystore by label.
    ///
    /// Returns the decrypted key bytes wrapped in `Zeroizing` for automatic cleanup.
    pub fn load(&self, label: &str) -> Result<Zeroizing<Vec<u8>>> {
        let entry = self
            .file
            .entries
            .get(label)
            .with_context(|| format!("No key with label '{label}' in keystore"))?;

        let wrapped = B64.decode(&entry.wrapped_key).context("Invalid wrapped key encoding")?;
        let aad = compute_entry_aad(&entry.id, &entry.algorithm, &entry.key_type, &entry.created);

        let plaintext = latticearc::decrypt_aes_gcm_with_aad_unverified(&wrapped, &self.kek, &aad)
            .map_err(|_err| {
                anyhow::anyhow!("Key unwrap failed for '{label}' — keystore may be corrupted")
            })?;

        Ok(Zeroizing::new(plaintext))
    }

    /// List all key entries (metadata only, no secret material).
    pub fn list(&self) -> Vec<(&str, &WrappedEntry)> {
        self.file.entries.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }

    /// Rotate a key: re-wrap new key material under the same label.
    ///
    /// Increments the rotation counter and updates the last_rotated timestamp.
    pub fn rotate(
        &mut self,
        label: &str,
        new_key_bytes: &[u8],
        new_public_key_bytes: Option<&[u8]>,
    ) -> Result<()> {
        let entry = self
            .file
            .entries
            .get(label)
            .with_context(|| format!("No key with label '{label}' to rotate"))?;

        // Preserve metadata but generate new wrapping
        let id = generate_key_id();
        let created = chrono::Utc::now().to_rfc3339();
        let algorithm = entry.algorithm.clone();
        let key_type = entry.key_type.clone();
        let rotation_count = entry.rotation_count.saturating_add(1);

        let aad = compute_entry_aad(&id, &algorithm, &key_type, &created);
        let wrapped =
            latticearc::encrypt_aes_gcm_with_aad_unverified(new_key_bytes, &self.kek, &aad)
                .map_err(|e| anyhow::anyhow!("Key wrapping failed during rotation: {e}"))?;

        let new_entry = WrappedEntry {
            id,
            algorithm,
            key_type,
            created,
            wrapped_key: B64.encode(&wrapped),
            public_key: new_public_key_bytes.map(|pk| B64.encode(pk)),
            rotation_count,
            last_rotated: Some(chrono::Utc::now().to_rfc3339()),
        };

        self.file.entries.insert(label.to_string(), new_entry);
        self.save()?;

        Ok(())
    }

    /// Delete a key from the keystore.
    pub fn delete(&mut self, label: &str) -> Result<()> {
        if self.file.entries.remove(label).is_none() {
            bail!("No key with label '{label}' in keystore");
        }
        self.save()
    }

    /// Export the public key for a keypair entry.
    ///
    /// Returns the raw public key bytes, or an error if the entry has no public key.
    pub fn export_public(&self, label: &str) -> Result<Vec<u8>> {
        let entry = self
            .file
            .entries
            .get(label)
            .with_context(|| format!("No key with label '{label}' in keystore"))?;

        let pk_b64 = entry
            .public_key
            .as_ref()
            .with_context(|| format!("Key '{label}' has no public key (symmetric key?)"))?;

        B64.decode(pk_b64).context("Invalid public key encoding")
    }

    /// Get the number of entries in the keystore.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.file.entries.len()
    }

    /// Check if the keystore is empty.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.file.entries.is_empty()
    }

    /// Get the path to the keystore file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Write the keystore to disk with restricted permissions.
    fn save(&self) -> Result<()> {
        let json =
            serde_json::to_string_pretty(&self.file).context("Failed to serialize keystore")?;
        std::fs::write(&self.path, &json)
            .with_context(|| format!("Failed to write keystore: {}", self.path.display()))?;

        restrict_file_permissions(&self.path)?;
        Ok(())
    }
}

// ============================================================================
// Free functions
// ============================================================================

/// Compute the AAD for a key entry: SHA-256(id || algorithm || key_type || created).
fn compute_entry_aad(
    id: &str,
    algorithm: &str,
    key_type: &StoredKeyType,
    created: &str,
) -> Vec<u8> {
    let key_type_str = match key_type {
        StoredKeyType::Symmetric => "symmetric",
        StoredKeyType::Keypair => "keypair",
        StoredKeyType::Public => "public",
    };

    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(b"|");
    hasher.update(algorithm.as_bytes());
    hasher.update(b"|");
    hasher.update(key_type_str.as_bytes());
    hasher.update(b"|");
    hasher.update(created.as_bytes());
    hasher.finalize().to_vec()
}

/// Generate a random key ID (32 hex chars = 16 random bytes).
fn generate_key_id() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Resolve the default keystore directory (~/.latticearc/keys/).
fn default_keystore_dir() -> Result<PathBuf> {
    let home = dirs_or_home()?;
    Ok(home.join(KEYSTORE_DIR))
}

/// Get the user's home directory.
fn dirs_or_home() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .context("Cannot determine home directory (HOME or USERPROFILE not set)")
}

/// Set owner-only read/write permissions on the keystore file (Unix).
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn temp_keystore_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    #[test]
    fn test_create_and_open_roundtrip() {
        let dir = temp_keystore_dir();
        let password = b"test-password-123";

        // Create
        let store = KeyStore::create(password, Some(dir.path())).unwrap();
        assert!(store.is_empty());
        assert!(store.path().exists());

        // Open with same password
        let store2 = KeyStore::open(password, Some(dir.path())).unwrap();
        assert!(store2.is_empty());
    }

    #[test]
    fn test_wrong_password_rejected() {
        let dir = temp_keystore_dir();
        KeyStore::create(b"correct-password", Some(dir.path())).unwrap();

        let result = KeyStore::open(b"wrong-password", Some(dir.path()));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Wrong password") || err_msg.contains("corrupted"),
            "Expected password error, got: {err_msg}"
        );
    }

    #[test]
    fn test_store_and_load_symmetric_key() {
        let dir = temp_keystore_dir();
        let password = b"store-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let key = [0x42u8; 32];
        store.store("my-aes-key", "aes-256", StoredKeyType::Symmetric, &key, None).unwrap();

        assert_eq!(store.len(), 1);

        let loaded = store.load("my-aes-key").unwrap();
        assert_eq!(loaded.as_slice(), &key);
    }

    #[test]
    fn test_store_and_load_keypair() {
        let dir = temp_keystore_dir();
        let password = b"keypair-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let sk = [0xABu8; 64];
        let pk = [0xCDu8; 32];
        store.store("my-keypair", "ed25519", StoredKeyType::Keypair, &sk, Some(&pk)).unwrap();

        let loaded = store.load("my-keypair").unwrap();
        assert_eq!(loaded.as_slice(), &sk);

        let exported_pk = store.export_public("my-keypair").unwrap();
        assert_eq!(exported_pk, &pk);
    }

    #[test]
    fn test_persistence_across_open() {
        let dir = temp_keystore_dir();
        let password = b"persist-test";

        // Create and store
        {
            let mut store = KeyStore::create(password, Some(dir.path())).unwrap();
            store.store("key1", "aes-256", StoredKeyType::Symmetric, &[0x11u8; 32], None).unwrap();
        }

        // Re-open and verify
        let store = KeyStore::open(password, Some(dir.path())).unwrap();
        assert_eq!(store.len(), 1);
        let loaded = store.load("key1").unwrap();
        assert_eq!(loaded.as_slice(), &[0x11u8; 32]);
    }

    #[test]
    fn test_delete_key() {
        let dir = temp_keystore_dir();
        let password = b"delete-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        store.store("to-delete", "aes-256", StoredKeyType::Symmetric, &[0x22u8; 32], None).unwrap();
        assert_eq!(store.len(), 1);

        store.delete("to-delete").unwrap();
        assert!(store.is_empty());

        // Should not be loadable
        assert!(store.load("to-delete").is_err());
    }

    #[test]
    fn test_rotate_key() {
        let dir = temp_keystore_dir();
        let password = b"rotate-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let old_key = [0x33u8; 32];
        let new_key = [0x44u8; 32];

        store.store("rotatable", "aes-256", StoredKeyType::Symmetric, &old_key, None).unwrap();

        store.rotate("rotatable", &new_key, None).unwrap();

        let loaded = store.load("rotatable").unwrap();
        assert_eq!(loaded.as_slice(), &new_key);

        let entries = store.list();
        let (_, entry) = entries.iter().find(|(l, _)| *l == "rotatable").unwrap();
        assert_eq!(entry.rotation_count, 1);
        assert!(entry.last_rotated.is_some());
    }

    #[test]
    fn test_list_entries() {
        let dir = temp_keystore_dir();
        let password = b"list-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        store.store("alpha", "aes-256", StoredKeyType::Symmetric, &[0x01u8; 32], None).unwrap();
        store
            .store("beta", "ml-dsa-65", StoredKeyType::Keypair, &[0x02u8; 64], Some(&[0x03u8; 32]))
            .unwrap();

        let entries = store.list();
        assert_eq!(entries.len(), 2);

        let labels: Vec<&str> = entries.iter().map(|(l, _)| *l).collect();
        assert!(labels.contains(&"alpha"));
        assert!(labels.contains(&"beta"));
    }

    #[test]
    fn test_duplicate_label_rejected() {
        let dir = temp_keystore_dir();
        let password = b"dup-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        store.store("dup", "aes-256", StoredKeyType::Symmetric, &[0x55u8; 32], None).unwrap();

        let result = store.store("dup", "aes-256", StoredKeyType::Symmetric, &[0x66u8; 32], None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_export_public_no_pk() {
        let dir = temp_keystore_dir();
        let password = b"nopk-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        store.store("sym-only", "aes-256", StoredKeyType::Symmetric, &[0x77u8; 32], None).unwrap();

        let result = store.export_public("sym-only");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no public key"));
    }

    #[test]
    fn test_delete_nonexistent() {
        let dir = temp_keystore_dir();
        let password = b"del-noexist";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let result = store.delete("ghost");
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_nonexistent() {
        let dir = temp_keystore_dir();
        let password = b"rot-noexist";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let result = store.rotate("ghost", &[0x99u8; 32], None);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_already_exists() {
        let dir = temp_keystore_dir();
        KeyStore::create(b"first", Some(dir.path())).unwrap();

        let result = KeyStore::create(b"second", Some(dir.path()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_aad_binds_metadata() {
        // Verify that AAD computation is deterministic for same inputs
        let aad1 = compute_entry_aad("id1", "aes-256", &StoredKeyType::Symmetric, "2026-01-01");
        let aad2 = compute_entry_aad("id1", "aes-256", &StoredKeyType::Symmetric, "2026-01-01");
        assert_eq!(aad1, aad2);

        // Different ID → different AAD
        let aad3 = compute_entry_aad("id2", "aes-256", &StoredKeyType::Symmetric, "2026-01-01");
        assert_ne!(aad1, aad3);

        // Different algorithm → different AAD
        let aad4 = compute_entry_aad("id1", "ml-kem-768", &StoredKeyType::Symmetric, "2026-01-01");
        assert_ne!(aad1, aad4);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_keystore_dir();
        KeyStore::create(b"perm-test", Some(dir.path())).unwrap();

        let path = dir.path().join(KEYSTORE_FILE);
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_multiple_keys_independent() {
        let dir = temp_keystore_dir();
        let password = b"multi-test";
        let mut store = KeyStore::create(password, Some(dir.path())).unwrap();

        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let key_c = [0xCCu8; 32];

        store.store("key-a", "aes-256", StoredKeyType::Symmetric, &key_a, None).unwrap();
        store.store("key-b", "aes-256", StoredKeyType::Symmetric, &key_b, None).unwrap();
        store.store("key-c", "aes-256", StoredKeyType::Symmetric, &key_c, None).unwrap();

        assert_eq!(store.load("key-a").unwrap().as_slice(), &key_a);
        assert_eq!(store.load("key-b").unwrap().as_slice(), &key_b);
        assert_eq!(store.load("key-c").unwrap().as_slice(), &key_c);

        // Delete middle key, others still accessible
        store.delete("key-b").unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.load("key-a").unwrap().as_slice(), &key_a);
        assert_eq!(store.load("key-c").unwrap().as_slice(), &key_c);
    }
}
