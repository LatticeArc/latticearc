//! Key file I/O for LatticeArc CLI.
//!
//! Delegates to [`latticearc::PortableKey`] (the library's standard key format).
//! Provides CLI-friendly wrappers and backward-compatible `KeyFile` API for
//! reading/writing key files.

use anyhow::{Context, Result, bail};
use latticearc::unified_api::key_format::{
    KeyAlgorithm, KeyData, KeyType as LpkKeyType, PortableKey,
};

// Re-export KeyType for backward compatibility with command files
pub(crate) use latticearc::unified_api::key_format::KeyType;

// ============================================================================
// KeyFile — backward-compatible wrapper around PortableKey
// ============================================================================

/// CLI key file — wraps `PortableKey` with a CLI-friendly interface.
///
/// Reads both the new PortableKey format and the legacy CLI v1 format.
pub(crate) struct KeyFile {
    /// The underlying portable key.
    inner: PortableKey,
    /// Algorithm name (cached for backward compat with `validate_algorithm`).
    pub algorithm: String,
    /// Key type.
    pub key_type: LpkKeyType,
}

impl KeyFile {
    /// Decode the key bytes (single-component keys).
    pub fn key_bytes(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        // Try single first, fall back to composite (concatenated for backward compat)
        if let Ok(bytes) = self.inner.key_data().decode_raw() {
            Ok(zeroize::Zeroizing::new(bytes))
        } else {
            // Composite key — concatenate PQ + classical for legacy callers
            let (pq, cl) = self
                .inner
                .key_data()
                .decode_composite()
                .map_err(|e| anyhow::anyhow!("Failed to decode key bytes: {e}"))?;
            let capacity = pq
                .len()
                .checked_add(cl.len())
                .ok_or_else(|| anyhow::anyhow!("Key data exceeds maximum size"))?;
            let mut combined = Vec::with_capacity(capacity);
            combined.extend_from_slice(&pq);
            combined.extend_from_slice(&cl);
            Ok(zeroize::Zeroizing::new(combined))
        }
    }

    /// Read a key file from disk (supports both PortableKey and legacy formats).
    pub fn read_from(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        // Try PortableKey first, fall back to legacy format
        let inner = PortableKey::from_json(&data)
            .or_else(|_| {
                PortableKey::from_legacy_json(&data)
                    .map_err(|e| anyhow::anyhow!("Invalid key file: {e}"))
            })
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        let algorithm = format!("{:?}", inner.algorithm()).to_lowercase().replace('_', "-");
        let key_type = inner.key_type();

        Ok(Self { inner, algorithm, key_type })
    }

    /// Validate that the key file algorithm matches the expected algorithm.
    pub fn validate_algorithm(&self, expected: &str) -> Result<()> {
        // Flexible matching: compare the KeyAlgorithm enum
        let Some(expected_alg) = parse_algorithm_name(expected) else {
            bail!("Unrecognized algorithm name: '{expected}'");
        };
        if self.inner.algorithm() != expected_alg {
            bail!(
                "Key algorithm mismatch: key file is '{:?}', expected '{expected}'",
                self.inner.algorithm()
            );
        }
        Ok(())
    }

    /// Get the underlying `PortableKey` for bridge operations.
    pub fn portable_key(&self) -> &PortableKey {
        &self.inner
    }
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile")
            .field("algorithm", &self.algorithm)
            .field("key_type", &self.key_type)
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Hybrid key parsing (PortableKey bridge)
// ============================================================================

/// Parse a hybrid signing secret key from a `KeyFile`.
pub(crate) fn parse_hybrid_sign_sk(
    key: &KeyFile,
) -> Result<latticearc::hybrid::sig_hybrid::HybridSigSecretKey> {
    key.portable_key()
        .to_hybrid_sig_secret_key()
        .map_err(|e| anyhow::anyhow!("Failed to parse hybrid signing secret key: {e}"))
}

// ============================================================================
// New PortableKey-based API (for new code)
// ============================================================================

/// Write a single-component key to a JSON file using `PortableKey`.
pub(crate) fn write_key(
    path: &std::path::Path,
    algorithm: KeyAlgorithm,
    key_type: LpkKeyType,
    key_bytes: &[u8],
    label: Option<String>,
) -> Result<()> {
    let mut key = PortableKey::new(algorithm, key_type, KeyData::from_raw(key_bytes));
    if let Some(l) = label {
        key.set_label(l);
    }
    key.write_to_file(path).with_context(|| format!("Failed to write {}", path.display()))
}

/// Write a composite (hybrid) key to a JSON file using `PortableKey`.
pub(crate) fn write_composite_key(
    path: &std::path::Path,
    algorithm: KeyAlgorithm,
    key_type: LpkKeyType,
    pq_bytes: &[u8],
    classical_bytes: &[u8],
    label: Option<String>,
) -> Result<()> {
    let mut key =
        PortableKey::new(algorithm, key_type, KeyData::from_composite(pq_bytes, classical_bytes));
    if let Some(l) = label {
        key.set_label(l);
    }
    key.write_to_file(path).with_context(|| format!("Failed to write {}", path.display()))
}

/// Parse a hybrid signing PK from concatenated raw bytes (pq ++ classical).
///
/// Used by legacy verify path where bytes were already extracted via `key_bytes()`.
pub(crate) fn parse_hybrid_sign_pk_from_bytes(
    bytes: &[u8],
) -> Result<latticearc::hybrid::sig_hybrid::HybridSigPublicKey> {
    let split = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| anyhow::anyhow!("Hybrid signing PK too short ({} bytes)", bytes.len()))?;
    if split == 0 {
        bail!("Hybrid signing PK has no PQ component ({} bytes)", bytes.len());
    }
    Ok(latticearc::hybrid::sig_hybrid::HybridSigPublicKey::new(
        bytes.get(..split).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
        bytes.get(split..).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
    ))
}

/// Parse a hybrid KEM PK from concatenated raw bytes (pq ++ classical).
pub(crate) fn parse_hybrid_kem_pk_from_bytes(
    bytes: &[u8],
) -> Result<latticearc::hybrid::kem_hybrid::HybridKemPublicKey> {
    let split = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| anyhow::anyhow!("Hybrid KEM PK too short ({} bytes)", bytes.len()))?;
    if split == 0 {
        bail!("Hybrid KEM PK has no PQ component ({} bytes)", bytes.len());
    }
    Ok(latticearc::hybrid::kem_hybrid::HybridKemPublicKey::new(
        bytes.get(..split).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
        bytes.get(split..).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
        latticearc::primitives::kem::MlKemSecurityLevel::MlKem768,
    ))
}

/// Parse an algorithm name string to `KeyAlgorithm`.
fn parse_algorithm_name(name: &str) -> Option<KeyAlgorithm> {
    match name {
        "ml-kem-512" => Some(KeyAlgorithm::MlKem512),
        "ml-kem-768" => Some(KeyAlgorithm::MlKem768),
        "ml-kem-1024" => Some(KeyAlgorithm::MlKem1024),
        "ml-dsa-44" => Some(KeyAlgorithm::MlDsa44),
        "ml-dsa-65" => Some(KeyAlgorithm::MlDsa65),
        "ml-dsa-87" => Some(KeyAlgorithm::MlDsa87),
        "slh-dsa-shake-128s" => Some(KeyAlgorithm::SlhDsaShake128s),
        "fn-dsa-512" => Some(KeyAlgorithm::FnDsa512),
        "fn-dsa-1024" => Some(KeyAlgorithm::FnDsa1024),
        "ed25519" => Some(KeyAlgorithm::Ed25519),
        "x25519" => Some(KeyAlgorithm::X25519),
        "aes-256" => Some(KeyAlgorithm::Aes256),
        "chacha20" => Some(KeyAlgorithm::ChaCha20),
        "hybrid-ml-kem-768-x25519" => Some(KeyAlgorithm::HybridMlKem768X25519),
        "hybrid-ml-kem-512-x25519" => Some(KeyAlgorithm::HybridMlKem512X25519),
        "hybrid-ml-kem-1024-x25519" => Some(KeyAlgorithm::HybridMlKem1024X25519),
        "hybrid-ml-dsa-65-ed25519" => Some(KeyAlgorithm::HybridMlDsa65Ed25519),
        "hybrid-ml-dsa-44-ed25519" => Some(KeyAlgorithm::HybridMlDsa44Ed25519),
        "hybrid-ml-dsa-87-ed25519" => Some(KeyAlgorithm::HybridMlDsa87Ed25519),
        _ => None,
    }
}
