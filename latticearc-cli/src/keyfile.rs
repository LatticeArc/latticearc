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

/// Parse key-file bytes, trying every supported format in turn.
///
/// Order:
/// 1. If the bytes are valid UTF-8, try LPK JSON, then legacy CLI v1 JSON.
/// 2. Fall through to LPK CBOR either way (binary inputs, or text that
///    happened to round-trip through a UTF-8 check but is really CBOR).
///
/// On total failure, the returned error mentions every format attempted
/// and preserves the LPK JSON error — the most common failure mode — as
/// its inner cause, instead of surfacing a low-level CBOR parse error
/// from bytes that were never CBOR.
fn parse_key_bytes(bytes: &[u8]) -> Result<PortableKey> {
    let text = std::str::from_utf8(bytes).ok();

    if let Some(text) = text {
        // Keep the JSON error for the final message instead of reparsing below.
        let json_err = match PortableKey::from_json(text) {
            Ok(key) => return Ok(key),
            Err(e) => e,
        };
        if let Ok(key) = PortableKey::from_legacy_json(text) {
            return Ok(key);
        }
        if let Ok(key) = PortableKey::from_cbor(bytes) {
            return Ok(key);
        }
        return Err(anyhow::anyhow!(
            "Invalid key file (tried JSON, legacy JSON, CBOR): {json_err}"
        ));
    }

    // Binary path: LPK CBOR only.
    PortableKey::from_cbor(bytes).map_err(|e| anyhow::anyhow!("Invalid CBOR key file: {e}"))
}

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

    /// Read a key file from disk.
    ///
    /// Accepts all three LPK formats plus the legacy CLI v1 JSON format:
    /// - **LPK JSON** (UTF-8 text, default format written by `keygen`)
    /// - **LPK CBOR** (binary, RFC 8949 — compact wire/storage format)
    /// - **Legacy CLI v1 JSON** (pre-LPK format — backward compat path)
    ///
    /// Format detection is heuristic: the file bytes are first tested for
    /// valid UTF-8 + JSON, then fallback to CBOR. A pure-binary CBOR file
    /// will fail the UTF-8 check and route directly to the CBOR parser.
    ///
    /// If the file contains a passphrase-encrypted key, prompts for the
    /// passphrase via [`resolve_existing_passphrase`] and unwraps it before
    /// returning. Plaintext key files are returned as-is.
    pub fn read_from(path: &std::path::Path) -> Result<Self> {
        // Round-20 audit fix #14: gate the file read behind a size
        // ceiling. Key files are well under 100 KiB in every supported
        // format (LPK JSON, LPK CBOR, legacy CLI v1 JSON); a 1 MiB cap
        // is generous and bounds OOM if a symlink to /dev/zero or a
        // sparse file ends up at this path. Verified by
        // tests/cli_integration.rs::round20_fix14_keyfile_size_cap_rejects_oversized_input
        // — that test fails with the unfixed code by hitting the
        // library's downstream parser limit instead of this CLI guard.
        const MAX_KEYFILE_BYTES: u64 = 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path)
            && meta.len() > MAX_KEYFILE_BYTES
        {
            anyhow::bail!(
                "Key file {} is {} bytes; maximum supported size is {} bytes. \
                 This is far above any legitimate LatticeArc key encoding.",
                path.display(),
                meta.len(),
                MAX_KEYFILE_BYTES
            );
        }
        // The LINT-OK tag must sit on the same line as `std::fs::read`
        // because `.github/workflows/lint-extras.yml` greps line-by-line.
        let bytes = std::fs::read(path) // LINT-OK: size-gated-by-MAX_KEYFILE_BYTES (1 MiB cap above)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let mut inner = parse_key_bytes(&bytes)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        // Transparently unlock passphrase-protected keys.
        unlock_if_encrypted(&mut inner)
            .with_context(|| format!("Failed to unlock {}", path.display()))?;

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
    write_key_protected(path, algorithm, key_type, key_bytes, label, None)
}

/// Write a single-component key, optionally encrypting secret/symmetric material
/// with a passphrase before persisting to disk.
///
/// `passphrase = Some(pp)` invokes [`PortableKey::encrypt_with_passphrase`] before
/// serializing. Public keys with `passphrase = Some(_)` are written unencrypted —
/// public keys do not need confidentiality protection.
pub(crate) fn write_key_protected(
    path: &std::path::Path,
    algorithm: KeyAlgorithm,
    key_type: LpkKeyType,
    key_bytes: &[u8],
    label: Option<String>,
    passphrase: Option<&[u8]>,
) -> Result<()> {
    let mut key = PortableKey::new(algorithm, key_type, KeyData::from_raw(key_bytes));
    if let Some(l) = label {
        key.set_label(l);
    }
    encrypt_if_secret(&mut key, key_type, passphrase)?;
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
    write_composite_key_protected(path, algorithm, key_type, pq_bytes, classical_bytes, label, None)
}

/// Composite-key counterpart to [`write_key_protected`].
pub(crate) fn write_composite_key_protected(
    path: &std::path::Path,
    algorithm: KeyAlgorithm,
    key_type: LpkKeyType,
    pq_bytes: &[u8],
    classical_bytes: &[u8],
    label: Option<String>,
    passphrase: Option<&[u8]>,
) -> Result<()> {
    let mut key =
        PortableKey::new(algorithm, key_type, KeyData::from_composite(pq_bytes, classical_bytes));
    if let Some(l) = label {
        key.set_label(l);
    }
    encrypt_if_secret(&mut key, key_type, passphrase)?;
    key.write_to_file(path).with_context(|| format!("Failed to write {}", path.display()))
}

/// Apply passphrase encryption to secret/symmetric keys only.
///
/// Public keys are written in plaintext regardless: they need integrity, not
/// confidentiality, and encrypting them at rest would prevent verifiers from
/// loading them without coordinating a passphrase.
fn encrypt_if_secret(
    key: &mut PortableKey,
    key_type: LpkKeyType,
    passphrase: Option<&[u8]>,
) -> Result<()> {
    let Some(pp) = passphrase else {
        return Ok(());
    };
    if !matches!(key_type, LpkKeyType::Secret | LpkKeyType::Symmetric) {
        return Ok(());
    }
    key.encrypt_with_passphrase(pp)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt key with passphrase: {e}"))
}

// ============================================================================
// Passphrase prompts
// ============================================================================

/// Read a passphrase from the controlling terminal without echoing it.
///
/// Used by `keygen` to prompt for a new passphrase (asks twice and verifies
/// they match) and by load paths to prompt for an existing passphrase.
pub(crate) fn read_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    let pp = rpassword::prompt_password(prompt).map_err(|e| {
        // Round-7 audit fix #7: rpassword opens /dev/tty (or the
        // Windows console handle) directly; in CI / Docker / non-tty
        // pipelines the open fails with a generic I/O error and the
        // user has no obvious next step. Detect that case and point
        // them at LATTICEARC_PASSPHRASE.
        let no_tty = !std::io::IsTerminal::is_terminal(&std::io::stdin());
        if no_tty {
            anyhow::anyhow!(
                "Failed to read passphrase from terminal: {e}. \
                 No interactive TTY is attached (CI, Docker, piped stdin?). \
                 For non-interactive use, set LATTICEARC_PASSPHRASE in the \
                 environment before invoking this command, then unset it \
                 immediately afterwards. See SECURITY.md for the env-var \
                 leak caveats."
            )
        } else {
            anyhow::anyhow!("Failed to read passphrase: {e}")
        }
    })?;
    Ok(zeroize::Zeroizing::new(pp))
}

/// Read a *new* passphrase from the terminal, prompting twice and rejecting
/// mismatches or empty values. Used at keygen time.
pub(crate) fn read_new_passphrase() -> Result<zeroize::Zeroizing<String>> {
    let pp1 = read_passphrase("Enter passphrase to protect secret key: ")?;
    if pp1.is_empty() {
        bail!("Passphrase must not be empty");
    }
    let pp2 = read_passphrase("Confirm passphrase: ")?;
    if pp1.as_bytes() != pp2.as_bytes() {
        bail!("Passphrases did not match");
    }
    Ok(pp1)
}

/// Resolve a passphrase from the `LATTICEARC_PASSPHRASE` env var (for
/// scripting / CI) or fall through to `tty_fallback()` — typically a prompt.
///
/// # Security trade-off — env var is convenient but leaky
///
/// Environment variables are visible to other processes running as the same
/// user via `/proc/<pid>/environ` (Linux), are inherited by child processes
/// across `fork()`/`exec()`, and can be captured in core dumps. For
/// interactive use, prefer the TTY prompt (do not export the variable).
/// `LATTICEARC_PASSPHRASE` is intended for CI / non-interactive automation
/// only — see `SECURITY.md` for the full threat model.
///
/// When the variable is read on a process whose stdin is a TTY, a warning is
/// emitted to `stderr`: that combination usually means an interactive user
/// has accidentally inherited the env from a prior shell session and is now
/// using a less-secure code path than intended.
///
/// Note: passphrases must NEVER be passed as command-line arguments — they
/// would be visible in `ps`, shell history, and crash dumps.
fn resolve_passphrase(
    tty_fallback: impl FnOnce() -> Result<zeroize::Zeroizing<String>>,
) -> Result<zeroize::Zeroizing<String>> {
    if let Ok(pp) = std::env::var("LATTICEARC_PASSPHRASE") {
        if pp.is_empty() {
            bail!("LATTICEARC_PASSPHRASE is set but empty");
        }
        // SECURITY: env-var passphrases have two known leak vectors and
        // we cannot mitigate either fully without `unsafe` code (which
        // the workspace `unsafe_code = "forbid"` policy bans).
        //
        // 1. Other processes running as the same UID can read
        //    `/proc/self/environ` of this process (or
        //    `/proc/<pid>/environ` for child processes). This applies
        //    for the lifetime of the process; we cannot
        //    `std::env::remove_var()` it because that's an unsafe API
        //    in the 2024 edition (data races with concurrent env reads
        //    in multi-threaded programs).
        // 2. Any subprocess we spawn after this call inherits the
        //    variable. We do not currently spawn subprocesses, but
        //    callers wrapping us must be aware.
        //
        // Mitigation contract: callers who use `LATTICEARC_PASSPHRASE`
        // in scripts should `unset LATTICEARC_PASSPHRASE` immediately
        // after the latticearc-cli invocation completes.
        //
        // We additionally warn loudly if a TTY is attached — that's the
        // strongest signal that the env-var path was unintentional
        // (a stale shell-export from a prior session).
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            eprintln!(
                "warning: LATTICEARC_PASSPHRASE is set on an interactive TTY session. \
                 Env-var passphrases are visible to same-UID processes via \
                 /proc/<pid>/environ for the lifetime of this process and to \
                 any subprocess we spawn. Unset the variable and use the \
                 prompt unless you are running in non-interactive automation. \
                 Scripts that intentionally use this path should `unset \
                 LATTICEARC_PASSPHRASE` immediately after this command exits."
            );
        }
        return Ok(zeroize::Zeroizing::new(pp));
    }
    tty_fallback()
}

/// Resolve a *new* passphrase for protecting a key being written to disk:
/// reads `LATTICEARC_PASSPHRASE` or falls back to a double-confirm tty prompt.
pub(crate) fn resolve_new_passphrase() -> Result<zeroize::Zeroizing<String>> {
    resolve_passphrase(read_new_passphrase)
}

/// Resolve an *existing* passphrase for unwrapping a key loaded from disk:
/// reads `LATTICEARC_PASSPHRASE` or falls back to a single-line tty prompt.
pub(crate) fn resolve_existing_passphrase() -> Result<zeroize::Zeroizing<String>> {
    resolve_passphrase(|| read_passphrase("Enter passphrase to unlock secret key: "))
}

/// Decrypt a `PortableKey` in place if it is passphrase-protected, prompting
/// the user for the passphrase via [`resolve_existing_passphrase`].
///
/// Plaintext keys are returned unchanged.
pub(crate) fn unlock_if_encrypted(key: &mut PortableKey) -> Result<()> {
    if !key.is_encrypted() {
        return Ok(());
    }
    let pp = resolve_existing_passphrase()?;
    key.decrypt_with_passphrase(pp.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to unlock key: {e}"))
}

/// Parse a hybrid signing PK from concatenated raw bytes (pq ++ classical).
///
/// Used by legacy verify path where bytes were already extracted via
/// `key_bytes()` without an accompanying scheme tag. The ML-DSA parameter
/// set is recovered from the PQ-component length, which is unambiguous
/// across the three FIPS 204 sets (1312/1952/2592 bytes for 44/65/87).
pub(crate) fn parse_hybrid_sign_pk_from_bytes(
    bytes: &[u8],
) -> Result<latticearc::hybrid::sig_hybrid::HybridSigPublicKey> {
    use latticearc::primitives::sig::ml_dsa::MlDsaParameterSet;
    let split = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| anyhow::anyhow!("Hybrid signing PK too short ({} bytes)", bytes.len()))?;
    if split == 0 {
        bail!("Hybrid signing PK has no PQ component ({} bytes)", bytes.len());
    }
    let parameter_set = match split {
        n if n == MlDsaParameterSet::MlDsa44.public_key_size() => MlDsaParameterSet::MlDsa44,
        n if n == MlDsaParameterSet::MlDsa65.public_key_size() => MlDsaParameterSet::MlDsa65,
        n if n == MlDsaParameterSet::MlDsa87.public_key_size() => MlDsaParameterSet::MlDsa87,
        n => bail!(
            "Hybrid signing PK PQ-component length {n} matches no known ML-DSA \
             parameter set (44={}, 65={}, 87={})",
            MlDsaParameterSet::MlDsa44.public_key_size(),
            MlDsaParameterSet::MlDsa65.public_key_size(),
            MlDsaParameterSet::MlDsa87.public_key_size(),
        ),
    };
    Ok(latticearc::hybrid::sig_hybrid::HybridSigPublicKey::new(
        parameter_set,
        bytes.get(..split).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
        bytes.get(split..).ok_or_else(|| anyhow::anyhow!("slice"))?.to_vec(),
    ))
}

/// Parse a hybrid KEM PK from concatenated raw bytes (pq ++ classical).
pub(crate) fn parse_hybrid_kem_pk_from_bytes(
    bytes: &[u8],
    algorithm: KeyAlgorithm,
) -> Result<latticearc::hybrid::kem_hybrid::HybridKemPublicKey> {
    use latticearc::primitives::kem::MlKemSecurityLevel;
    let level = match algorithm {
        KeyAlgorithm::HybridMlKem512X25519 => MlKemSecurityLevel::MlKem512,
        KeyAlgorithm::HybridMlKem768X25519 => MlKemSecurityLevel::MlKem768,
        KeyAlgorithm::HybridMlKem1024X25519 => MlKemSecurityLevel::MlKem1024,
        other => {
            bail!("parse_hybrid_kem_pk_from_bytes called with non-hybrid-KEM algorithm {other:?}")
        }
    };
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
        level,
    ))
}

/// Parse an algorithm name string to `KeyAlgorithm`. Delegates to the
/// library's [`KeyAlgorithm::from_canonical_name`] so the CLI and the
/// `from_legacy_json` parser share one source of truth — no risk of
/// drift when a new wire name is added.
fn parse_algorithm_name(name: &str) -> Option<KeyAlgorithm> {
    KeyAlgorithm::from_canonical_name(name)
}
