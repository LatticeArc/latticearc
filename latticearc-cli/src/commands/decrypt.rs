//! Decrypt command — authenticated decryption of files.
//!
//! Reverses the encryption performed by the `encrypt` command. Reads the
//! JSON-formatted encrypted file, validates the authentication tag, and
//! recovers the original plaintext.
//!
//! **Integrity check:** AES-256-GCM decryption fails if the ciphertext has
//! been modified in any way (the 16-byte authentication tag won't match).
//! This protects against tampering and truncation attacks.
//!
//! **Key types accepted:**
//! - `symmetric` — for AES-256-GCM decryption
//! - `public` — rejected with a clear error message
//! - `secret` — for hybrid or PQ-only decryption (auto-detected from scheme)

use anyhow::{Context, Result, bail};
use clap::Args;
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Arguments for the `decrypt` subcommand.
#[derive(Args)]
pub(crate) struct DecryptArgs {
    /// Input file containing encrypted JSON (reads from stdin if omitted).
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output file for decrypted data (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Key file path (symmetric key or hybrid secret key).
    #[arg(short, long)]
    pub key: PathBuf,
    /// Overwrite the output file if it already exists. Default: false.
    /// Round-26 audit fix (H12).
    #[arg(long)]
    pub force: bool,
}

/// Execute the decrypt command.
pub(crate) fn run(args: DecryptArgs) -> Result<()> {
    let cipher_json = read_input_string(&args.input)?;
    let key_file = KeyFile::read_from(&args.key)?;

    let encrypted =
        latticearc::unified_api::serialization::deserialize_encrypted_output(&cipher_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse encrypted data: {e}"))?;

    let plaintext = match key_file.key_type {
        KeyType::Symmetric => decrypt_symmetric(&encrypted, &key_file)?,
        KeyType::Secret => {
            // Determine if this is a hybrid or PQ-only secret key
            if encrypted.scheme().requires_pq_key() {
                decrypt_pq_only(&encrypted, &key_file)?
            } else {
                decrypt_hybrid(&encrypted, &key_file)?
            }
        }
        KeyType::Public => {
            bail!("Cannot decrypt with a public key. Provide the secret key.");
        }
        _ => anyhow::bail!("Unsupported KeyType variant"),
    };

    write_output(&args.output, &plaintext, args.force)
}

fn decrypt_symmetric(
    encrypted: &latticearc::EncryptedOutput,
    key_file: &KeyFile,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let key_bytes = key_file.key_bytes()?;
    if key_bytes.len() != 32 {
        bail!("AES-256 requires a 32-byte key, got {} bytes", key_bytes.len());
    }

    latticearc::decrypt(
        encrypted,
        latticearc::DecryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new(),
    )
    // Round-26 audit fix (M19): uniform "Decryption failed: <scheme>"
    // prefix across all three branches so scripted callers cannot
    // distinguish symmetric vs hybrid vs PQ-only failure paths from
    // stderr.
    .map_err(|e| anyhow::anyhow!("Decryption failed (symmetric): {e}"))
}

fn decrypt_hybrid(
    encrypted: &latticearc::EncryptedOutput,
    key_file: &KeyFile,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // Reconstruct HybridKemSecretKey from the PortableKey.
    // ML-KEM public key is extracted from the secret key file's metadata
    // (stored at keygen time, following PKCS#12 bundling pattern).
    let hybrid_sk = key_file
        .portable_key()
        .to_hybrid_secret_key()
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct hybrid secret key: {e}"))?;

    latticearc::decrypt(
        encrypted,
        latticearc::DecryptKey::Hybrid(&hybrid_sk),
        latticearc::CryptoConfig::new(),
    )
    .map_err(|e| anyhow::anyhow!("Decryption failed (hybrid): {e}"))
}

fn decrypt_pq_only(
    encrypted: &latticearc::EncryptedOutput,
    key_file: &KeyFile,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let level = super::common::resolve_ml_kem_level(key_file.portable_key().algorithm())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let sk_bytes = key_file.key_bytes()?;

    // PqOnlySecretKey now requires the recipient PK so the HKDF info on
    // decrypt can bind to identity (HPKE / RFC 9180 §5.1). The PK is
    // stored in the key file's metadata at keygen time under the same
    // `ml_kem_pk` slot used by the hybrid path.
    let pk_b64 =
        key_file.portable_key().metadata().get("ml_kem_pk").and_then(|v| v.as_str()).ok_or_else(
            || {
                anyhow::anyhow!(
                    "PQ-only secret key file is missing the 'ml_kem_pk' metadata field; \
                 regenerate the keypair with the latest CLI."
                )
            },
        )?;
    let pk_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pk_b64)
        .map_err(|e| anyhow::anyhow!("Invalid 'ml_kem_pk' base64 in metadata: {e}"))?;

    let pq_sk = latticearc::PqOnlySecretKey::from_bytes(level, &sk_bytes, &pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid PQ-only secret key: {e}"))?;

    latticearc::decrypt(
        encrypted,
        latticearc::DecryptKey::PqOnly(&pq_sk),
        latticearc::CryptoConfig::new().crypto_mode(latticearc::CryptoMode::PqOnly),
    )
    .map_err(|e| anyhow::anyhow!("Decryption failed (pq-only): {e}"))
}

fn read_input_string(path: &Option<PathBuf>) -> Result<String> {
    // Round-9 audit fix #3: route through the shared helper.
    super::common::read_file_or_stdin_string(
        path.as_deref(),
        super::common::CLI_MAX_DECRYPTION_INPUT_BYTES,
        "decrypt",
    )
}

fn write_output(path: &Option<PathBuf>, data: &[u8], force: bool) -> Result<()> {
    if let Some(p) = path {
        // Atomic write with 0o600. `tempfile::NamedTempFile` already
        // creates files with mode 0o600 and `persist()` preserves that;
        // `.secret_mode()` is retained as defense-in-depth in case
        // tempfile's default ever changes.
        // Round-26 audit fix (H12): only overwrite when --force is
        // passed.
        latticearc::unified_api::atomic_write::AtomicWrite::new(data)
            .secret_mode()
            .overwrite_existing(force)
            .write(p)
            .with_context(|| {
                format!("Failed to write {} (use --force to overwrite)", p.display())
            })?;
        // Path on stderr would leak through process accounting and log
        // aggregation; route to tracing::debug! instead.
        tracing::debug!(path = %p.display(), "decrypted data written");
    } else {
        // Stdout-as-default-target hazard: writing decrypted plaintext
        // to a TTY exposes it to recorded shell sessions, screen
        // sharing, scrollback, and any logging proxy. When the user is
        // interactive, surface a one-line warning to stderr. Pipelines
        // (`| tee`, file redirection) where stdout is not a TTY get no
        // warning.
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            eprintln!(
                "warning: decrypted plaintext is being written to a TTY. \
                 Pass --output <file> to write to disk with 0600 permissions, \
                 or pipe stdout to avoid leaving secrets in scrollback."
            );
        }
        // Try to print as UTF-8, fall back to hex. The hex encoding is
        // wrapped in `Zeroizing<String>` so a derived plaintext copy
        // doesn't outlive the source `Zeroizing<Vec<u8>>` — otherwise
        // the encoded string would linger on the heap until allocator
        // reclaim.
        if let Ok(s) = std::str::from_utf8(data) {
            print!("{s}");
        } else {
            let encoded = zeroize::Zeroizing::new(hex::encode(data));
            print!("{}", encoded.as_str());
        }
    }
    Ok(())
}
