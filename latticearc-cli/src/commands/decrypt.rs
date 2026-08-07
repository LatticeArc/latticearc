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

use anyhow::{Result, bail};
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
    #[arg(long)]
    pub force: bool,
    /// Allow writing decrypted plaintext to a TTY. Without this flag the
    /// command refuses to emit plaintext when stdout is a terminal — TTY
    /// output exposes secrets to shell scrollback, session recorders,
    /// screen sharing, and CI log aggregators. Use `--output <file>` to
    /// write to disk (0600 perms) or pipe stdout; `--print-to-tty` is
    /// reserved for explicit interactive inspection. (L9 fix)
    #[arg(long)]
    pub print_to_tty: bool,
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

    write_output(&args.output, &plaintext, args.force, args.print_to_tty)
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
    // the prior M19 fix kept a `(symmetric)`
    // parenthetical and `{e}` interpolation that re-introduced the
    // oracle the comment claimed to close — scripted callers could
    // distinguish symmetric vs hybrid vs PQ-only branches from stderr,
    // and the upstream `e` leaked inner library wording. Now bare
    // "Decryption failed", uniform across all three branches; per-stage
    // cause is preserved via `tracing::debug!` for operator debugging.
    .map_err(|e| {
        tracing::debug!(error = %e, scheme = "symmetric", "decrypt failed");
        anyhow::anyhow!("Decryption failed")
    })
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
    .map_err(|e| {
        // bare "Decryption failed"; cause to tracing.
        tracing::debug!(error = %e, scheme = "hybrid", "decrypt failed");
        anyhow::anyhow!("Decryption failed")
    })
}

fn decrypt_pq_only(
    encrypted: &latticearc::EncryptedOutput,
    key_file: &KeyFile,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let level = super::common::resolve_ml_kem_level(key_file.portable_key().algorithm())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let sk_bytes = key_file.key_bytes()?;

    // derive the recipient PK from the SK's embedded PK
    // (FIPS 203 §6.1) instead of trusting the unauthenticated
    // `ml_kem_pk` metadata field. A file-write attacker who could
    // previously swap that metadata to break the HPKE channel binding
    // can no longer affect the derivation — the PK comes from inside
    // the SK blob itself.
    let pq_sk = latticearc::PqOnlySecretKey::from_sk_bytes(level, &sk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid PQ-only secret key: {e}"))?;

    latticearc::decrypt(
        encrypted,
        latticearc::DecryptKey::PqOnly(&pq_sk),
        latticearc::CryptoConfig::new().crypto_mode(latticearc::CryptoMode::PqOnly),
    )
    .map_err(|e| {
        // bare "Decryption failed"; cause to tracing.
        tracing::debug!(error = %e, scheme = "pq-only", "decrypt failed");
        anyhow::anyhow!("Decryption failed")
    })
}

fn read_input_string(path: &Option<PathBuf>) -> Result<String> {
    // route through the shared helper.
    super::common::read_file_or_stdin_string(
        path.as_deref(),
        super::common::CLI_MAX_DECRYPTION_INPUT_BYTES,
        "decrypt",
    )
}

fn write_output(
    path: &Option<PathBuf>,
    data: &[u8],
    force: bool,
    print_to_tty: bool,
) -> Result<()> {
    // Decrypted plaintext is secret: `secret_file_mode=true` selects
    // `.secret_mode()` (0600 perms; `tempfile::NamedTempFile` already
    // creates files at 0600 and `persist()` preserves that, so this is
    // defense-in-depth in case tempfile's default ever changes). The TTY
    // guard (L9 fix) hard-fails writing plaintext to an interactive
    // terminal unless `--print-to-tty` is explicit — pipelines and file
    // redirects (stdout not a TTY) are unaffected.
    super::common::write_output_or_stdout(
        path.as_deref(),
        data,
        force,
        true,
        Some((super::common::DECRYPT_TTY_REFUSAL, print_to_tty)),
        "decrypted data",
    )
}
