//! Encrypt command — authenticated encryption of files.
//!
//! Supports two encryption modes:
//!
//! - **AES-256-GCM** (SP 800-38D) — symmetric authenticated encryption using a
//!   shared 32-byte key. Provides confidentiality + integrity. Each encryption
//!   uses a random 12-byte nonce (never reused).
//! - **Hybrid** (ML-KEM-768 + X25519 + AES-256-GCM) — post-quantum hybrid
//!   encryption using a recipient's public key. Generates an ephemeral keypair
//!   internally.
//!
//! **Output format:** The encrypted data is written as a self-contained JSON file
//! containing the Base64-encoded ciphertext, nonce, and algorithm metadata. This
//! JSON format ensures the encrypted file can be stored, transmitted, and
//! decrypted without any external state.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Encryption mode.
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum EncryptMode {
    /// AES-256-GCM symmetric encryption (FIPS validated).
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption (RFC 8439, non-FIPS).
    Chacha20Poly1305,
    /// Hybrid ML-KEM-768 + X25519 + AES-256-GCM (generates ephemeral keypair).
    Hybrid,
}

/// Arguments for the `encrypt` subcommand.
#[derive(Args)]
pub(crate) struct EncryptArgs {
    /// Encryption mode (expert override). Ignored when --use-case is provided.
    #[arg(short, long, value_enum)]
    pub mode: Option<EncryptMode>,
    /// Use case for automatic algorithm selection (recommended).
    #[arg(long, value_parser = super::common::parse_use_case,
          value_name = "USE_CASE")]
    pub use_case: Option<latticearc::types::types::UseCase>,
    /// Security level override (default: high).
    #[arg(long, value_parser = super::common::parse_security_level,
          value_name = "LEVEL")]
    pub security_level: Option<latticearc::types::types::SecurityLevel>,
    /// Compliance mode (default, fips, cnsa-2.0).
    #[arg(long, value_parser = super::common::parse_compliance,
          value_name = "MODE")]
    pub compliance: Option<latticearc::types::types::ComplianceMode>,
    /// Input file to encrypt (reads from stdin if omitted).
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output file for encrypted data (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Key file path (symmetric key for AES, public key for hybrid).
    #[arg(short, long)]
    pub key: PathBuf,
}

/// Execute the encrypt command.
pub(crate) fn run(args: EncryptArgs) -> Result<()> {
    let plaintext = read_input(&args.input)?;
    let key_file = KeyFile::read_from(&args.key)?;

    // Use-case-driven path
    if args.use_case.is_some() {
        if args.mode.is_some() {
            eprintln!(
                "Warning: --mode is ignored when --use-case is provided. \
                 The library selects the optimal encryption scheme automatically."
            );
        }
        let json_output = encrypt_with_config(&plaintext, &key_file, &args)?;
        return write_output(&args.output, &json_output);
    }

    // Expert path (or default)
    let mode = args.mode.unwrap_or(EncryptMode::Aes256Gcm);
    let json_output = match mode {
        EncryptMode::Aes256Gcm => encrypt_symmetric(&plaintext, &key_file)?,
        EncryptMode::Chacha20Poly1305 => encrypt_chacha20(&plaintext, &key_file)?,
        EncryptMode::Hybrid => encrypt_hybrid(&plaintext, &key_file)?,
    };

    write_output(&args.output, &json_output)
}

/// Encrypt using the library's unified API with use-case-driven config.
fn encrypt_with_config(plaintext: &[u8], key_file: &KeyFile, args: &EncryptArgs) -> Result<String> {
    let config = super::common::build_config(args.use_case, args.security_level, &args.compliance);

    // Determine key type from the key file and encrypt
    match key_file.key_type {
        KeyType::Symmetric => {
            let key_bytes = key_file.key_bytes()?;
            let config = config.force_scheme(latticearc::CryptoScheme::Symmetric);
            let encrypted = latticearc::encrypt(
                plaintext,
                latticearc::EncryptKey::Symmetric(&key_bytes),
                config,
            )
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
            latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
                .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
        }
        KeyType::Public => {
            let pk_bytes = key_file.key_bytes()?;
            let pk = crate::keyfile::parse_hybrid_kem_pk_from_bytes(&pk_bytes)?;
            let encrypted =
                latticearc::encrypt(plaintext, latticearc::EncryptKey::Hybrid(&pk), config)
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
            latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
                .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
        }
        _ => bail!(
            "Expected symmetric or public key file for encryption, got {:?}",
            key_file.key_type
        ),
    }
}

fn encrypt_symmetric(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Symmetric {
        bail!("Expected symmetric key file, got {:?}", key_file.key_type);
    }

    let key_bytes = key_file.key_bytes()?;
    if key_bytes.len() != 32 {
        bail!("AES-256 requires a 32-byte key, got {} bytes", key_bytes.len());
    }

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric),
    )
    .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn encrypt_chacha20(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Symmetric {
        bail!("Expected symmetric key file for ChaCha20 encryption, got {:?}", key_file.key_type);
    }
    let key_bytes = key_file.key_bytes()?;

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric),
    )
    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn encrypt_hybrid(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for hybrid encryption, got {:?}", key_file.key_type);
    }

    let pk_bytes = key_file.key_bytes()?;
    let pk = crate::keyfile::parse_hybrid_kem_pk_from_bytes(&pk_bytes)?;

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Hybrid(&pk),
        latticearc::CryptoConfig::new(),
    )
    .map_err(|e| anyhow::anyhow!("Hybrid encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    if let Some(p) = path {
        std::fs::read(p).with_context(|| format!("Failed to read {}", p.display()))
    } else {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).context("Failed to read from stdin")?;
        Ok(buf)
    }
}

fn write_output(path: &Option<PathBuf>, data: &str) -> Result<()> {
    match path {
        Some(p) => {
            std::fs::write(p, data).with_context(|| format!("Failed to write {}", p.display()))?;
            println!("Encrypted data written to: {}", p.display());
        }
        None => {
            println!("{data}");
        }
    }
    Ok(())
}
