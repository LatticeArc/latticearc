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
    /// Encryption mode.
    #[arg(short, long, value_enum, default_value = "aes256-gcm")]
    pub mode: EncryptMode,
    /// Input file to encrypt (reads from stdin if omitted).
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output file for encrypted data (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Key file path (symmetric key for AES/ChaCha20, public key for hybrid).
    #[arg(short, long)]
    pub key: PathBuf,
}

/// Execute the encrypt command.
pub(crate) fn run(args: EncryptArgs) -> Result<()> {
    let plaintext = read_input(&args.input)?;
    let key_file = KeyFile::read_from(&args.key)?;

    let json_output = match args.mode {
        EncryptMode::Aes256Gcm => encrypt_symmetric(&plaintext, &key_file)?,
        EncryptMode::Chacha20Poly1305 => encrypt_chacha20(&plaintext, &key_file)?,
        EncryptMode::Hybrid => encrypt_hybrid(&plaintext, &key_file)?,
    };

    write_output(&args.output, &json_output)
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

fn encrypt_chacha20(_plaintext: &[u8], _key_file: &KeyFile) -> Result<String> {
    if latticearc::fips_available() {
        bail!(
            "ChaCha20-Poly1305 is not FIPS 140-3 approved.\n\
             Use --mode aes256-gcm for FIPS-compliant symmetric encryption.\n\
             ChaCha20-Poly1305 is available via the library API in non-FIPS builds."
        );
    }

    bail!("ChaCha20-Poly1305 encryption is not available in this build.");
}

fn encrypt_hybrid(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for hybrid encryption, got {:?}", key_file.key_type);
    }

    let pk_bytes = key_file.key_bytes()?;
    let pk = super::keygen::parse_hybrid_kem_pk(&pk_bytes)?;

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
