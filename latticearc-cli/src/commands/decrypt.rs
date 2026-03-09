//! Decrypt command.

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
            bail!(
                "Hybrid decryption requires an in-memory secret key. \
                 Use the library API directly for hybrid decryption."
            );
        }
        KeyType::Public => {
            bail!("Cannot decrypt with a public key. Provide the secret key.");
        }
    };

    write_output(&args.output, &plaintext)
}

fn decrypt_symmetric(
    encrypted: &latticearc::EncryptedOutput,
    key_file: &KeyFile,
) -> Result<Vec<u8>> {
    let key_bytes = key_file.key_bytes()?;
    if key_bytes.len() != 32 {
        bail!("AES-256 requires a 32-byte key, got {} bytes", key_bytes.len());
    }

    let decrypted = latticearc::decrypt(
        encrypted,
        latticearc::DecryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new(),
    )
    .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    Ok(decrypted)
}

fn read_input_string(path: &Option<PathBuf>) -> Result<String> {
    if let Some(p) = path {
        std::fs::read_to_string(p).with_context(|| format!("Failed to read {}", p.display()))
    } else {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).context("Failed to read from stdin")?;
        Ok(buf)
    }
}

fn write_output(path: &Option<PathBuf>, data: &[u8]) -> Result<()> {
    match path {
        Some(p) => {
            std::fs::write(p, data).with_context(|| format!("Failed to write {}", p.display()))?;
            println!("Decrypted data written to: {}", p.display());
        }
        None => {
            // Try to print as UTF-8, fall back to hex
            match std::str::from_utf8(data) {
                Ok(s) => print!("{s}"),
                Err(_) => print!("{}", hex::encode(data)),
            }
        }
    }
    Ok(())
}
