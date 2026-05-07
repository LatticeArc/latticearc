//! Hash command — compute cryptographic fingerprints of files.
//!
//! A cryptographic hash produces a fixed-size "fingerprint" of a file. Even a
//! single bit change in the input produces a completely different hash output.
//! This makes hashes useful for verifying file integrity.
//!
//! **Supported algorithms:**
//!
//! | Algorithm   | Standard   | Output | Notes                          |
//! |-------------|------------|--------|--------------------------------|
//! | SHA3-256    | FIPS 202   | 32 B   | Default. NIST's newest family. |
//! | SHA-256     | FIPS 180-4 | 32 B   | Widely used (Git, TLS).        |
//! | SHA-512     | FIPS 180-4 | 64 B   | Larger output, same family.    |
//! | BLAKE2b-256 | RFC 7693   | 32 B   | Fast, modern, used by Argon2.  |
//!
//! **Output formats:** `hex` (default, lowercase) or `base64`.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

/// Hash algorithm.
#[derive(Debug, Clone, clap::ValueEnum)]
pub(crate) enum HashAlgorithm {
    /// SHA3-256 (FIPS 202, 32-byte output). Default.
    #[value(name = "sha3-256")]
    Sha3_256,
    /// SHA-256 (FIPS 180-4, 32-byte output).
    #[value(name = "sha-256")]
    Sha256,
    /// SHA-512 (FIPS 180-4, 64-byte output).
    #[value(name = "sha-512")]
    Sha512,
    /// BLAKE2b-256 (RFC 7693, 32-byte output).
    #[value(name = "blake2b")]
    Blake2b,
}

/// Arguments for the `hash` subcommand.
#[derive(Args)]
pub(crate) struct HashArgs {
    /// Hash algorithm to use.
    #[arg(short, long, value_enum, default_value = "sha3-256")]
    pub algorithm: HashAlgorithm,
    /// Input file to hash (reads from stdin if omitted).
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output format: hex (default) or base64.
    #[arg(short, long, default_value = "hex")]
    pub format: OutputFormat,
    /// Print only the encoded digest (no `ALG: ` prefix). Use this when
    /// piping to `sha256sum -c` style tools or comparing byte-for-byte.
    #[arg(long)]
    pub raw: bool,
}

/// Output encoding format.
#[derive(Debug, Clone, clap::ValueEnum)]
pub(crate) enum OutputFormat {
    /// Hexadecimal encoding.
    Hex,
    /// Base64 encoding.
    Base64,
}

/// Execute the hash command.
pub(crate) fn run(args: HashArgs) -> Result<()> {
    let data = read_input(&args.input)?;

    let (alg_label, hash_bytes) = match args.algorithm {
        HashAlgorithm::Sha3_256 => {
            let hash = latticearc::hash_data(&data);
            ("SHA3-256", hash.to_vec())
        }
        HashAlgorithm::Sha256 => {
            let hash = latticearc::primitives::hash::sha256(&data)
                .map_err(|e| anyhow::anyhow!("SHA-256 hash failed: {e}"))?;
            ("SHA-256", hash.to_vec())
        }
        HashAlgorithm::Sha512 => {
            let hash = latticearc::primitives::hash::sha512(&data)
                .map_err(|e| anyhow::anyhow!("SHA-512 hash failed: {e}"))?;
            ("SHA-512", hash.to_vec())
        }
        HashAlgorithm::Blake2b => {
            let hash = latticearc::primitives::hash::blake2b_256(&data);
            ("BLAKE2b-256", hash.to_vec())
        }
    };

    let encoded = match args.format {
        OutputFormat::Hex => hex::encode(&hash_bytes),
        OutputFormat::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&hash_bytes)
        }
    };

    if args.raw {
        // No prefix, no trailing newline — byte-exact for `sha256sum -c`
        // and similar pipelines.
        print!("{encoded}");
    } else {
        println!("{alg_label}: {encoded}");
    }
    Ok(())
}

fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    // route through the shared helper.
    super::common::read_file_or_stdin(
        path.as_deref(),
        super::common::CLI_MAX_HASH_INPUT_BYTES,
        "hash",
    )
}
