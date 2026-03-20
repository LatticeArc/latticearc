//! KDF command — derive cryptographic keys from input material.
//!
//! Key Derivation Functions (KDFs) stretch or transform passwords, shared
//! secrets, or raw key material into one or more cryptographic keys of a
//! desired length.
//!
//! **Supported algorithms:**
//!
//! | Algorithm        | Standard   | Use case                                  |
//! |------------------|------------|-------------------------------------------|
//! | HKDF-SHA256      | SP 800-56C | Deriving keys from high-entropy material.  |
//! | PBKDF2-HMAC-SHA256 | SP 800-132 | Deriving keys from passwords (slow hash). |
//!
//! **When to use which:**
//! - **HKDF** is for *non-password* input (DH shared secrets, random bytes).
//!   It's fast, deterministic, and domain-separable via `--info`.
//! - **PBKDF2** is for *passwords*. It's deliberately slow (600,000 iterations
//!   by default) to resist brute-force attacks on weak passwords.
//!
//! **Output formats:** `hex` (default, lowercase) or `base64`.
//!
//! **HKDF output limit:** max 8,160 bytes (255 × 32 for SHA-256, per RFC 5869).

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

/// KDF algorithm.
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum KdfAlgorithm {
    /// HKDF-SHA256 (SP 800-56C). Requires --salt and --info.
    Hkdf,
    /// PBKDF2-HMAC-SHA256. Requires --salt and --iterations.
    Pbkdf2,
}

/// Arguments for the `kdf` subcommand.
#[derive(Args)]
pub(crate) struct KdfArgs {
    /// KDF algorithm.
    #[arg(short, long, value_enum)]
    pub algorithm: KdfAlgorithm,
    /// Input key material (hex-encoded) or password (for PBKDF2).
    #[arg(short, long)]
    pub input: String,
    /// Salt (hex-encoded).
    #[arg(short, long)]
    pub salt: String,
    /// Output key length in bytes.
    #[arg(short, long, default_value = "32")]
    pub length: usize,
    /// Info string for HKDF (optional).
    #[arg(long)]
    pub info: Option<String>,
    /// Iteration count for PBKDF2 (default 600000).
    #[arg(long, default_value = "600000")]
    pub iterations: u32,
    /// Output format: hex (default) or base64.
    #[arg(short, long, default_value = "hex")]
    pub format: super::hash::OutputFormat,
}

/// Execute the kdf command.
pub(crate) fn run(args: KdfArgs) -> Result<()> {
    let salt = hex::decode(&args.salt).context("Invalid hex in --salt")?;

    let derived = match args.algorithm {
        KdfAlgorithm::Hkdf => derive_hkdf(&args, &salt)?,
        KdfAlgorithm::Pbkdf2 => derive_pbkdf2(&args, &salt)?,
    };

    let encoded = match args.format {
        super::hash::OutputFormat::Hex => hex::encode(&derived),
        super::hash::OutputFormat::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&derived)
        }
    };

    println!("{encoded}");
    Ok(())
}

fn derive_hkdf(args: &KdfArgs, salt: &[u8]) -> Result<Vec<u8>> {
    let ikm = zeroize::Zeroizing::new(
        hex::decode(&args.input).context("Invalid hex in --input for HKDF")?,
    );
    let info = args.info.as_deref().unwrap_or("");

    if args.length == 0 || args.length > 8160 {
        bail!("Output length must be 1..=8160 bytes");
    }

    latticearc::derive_key_with_info(
        &ikm,
        salt,
        args.length,
        info.as_bytes(),
        latticearc::SecurityMode::Unverified,
    )
    .map_err(|e| anyhow::anyhow!("HKDF derivation failed: {e}"))
}

fn derive_pbkdf2(args: &KdfArgs, salt: &[u8]) -> Result<Vec<u8>> {
    let password = args.input.as_bytes();

    if args.length == 0 {
        bail!("Output length must be > 0");
    }

    let params = latticearc::primitives::kdf::Pbkdf2Params::with_salt(salt)
        .iterations(args.iterations)
        .key_length(args.length);

    let result = latticearc::primitives::kdf::pbkdf2(password, &params)
        .map_err(|e| anyhow::anyhow!("PBKDF2 derivation failed: {e}"))?;

    Ok(result.key().to_vec())
}
