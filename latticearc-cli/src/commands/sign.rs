//! Sign command — create digital signatures over files.
//!
//! Routes through the library's unified `sign_with_key()` API, which handles
//! FIPS self-test verification, resource limits, and produces a `SignedData`
//! envelope with scheme metadata + timestamp + embedded public key.
//!
//! The `--algorithm` flag is an expert override for backward compatibility.
//! When `--public-key` is provided, the unified API is used regardless.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Signing algorithm (expert override — prefer --use-case or --public-key).
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum SignAlgorithm {
    /// ML-DSA-65 (FIPS 204) — default post-quantum signature.
    MlDsa65,
    /// ML-DSA-44 (FIPS 204) — faster, smaller.
    MlDsa44,
    /// ML-DSA-87 (FIPS 204) — highest security.
    MlDsa87,
    /// SLH-DSA-SHAKE-128s (FIPS 205) — hash-based, stateless.
    SlhDsa,
    /// FN-DSA-512 (FIPS 206) — compact lattice signatures.
    FnDsa,
    /// Ed25519 — classical elliptic curve.
    Ed25519,
    /// Hybrid ML-DSA-65 + Ed25519 — combined PQ + classical.
    Hybrid,
}

/// Arguments for the `sign` subcommand.
#[derive(Args)]
pub(crate) struct SignArgs {
    /// Signing algorithm (expert override, deprecated — prefer --use-case).
    #[arg(short, long, value_enum)]
    pub algorithm: Option<SignAlgorithm>,
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
    /// Input file to sign.
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output file for the signature (defaults to <input>.sig.json).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Secret key file for signing.
    #[arg(short, long)]
    pub key: PathBuf,
    /// Public key file (required for unified API — embeds PK in SignedData).
    #[arg(long)]
    pub public_key: Option<PathBuf>,
}

/// Execute the sign command.
pub(crate) fn run(args: SignArgs) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let key_file = KeyFile::read_from(&args.key)?;
    if key_file.key_type != KeyType::Secret {
        bail!("Expected secret key file for signing, got {:?}", key_file.key_type);
    }
    let sk_bytes = key_file.key_bytes()?;

    // Unified API path: when public key is provided, use sign_with_key → SignedData
    if let Some(pk_path) = &args.public_key {
        return sign_unified(&data, &sk_bytes, pk_path, &args);
    }

    // Legacy path: explicit --algorithm required
    let Some(algorithm) = &args.algorithm else {
        bail!(
            "Either --public-key (recommended) or --algorithm (legacy) is required.\n\
             Recommended: latticearc sign --input <FILE> --key <SECRET> --public-key <PUBLIC>\n\
             Legacy:      latticearc sign --algorithm <ALG> --input <FILE> --key <SECRET>"
        )
    };

    let alg_name = algorithm_name(algorithm);
    key_file.validate_algorithm(alg_name)?;

    let sig_bytes = match algorithm {
        SignAlgorithm::MlDsa65 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA65,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::MlDsa44 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::MlDsa87 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::SlhDsa => latticearc::sign_pq_slh_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::slh_dsa::SecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::FnDsa => {
            latticearc::sign_pq_fn_dsa(&data, &sk_bytes, latticearc::SecurityMode::Unverified)
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
        SignAlgorithm::Ed25519 => {
            latticearc::sign_ed25519(&data, &sk_bytes, latticearc::SecurityMode::Unverified)
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
        SignAlgorithm::Hybrid => {
            return sign_hybrid_legacy(&data, &key_file, &args);
        }
    };

    use base64::Engine;
    let output = serde_json::json!({
        "algorithm": alg_name,
        "signature": base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
    });

    write_signature(&args, &serde_json::to_string_pretty(&output)?)
}

/// Sign using the library's unified `sign_with_key()` API.
///
/// Produces a `SignedData` envelope (scheme + timestamp + public key + signature)
/// that can be verified by the library's `verify()` function directly.
fn sign_unified(
    data: &[u8],
    sk_bytes: &[u8],
    pk_path: &std::path::Path,
    args: &SignArgs,
) -> Result<()> {
    let pk_file = KeyFile::read_from(pk_path)?;
    if pk_file.key_type != KeyType::Public {
        bail!("Expected public key file, got {:?}", pk_file.key_type);
    }
    let pk_bytes = pk_file.key_bytes()?;

    let config = super::common::build_config(args.use_case, args.security_level, &args.compliance);

    let signed = latticearc::sign_with_key(data, sk_bytes, &pk_bytes, config)
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?;

    let json = latticearc::unified_api::serialization::serialize_signed_data(&signed)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))?;

    write_signature(args, &json)
}

/// Legacy hybrid signing (custom JSON format).
fn sign_hybrid_legacy(data: &[u8], key_file: &KeyFile, args: &SignArgs) -> Result<()> {
    let sk = crate::keyfile::parse_hybrid_sign_sk(key_file)?;
    let signature = latticearc::sign_hybrid(data, &sk, latticearc::SecurityMode::Unverified)
        .map_err(|e| anyhow::anyhow!("Hybrid signing failed: {e}"))?;

    use base64::Engine;
    let output = serde_json::json!({
        "algorithm": "hybrid-ml-dsa-65-ed25519",
        "ml_dsa_sig": base64::engine::general_purpose::STANDARD.encode(&signature.ml_dsa_sig),
        "ed25519_sig": base64::engine::general_purpose::STANDARD.encode(&signature.ed25519_sig),
    });

    write_signature(args, &serde_json::to_string_pretty(&output)?)
}

/// Map algorithm enum to canonical key file algorithm name.
fn algorithm_name(alg: &SignAlgorithm) -> &'static str {
    match alg {
        SignAlgorithm::MlDsa65 => "ml-dsa-65",
        SignAlgorithm::MlDsa44 => "ml-dsa-44",
        SignAlgorithm::MlDsa87 => "ml-dsa-87",
        SignAlgorithm::SlhDsa => "slh-dsa-shake-128s",
        SignAlgorithm::FnDsa => "fn-dsa-512",
        SignAlgorithm::Ed25519 => "ed25519",
        SignAlgorithm::Hybrid => "hybrid-ml-dsa-65-ed25519",
    }
}

fn write_signature(args: &SignArgs, json: &str) -> Result<()> {
    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        let new_ext = match p.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.sig.json"),
            None => "sig.json".to_string(),
        };
        p.set_extension(new_ext);
        p
    });

    std::fs::write(&output_path, json)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    println!("Signature written to: {}", output_path.display());
    Ok(())
}
