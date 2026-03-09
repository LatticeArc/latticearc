//! Sign command.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Signing algorithm.
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
    /// FN-DSA-512 (FIPS 206 draft) — compact lattice signatures.
    FnDsa,
    /// Ed25519 — classical elliptic curve.
    Ed25519,
    /// Hybrid ML-DSA-65 + Ed25519 — combined PQ + classical.
    Hybrid,
}

/// Arguments for the `sign` subcommand.
#[derive(Args)]
pub(crate) struct SignArgs {
    /// Signing algorithm.
    #[arg(short, long, value_enum)]
    pub algorithm: SignAlgorithm,
    /// Input file to sign.
    #[arg(short, long)]
    pub input: PathBuf,
    /// Output file for the signature (defaults to <input>.sig.json).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Secret key file for signing.
    #[arg(short, long)]
    pub key: PathBuf,
}

/// Map algorithm enum to the canonical key file algorithm name.
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

/// Execute the sign command.
pub(crate) fn run(args: SignArgs) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let key_file = KeyFile::read_from(&args.key)?;
    if key_file.key_type != KeyType::Secret {
        bail!("Expected secret key file for signing, got {:?}", key_file.key_type);
    }

    // Validate algorithm matches key file
    let alg_name = algorithm_name(&args.algorithm);
    key_file.validate_algorithm(alg_name)?;

    let sk_bytes = key_file.key_bytes()?;

    let sig_bytes = match args.algorithm {
        SignAlgorithm::MlDsa65 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA65,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?,
        SignAlgorithm::MlDsa44 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-44 signing failed: {e}"))?,
        SignAlgorithm::MlDsa87 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-87 signing failed: {e}"))?,
        SignAlgorithm::SlhDsa => latticearc::sign_pq_slh_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::slh_dsa::SecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("SLH-DSA signing failed: {e}"))?,
        SignAlgorithm::FnDsa => {
            latticearc::sign_pq_fn_dsa(&data, &sk_bytes, latticearc::SecurityMode::Unverified)
                .map_err(|e| anyhow::anyhow!("FN-DSA signing failed: {e}"))?
        }
        SignAlgorithm::Ed25519 => {
            latticearc::sign_ed25519(&data, &sk_bytes, latticearc::SecurityMode::Unverified)
                .map_err(|e| anyhow::anyhow!("Ed25519 signing failed: {e}"))?
        }
        SignAlgorithm::Hybrid => {
            return sign_hybrid(&data, &sk_bytes, &args);
        }
    };

    use base64::Engine;
    let output = serde_json::json!({
        "algorithm": alg_name,
        "signature": base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
    });

    write_signature(&args, &output)
}

fn sign_hybrid(data: &[u8], sk_bytes: &[u8], args: &SignArgs) -> Result<()> {
    let sk = super::keygen::parse_hybrid_sign_sk(sk_bytes)?;

    let signature = latticearc::sign_hybrid(data, &sk, latticearc::SecurityMode::Unverified)
        .map_err(|e| anyhow::anyhow!("Hybrid signing failed: {e}"))?;

    use base64::Engine;
    let output = serde_json::json!({
        "algorithm": "hybrid-ml-dsa-65-ed25519",
        "ml_dsa_sig": base64::engine::general_purpose::STANDARD.encode(&signature.ml_dsa_sig),
        "ed25519_sig": base64::engine::general_purpose::STANDARD.encode(&signature.ed25519_sig),
    });

    write_signature(args, &output)
}

fn write_signature(args: &SignArgs, output: &serde_json::Value) -> Result<()> {
    let json = serde_json::to_string_pretty(output)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))?;

    let output_path = args.output.clone().unwrap_or_else(|| {
        let mut p = args.input.clone();
        let new_ext = match p.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.sig.json"),
            None => "sig.json".to_string(),
        };
        p.set_extension(new_ext);
        p
    });

    std::fs::write(&output_path, &json)
        .with_context(|| format!("Failed to write {}", output_path.display()))?;

    println!("Signature written to: {}", output_path.display());
    Ok(())
}
