//! Verify command.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Verification algorithm.
#[derive(Debug, Clone, ValueEnum)]
pub(crate) enum VerifyAlgorithm {
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
    /// SLH-DSA-SHAKE-128s (FIPS 205).
    SlhDsa,
    /// FN-DSA-512 (FIPS 206 draft).
    FnDsa,
    /// Ed25519.
    Ed25519,
    /// Hybrid ML-DSA-65 + Ed25519.
    Hybrid,
}

/// Arguments for the `verify` subcommand.
#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// Verification algorithm.
    #[arg(short, long, value_enum)]
    pub algorithm: VerifyAlgorithm,
    /// Input file that was signed.
    #[arg(short, long)]
    pub input: PathBuf,
    /// Signature JSON file.
    #[arg(short, long)]
    pub signature: PathBuf,
    /// Public key file for verification.
    #[arg(short, long)]
    pub key: PathBuf,
}

/// Execute the verify command.
pub(crate) fn run(args: VerifyArgs) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let key_file = KeyFile::read_from(&args.key)?;
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for verification, got {:?}", key_file.key_type);
    }

    // Validate algorithm matches key file
    let expected_alg = match args.algorithm {
        VerifyAlgorithm::MlDsa65 => "ml-dsa-65",
        VerifyAlgorithm::MlDsa44 => "ml-dsa-44",
        VerifyAlgorithm::MlDsa87 => "ml-dsa-87",
        VerifyAlgorithm::SlhDsa => "slh-dsa-shake-128s",
        VerifyAlgorithm::FnDsa => "fn-dsa-512",
        VerifyAlgorithm::Ed25519 => "ed25519",
        VerifyAlgorithm::Hybrid => "hybrid-ml-dsa-65-ed25519",
    };
    key_file.validate_algorithm(expected_alg)?;

    let sig_json = std::fs::read_to_string(&args.signature)
        .with_context(|| format!("Failed to read {}", args.signature.display()))?;

    let pk_bytes = key_file.key_bytes()?;

    let valid = match args.algorithm {
        VerifyAlgorithm::Hybrid => verify_hybrid(&data, &sig_json, &pk_bytes)?,
        _ => verify_standard(&data, &sig_json, &pk_bytes, &args.algorithm)?,
    };

    if valid {
        println!("Signature is VALID.");
        Ok(())
    } else {
        bail!("Signature is INVALID.")
    }
}

fn verify_standard(
    data: &[u8],
    sig_json: &str,
    pk_bytes: &[u8],
    algorithm: &VerifyAlgorithm,
) -> Result<bool> {
    // Parse the signature JSON to extract raw signature bytes
    let sig_obj: serde_json::Value =
        serde_json::from_str(sig_json).context("Failed to parse signature JSON")?;

    use base64::Engine;
    let sig_b64 = sig_obj
        .get("signature")
        .and_then(|v| v.as_str())
        .context("Missing 'signature' field in signature JSON")?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .context("Invalid base64 in signature")?;

    match algorithm {
        VerifyAlgorithm::MlDsa65 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA65,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 verification failed: {e}")),
        VerifyAlgorithm::MlDsa44 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-44 verification failed: {e}")),
        VerifyAlgorithm::MlDsa87 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("ML-DSA-87 verification failed: {e}")),
        VerifyAlgorithm::SlhDsa => latticearc::verify_pq_slh_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::slh_dsa::SecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("SLH-DSA verification failed: {e}")),
        VerifyAlgorithm::FnDsa => latticearc::verify_pq_fn_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("FN-DSA verification failed: {e}")),
        VerifyAlgorithm::Ed25519 => latticearc::verify_ed25519(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Ed25519 verification failed: {e}")),
        VerifyAlgorithm::Hybrid => bail!("Internal error: hybrid handled separately"),
    }
}

fn verify_hybrid(data: &[u8], sig_json: &str, pk_bytes: &[u8]) -> Result<bool> {
    let sig: serde_json::Value =
        serde_json::from_str(sig_json).context("Failed to parse hybrid signature JSON")?;

    use base64::Engine;
    let ml_dsa_b64 = sig
        .get("ml_dsa_sig")
        .and_then(|v| v.as_str())
        .context("Missing 'ml_dsa_sig' field in hybrid signature")?;
    let ml_dsa_sig = base64::engine::general_purpose::STANDARD
        .decode(ml_dsa_b64)
        .context("Invalid base64 in ml_dsa_sig")?;

    let ed25519_b64 = sig
        .get("ed25519_sig")
        .and_then(|v| v.as_str())
        .context("Missing 'ed25519_sig' field in hybrid signature")?;
    let ed25519_sig = base64::engine::general_purpose::STANDARD
        .decode(ed25519_b64)
        .context("Invalid base64 in ed25519_sig")?;

    let pk = super::keygen::parse_hybrid_sign_pk(pk_bytes)?;

    let hybrid_sig = latticearc::hybrid::sig_hybrid::HybridSignature { ml_dsa_sig, ed25519_sig };

    latticearc::verify_hybrid_signature(
        data,
        &hybrid_sig,
        &pk,
        latticearc::SecurityMode::Unverified,
    )
    .map_err(|e| anyhow::anyhow!("Hybrid verification failed: {e}"))
}
