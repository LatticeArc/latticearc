//! Verify command — check digital signatures with auto-detection.
//!
//! Verifies that a signature file is valid for a given input file and public key.
//!
//! **Algorithm auto-detection:** If `--algorithm` is omitted, the algorithm is
//! read from the signature file's `"algorithm"` JSON field. This means users
//! don't need to remember which algorithm was used to sign.
//!
//! **Verification flow:**
//! 1. Read the original file and the signature JSON
//! 2. Auto-detect or validate the algorithm
//! 3. Validate the public key matches the expected algorithm
//! 4. Verify the signature using the `latticearc` library
//! 5. Print `VALID` (exit 0) or `INVALID` (exit 1)
//!
//! **Security:** The verifier validates algorithm/key consistency before
//! performing cryptographic verification. Algorithm field tampering in the
//! signature file is detected because the key won't match.

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
    /// Verification algorithm. If omitted, auto-detected from the signature file.
    #[arg(short, long, value_enum)]
    pub algorithm: Option<VerifyAlgorithm>,
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

/// Detect algorithm from the "algorithm" field in a .sig.json file.
fn detect_algorithm(sig_json: &str) -> Result<VerifyAlgorithm> {
    let sig: serde_json::Value =
        serde_json::from_str(sig_json).context("Failed to parse signature JSON")?;
    let alg_str = sig
        .get("algorithm")
        .and_then(|v| v.as_str())
        .context("Signature file missing 'algorithm' field — cannot auto-detect")?;
    match alg_str {
        "ml-dsa-65" => Ok(VerifyAlgorithm::MlDsa65),
        "ml-dsa-44" => Ok(VerifyAlgorithm::MlDsa44),
        "ml-dsa-87" => Ok(VerifyAlgorithm::MlDsa87),
        "slh-dsa-shake-128s" => Ok(VerifyAlgorithm::SlhDsa),
        "fn-dsa-512" => Ok(VerifyAlgorithm::FnDsa),
        "ed25519" => Ok(VerifyAlgorithm::Ed25519),
        "hybrid-ml-dsa-65-ed25519" => Ok(VerifyAlgorithm::Hybrid),
        other => bail!("Unknown algorithm in signature file: '{other}'"),
    }
}

/// Execute the verify command.
pub(crate) fn run(args: VerifyArgs) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let key_file = KeyFile::read_from(&args.key)?;
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for verification, got {:?}", key_file.key_type);
    }

    let sig_json = std::fs::read_to_string(&args.signature)
        .with_context(|| format!("Failed to read {}", args.signature.display()))?;

    // Auto-detect algorithm from signature file if not specified
    let algorithm = if let Some(alg) = args.algorithm {
        alg
    } else {
        let detected = detect_algorithm(&sig_json)?;
        eprintln!("Auto-detected algorithm: {:?}", algorithm_name(&detected));
        detected
    };

    // Validate algorithm matches key file
    let expected_alg = algorithm_name(&algorithm);
    key_file.validate_algorithm(expected_alg)?;

    let pk_bytes = key_file.key_bytes()?;

    let valid = match algorithm {
        VerifyAlgorithm::Hybrid => verify_hybrid(&data, &sig_json, &pk_bytes)?,
        _ => verify_standard(&data, &sig_json, &pk_bytes, &algorithm)?,
    };

    if valid {
        println!("Signature is VALID.");
        Ok(())
    } else {
        bail!("Signature is INVALID.")
    }
}

/// Map verify algorithm enum to canonical key file algorithm name.
fn algorithm_name(alg: &VerifyAlgorithm) -> &'static str {
    match alg {
        VerifyAlgorithm::MlDsa65 => "ml-dsa-65",
        VerifyAlgorithm::MlDsa44 => "ml-dsa-44",
        VerifyAlgorithm::MlDsa87 => "ml-dsa-87",
        VerifyAlgorithm::SlhDsa => "slh-dsa-shake-128s",
        VerifyAlgorithm::FnDsa => "fn-dsa-512",
        VerifyAlgorithm::Ed25519 => "ed25519",
        VerifyAlgorithm::Hybrid => "hybrid-ml-dsa-65-ed25519",
    }
}

fn verify_standard(
    data: &[u8],
    sig_json: &str,
    pk_bytes: &[u8],
    algorithm: &VerifyAlgorithm,
) -> Result<bool> {
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
