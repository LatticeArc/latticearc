//! Verify command — check digital signatures.
//!
//! Supports two signature formats:
//!
//! **SignedData (recommended):** Produced by `sign --public-key`. Contains scheme
//! metadata, timestamp, and public key — the library's `verify()` handles everything.
//! No `--algorithm` or `--key` flags needed (both are embedded in the signature).
//!
//! **Legacy JSON:** Produced by `sign --algorithm`. Requires `--key` (public key)
//! and optionally `--algorithm` (auto-detected from the signature file).

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// Verification algorithm (legacy mode only).
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
    /// FN-DSA-512 (FIPS 206).
    FnDsa,
    /// Ed25519.
    Ed25519,
    /// Hybrid ML-DSA-65 + Ed25519.
    Hybrid,
}

/// Arguments for the `verify` subcommand.
#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// Verification algorithm (legacy mode). Auto-detected from signature file if omitted.
    #[arg(short, long, value_enum)]
    pub algorithm: Option<VerifyAlgorithm>,
    /// Use case for configuration (optional).
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
    /// Input file that was signed.
    #[arg(short, long)]
    pub input: PathBuf,
    /// Signature file (SignedData JSON or legacy JSON).
    #[arg(short, long)]
    pub signature: PathBuf,
    /// Public key file (required for legacy format, optional for SignedData).
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

/// Execute the verify command.
pub(crate) fn run(args: VerifyArgs) -> Result<()> {
    let sig_json = std::fs::read_to_string(&args.signature)
        .with_context(|| format!("Failed to read {}", args.signature.display()))?;

    // Try SignedData format first (produced by sign --public-key)
    if let Ok(signed) = latticearc::unified_api::serialization::deserialize_signed_data(&sig_json) {
        let data = std::fs::read(&args.input)
            .with_context(|| format!("Failed to read {}", args.input.display()))?;

        // Verify the signed data matches the input file
        if signed.data != data {
            bail!(
                "Signature was created over different data than the input file.\n\
                 The SignedData envelope contains the original data — it does not match \
                 the file at '{}'.",
                args.input.display()
            );
        }

        let config =
            super::common::build_config(args.use_case, args.security_level, &args.compliance);
        let valid = latticearc::verify(&signed, config)
            .map_err(|e| anyhow::anyhow!("Verification failed: {e}"))?;

        return if valid {
            println!("Signature is VALID. (scheme: {})", signed.scheme);
            Ok(())
        } else {
            bail!("Signature is INVALID.")
        };
    }

    // Fall back to legacy format (requires --key)
    let key_path = args.key.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Public key file (--key) is required for legacy signature format.\n\
             Signatures created with 'sign --public-key' embed the public key \
             and don't need --key."
        )
    })?;

    verify_legacy(&args, &sig_json, key_path)
}

/// Legacy verification path — custom JSON format + primitive-level API.
fn verify_legacy(args: &VerifyArgs, sig_json: &str, key_path: &std::path::Path) -> Result<()> {
    let data = std::fs::read(&args.input)
        .with_context(|| format!("Failed to read {}", args.input.display()))?;

    let key_file = KeyFile::read_from(key_path)?;
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for verification, got {:?}", key_file.key_type);
    }

    let algorithm = if let Some(alg) = &args.algorithm {
        alg.clone()
    } else {
        let detected = detect_algorithm(sig_json)?;
        eprintln!("Auto-detected algorithm: {}", algorithm_name(&detected));
        detected
    };

    let expected_alg = algorithm_name(&algorithm);
    key_file.validate_algorithm(expected_alg)?;

    let pk_bytes = key_file.key_bytes()?;

    let valid = match algorithm {
        VerifyAlgorithm::Hybrid => verify_hybrid(&data, sig_json, &pk_bytes)?,
        _ => verify_standard(&data, sig_json, &pk_bytes, &algorithm)?,
    };

    if valid {
        println!("Signature is VALID.");
        Ok(())
    } else {
        bail!("Signature is INVALID.")
    }
}

/// Detect algorithm from the "algorithm" field in a legacy .sig.json file.
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
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
        VerifyAlgorithm::MlDsa44 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
        VerifyAlgorithm::MlDsa87 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::MlDsaParameterSet::MLDSA87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
        VerifyAlgorithm::SlhDsa => latticearc::verify_pq_slh_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::slh_dsa::SecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
        VerifyAlgorithm::FnDsa => latticearc::verify_pq_fn_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
        VerifyAlgorithm::Ed25519 => latticearc::verify_ed25519(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Verification failed: {e}")),
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

    let pk = crate::keyfile::parse_hybrid_sign_pk_from_bytes(pk_bytes)?;
    let hybrid_sig = latticearc::hybrid::sig_hybrid::HybridSignature { ml_dsa_sig, ed25519_sig };

    latticearc::verify_hybrid_signature(
        data,
        &hybrid_sig,
        &pk,
        latticearc::SecurityMode::Unverified,
    )
    .map_err(|e| anyhow::anyhow!("Hybrid verification failed: {e}"))
}
