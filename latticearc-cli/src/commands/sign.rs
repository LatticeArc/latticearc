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
    /// Signing algorithm (expert override; prefer --use-case for automatic selection).
    /// clap-level conflicts_with surfaces the
    /// constraint in --help.
    #[arg(short, long, value_enum, conflicts_with = "use_case")]
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
    /// Input file to sign (reads from stdin if omitted).
    ///
    /// When omitted, input is read from stdin. The default `--output`
    /// derivation (`<input>.sig.json`) is unavailable in stdin mode —
    /// pass `--output` explicitly.
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output file for the signature (defaults to <input>.sig.json).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Secret key file for signing.
    #[arg(short, long)]
    pub key: PathBuf,
    /// Public key file (required for unified API — embeds PK in SignedData).
    #[arg(long)]
    pub public_key: Option<PathBuf>,
    /// Overwrite the output file if it already exists. Default: false.
    #[arg(long)]
    pub force: bool,
}

/// Execute the sign command.
pub(crate) fn run(args: SignArgs) -> Result<()> {
    // Stdin mode — `--output` becomes
    // mandatory because we can't derive it from a non-existent
    // `<input>.sig.json`. shared helper.
    if args.input.is_none() && args.output.is_none() {
        bail!("--output is required when --input is omitted (stdin mode)");
    }
    let data = super::common::read_file_or_stdin(
        args.input.as_deref(),
        super::common::CLI_MAX_SIGNATURE_INPUT_BYTES,
        "sign",
    )?;

    let key_file = KeyFile::read_from(&args.key)?;
    if key_file.key_type != KeyType::Secret {
        bail!("Expected secret key file for signing, got {}", key_file.key_type.canonical_name());
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
             Recommended: latticearc-cli sign --input <FILE> --key <SECRET> --public-key <PUBLIC>\n\
             Legacy:      latticearc-cli sign --algorithm <ALG> --input <FILE> --key <SECRET>"
        )
    };

    let alg_name = algorithm_name(algorithm);
    key_file.validate_algorithm(alg_name)?;

    let sig_bytes = match algorithm {
        SignAlgorithm::MlDsa65 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::MlDsa44 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::MlDsa87 => latticearc::sign_pq_ml_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::SlhDsa => latticearc::sign_pq_slh_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
        SignAlgorithm::FnDsa => latticearc::sign_pq_fn_dsa(
            &data,
            &sk_bytes,
            latticearc::primitives::sig::fndsa::FnDsaSecurityLevel::Level512,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?,
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
///
/// When the caller hasn't passed `--use-case` / `--security-level`, the
/// signing scheme is inferred from the public key file's algorithm so that
/// keys generated via `keygen --use-case ...` sign under the same scheme they
/// were generated with. Without this inference, the library would fall back
/// to its default scheme (hybrid-ml-dsa-65-ed25519) and reject the key as a
/// length mismatch.
fn sign_unified(
    data: &[u8],
    sk_bytes: &[u8],
    pk_path: &std::path::Path,
    args: &SignArgs,
) -> Result<()> {
    let pk_file = KeyFile::read_from(pk_path)?;
    if pk_file.key_type != KeyType::Public {
        bail!("Expected public key file, got {}", pk_file.key_type.canonical_name());
    }
    let pk_bytes = pk_file.key_bytes()?;

    let config = super::common::build_signing_config(
        args.use_case,
        args.security_level,
        &args.compliance,
        pk_file.portable_key().algorithm(),
    );

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
        "ml_dsa_sig": base64::engine::general_purpose::STANDARD.encode(signature.ml_dsa_sig()),
        "ed25519_sig": base64::engine::general_purpose::STANDARD.encode(signature.ed25519_sig()),
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
    let output_path = if let Some(p) = args.output.clone() {
        p
    } else {
        // run() guarantees --output is set when --input is None
        // (stdin mode), so the only way to reach this branch is
        // with input=Some — derive `<input>.sig.json`.
        let mut p = args.input.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "internal error: write_signature called with both --input and --output unset"
            )
        })?;
        let new_ext = match p.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.sig.json"),
            None => "sig.json".to_string(),
        };
        p.set_extension(new_ext);
        p
    };

    // Atomic write — sig files aren't secret but partial-file-at-rest
    // is still a script-corruption hazard.
    // only overwrite when --force is passed.
    // LINT-OK: public-write-signature (signatures are not secret)
    latticearc::unified_api::atomic_write::AtomicWrite::new(json.as_bytes())
        .overwrite_existing(args.force)
        .write(&output_path)
        .with_context(|| {
            format!("Failed to write {} (use --force to overwrite)", output_path.display())
        })?;

    // path on stderr leaked to process accounting
    // (auditd, strace) and log aggregators reading the FD. Path names
    // can be sensitive (project codenames, classified directories).
    // Demote to tracing::debug! — operators who want operational
    // confirmation can re-enable it via RUST_LOG.
    tracing::debug!(path = %output_path.display(), "signature written");
    Ok(())
}
