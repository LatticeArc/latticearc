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
    /// Input file that was signed (reads from stdin if omitted).
    ///
    /// Symmetric with the round-7 `sign --input <stdin>` path: a CI
    /// pipeline that hashes a stream and signs it should be able to
    /// verify the same way without staging to a temp file.
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Signature file (SignedData JSON or legacy JSON).
    #[arg(short, long)]
    pub signature: PathBuf,
    /// Public key file (required for legacy format, optional for SignedData).
    #[arg(short, long)]
    pub key: Option<PathBuf>,
}

/// Execute the verify command.
///
/// Returns `Ok(true)` for VALID, `Ok(false)` for INVALID (forgery /
/// tampering), or `Err(_)` for operational errors (missing file, bad
/// key, etc.). `main` translates the boolean into the documented
/// 0/1/≥2 exit-code contract via `std::process::exit(1)` AFTER all
/// destructors run — round-8 audit fix #5 noted that exiting from
/// inside `verify::run` skipped Drop on local `KeyFile`/`Vec<u8>`
/// state, which is currently benign (PK is non-secret) but would
/// silently regress if the same pattern were copied to sign or
/// decrypt.
pub(crate) fn run(args: VerifyArgs) -> Result<bool> {
    let input_data = read_verify_input(&args)?;
    // open-once with `take(limit + 1)` instead of the
    // previous stat-then-read sequence. The old shape was the same
    // TOCTOU pattern that round-26 H15 fixed for keyfiles — between
    // the `metadata().len()` check and the `read_to_string` call, a
    // path swap could let a multi-gig signature file slip past the
    // 100 MiB cap. Also closes round-30 M5: `metadata().len()`
    // returns 0 for `/dev/zero` / FIFOs, so the subsequent read was
    // unbounded for special files.
    let sig_bytes = super::common::read_file_with_cap(
        &args.signature,
        super::common::CLI_MAX_SIGNATURE_INPUT_BYTES,
        "verify",
    )?;
    let sig_json = String::from_utf8(sig_bytes)
        .with_context(|| format!("{} is not valid UTF-8", args.signature.display()))?;

    // Try SignedData format first (produced by sign --public-key)
    if let Ok(signed) = latticearc::unified_api::serialization::deserialize_signed_data(&sig_json) {
        // Verify the signed data matches the input file. `signed.data`
        // currently carries public message material, so the comparison
        // doesn't need to be CT in the threat-model sense — but the
        // round-34 L11 attempt to use `ct_eq` was self-defeating
        // (the outer `if signed.data.len() == input_data.len()`
        // length-branch made the ct_eq dead). Drop the cargo-cult CT
        // wrapper and use straightforward `==`. If a future caller
        // routes secret bytes through this path, the responsibility
        // is to handle CT at THAT site, not to pretend this site is
        // CT when it can't be.
        if signed.data != input_data {
            bail!(
                "Signature was created over different data than the input.\n\
                 The SignedData envelope contains the original data — it does not match \
                 the data at {}.",
                input_label(&args)
            );
        }

        let config =
            super::common::build_config(args.use_case, args.security_level, &args.compliance);
        // opaque user-facing message; route the upstream
        // `e` to tracing::debug! only. Mirrors round-28 H3's decrypt
        // collapse — the inner library error wording is not part of
        // the user contract and was leaking implementation detail.
        let valid = latticearc::verify(&signed, config).map_err(|e| {
            tracing::debug!(error = ?e, "verify (SignedData path) rejected");
            anyhow::anyhow!("Verification failed")
        })?;

        // return the result; `main` does the
        // exit-code translation after destructors. The 0/1/≥2 contract
        // (round-7 fix #8 + #11) is preserved at the boundary, not
        // here.
        // Stream choice: VALID on stdout, INVALID on stderr. The
        // round-20 audit (#17) flagged this asymmetry — stdout-only
        // test capture (`run_ok`) wouldn't catch a swap regression.
        // We keep the asymmetry because (a) ~16 existing integration
        // tests assert VALID via stdout capture, and (b) the
        // machine-readable verdict is the exit code (Ok(true)/false),
        // which IS symmetric — verdict text on either stream is
        // operator status only. Tests that need stream-swap protection
        // should use `run_ok_combined`.
        if valid {
            println!("Signature is VALID. (scheme: {})", signed.scheme);
        } else {
            eprintln!("Signature is INVALID.");
        }
        return Ok(valid);
    }

    // Fall back to legacy format (requires --key)
    let key_path = args.key.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Public key file (--key) is required for legacy signature format.\n\
             Signatures created with 'sign --public-key' embed the public key \
             and don't need --key."
        )
    })?;

    verify_legacy(&args, &sig_json, key_path, input_data)
}

/// Read the verify input from `--input <path>` or stdin (round-7 fix
/// #10). Round-8 fix #13: routes through the shared helper.
fn read_verify_input(args: &VerifyArgs) -> Result<Vec<u8>> {
    super::common::read_file_or_stdin(
        args.input.as_deref(),
        super::common::CLI_MAX_SIGNATURE_INPUT_BYTES,
        "verify",
    )
}

/// Human-readable label for the input source — used in error messages.
fn input_label(args: &VerifyArgs) -> String {
    args.input
        .as_ref()
        .map(|p| format!("'{}'", p.display()))
        .unwrap_or_else(|| "<stdin>".to_string())
}

/// Legacy verification path — custom JSON format + primitive-level API.
fn verify_legacy(
    args: &VerifyArgs,
    sig_json: &str,
    key_path: &std::path::Path,
    data: Vec<u8>,
) -> Result<bool> {
    // `data` is threaded in from `run` — round-8 audit fix #2. Reading
    // input again here would drain stdin a second time in pipe mode,
    // returning empty bytes and silently producing INVALID for any
    // legacy-format signature piped on stdin.

    let key_file = KeyFile::read_from(key_path)?;
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for verification, got {:?}", key_file.key_type);
    }

    let algorithm = if let Some(alg) = &args.algorithm {
        alg.clone()
    } else {
        let detected = detect_algorithm(sig_json)?;
        // algorithm name isn't secret but is
        // enumerable across log aggregation targets. Demote to debug.
        tracing::debug!(algorithm = %algorithm_name(&detected), "auto-detected legacy verify algorithm");
        detected
    };

    let expected_alg = algorithm_name(&algorithm);
    key_file.validate_algorithm(expected_alg)?;

    let pk_bytes = key_file.key_bytes()?;

    let valid = match algorithm {
        VerifyAlgorithm::Hybrid => verify_hybrid(&data, sig_json, &pk_bytes)?,
        _ => verify_standard(&data, sig_json, &pk_bytes, &algorithm)?,
    };

    // return the verdict; `main` translates
    // `Ok(false)` into exit 1 after destructors.
    // See SignedData branch above for the stream-asymmetry rationale.
    if valid {
        println!("Signature is VALID.");
    } else {
        eprintln!("Signature is INVALID.");
    }
    Ok(valid)
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
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
        VerifyAlgorithm::MlDsa44 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
        VerifyAlgorithm::MlDsa87 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
        VerifyAlgorithm::SlhDsa => latticearc::verify_pq_slh_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
        VerifyAlgorithm::FnDsa => latticearc::verify_pq_fn_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::fndsa::FnDsaSecurityLevel::Level512,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
        VerifyAlgorithm::Ed25519 => latticearc::verify_ed25519(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )
        .map_err(|e| {
            tracing::debug!(error = ?e, "verify (legacy path) rejected");
            anyhow::anyhow!("Verification failed")
        }),
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
    let hybrid_sig = latticearc::hybrid::sig_hybrid::HybridSignature::new(ml_dsa_sig, ed25519_sig);

    // preserve the CLI 0/1/≥2 exit-code
    // contract. The unified-API wrapper maps the underlying
    // `HybridSignatureError::VerificationFailed` → `CoreError::
    // VerificationFailed`; if we surface that as `anyhow::Error` the
    // caller sees exit ≥2 (operational failure) instead of exit 1
    // (forged signature). Translate `CoreError::VerificationFailed` to
    // `Ok(false)` so the outer dispatch returns exit 1 — same shape as
    // the ML-DSA / SLH-DSA / FN-DSA paths.
    use latticearc::CoreError;
    match latticearc::verify_hybrid_signature(
        data,
        &hybrid_sig,
        &pk,
        latticearc::SecurityMode::Unverified,
    ) {
        Ok(valid) => Ok(valid),
        Err(CoreError::VerificationFailed) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Hybrid verification failed: {e}")),
    }
}
