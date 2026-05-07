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
    /// Symmetric with `sign --input <stdin>`: a CI pipeline that
    /// hashes a stream and signs it should be able to verify the
    /// same way without staging to a temp file.
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
/// destructors run — exiting from inside `verify::run` would skip
/// Drop on local `KeyFile`/`Vec<u8>` state, which is currently benign
/// (PK is non-secret) but would silently regress if the same pattern
/// were copied to `sign` or `decrypt`.
pub(crate) fn run(args: VerifyArgs) -> Result<bool> {
    let input_data = read_verify_input(&args)?;
    // open-once with `take(limit + 1)` instead of stat-then-read.
    // A `metadata().len()` + `read_to_string` sequence is TOCTOU: a
    // path swap between the size check and the read can let a
    // multi-gig file slip past the cap. `metadata().len()` also
    // returns 0 for `/dev/zero` / FIFOs, so a subsequent read of an
    // unbounded special file would have no upper bound.
    let sig_bytes = super::common::read_file_with_cap(
        &args.signature,
        super::common::CLI_MAX_SIGNATURE_INPUT_BYTES,
        "verify",
    )?;
    let sig_json = String::from_utf8(sig_bytes)
        .with_context(|| format!("{} is not valid UTF-8", args.signature.display()))?;

    // Detect whether the file is in the SignedData envelope shape
    // *before* committing to a verifier. The shape check is a
    // structural pre-pass: if the JSON has the unified-API SignedData
    // fields (`metadata.signature`, `metadata.signature_algorithm`,
    // `scheme`), require `deserialize_signed_data` to succeed; any
    // deserialization failure collapses to `print_invalid()`. Without
    // this gate, an `if let Ok(...)` shape silently falls through to
    // the legacy auto-detect branch and emits a distinguishable
    // "Signature file missing 'algorithm' field" — letting an
    // attacker tell apart "I tampered with metadata.signature_algorithm"
    // from "wrong signature" by stderr text (Pattern-6).
    let looks_like_signed_data = serde_json::from_str::<serde_json::Value>(&sig_json)
        .ok()
        .and_then(|v| {
            v.get("metadata")?.get("signature")?;
            v.get("metadata")?.get("signature_algorithm")?;
            v.get("scheme")?;
            Some(())
        })
        .is_some();
    if looks_like_signed_data {
        // Deserialize INSIDE the structural gate (not before it), so a
        // hoist or reorder can't silently fall through to the legacy
        // auto-detect branch and reopen the Pattern-6 distinguisher
        // (legacy branch emitted "Signature file missing 'algorithm'
        // field" — distinguishable from a crypto-reject error).
        let signed =
            match latticearc::unified_api::serialization::deserialize_signed_data(&sig_json) {
                Ok(signed) => signed,
                Err(e) => {
                    tracing::debug!(
                        error = ?e,
                        "verify (SignedData shape detected, parse rejected)"
                    );
                    return Ok(print_invalid());
                }
            };
        // Verify the signed data matches the input file. `signed.data`
        // currently carries public message material, so the comparison
        // doesn't need to be CT in the threat-model sense. A `ct_eq`
        // wrapper here would be cargo-cult: a length-equality branch
        // before it would make the CT comparison dead anyway. If a
        // future caller routes secret bytes through this path, the
        // responsibility is to handle CT at THAT site, not to pretend
        // this site is CT when it can't be.
        //
        // A mismatch is attacker-controllable (the SignedData envelope
        // is loaded from a file the attacker may have written) and so
        // must collapse to `print_invalid()` — emitting a
        // distinguishable "Signature was created over different data"
        // error would let an attacker tell apart "I tampered with
        // signed.data" from "I tampered with the signature bytes" by
        // branching on stderr text (Pattern-6). Debug-log the original
        // detail so operators investigating a legitimate user mistake
        // (signed the wrong file) can recover the context with
        // `RUST_LOG=debug`.
        if signed.data != input_data {
            tracing::debug!(
                input = %input_label(&args),
                "verify (SignedData path) rejected: embedded data does not match input"
            );
            return Ok(print_invalid());
        }

        let config =
            super::common::build_config(args.use_case, args.security_level, &args.compliance);
        // A `latticearc::verify(...)` Err (e.g. malformed public key)
        // collapses to the same user-visible outcome as `Ok(false)` so
        // an attacker can't distinguish the structural / crypto /
        // library-error paths via stderr text or exit-code class. See
        // `print_invalid()` for the centralised reject contract.
        let valid = match latticearc::verify(&signed, config) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = ?e, "verify (SignedData path) rejected");
                return Ok(print_invalid());
            }
        };

        // return the result; `main` does the exit-code translation
        // after destructors so the 0/1/≥2 contract is preserved at
        // the boundary, not here.
        //
        // Stream choice: VALID on stdout, INVALID on stderr. The
        // asymmetry is intentional — the machine-readable verdict is
        // the exit code (Ok(true)/false), which IS symmetric. Verdict
        // text on either stream is operator status only. Tests that
        // need stream-swap protection should use `run_ok_combined`.
        if valid {
            println!("Signature is VALID. (scheme: {})", signed.scheme);
            return Ok(true);
        }
        return Ok(print_invalid());
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

/// Centralised reject for any path that must be indistinguishable
/// from a cryptographic-verification failure: emits the same INVALID
/// stderr line and returns `false` (which `run`'s callers translate
/// to exit code 1, the "invalid" class — distinct from the ≥2 "error"
/// class).
///
/// # SECURITY: indistinguishability contract
///
/// Every reject path triggered by **attacker-controllable** signature-
/// file content MUST funnel through `print_invalid()` (or, in
/// `verify_legacy`, through the closure that maps `Err(_)` →
/// `print_invalid()` via `unwrap_or_else`). The distinguishers this
/// contract closes are concrete and have been observed in audit:
///
/// 1. **Stderr text** — a stricter message ("Invalid base64 in
///    signature", "Unknown algorithm", "Verification failed",
///    "Signature was created over different data than the input",
///    "Hybrid verification failed: <upstream detail>") lets an
///    attacker probe which validation step rejected by reading the
///    process's stderr stream.
/// 2. **Exit-code class** — bubbling an `Err(_)` out of `run` lands
///    at exit ≥2 ("operational error"), distinct from the `Ok(false)`
///    → exit 1 ("invalid signature") class. An attacker can
///    distinguish the two with `[ $? -eq 1 ]` vs `[ $? -ge 2 ]`.
/// 3. **Echo amplification** — interpolating an attacker-controlled
///    field (`{other}` from the `algorithm` JSON value, `{e}` from a
///    structured upstream error) into the error string both reveals
///    the field's content AND amplifies its length (attacker writes
///    1 MiB → log line is 1 MiB).
///
/// The "operator-side" errors in `verify_legacy` (missing `--key`,
/// wrong key type, encrypted key without passphrase, operator-picked
/// `--algorithm` mismatching the key) are NOT reachable by an
/// attacker who can only tamper with the signature file, so they keep
/// helpful error messages and surface as exit ≥2. See `verify_legacy`
/// docs for the boundary.
///
/// **When adding a new reject path:** if it can be triggered by the
/// content of `--signature` (or, for SignedData, by the embedded
/// `signed.data` / `signed.metadata`), it MUST route through
/// `print_invalid()`; preserve any operator-facing detail in
/// `tracing::debug` instead of `eprintln!` / `bail!` / `anyhow!`.
fn print_invalid() -> bool {
    eprintln!("Signature is INVALID.");
    false
}

/// Read the verify input from `--input <path>` or stdin via the
/// shared file-or-stdin helper.
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

/// Dispatch shape for the verify-side step in `verify_legacy`.
///
/// The variant is chosen in Phase 1c (operator-side parsing) so that
/// hybrid pk-parse failures — which indicate a malformed operator key
/// file, NOT a tampered signature — surface as helpful `Err` at exit
/// ≥2 rather than collapsing into `print_invalid()`. By the time the
/// Phase-2 closure dispatches, the type system guarantees the right
/// pk shape for the chosen algorithm.
enum LegacyVerifier<'a> {
    Standard { algorithm: VerifyAlgorithm, pk_bytes: &'a [u8] },
    Hybrid { pk: latticearc::hybrid::sig_hybrid::HybridSigPublicKey },
}

/// Legacy verification path — custom JSON format + primitive-level API.
///
/// # Pattern-6 boundary
///
/// `verify_legacy` splits its work into two phases with different
/// error-handling contracts:
///
/// 1. **Operator-side validation** (key file existence, key type,
///    encrypted-key passphrase, operator-picked `--algorithm` vs key
///    mismatch, hybrid pk byte-layout parse). Errors here surface as
///    `Err(_)` and become CLI exit code ≥2 ("operational error") with
///    a helpful stderr message. The threat model treats the operator's
///    `--key` file as trusted — an attacker cannot reach these paths
///    by tampering with the signature file.
///
/// 2. **Signature-side validation** (algorithm auto-detect from the
///    signature JSON, base64/JSON parse, missing fields, validate-
///    algorithm vs auto-detected name, crypto verification). Errors
///    here are attacker-controllable (the signature file may have been
///    tampered) and so collapse via `unwrap_or_else` to `false`, which
///    routes through [`print_invalid()`]. Without the collapse, an
///    attacker could distinguish "I broke the JSON envelope" from "I
///    broke the signature" by reading stderr text or exit-code class
///    (Pattern-6). The original detail is preserved in `tracing::debug`
///    for operators investigating a legitimate user mistake.
fn verify_legacy(
    args: &VerifyArgs,
    sig_json: &str,
    key_path: &std::path::Path,
    data: Vec<u8>,
) -> Result<bool> {
    // `data` is threaded in from `run`. Reading input again here
    // would drain stdin a second time in pipe mode, returning empty
    // bytes and silently producing INVALID for any legacy-format
    // signature piped on stdin.

    // ── Phase 1a: read operator key file (helpful errors, exit ≥2) ──
    let key_file = KeyFile::read_from(key_path)?;
    if key_file.key_type != KeyType::Public {
        // `canonical_name()` instead of `{:?}` Debug: the Debug repr
        // of a `#[non_exhaustive]` enum is variant-fingerprintable
        // across versions.
        bail!(
            "Expected public key file for verification, got {}",
            key_file.key_type.canonical_name()
        );
    }
    let pk_bytes = key_file.key_bytes()?;

    // ── Phase 1b: operator-picked algorithm vs key (helpful err) ──
    if let Some(cli_alg) = &args.algorithm {
        key_file.validate_algorithm(algorithm_name(cli_alg))?;
    }

    // ── Phase 1c: determine algorithm + parse operator-side pk ──
    //
    // Algorithm determination has a mixed posture:
    //   * `--algorithm <X>` came from the operator → trusted.
    //   * Auto-detect comes from the signature file → attacker-
    //     controllable. If detection fails or the auto-detected
    //     algorithm doesn't match the key, collapse to `print_invalid()`
    //     immediately; both shapes are signature-side rejects.
    //
    // Once the algorithm is known, the *pk byte-layout parse* is
    // operator-side regardless of where the algorithm came from
    // (`pk_bytes` is the operator's key file). A malformed hybrid pk
    // is operator misuse, not an attacker action — surface it as a
    // helpful Err.
    let algorithm = if let Some(alg) = args.algorithm.clone() {
        alg
    } else {
        let Some(detected) = detect_algorithm(sig_json) else {
            tracing::debug!("verify (legacy auto-detect) rejected: algorithm undetectable");
            return Ok(print_invalid());
        };
        tracing::debug!(
            algorithm = %algorithm_name(&detected),
            "auto-detected legacy verify algorithm"
        );
        if let Err(e) = key_file.validate_algorithm(algorithm_name(&detected)) {
            tracing::debug!(error = ?e, "verify (legacy auto-detect) rejected: alg mismatch");
            return Ok(print_invalid());
        }
        detected
    };

    let verifier = match algorithm {
        VerifyAlgorithm::Hybrid => {
            // pk parse failure here is operator-side (their key file
            // is malformed) — bubble as helpful Err.
            let pk = crate::keyfile::parse_hybrid_sign_pk_from_bytes(&pk_bytes)?;
            LegacyVerifier::Hybrid { pk }
        }
        other => LegacyVerifier::Standard { algorithm: other, pk_bytes: &pk_bytes },
    };

    // ── Phase 2: signature-side verify (collapses to print_invalid) ──
    //
    // Any error here — JSON parse, missing field, base64 decode, or a
    // crypto-library error from the verify_* helpers — collapses to
    // `false` via `unwrap_or_else`, routing through `print_invalid()`.
    // The original error is debug-logged so operators can recover
    // detail at `RUST_LOG=debug`.
    let valid = match verifier {
        LegacyVerifier::Hybrid { ref pk } => verify_hybrid(&data, sig_json, pk),
        LegacyVerifier::Standard { algorithm, pk_bytes } => {
            verify_standard(&data, sig_json, pk_bytes, &algorithm)
        }
    }
    .unwrap_or_else(|e| {
        tracing::debug!(error = ?e, "verify (legacy path) rejected");
        false
    });

    // Route both VALID and INVALID through their respective helpers
    // so the reject contract (see `print_invalid()`) cannot drift via
    // an inline `eprintln!`.
    if valid {
        println!("Signature is VALID.");
        Ok(true)
    } else {
        Ok(print_invalid())
    }
}

/// Detect algorithm from the "algorithm" field in a legacy .sig.json file.
///
/// Returns `None` for any reason the algorithm can't be identified —
/// JSON parse failure, missing `"algorithm"` field, non-string value,
/// or an unrecognised name. Returning `Option` (not `Result`) is
/// load-bearing for the Pattern-6 collapse contract: every "couldn't
/// detect" cause must be indistinguishable from every other one to
/// stop attacker-controllable signature-file content from carving out
/// a stderr-text side channel. The caller (`verify_legacy`) maps
/// `None` into the same `print_invalid()` outcome as a crypto reject;
/// operator-facing detail is recovered via `tracing::debug` at
/// `RUST_LOG=debug`.
///
/// In particular, NEVER interpolate the `algorithm` field into an
/// error string — an attacker can supply an arbitrarily long value,
/// producing a proportionally large log line and a variant-name
/// oracle for which validation step rejected.
fn detect_algorithm(sig_json: &str) -> Option<VerifyAlgorithm> {
    let sig: serde_json::Value = serde_json::from_str(sig_json).ok()?;
    let alg_str = sig.get("algorithm").and_then(|v| v.as_str())?;
    match alg_str {
        "ml-dsa-65" => Some(VerifyAlgorithm::MlDsa65),
        "ml-dsa-44" => Some(VerifyAlgorithm::MlDsa44),
        "ml-dsa-87" => Some(VerifyAlgorithm::MlDsa87),
        "slh-dsa-shake-128s" => Some(VerifyAlgorithm::SlhDsa),
        "fn-dsa-512" => Some(VerifyAlgorithm::FnDsa),
        "ed25519" => Some(VerifyAlgorithm::Ed25519),
        "hybrid-ml-dsa-65-ed25519" => Some(VerifyAlgorithm::Hybrid),
        _ => None,
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

/// Verify a non-hybrid legacy signature.
///
/// Errors here — JSON parse, missing fields, base64 decode, crypto
/// reject from a `latticearc::verify_*` helper — propagate as
/// `Err(anyhow::Error)` and are caught by the closure in
/// `verify_legacy`, which collapses them to `print_invalid()`. Do NOT
/// re-flatten errors per arm with `.map_err(|_| anyhow!("..."))` — a
/// per-arm message becomes its own Pattern-6 distinguisher. Let
/// errors propagate raw; the closure-level collapse handles
/// indistinguishability uniformly.
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

    let valid = match algorithm {
        VerifyAlgorithm::MlDsa65 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::MlDsa44 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::MlDsa87 => latticearc::verify_pq_ml_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::SlhDsa => latticearc::verify_pq_slh_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::FnDsa => latticearc::verify_pq_fn_dsa(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::primitives::sig::fndsa::FnDsaSecurityLevel::Level512,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::Ed25519 => latticearc::verify_ed25519(
            data,
            &sig_bytes,
            pk_bytes,
            latticearc::SecurityMode::Unverified,
        )?,
        VerifyAlgorithm::Hybrid => bail!("Internal error: hybrid handled separately"),
    };
    Ok(valid)
}

/// Verify a hybrid legacy signature against a parsed hybrid public key.
///
/// The pk is parsed by the caller (`verify_legacy` Phase 1c) so that
/// pk-parse failures — which indicate a malformed *operator* key file
/// — surface as helpful Errs at exit ≥2, not collapse into INVALID.
/// Errors from THIS function (signature JSON parse, base64 decode,
/// missing fields, crypto reject) are signature-side and propagate
/// for the closure in `verify_legacy` to collapse to `print_invalid()`.
fn verify_hybrid(
    data: &[u8],
    sig_json: &str,
    pk: &latticearc::hybrid::sig_hybrid::HybridSigPublicKey,
) -> Result<bool> {
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

    let hybrid_sig = latticearc::hybrid::sig_hybrid::HybridSignature::new(ml_dsa_sig, ed25519_sig);

    // Preserve the CLI 0/1/≥2 exit-code contract. The unified-API
    // wrapper maps `HybridSignatureError::VerificationFailed` →
    // `CoreError::VerificationFailed`; translating that variant to
    // `Ok(false)` routes through `verify_legacy`'s `print_invalid()`
    // arm (exit 1).
    //
    // Any other `Err` propagates via `anyhow::Error::new(e)` — the
    // typed source survives for `tracing::debug`, but no upstream
    // error string is interpolated into stderr. A structured upstream
    // error like "ML-DSA component verify failed" vs "Ed25519
    // component verify failed" would otherwise tell an attacker which
    // half of the hybrid pair rejected.
    use latticearc::CoreError;
    match latticearc::verify_hybrid_signature(
        data,
        &hybrid_sig,
        pk,
        latticearc::SecurityMode::Unverified,
    ) {
        Ok(valid) => Ok(valid),
        Err(CoreError::VerificationFailed) => Ok(false),
        Err(e) => Err(anyhow::Error::new(e)),
    }
}
