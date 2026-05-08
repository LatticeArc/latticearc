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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
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
    /// Public key file. Required for legacy format. Optional for
    /// SignedData — but **WARNING**: omitting `--key` for a SignedData
    /// envelope trusts the public key embedded in the envelope
    /// itself, which an attacker who delivered the envelope chose.
    /// Pass `--key` to enforce a specific trust anchor; the verifier
    /// will reject the signature if the operator's `--key` does not
    /// match the embedded public key.
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
                    // `%e` Display, not `?e` Debug — Display shows the
                    // top-level deserialize error message (typed,
                    // bounded), while Debug walks the source chain
                    // which can contain attacker-controlled JSON
                    // snippets via the underlying `serde_json::Error`.
                    tracing::debug!(
                        error = %e,
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

        // SECURITY: if the operator passed `--key`, ENFORCE that the
        // embedded `signed.metadata.public_key` matches. Without this
        // check, a SignedData envelope crafted with an attacker's own
        // (key, sig, data) triple verifies against ANY operator-
        // trusted `--key` because `latticearc::verify` uses the
        // embedded public key. The user-facing contract "verify this
        // signature against my trusted key" silently becomes "verify
        // this signature against the key it carries".
        //
        // Mismatch is attacker-controllable and collapses to
        // `print_invalid()` for Pattern-6 indistinguishability with
        // crypto reject. Plain `==` is sufficient: both sides are
        // public keys, not secret material, and the operator's key is
        // fixed across the call so per-invocation timing cannot be
        // amplified across runs.
        //
        // `--key` for SignedData remains optional: omitting it falls
        // through to the embedded-key trust shape, appropriate when
        // the operator has not asserted a specific trust anchor.
        if let Some(key_path) = args.key.as_ref() {
            let pk_bytes = load_operator_public_key(key_path)?;
            if *pk_bytes != signed.metadata.public_key {
                tracing::debug!(
                    "verify (SignedData path) rejected: --key bytes do not match embedded public_key"
                );
                return Ok(print_invalid());
            }
        }

        // Operator-side `--algorithm` cross-check: if the operator
        // asserted an algorithm via `--algorithm`, the envelope's
        // scheme MUST match. This mirrors `verify_legacy` Phase 1b's
        // operator-picked algorithm vs key cross-check, but on the
        // SignedData path the comparison is between the operator's
        // assertion and the envelope's declared scheme.
        //
        // Strip the optional `pq-` prefix on the envelope side: the
        // unified sign API emits both forms ("ml-dsa-65" and
        // "pq-ml-dsa-65") for the same scheme depending on policy,
        // but `algorithm_name` canonicalises to the un-prefixed form.
        //
        // SECURITY: the envelope's `signature_algorithm` field is
        // attacker-controllable (the envelope is loaded from a file
        // the attacker may have written). The bail message therefore
        // does NOT interpolate it — an attacker writing
        // `signature_algorithm: "X".repeat(1_000_000)` would otherwise
        // produce a 1 MiB stderr line on operator misuse. Operators
        // who need the envelope-side detail can recover it via
        // `RUST_LOG=debug`. Mismatch bubbles as helpful `Err` (exit
        // ≥2) — operator misuse, not an attacker action.
        if let Some(cli_alg) = args.algorithm {
            let envelope_alg = signed
                .metadata
                .signature_algorithm
                .strip_prefix("pq-")
                .unwrap_or(&signed.metadata.signature_algorithm);
            let operator_alg = algorithm_name(cli_alg);
            if envelope_alg != operator_alg {
                tracing::debug!(
                    envelope_scheme = %signed.metadata.signature_algorithm,
                    operator_assertion = operator_alg,
                    "verify (SignedData) rejected: --algorithm vs envelope scheme mismatch"
                );
                bail!(
                    "Algorithm mismatch: --algorithm asserts '{operator_alg}' but the \
                     SignedData envelope declares a different scheme. Either omit \
                     --algorithm to verify against the embedded scheme, or pass \
                     --algorithm matching the envelope. Set RUST_LOG=debug for the \
                     envelope's declared scheme."
                );
            }
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
                // `%e` Display — see deserialize_signed_data branch above
                // for the rationale on attacker-content avoidance.
                tracing::debug!(error = %e, "verify (SignedData path) rejected");
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
/// # Tracing observability boundary (workspace-wide)
///
/// `tracing::debug!` calls used as the safe alternative below ARE
/// observable on stderr when the operator (or a CI runner) sets
/// `RUST_LOG=debug`. The default subscriber's filter ships at
/// `INFO`/`WARN`, so production deployments don't expose this surface
/// — but the contract isn't "this never reaches stderr", it's "this
/// never reaches stderr at default log levels". Treat that as a
/// reasonable trade-off: operator-side debugging is the legitimate
/// reason debug logs exist, and an attacker who can flip the
/// operator's `RUST_LOG` already has more powerful capabilities than
/// reading verify error text.
///
/// **What's safe to put inside `tracing::debug!` calls:**
/// - Errors via `error = %e` (Display) — fine. anyhow's Display
///   shows ONLY the outermost `.context(...)` message, which is
///   static text we author ourselves ("Failed to parse signature
///   JSON", "Invalid base64 in signature", etc.). The attacker-
///   controlled detail lives in the source chain, which Display
///   does not walk.
/// - The chosen algorithm name — fine; not secret, comes from a
///   small fixed set, useful for debugging mismatches.
/// - A short reject reason string (e.g. "alg mismatch", "data
///   mismatch") — fine.
///
/// **What's NOT safe inside `tracing::debug!` calls:**
/// - Raw signature bytes, key bytes, or any base64 thereof — even at
///   `RUST_LOG=debug`, plaintext key material in logs is a separate
///   incident class.
/// - `error = ?e` (Debug) where `e` is `anyhow::Error` or any error
///   whose source chain reaches `serde_json::Error` /
///   `base64::DecodeError`. Debug walks the full source chain, and
///   those underlying errors carry attacker-controlled JSON snippets
///   and byte offsets / values from the input. Use `%e` (Display)
///   instead — Display shows only the outermost message, which is
///   static text we author. This contract applies workspace-wide to
///   every reject-collapse `tracing::debug!` call that handles an
///   error potentially wrapping attacker-controlled parser output.
/// - Attacker-controlled fields verbatim (the `algorithm` JSON
///   value, arbitrary error strings from the parsed signature).
///
/// **Narrow exception — `?e` IS safe when:**
/// - `e` has a concrete typed `Debug` impl whose source chain does
///   NOT reach `anyhow::Error` / `serde_json::Error` /
///   `base64::DecodeError`. Closure parameters typed `&dyn
///   std::fmt::Debug` whose producers are bounded internal crate
///   enums fall into this category. The ONLY currently-sanctioned
///   site is the `log_reject` closure inside
///   `latticearc::primitives::sig::ml_dsa::SigningKey::sign_message`
///   (search for "tracing-observability contract" in that file).
///   New uses of this exception MUST cite the rationale at the
///   call site AND be added to this allowlist; do not extend the
///   exception by analogy to similar-looking sites.
///
/// # When adding a new reject path
///
/// If the path can be triggered by the content of `--signature` (or,
/// for SignedData, by the embedded `signed.data` / `signed.metadata`),
/// it MUST route through `print_invalid()`; preserve any operator-
/// facing detail in `tracing::debug` instead of `eprintln!` / `bail!`
/// / `anyhow!` — and follow the safe-content rules above.
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

/// Load the operator's `--key` file and require it to be a public key.
///
/// **Scope: this helper does ONLY the read + key-type check.** It
/// does NOT validate the key's algorithm against any specific
/// operator-asserted algorithm — that cross-check is the caller's
/// responsibility (see `verify_legacy` Phase 1b for the canonical
/// pattern, and the SignedData `--key` byte-equality block in `run`
/// for the alternative shape). A new caller that copies this helper
/// without also implementing the algorithm check creates an
/// operator-intent vs envelope-content mismatch — the same class of
/// signature-verification bypass the SignedData `--key` enforcement
/// closes.
///
/// The `canonical_name()` form of the key-type rejection is used
/// instead of `{:?}` Debug — the Debug repr of a `#[non_exhaustive]`
/// enum is variant-fingerprintable across versions.
fn read_operator_public_key_file(key_path: &std::path::Path) -> Result<KeyFile> {
    let key_file = KeyFile::read_from(key_path)?;
    if key_file.key_type != KeyType::Public {
        bail!(
            "Expected public key file for verification, got {}",
            key_file.key_type.canonical_name()
        );
    }
    Ok(key_file)
}

/// Load the operator's `--key` file and decode the raw public-key
/// bytes. Combines `read_operator_public_key_file` + `key_bytes()`
/// for callers that don't need the `KeyFile` itself.
fn load_operator_public_key(key_path: &std::path::Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    read_operator_public_key_file(key_path)?.key_bytes()
}

/// The six non-hybrid `VerifyAlgorithm` variants, lifted into their
/// own enum so `verify_standard` can be type-enforced as never
/// receiving `Hybrid` — without this, an unreachable `bail!("Internal
/// error...")` arm sits in `verify_standard` waiting for a future
/// variant addition to silently make it reachable.
#[derive(Debug, Clone, Copy)]
enum NonHybridAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsa,
    FnDsa,
    Ed25519,
}

/// Dispatch shape for the verify-side step in `verify_legacy`.
///
/// The variant is chosen in Phase 1c (operator-side parsing) so that
/// hybrid pk-parse failures — which indicate a malformed operator key
/// file, NOT a tampered signature — surface as helpful `Err` at exit
/// ≥2 rather than collapsing into `print_invalid()`. By the time the
/// Phase-2 closure dispatches, the type system guarantees the right
/// pk shape for the chosen algorithm: `Standard` cannot carry
/// `Hybrid` (rejected by `NonHybridAlgorithm`) and `Hybrid` carries
/// the parsed pk directly.
///
/// # Field-name asymmetry: `pk_bytes` vs `pk`
///
/// The two variants intentionally name their pk field differently
/// because they hold different things at different stages of parsing:
/// `Standard` carries raw bytes that the per-algorithm crypto helper
/// will pass straight to the verify primitive (no operator-side parse
/// needed); `Hybrid` carries the already-parsed `HybridSigPublicKey`
/// because the hybrid wire format requires an operator-trusted
/// byte-layout parse that lives in Phase 1c — failure there must
/// bubble as helpful `Err`, not collapse to INVALID.
enum LegacyVerifier<'a> {
    Standard { algorithm: NonHybridAlgorithm, pk_bytes: &'a [u8] },
    Hybrid { pk: latticearc::hybrid::sig_hybrid::HybridSigPublicKey },
}

/// Project a `VerifyAlgorithm` onto its non-hybrid sub-domain. The
/// `Hybrid` variant has no representation in `NonHybridAlgorithm` and
/// produces `Err(())`; the caller (`verify_legacy` Phase 1c) routes
/// that case to `LegacyVerifier::Hybrid` after parsing the operator
/// pk. Implemented as `TryFrom` rather than a hand-named constructor
/// to align with the standard library projection-conversion idiom.
impl TryFrom<VerifyAlgorithm> for NonHybridAlgorithm {
    type Error = ();

    fn try_from(alg: VerifyAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            VerifyAlgorithm::MlDsa44 => Ok(Self::MlDsa44),
            VerifyAlgorithm::MlDsa65 => Ok(Self::MlDsa65),
            VerifyAlgorithm::MlDsa87 => Ok(Self::MlDsa87),
            VerifyAlgorithm::SlhDsa => Ok(Self::SlhDsa),
            VerifyAlgorithm::FnDsa => Ok(Self::FnDsa),
            VerifyAlgorithm::Ed25519 => Ok(Self::Ed25519),
            VerifyAlgorithm::Hybrid => Err(()),
        }
    }
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
    let key_file = read_operator_public_key_file(key_path)?;
    let pk_bytes = key_file.key_bytes()?;

    // ── Phase 1b: operator-picked algorithm vs key (helpful err) ──
    if let Some(cli_alg) = args.algorithm {
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
    let algorithm = if let Some(alg) = args.algorithm {
        alg
    } else {
        let Some(detected) = detect_algorithm(sig_json) else {
            tracing::debug!("verify (legacy auto-detect) rejected: algorithm undetectable");
            return Ok(print_invalid());
        };
        tracing::debug!(
            algorithm = %algorithm_name(detected),
            "auto-detected legacy verify algorithm"
        );
        if let Err(e) = key_file.validate_algorithm(algorithm_name(detected)) {
            // `%e` Display, not `?e` Debug — see Phase 2 closure below
            // for the full rationale on attacker-content avoidance in
            // tracing output.
            tracing::debug!(error = %e, "verify (legacy auto-detect) rejected: alg mismatch");
            return Ok(print_invalid());
        }
        detected
    };

    let verifier = if let Ok(non_hybrid) = NonHybridAlgorithm::try_from(algorithm) {
        LegacyVerifier::Standard { algorithm: non_hybrid, pk_bytes: &pk_bytes }
    } else {
        // Algorithm was Hybrid (the only `Err`-returning case).
        // pk parse failure here is operator-side (their key file is
        // malformed) — bubble as helpful Err.
        let pk = crate::keyfile::parse_hybrid_sign_pk_from_bytes(&pk_bytes)?;
        LegacyVerifier::Hybrid { pk }
    };

    // ── Phase 2: signature-side verify (returns plain `bool`) ──
    //
    // `verify_standard` and `verify_hybrid` both return `bool` directly
    // (NOT `Result<bool>`): any error inside them — JSON parse, missing
    // field, base64 decode, crypto reject — collapses internally to
    // `false` with a `%e` Display debug-log. The `-> bool` return type
    // is structural: a future maintainer who tries to bubble an
    // operator-side error from these functions gets a compile error,
    // which prevents accidentally widening the Phase-2 collapse to
    // swallow operator state.
    let valid = match &verifier {
        LegacyVerifier::Hybrid { pk } => verify_hybrid(&data, sig_json, pk),
        LegacyVerifier::Standard { algorithm, pk_bytes } => {
            verify_standard(&data, sig_json, pk_bytes, *algorithm)
        }
    };

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
fn algorithm_name(alg: VerifyAlgorithm) -> &'static str {
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
/// Returns a plain `bool` — never `Err`. All signature-side errors
/// (JSON parse, missing fields, base64 decode, crypto reject from a
/// `latticearc::verify_*` helper) collapse internally to `false` with
/// the underlying cause debug-logged via `%e` (Display only — see
/// `print_invalid()` SECURITY contract).
///
/// The `-> bool` return type is structural enforcement of the
/// Phase-2 contract: a future maintainer who tries to bubble an
/// operator-side error (e.g. by adding a `?` on a non-signature-side
/// fallible call) gets a compile error rather than silently widening
/// the closure-collapse to swallow operator state.
///
/// Do NOT re-flatten errors per arm with `.map_err(|_| anyhow!("..."))`
/// — a per-arm message becomes its own Pattern-6 distinguisher. Let
/// errors propagate raw to the inner closure boundary; the function-
/// level `unwrap_or_else` handles indistinguishability uniformly.
fn verify_standard(
    data: &[u8],
    sig_json: &str,
    pk_bytes: &[u8],
    algorithm: NonHybridAlgorithm,
) -> bool {
    (|| -> Result<bool> {
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

        // Exhaustive over `NonHybridAlgorithm`. If a new variant is
        // added there, this match becomes a compile error rather than
        // a hidden unreachable arm.
        let valid = match algorithm {
            NonHybridAlgorithm::MlDsa65 => latticearc::verify_pq_ml_dsa(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa65,
                latticearc::SecurityMode::Unverified,
            )?,
            NonHybridAlgorithm::MlDsa44 => latticearc::verify_pq_ml_dsa(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa44,
                latticearc::SecurityMode::Unverified,
            )?,
            NonHybridAlgorithm::MlDsa87 => latticearc::verify_pq_ml_dsa(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::primitives::sig::ml_dsa::MlDsaParameterSet::MlDsa87,
                latticearc::SecurityMode::Unverified,
            )?,
            NonHybridAlgorithm::SlhDsa => latticearc::verify_pq_slh_dsa(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::primitives::sig::slh_dsa::SlhDsaSecurityLevel::Shake128s,
                latticearc::SecurityMode::Unverified,
            )?,
            NonHybridAlgorithm::FnDsa => latticearc::verify_pq_fn_dsa(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::primitives::sig::fndsa::FnDsaSecurityLevel::Level512,
                latticearc::SecurityMode::Unverified,
            )?,
            NonHybridAlgorithm::Ed25519 => latticearc::verify_ed25519(
                data,
                &sig_bytes,
                pk_bytes,
                latticearc::SecurityMode::Unverified,
            )?,
        };
        Ok(valid)
    })()
    .unwrap_or_else(|e| {
        tracing::debug!(error = %e, "verify (legacy standard path) rejected");
        false
    })
}

/// Verify a hybrid legacy signature against a parsed hybrid public key.
///
/// Returns a plain `bool` — never `Err`. All signature-side errors
/// (JSON parse, missing fields, base64 decode, crypto reject)
/// collapse internally to `false` with a `%e` Display debug-log.
/// Same `-> bool` structural enforcement as `verify_standard`: a
/// future maintainer cannot bubble an operator-side error out of
/// this function and accidentally widen the Phase-2 collapse.
///
/// The pk is parsed by the caller (`verify_legacy` Phase 1c) so that
/// pk-parse failures — which indicate a malformed *operator* key file
/// — surface as helpful `Err` at exit ≥2 there, not collapse into
/// INVALID here.
fn verify_hybrid(
    data: &[u8],
    sig_json: &str,
    pk: &latticearc::hybrid::sig_hybrid::HybridSigPublicKey,
) -> bool {
    (|| -> Result<bool> {
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

        let hybrid_sig =
            latticearc::hybrid::sig_hybrid::HybridSignature::new(ml_dsa_sig, ed25519_sig);

        // CoreError::VerificationFailed is a routine cryptographic
        // reject (`Ok(false)`-equivalent). Any other CoreError variant
        // is propagated as anyhow::Error::new(e) — the typed source
        // survives for `%e` Display, which on CoreError gives a fixed
        // variant message without attacker-controlled interpolation.
        // A structured upstream error like "ML-DSA component verify
        // failed" vs "Ed25519 component verify failed" would otherwise
        // tell an attacker which half of the hybrid pair rejected.
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
    })()
    .unwrap_or_else(|e| {
        tracing::debug!(error = %e, "verify (legacy hybrid path) rejected");
        false
    })
}
