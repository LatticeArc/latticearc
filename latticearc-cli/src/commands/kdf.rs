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
    ///
    /// **SECURITY:** Passing a password as a CLI argument is visible in
    /// `ps`, `/proc/<pid>/cmdline`, shell history, and kernel audit
    /// logs. For PBKDF2 use cases, prefer one of:
    /// - Read from `LATTICEARC_KDF_INPUT` env var (set then `unset`).
    /// - Pipe the password on stdin and pass `--input-stdin`.
    ///
    /// `--input` is supported for HKDF (where the input is hex-encoded
    /// non-secret material) and for backwards-compat with KAT replay
    /// scripts.
    #[arg(short, long, conflicts_with = "input_stdin")]
    pub input: Option<String>,
    /// Read the input from stdin (one line, no trailing newline). Use
    /// instead of `--input` when the input is a secret (PBKDF2
    /// password) and you don't want it in `ps` / shell history.
    #[arg(long, conflicts_with = "input")]
    pub input_stdin: bool,
    /// Salt (hex-encoded).
    #[arg(short, long)]
    pub salt: String,
    /// Output key length in bytes.
    #[arg(short, long, default_value = "32")]
    pub length: usize,
    /// Info string for HKDF (optional).
    #[arg(long)]
    pub info: Option<String>,
    /// Iteration count for PBKDF2 (default 600000, OWASP 2023 minimum
    /// for HMAC-SHA256). Values below 600,000 are rejected unless
    /// `--allow-weak-iterations` is also passed.
    #[arg(long, default_value = "600000")]
    pub iterations: u32,
    /// Bypass the OWASP-2023 PBKDF2 iteration floor (600,000). Reserved
    /// for KAT replay and reproducibility against legacy fixtures.
    /// Production use is unsupported.
    #[arg(long)]
    pub allow_weak_iterations: bool,
    /// Output format: hex (default) or base64.
    #[arg(short, long, default_value = "hex")]
    pub format: super::hash::OutputFormat,
}

/// Execute the kdf command.
pub(crate) fn run(args: KdfArgs) -> Result<()> {
    let salt = hex::decode(&args.salt).context("Invalid hex in --salt")?;

    let resolved_input = resolve_input(&args)?;

    let derived = match args.algorithm {
        KdfAlgorithm::Hkdf => derive_hkdf_with_input(&args, &salt, &resolved_input)?,
        KdfAlgorithm::Pbkdf2 => derive_pbkdf2_with_input(&args, &salt, &resolved_input)?,
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

/// Resolve the input string from one of:
/// - `--input <value>` (CLI argument; visible in `ps`/history — flagged
///   in the arg's docstring and acceptable for HKDF / KAT replay).
/// - `--input-stdin` (read one line from stdin, no trailing newline;
///   the recommended path for PBKDF2 passwords).
/// - `LATTICEARC_KDF_INPUT` env var (recommended for scripted PBKDF2;
///   caller must `unset` immediately afterwards — see SECURITY.md).
///
/// Exactly one source must be provided. The result is `Zeroizing` so
/// password material is wiped at function exit.
///
/// # Precedence intentionally differs from `keyfile::resolve_passphrase`
///
/// `keyfile::resolve_passphrase` checks `LATTICEARC_PASSPHRASE` FIRST
/// (env > prompt). Here we check `--input` first, then `--input-stdin`,
/// then the env var. The asymmetry is intentional, not a bug:
///
/// - Passphrase: there is only ONE possible explicit source (the prompt
///   — there's no `--passphrase <value>` flag, deliberately, because
///   that would put the secret on the command line). The env var is
///   THE escape hatch for non-interactive use, so env-first is right.
/// - KDF input: there are THREE possible explicit sources, and CLI
///   ergonomics demand that an explicit `--input` or `--input-stdin`
///   take precedence over a stale env var that may have leaked in from
///   a parent shell. Otherwise `LATTICEARC_KDF_INPUT=foo
///   latticearc-cli kdf --input bar …` would silently use `foo`.
///
/// Round-8 audit fix #7 requires this justification be inline.
fn resolve_input(args: &KdfArgs) -> Result<zeroize::Zeroizing<String>> {
    if let Some(s) = args.input.as_deref() {
        return Ok(zeroize::Zeroizing::new(s.to_string()));
    }
    if args.input_stdin {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut buf = String::new();
        stdin.lock().read_line(&mut buf).context("Failed to read --input-stdin")?;
        // Strip a single trailing newline (LF or CRLF) — common when
        // the user does `echo password | latticearc-cli kdf …`.
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        if buf.is_empty() {
            bail!("--input-stdin received an empty line");
        }
        return Ok(zeroize::Zeroizing::new(buf));
    }
    if let Ok(env_val) = std::env::var("LATTICEARC_KDF_INPUT") {
        if env_val.is_empty() {
            bail!("LATTICEARC_KDF_INPUT is set but empty");
        }
        return Ok(zeroize::Zeroizing::new(env_val));
    }
    bail!(
        "kdf requires one of: --input <value>, --input-stdin, or \
         LATTICEARC_KDF_INPUT in the environment. For PBKDF2 passwords, \
         prefer --input-stdin (`echo $PASS | latticearc-cli kdf --input-stdin …`) \
         so the password isn't visible in `ps` / shell history."
    )
}

fn derive_hkdf_with_input(args: &KdfArgs, salt: &[u8], input: &str) -> Result<Vec<u8>> {
    let ikm =
        zeroize::Zeroizing::new(hex::decode(input).context("Invalid hex in --input for HKDF")?);
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

/// OWASP 2023 minimum iteration count for PBKDF2-HMAC-SHA256.
/// Library `pbkdf2()` already enforces a hard floor of 1,000 (the
/// SP 800-132 absolute minimum); the CLI raises that to the OWASP
/// recommendation as the public-facing default to reflect the
/// password-hashing use case the CLI targets.
const OWASP_PBKDF2_MIN_ITERATIONS: u32 = 600_000;

fn derive_pbkdf2_with_input(args: &KdfArgs, salt: &[u8], input: &str) -> Result<Vec<u8>> {
    let password = zeroize::Zeroizing::new(input.as_bytes().to_vec());

    if args.length == 0 {
        bail!("Output length must be > 0");
    }

    if args.iterations < OWASP_PBKDF2_MIN_ITERATIONS && !args.allow_weak_iterations {
        bail!(
            "PBKDF2 iteration count {iters} is below the OWASP 2023 minimum of {min}. \
             Pass --allow-weak-iterations to bypass (KAT replay only — not for production).",
            iters = args.iterations,
            min = OWASP_PBKDF2_MIN_ITERATIONS
        );
    }
    if args.iterations < OWASP_PBKDF2_MIN_ITERATIONS {
        eprintln!(
            "warning: PBKDF2 iteration count {iters} is below the OWASP 2023 \
             minimum ({min}); --allow-weak-iterations was passed.",
            iters = args.iterations,
            min = OWASP_PBKDF2_MIN_ITERATIONS
        );
    }

    let params = latticearc::primitives::kdf::Pbkdf2Params::with_salt(salt)
        .iterations(args.iterations)
        .key_length(args.length);

    let result = latticearc::primitives::kdf::pbkdf2(&password, &params)
        .map_err(|e| anyhow::anyhow!("PBKDF2 derivation failed: {e}"))?;

    Ok(result.key().to_vec())
}
