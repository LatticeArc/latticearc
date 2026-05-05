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
    /// PBKDF2 (SP 800-132). Requires --salt and --iterations. PRF
    /// configurable via --prf (default hmac-sha256).
    Pbkdf2,
}

/// PBKDF2 PRF choice. Round-26 audit fix (H14).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum PbkdfPrf {
    /// HMAC-SHA256 (OWASP 2023 floor: 600,000 iterations).
    HmacSha256,
    /// HMAC-SHA512 (OWASP 2023 floor: 210,000 iterations).
    HmacSha512,
}

impl PbkdfPrf {
    fn to_lib(self) -> latticearc::primitives::kdf::PrfType {
        match self {
            Self::HmacSha256 => latticearc::primitives::kdf::PrfType::HmacSha256,
            Self::HmacSha512 => latticearc::primitives::kdf::PrfType::HmacSha512,
        }
    }

    /// OWASP 2023 minimum iteration count for this PRF. Delegates to
    /// the library's canonical `Pbkdf2Params::min_iterations` so the
    /// CLI and library stay in lockstep on the per-PRF floor.
    fn min_iterations(self) -> u32 {
        latticearc::primitives::kdf::Pbkdf2Params::min_iterations(self.to_lib())
    }
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
    /// for HMAC-SHA256). Values below the per-PRF OWASP floor are
    /// rejected unless `--allow-weak-iterations` is also passed.
    /// Per-PRF floors: HMAC-SHA256 → 600,000; HMAC-SHA512 → 210,000.
    #[arg(long, default_value = "600000")]
    pub iterations: u32,
    /// PRF for PBKDF2 (default: hmac-sha256). Round-26 audit fix (H14).
    /// HMAC-SHA512 was reachable from the library API but unreachable
    /// from the CLI before this flag.
    #[arg(long, value_enum, default_value = "hmac-sha256")]
    pub prf: PbkdfPrf,
    /// Bypass the OWASP-2023 PBKDF2 iteration floor (600,000). Reserved
    /// for KAT replay and reproducibility against legacy fixtures.
    /// Production use is unsupported.
    #[arg(long)]
    pub allow_weak_iterations: bool,
    /// Allow `--input <secret>` with `--algorithm pbkdf2`. Reserved for
    /// KAT replay and reproducibility — production use is unsupported
    /// because argv-passed secrets are visible to `ps`, kernel audit
    /// logs, and shell history.
    #[arg(long)]
    pub allow_argv_secret: bool,
    /// Output format: hex (default) or base64.
    #[arg(short, long, default_value = "hex")]
    pub format: super::hash::OutputFormat,
}

/// Execute the kdf command.
pub(crate) fn run(args: KdfArgs) -> Result<()> {
    if args.salt.is_empty() {
        bail!(
            "--salt must not be empty. PBKDF2 requires ≥16 bytes (NIST SP 800-132 §5.1); \
             HKDF accepts an empty salt but a fixed application-specific salt is preferred."
        );
    }
    let salt = hex::decode(&args.salt).context("Invalid hex in --salt")?;
    // the previous version's error message
    // claimed "PBKDF2 requires ≥16 bytes" but only `is_empty()` was
    // checked. A 1-byte salt (`--salt aa`) silently passed. Enforce
    // the SP 800-132 §5.1 minimum here for PBKDF2 — HKDF tolerates
    // shorter salts but the CLI surface is shared, so apply the
    // tighter rule.
    if matches!(args.algorithm, KdfAlgorithm::Pbkdf2) && salt.len() < 16 {
        bail!(
            "--salt is {} byte(s); PBKDF2 requires ≥16 bytes (NIST SP 800-132 §5.1).",
            salt.len()
        );
    }

    // PBKDF2 with `--input` puts the password on argv (visible in `ps`,
    // `/proc/<pid>/cmdline`, shell history). The `--input` flag's docstring
    // calls this out, but argv routing is not algorithm-aware in clap, so
    // a user can still combine `--algorithm pbkdf2 --input <password>`
    // without the warning binding. Reject unless explicitly opted in via
    // `--allow-argv-secret` (KAT replay only).
    if matches!(args.algorithm, KdfAlgorithm::Pbkdf2)
        && args.input.is_some()
        && !args.allow_argv_secret
    {
        bail!(
            "Refusing to read a PBKDF2 password from --input because the value is visible in \
             `ps`, `/proc/<pid>/cmdline`, and shell history. Use --input-stdin (recommended) \
             or LATTICEARC_KDF_INPUT. Pass --allow-argv-secret to bypass for KAT replay only."
        );
    }

    let resolved_input = resolve_input(&args)?;

    let derived = match args.algorithm {
        KdfAlgorithm::Hkdf => derive_hkdf_with_input(&args, &salt, &resolved_input)?,
        KdfAlgorithm::Pbkdf2 => derive_pbkdf2_with_input(&args, &salt, &resolved_input)?,
    };

    // Encoded output stays in `Zeroizing<String>` so password-derived key
    // material can't linger on the heap until allocator reclaim.
    let encoded: zeroize::Zeroizing<String> = match args.format {
        super::hash::OutputFormat::Hex => zeroize::Zeroizing::new(hex::encode(derived.as_slice())),
        super::hash::OutputFormat::Base64 => {
            use base64::Engine;
            zeroize::Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode(derived.as_slice()),
            )
        }
    };

    // TTY guard mirrors `commands/decrypt.rs` —
    // derived key bytes shouldn't land in interactive scrollback by
    // default. `print!` (no trailing newline) matches the
    // length-bound the user sees in scripts; the warning is on stderr
    // so pipelines aren't polluted.
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        eprintln!(
            "warning: derived KDF output is being written to a TTY. \
             Pipe stdout to a file or downstream tool to avoid leaving \
             key material in shell scrollback."
        );
    }
    print!("{}", encoded.as_str());
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
        use std::io::Read;
        // Cap the read at 1 MiB. `read_line` is unbounded by default —
        // piping `/dev/urandom` would OOM the process. Other CLI input
        // paths route through `read_file_with_cap` /
        // `read_stdin_with_limit`; mirror that discipline here.
        const KDF_INPUT_MAX: u64 = 1024 * 1024;
        let mut buf_bytes = Vec::new();
        let mut limited = std::io::stdin().take(KDF_INPUT_MAX.saturating_add(1));
        limited.read_to_end(&mut buf_bytes).context("Failed to read --input-stdin")?;
        if buf_bytes.len() as u64 > KDF_INPUT_MAX {
            bail!(
                "--input-stdin exceeded {} bytes; refusing to derive a KDF input from an unbounded stream",
                KDF_INPUT_MAX
            );
        }
        let mut buf =
            String::from_utf8(buf_bytes).context("--input-stdin contains invalid UTF-8")?;
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
        // emit a TTY warning when the env-var
        // path is used. Env vars are visible via `/proc/<pid>/environ`
        // for any process the user can read (typically the same UID).
        // `keyfile.rs::resolve_passphrase` already warns for the
        // analogous LATTICEARC_PASSPHRASE; the kdf path was missing
        // the parallel warning.
        // Mirrors `keyfile.rs::resolve_passphrase`: emit a tracing
        // warning on EVERY env-var read (so audit pipelines that
        // scrape `warn` events see every use), and additionally
        // print to stderr on a TTY so an interactive operator gets
        // immediate visible feedback even with no tracing
        // subscriber wired up.
        use std::io::IsTerminal;
        let is_tty = std::io::stdin().is_terminal();
        if is_tty {
            eprintln!(
                "warning: reading KDF input from LATTICEARC_KDF_INPUT. \
                 Env vars are readable via /proc/<pid>/environ by processes \
                 owned by the same user. Prefer --input-stdin for genuinely \
                 secret input, and `unset LATTICEARC_KDF_INPUT` immediately \
                 after this invocation."
            );
            tracing::warn!(
                tty = true,
                "LATTICEARC_KDF_INPUT used on interactive TTY (likely accidental)"
            );
        } else {
            tracing::warn!(
                tty = false,
                "LATTICEARC_KDF_INPUT used non-interactively; ensure the \
                 wrapping script unsets it immediately after the command \
                 exits"
            );
        }
        return Ok(zeroize::Zeroizing::new(env_val));
    }
    bail!(
        "kdf requires one of: --input <value>, --input-stdin, or \
         LATTICEARC_KDF_INPUT in the environment. For PBKDF2 passwords, \
         prefer --input-stdin so the password is not visible in `ps` / \
         `/proc/<pid>/cmdline` / shell history. Recommended pattern:\n\
         \n\
            read -rs PASS && printf '%s' \"$PASS\" | latticearc-cli kdf --input-stdin …\n\
         \n\
         `read -rs` reads silently into a shell variable, and `printf '%s'` \
         pipes the value without writing it to the shell history."
    )
}

/// Upper bound on KDF output length applied by the CLI to both HKDF and
/// PBKDF2. Set to HKDF-SHA256's algorithmic maximum (255 × 32 = 8160
/// bytes) so the same constant is correct for both algorithms — PBKDF2
/// has no algorithmic ceiling but allowing arbitrary `--length` is a
/// trivial self-DoS (e.g. `--length 1073741824` allocates 1 GiB and
/// then runs 600k iterations per block).
///
/// previously this constant was 8192 and used
/// only by the PBKDF2 path; HKDF independently hardcoded 8160 in its
/// `bail!` check. The constants silently desynced. Both paths now
/// reference this single source of truth.
const CLI_MAX_KDF_OUTPUT_LEN: usize = 8160;

fn derive_hkdf_with_input(
    args: &KdfArgs,
    salt: &[u8],
    input: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let ikm =
        zeroize::Zeroizing::new(hex::decode(input).context("Invalid hex in --input for HKDF")?);
    let info = args.info.as_deref().unwrap_or("");

    if args.length == 0 || args.length > CLI_MAX_KDF_OUTPUT_LEN {
        bail!("Output length must be 1..={CLI_MAX_KDF_OUTPUT_LEN} bytes");
    }

    let derived = latticearc::derive_key_with_info(
        &ikm,
        salt,
        args.length,
        info.as_bytes(),
        latticearc::SecurityMode::Unverified,
    )
    .map_err(|e| anyhow::anyhow!("HKDF derivation failed: {e}"))?;
    // `derive_key_with_info` now returns Zeroizing<Vec<u8>> directly.
    Ok(derived)
}

// the previous hardcoded
// `OWASP_PBKDF2_MIN_ITERATIONS = 600_000` was the floor for HMAC-SHA256
// only, regardless of the PRF actually selected. The CLI now looks up
// the per-PRF floor via `PbkdfPrf::min_iterations()` so HMAC-SHA512
// callers get the correct 210,000 floor.

fn derive_pbkdf2_with_input(
    args: &KdfArgs,
    salt: &[u8],
    input: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let password = zeroize::Zeroizing::new(input.as_bytes().to_vec());

    if args.length == 0 || args.length > CLI_MAX_KDF_OUTPUT_LEN {
        bail!(
            "Output length must be 1..={CLI_MAX_KDF_OUTPUT_LEN} bytes (PBKDF2 has no \
             algorithmic ceiling but the CLI caps to prevent self-DoS)."
        );
    }

    let owasp_min = args.prf.min_iterations();
    if args.iterations < owasp_min && !args.allow_weak_iterations {
        bail!(
            "PBKDF2 iteration count {iters} is below the OWASP 2023 minimum of {min} \
             for the selected PRF ({prf:?}). Pass --allow-weak-iterations to bypass \
             (KAT replay only — not for production).",
            iters = args.iterations,
            min = owasp_min,
            prf = args.prf,
        );
    }
    if args.iterations < owasp_min {
        // emit BOTH eprintln! (so an interactive operator
        // sees the warning even with no tracing subscriber configured)
        // AND tracing::warn! (so audit-log pipelines that scrape `warn`
        // events from JSON-formatted tracing output capture it). Stderr
        // alone is lost when the CLI is invoked from a script that
        // redirects 2>/dev/null; tracing alone is silent on a default
        // CLI install with no subscriber. Both is the safe default.
        eprintln!(
            "warning: PBKDF2 iteration count {iters} is below the OWASP 2023 \
             minimum ({min}) for {prf:?}; --allow-weak-iterations was passed.",
            iters = args.iterations,
            min = owasp_min,
            prf = args.prf,
        );
        tracing::warn!(
            iterations = args.iterations,
            owasp_minimum = owasp_min,
            prf = ?args.prf,
            "PBKDF2 iteration count below OWASP 2023 minimum; --allow-weak-iterations bypassed"
        );
    }

    let params = latticearc::primitives::kdf::Pbkdf2Params::with_salt(salt)
        .iterations(args.iterations)
        .key_length(args.length)
        .prf(args.prf.to_lib());

    // The library `pbkdf2()` rejects iteration counts below the per-PRF
    // OWASP 2023 floor (600 k for HMAC-SHA256, 210 k for HMAC-SHA512)
    // — that's the right policy for typical callers. The CLI's
    // `--allow-weak-iterations` flag exists specifically for KAT
    // replay, where lower counts are required to match published test
    // vectors (RFC 6070 uses iterations as low as 1). When the flag
    // is set, we route through `pbkdf2_kat` so the legitimate KAT
    // path actually works; the operator already saw the
    // "KAT replay only — not for production" warning above.
    let result = if args.allow_weak_iterations && args.iterations < owasp_min {
        latticearc::primitives::kdf::pbkdf2_kat(&password, &params)
            .map_err(|e| anyhow::anyhow!("PBKDF2 derivation failed: {e}"))?
    } else {
        latticearc::primitives::kdf::pbkdf2(&password, &params)
            .map_err(|e| anyhow::anyhow!("PBKDF2 derivation failed: {e}"))?
    };

    Ok(zeroize::Zeroizing::new(result.expose_secret().to_vec()))
}
