//! Shared CLI types for use-case-driven operations.
//!
//! Maps CLI string values directly to library enums — no wrapper types.
//! The library's `UseCase`, `SecurityLevel`, and `ComplianceMode` are used
//! directly in clap args via custom `value_parser` functions.

use latticearc::types::types::{ComplianceMode, SecurityLevel, UseCase};

/// All valid use case CLI values. Single source of truth for help text and parsing.
const USE_CASES: &[(&str, UseCase)] = &[
    ("secure-messaging", UseCase::SecureMessaging),
    ("email-encryption", UseCase::EmailEncryption),
    ("vpn-tunnel", UseCase::VpnTunnel),
    ("api-security", UseCase::ApiSecurity),
    ("file-storage", UseCase::FileStorage),
    ("database-encryption", UseCase::DatabaseEncryption),
    ("cloud-storage", UseCase::CloudStorage),
    ("backup-archive", UseCase::BackupArchive),
    ("config-secrets", UseCase::ConfigSecrets),
    ("authentication", UseCase::Authentication),
    ("session-token", UseCase::SessionToken),
    ("digital-certificate", UseCase::DigitalCertificate),
    ("key-exchange", UseCase::KeyExchange),
    ("financial-transactions", UseCase::FinancialTransactions),
    ("legal-documents", UseCase::LegalDocuments),
    ("blockchain-transaction", UseCase::BlockchainTransaction),
    ("healthcare-records", UseCase::HealthcareRecords),
    ("government-classified", UseCase::GovernmentClassified),
    ("payment-card", UseCase::PaymentCard),
    ("iot-device", UseCase::IoTDevice),
    ("firmware-signing", UseCase::FirmwareSigning),
    ("audit-log", UseCase::AuditLog),
];

const SECURITY_LEVELS: &[(&str, SecurityLevel)] = &[
    ("standard", SecurityLevel::Standard),
    ("high", SecurityLevel::High),
    ("maximum", SecurityLevel::Maximum),
];

const COMPLIANCE_MODES: &[(&str, ComplianceMode)] = &[
    ("default", ComplianceMode::Default),
    ("fips", ComplianceMode::Fips140_3),
    ("cnsa-2.0", ComplianceMode::Cnsa2_0),
];

/// Parse a use case from a CLI string.
pub(crate) fn parse_use_case(s: &str) -> Result<UseCase, String> {
    USE_CASES.iter().find(|(name, _)| *name == s).map(|(_, uc)| *uc).ok_or_else(|| {
        let valid: Vec<&str> = USE_CASES.iter().map(|(n, _)| *n).collect();
        format!("Unknown use case '{s}'. Valid values:\n  {}", valid.join(", "))
    })
}

/// Parse a security level from a CLI string.
pub(crate) fn parse_security_level(s: &str) -> Result<SecurityLevel, String> {
    SECURITY_LEVELS.iter().find(|(name, _)| *name == s).map(|(_, sl)| *sl).ok_or_else(|| {
        let valid: Vec<&str> = SECURITY_LEVELS.iter().map(|(n, _)| *n).collect();
        format!("Unknown security level '{s}'. Valid: {}", valid.join(", "))
    })
}

/// Parse a compliance mode from a CLI string.
pub(crate) fn parse_compliance(s: &str) -> Result<ComplianceMode, String> {
    COMPLIANCE_MODES.iter().find(|(name, _)| *name == s).map(|(_, cm)| cm.clone()).ok_or_else(
        || {
            let valid: Vec<&str> = COMPLIANCE_MODES.iter().map(|(n, _)| *n).collect();
            format!("Unknown compliance mode '{s}'. Valid: {}", valid.join(", "))
        },
    )
}

/// Resolve ML-KEM security level from a key file's algorithm.
///
/// Maps `KeyAlgorithm::MlKem512/768/1024` to the corresponding `MlKemSecurityLevel`.
/// Returns an error for non-ML-KEM algorithms.
pub(crate) fn resolve_ml_kem_level(
    algorithm: latticearc::unified_api::key_format::KeyAlgorithm,
) -> Result<latticearc::primitives::kem::ml_kem::MlKemSecurityLevel, String> {
    use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
    use latticearc::unified_api::key_format::KeyAlgorithm;
    match algorithm {
        KeyAlgorithm::MlKem512 => Ok(MlKemSecurityLevel::MlKem512),
        KeyAlgorithm::MlKem768 => Ok(MlKemSecurityLevel::MlKem768),
        KeyAlgorithm::MlKem1024 => Ok(MlKemSecurityLevel::MlKem1024),
        _ => Err(format!(
            "PQ-only operation requires an ML-KEM key (ml-kem512/768/1024), got {}",
            algorithm.canonical_name()
        )),
    }
}

/// Map ML-KEM security level to the corresponding `SecurityLevel`.
///
/// Delegates to the library's canonical mapping in the policy engine.
pub(crate) fn ml_kem_to_security_level(
    level: latticearc::primitives::kem::ml_kem::MlKemSecurityLevel,
) -> SecurityLevel {
    latticearc::unified_api::selector::ml_kem_level_to_security_level(level)
}

/// Build a `CryptoConfig` from optional CLI values.
pub(crate) fn build_config<'a>(
    use_case: Option<UseCase>,
    security_level: Option<SecurityLevel>,
    compliance: &Option<ComplianceMode>,
) -> latticearc::CryptoConfig<'a> {
    let mut config = latticearc::CryptoConfig::new();

    if let Some(uc) = use_case {
        config = config.use_case(uc);
    }

    if let Some(sl) = security_level {
        config = config.security_level(sl);
    }

    if let Some(cm) = compliance {
        config = config.compliance(cm.clone());
    }

    config
}

/// Maximum input size for symmetric / KEM-bound encrypt commands. Matches
/// `latticearc::primitives::resource_limits` defaults (100 MiB plaintext).
pub(crate) const CLI_MAX_ENCRYPTION_INPUT_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum input size for decrypt commands. Decrypt reads a JSON envelope
/// containing the ciphertext (base64-encoded), so the wire size can be ~1.5x
/// the plaintext limit. Cap at 200 MiB to give the library room to enforce
/// its 100 MiB plaintext limit on the decoded bytes.
pub(crate) const CLI_MAX_DECRYPTION_INPUT_BYTES: u64 = 200 * 1024 * 1024;

/// Maximum input size for sign / verify commands.
///
/// The CLI pre-check exists purely for OOM protection — it is NOT a duplicate
/// of the library's semantic limits. The library's unified `sign_with_key`
/// path independently enforces its own `validate_signature_size` bound (64
/// KiB by default), while legacy primitive paths (`sign_ed25519`,
/// `sign_pq_ml_dsa`, etc.) accept arbitrarily large inputs. The CLI aligns
/// with the encryption limit so that any legitimate operation succeeds and
/// only truly runaway inputs are blocked at the CLI boundary.
pub(crate) const CLI_MAX_SIGNATURE_INPUT_BYTES: u64 = 100 * 1024 * 1024;

/// Maximum input size for hash commands. Hashing has no library-level limit,
/// but a 1 GiB ceiling protects against accidental OOM if the user pipes
/// `/dev/urandom` or a multi-gigabyte file. Adjust if you need to hash
/// larger blobs (use streaming instead).
pub(crate) const CLI_MAX_HASH_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// read a file with a hard size cap by opening
/// once and using a `Take` adapter. A previous stat-then-open shape
/// (`metadata().len()` + `std::fs::read`) was unsafe because
/// `metadata().len()` returns 0 for `/dev/zero`, FIFOs, `/proc/*`,
/// etc., letting the subsequent read consume unbounded bytes from
/// those special files; it was also a TOCTOU surface (same shape
/// was fixed in `keyfile.rs` separately). This open-once helper is
/// the single canonical entry point for capped CLI reads — used by
/// every command that takes a file path (encrypt / sign / hash /
/// verify / kdf).
///
/// this helper does not stat first, so the
/// previous "non-ENOENT silent bypass" failure mode is gone by
/// construction — `File::open` surfaces every error path uniformly.
///
/// Returns the file contents (≤ `limit_bytes`) or a user-facing error
/// referencing `operation`.
pub(crate) fn read_file_with_cap(
    path: &std::path::Path,
    limit_bytes: u64,
    operation: &str,
) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;
    use std::io::Read;
    // Symlink rejection mirrors `keyfile.rs::read_from`. A
    // predictable-path symlink in /tmp could otherwise exfiltrate an
    // arbitrary file via the AEAD/sign output. `LATTICEARC_ALLOW_SYMLINK_INPUT=1`
    // opts in (e.g., for callers who legitimately route through
    // `~/symlinks/foo`).
    let allow_symlinks = std::env::var("LATTICEARC_ALLOW_SYMLINK_INPUT")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    // M10: open with `O_NOFOLLOW` (when symlinks are
    // disallowed) so the symlink check happens atomically at open
    // time. The previous form did `symlink_metadata`
    // followed by a separate `File::open` — a swap on /tmp between
    // the two syscalls would defeat the guard. On Windows, the
    // `O_NOFOLLOW`-equivalent isn't standard; fall back to the stat
    // form (Windows /tmp races are less of a concern in practice
    // and the unix gate is the primary deployment target).
    // Hardcoded `O_NOFOLLOW` per target_os — the workspace deny.toml
    // bans `libc` and `nix` as direct deps, and pulling in `rustix`
    // for one constant is heavyweight. The values below are the
    // ABI-stable constants documented in each kernel's `fcntl.h`.
    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0o400000;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    const O_NOFOLLOW: i32 = 0x100;
    // ELOOP raw OS error code (40 on Linux/glibc, 62 on
    // macOS/BSD). `std::io::Error::raw_os_error()` exposes this
    // directly; we just need to know it.
    #[cfg(target_os = "linux")]
    const ELOOP: i32 = 40;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    const ELOOP: i32 = 62;

    let file = {
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            if !allow_symlinks {
                // O_NOFOLLOW: open() returns ELOOP if the final path
                // component is a symlink. Atomic with the open;
                // closes the prior L1 stat-then-open TOCTOU.
                opts.custom_flags(O_NOFOLLOW);
            }
            opts.open(path).map_err(|e| {
                if e.raw_os_error() == Some(ELOOP) && !allow_symlinks {
                    anyhow::anyhow!(
                        "Refusing to read input file {} because it is a symlink. \
                         Set LATTICEARC_ALLOW_SYMLINK_INPUT=1 to opt in (rare; only \
                         needed when the input path is intentionally indirected).",
                        path.display()
                    )
                } else {
                    anyhow::anyhow!("Failed to open {}: {e}", path.display())
                }
            })?
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        )))]
        {
            // Windows / unknown-unix fallback: stat-then-open with a
            // documented TOCTOU window. Primary deployment targets
            // are the Unix variants above where the atomic
            // `O_NOFOLLOW` path closes it.
            let symlink_meta = std::fs::symlink_metadata(path)
                .with_context(|| format!("Failed to stat {}", path.display()))?;
            if symlink_meta.file_type().is_symlink() && !allow_symlinks {
                anyhow::bail!(
                    "Refusing to read input file {} because it is a symlink. \
                     Set LATTICEARC_ALLOW_SYMLINK_INPUT=1 to opt in (rare; only \
                     needed when the input path is intentionally indirected).",
                    path.display()
                );
            }
            std::fs::File::open(path)
                .with_context(|| format!("Failed to open {}", path.display()))?
        }
    };
    let mut buf = Vec::new();
    let mut limited = file.take(limit_bytes.saturating_add(1));
    limited.read_to_end(&mut buf).with_context(|| format!("Failed to read {}", path.display()))?;
    if buf.len() as u64 > limit_bytes {
        anyhow::bail!(
            "Input from {} exceeded {limit_bytes} bytes; the {operation} command rejects \
             inputs larger than this. Split the file or use a streaming workflow.",
            path.display(),
        );
    }
    Ok(buf)
}

/// Read bytes from stdin, capped at `limit_bytes`.
///
/// Since stdin cannot be stat-ed, the cap is enforced by a bounded reader
/// (`take(limit + 1)`) so we can detect overflow by observing whether the
/// reader returned more than `limit_bytes`. Returns a user-facing error
/// mentioning `operation` on overflow.
pub(crate) fn read_stdin_with_limit(limit_bytes: u64, operation: &str) -> anyhow::Result<Vec<u8>> {
    use anyhow::Context;
    use std::io::Read;
    let mut buf = Vec::new();
    let mut limited = std::io::stdin().take(limit_bytes.saturating_add(1));
    limited.read_to_end(&mut buf).context("Failed to read from stdin")?;
    if buf.len() as u64 > limit_bytes {
        anyhow::bail!(
            "Stdin input exceeded {limit_bytes} bytes; the {operation} command rejects \
             inputs larger than this. Split the file or use a streaming workflow."
        );
    }
    Ok(buf)
}

/// Read input bytes from a file path or stdin (when `path` is `None`),
/// applying the same `limit_bytes` cap to both sources.
///
/// Centralises the duplicated `if let Some(path) = … else stdin`
/// pattern that previously lived in encrypt / decrypt / sign / verify /
/// hash.
///
/// # Errors
///
/// Returns the underlying I/O error or the size-cap rejection from
/// [`read_file_with_cap`] / [`read_stdin_with_limit`].
pub(crate) fn read_file_or_stdin(
    path: Option<&std::path::Path>,
    limit_bytes: u64,
    operation: &str,
) -> anyhow::Result<Vec<u8>> {
    if let Some(p) = path {
        // use the open-once `read_file_with_cap` helper rather than
        // any stat-then-read shape (`metadata().len()` returns 0 for
        // `/dev/zero`, FIFOs, and `/proc/*` — letting the subsequent
        // read consume unbounded bytes). This helper is used by
        // encrypt / sign / hash / verify --input, so the gap would
        // affect every CLI command that takes a file path.
        read_file_with_cap(p, limit_bytes, operation)
    } else {
        read_stdin_with_limit(limit_bytes, operation)
    }
}

/// Like [`read_file_or_stdin`] but returns a UTF-8 `String`. Used by
/// commands that operate on JSON envelopes (e.g. `decrypt` parses an
/// `EncryptedOutput` JSON envelope before any cryptographic work).
///
/// # Errors
///
/// Returns the underlying I/O error, the size-cap rejection, or a
/// UTF-8 validation error if the input is not valid UTF-8 text.
pub(crate) fn read_file_or_stdin_string(
    path: Option<&std::path::Path>,
    limit_bytes: u64,
    operation: &str,
) -> anyhow::Result<String> {
    use anyhow::Context;
    if let Some(p) = path {
        // same open-once pattern as
        // `read_file_or_stdin`. UTF-8 validation happens after the
        // capped read so a multi-gig non-UTF-8 file can't OOM the
        // process before the validity check.
        let bytes = read_file_with_cap(p, limit_bytes, operation)?;
        String::from_utf8(bytes).with_context(|| format!("{} is not valid UTF-8", p.display()))
    } else {
        read_stdin_string_with_limit(limit_bytes, operation)
    }
}

/// Read a UTF-8 string from stdin, capped at `limit_bytes`.
///
/// Used by commands that operate on JSON envelopes (decrypt, verify) where
/// the input must already be text.
pub(crate) fn read_stdin_string_with_limit(
    limit_bytes: u64,
    operation: &str,
) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::Read;
    let mut buf = String::new();
    let mut limited = std::io::stdin().take(limit_bytes.saturating_add(1));
    limited.read_to_string(&mut buf).context("Failed to read from stdin")?;
    if buf.len() as u64 > limit_bytes {
        anyhow::bail!(
            "Stdin input exceeded {limit_bytes} bytes; the {operation} command rejects \
             inputs larger than this. Split the file or use a streaming workflow."
        );
    }
    Ok(buf)
}

/// Infer a `SecurityLevel` from a key file's algorithm.
///
/// Used by `sign`/`verify` when the caller loads an existing key file and
/// hasn't explicitly chosen a scheme. The library's signature-scheme selector
/// maps `SecurityLevel::{Standard, High, Maximum}` to
/// `hybrid-ml-dsa-{44, 65, 87}-ed25519` respectively (see
/// `latticearc::unified_api::selector::SimpleSchemeSelector::select_signature_scheme`),
/// so passing the inferred level produces a config that will select the same
/// scheme the key was generated under.
///
/// Returns `None` for non-signing algorithms (KEMs, symmetric) — callers
/// should fall back to their own defaults or surface an error.
pub(crate) fn infer_signature_security_level(
    algorithm: latticearc::unified_api::key_format::KeyAlgorithm,
) -> Option<SecurityLevel> {
    use latticearc::unified_api::key_format::KeyAlgorithm;
    match algorithm {
        // Hybrid signing schemes — map to the security level the selector
        // resolves back to the same scheme.
        KeyAlgorithm::HybridMlDsa44Ed25519 => Some(SecurityLevel::Standard),
        KeyAlgorithm::HybridMlDsa65Ed25519 => Some(SecurityLevel::High),
        KeyAlgorithm::HybridMlDsa87Ed25519 => Some(SecurityLevel::Maximum),
        // PQ-only ML-DSA — security level is the same, but the caller MUST
        // also force PQ-only mode (see `infer_crypto_mode`). Otherwise the
        // default `CryptoMode::Hybrid` will resolve to a hybrid scheme and
        // reject the pure-PQ key as a length mismatch.
        KeyAlgorithm::MlDsa44 => Some(SecurityLevel::Standard),
        KeyAlgorithm::MlDsa65 => Some(SecurityLevel::High),
        KeyAlgorithm::MlDsa87 => Some(SecurityLevel::Maximum),
        _ => None,
    }
}

/// Infer the `CryptoMode` from a key file's algorithm.
///
/// Pure-PQ algorithms (ML-DSA-44/65/87) require `CryptoMode::PqOnly`;
/// hybrid algorithms (hybrid-ml-dsa-*-ed25519) require `CryptoMode::Hybrid`.
/// Returning the correct mode here prevents the library from trying to parse
/// a pure-PQ key as a hybrid key (or vice versa) and failing with a length
/// mismatch.
///
/// Returns `None` for non-signing algorithms — callers fall back to the
/// library default (hybrid).
pub(crate) fn infer_crypto_mode(
    algorithm: latticearc::unified_api::key_format::KeyAlgorithm,
) -> Option<latticearc::CryptoMode> {
    use latticearc::unified_api::key_format::KeyAlgorithm;
    match algorithm {
        KeyAlgorithm::HybridMlDsa44Ed25519
        | KeyAlgorithm::HybridMlDsa65Ed25519
        | KeyAlgorithm::HybridMlDsa87Ed25519 => Some(latticearc::CryptoMode::Hybrid),
        KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
            Some(latticearc::CryptoMode::PqOnly)
        }
        _ => None,
    }
}

/// Build a `CryptoConfig` for a sign/verify operation, filling in defaults
/// from the key file's algorithm when the user hasn't specified a scheme.
///
/// Precedence (highest wins):
///   1. Explicit `--use-case` or `--security-level`
///   2. Level inferred from the key file's algorithm
///   3. Library default
pub(crate) fn build_signing_config<'a>(
    use_case: Option<UseCase>,
    security_level: Option<SecurityLevel>,
    compliance: &Option<ComplianceMode>,
    key_algorithm: latticearc::unified_api::key_format::KeyAlgorithm,
) -> latticearc::CryptoConfig<'a> {
    let user_chose_scheme = use_case.is_some() || security_level.is_some();

    let effective_level = security_level.or_else(|| {
        if use_case.is_some() { None } else { infer_signature_security_level(key_algorithm) }
    });

    let mut config = build_config(use_case, effective_level, compliance);

    // Only infer mode when the user didn't pick a scheme explicitly — if they
    // did, respect their choice (they may want to coerce a key through a
    // different scheme for testing / migration).
    if !user_chose_scheme && let Some(mode) = infer_crypto_mode(key_algorithm) {
        config = config.crypto_mode(mode);
    }

    config
}
