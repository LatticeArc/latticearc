//! Encrypt command — authenticated encryption of files.
//!
//! Supports three encryption modes:
//!
//! - **AES-256-GCM** (SP 800-38D) — symmetric authenticated encryption using a
//!   shared 32-byte key. Provides confidentiality + integrity. Each encryption
//!   uses a random 12-byte nonce (never reused).
//! - **Hybrid** (ML-KEM-768 + X25519 + AES-256-GCM) — post-quantum hybrid
//!   encryption using a recipient's public key. Generates an ephemeral keypair
//!   internally.
//! - **PQ-only** (ML-KEM + AES-256-GCM) — pure post-quantum encryption without
//!   a classical (X25519) component. Required for CNSA 2.0 compliance.
//!
//! **Output format:** The encrypted data is written as a self-contained JSON file
//! containing the Base64-encoded ciphertext, nonce, and algorithm metadata. This
//! JSON format ensures the encrypted file can be stored, transmitted, and
//! decrypted without any external state.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use std::path::PathBuf;

use crate::keyfile::{KeyFile, KeyType};

/// True when the key file is a pure-PQ ML-KEM public key (no classical
/// X25519 component). Hybrid `HybridMlKem*X25519` PKs return false.
/// Used by both the use-case-driven path and the expert-mode inference
/// to route pure-PQ keys away from the hybrid splitter (which would
/// misinterpret the trailing bytes as X25519 and produce garbage
/// ciphertext). Single source of truth — round-26 simplify pass.
fn is_pq_only_key(key_file: &KeyFile) -> bool {
    use latticearc::unified_api::key_format::KeyAlgorithm;
    matches!(
        key_file.portable_key().algorithm(),
        KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024
    )
}

/// Encryption mode.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum EncryptMode {
    /// AES-256-GCM symmetric encryption (FIPS validated).
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric encryption (RFC 8439, non-FIPS).
    Chacha20Poly1305,
    /// Hybrid ML-KEM-768 + X25519 + AES-256-GCM (generates ephemeral keypair).
    Hybrid,
    /// PQ-only ML-KEM + AES-256-GCM (no classical component, CNSA 2.0).
    PqOnly,
}

/// Arguments for the `encrypt` subcommand.
#[derive(Args)]
pub(crate) struct EncryptArgs {
    /// Encryption mode (expert override). Ignored when --use-case is provided.
    /// clap-level `conflicts_with` makes the
    /// constraint visible in --help instead of just emitting a runtime
    /// warning.
    #[arg(short, long, value_enum, conflicts_with = "use_case")]
    pub mode: Option<EncryptMode>,
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
    /// Input file to encrypt (reads from stdin if omitted).
    #[arg(short, long)]
    pub input: Option<PathBuf>,
    /// Output file for encrypted data (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Key file path (symmetric key for AES, public key for hybrid).
    #[arg(short, long)]
    pub key: PathBuf,
    /// Overwrite the output file if it already exists. Default: false
    /// (refuses to clobber). Round-26 audit fix (H12).
    #[arg(long)]
    pub force: bool,
}

/// Execute the encrypt command.
pub(crate) fn run(args: EncryptArgs) -> Result<()> {
    let plaintext = read_input(&args.input)?;
    let key_file = KeyFile::read_from(&args.key)?;

    // Use-case-driven path
    if args.use_case.is_some() {
        if args.mode.is_some() {
            eprintln!(
                "Warning: --mode is ignored when --use-case is provided. \
                 The library selects the optimal encryption scheme automatically. \
                 For PQ-only with a use case, pass --use-case <X> on its own \
                 with a PQ-only key (the library auto-detects CryptoMode from the key type)."
            );
        }
        let json_output = encrypt_with_config(&plaintext, &key_file, &args)?;
        return write_output(&args.output, &json_output, args.force);
    }

    // Expert path (or default). When `--mode` is omitted, infer it from
    // the key file's type — a hybrid PK should default to hybrid, a
    // symmetric key to AES-256-GCM. Without this inference (round-7
    // audit fix #12), passing a hybrid PK without `--mode hybrid`
    // produced "Expected symmetric key file, got Public" — accurate
    // but surprising for the common case.
    //
    // branch on the key's algorithm so
    // pure-PQ ML-KEM PKs are routed to `PqOnly` and hybrid
    // `HybridMlKem*X25519` PKs to `Hybrid`. Previously we forced
    // `Hybrid` for any `KeyType::Public`, which made the hybrid splitter
    // treat the trailing 32 bytes of an ML-KEM-768 PK (1184 bytes) as
    // X25519 → garbage ciphertext. The use-case path already handled
    // this correctly via `is_pq_only`; the expert path was the gap.
    let mode = match args.mode {
        Some(m) => m,
        None => match key_file.key_type {
            KeyType::Public => {
                if is_pq_only_key(&key_file) {
                    EncryptMode::PqOnly
                } else {
                    EncryptMode::Hybrid
                }
            }
            _ => EncryptMode::Aes256Gcm,
        },
    };
    let json_output = match mode {
        EncryptMode::Aes256Gcm => encrypt_symmetric(&plaintext, &key_file)?,
        EncryptMode::Chacha20Poly1305 => encrypt_chacha20(&plaintext, &key_file)?,
        EncryptMode::Hybrid => encrypt_hybrid(&plaintext, &key_file)?,
        EncryptMode::PqOnly => encrypt_pq_only_mode(&plaintext, &key_file, &args)?,
    };

    write_output(&args.output, &json_output, args.force)
}

/// Encrypt using the library's unified API with use-case-driven config.
fn encrypt_with_config(plaintext: &[u8], key_file: &KeyFile, args: &EncryptArgs) -> Result<String> {
    let config = super::common::build_config(args.use_case, args.security_level, &args.compliance);

    // Determine key type from the key file and encrypt
    match key_file.key_type {
        KeyType::Symmetric => {
            let key_bytes = key_file.key_bytes()?;
            let config = config.force_scheme(latticearc::CryptoScheme::Symmetric);
            let encrypted = latticearc::encrypt(
                plaintext,
                latticearc::EncryptKey::Symmetric(&key_bytes),
                config,
            )
            .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
            latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
                .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
        }
        KeyType::Public => {
            // Auto-route based on the key's algorithm: pure-PQ ML-KEM keys
            // must go through the PqOnly path; hybrid keys stay on Hybrid.
            // Without this split, `encrypt --use-case X --key pure_pq.pub.json`
            // would try to parse a pure-PQ key as hybrid and fail with a
            // length mismatch — the same bug class as the signing-path bug
            // fixed alongside this change.
            if is_pq_only_key(key_file) {
                // Delegate to the dedicated PQ-only path so CryptoMode and
                // key-parsing are consistent with the algorithm.
                return encrypt_pq_only_mode(plaintext, key_file, args);
            }

            let alg = key_file.portable_key().algorithm();
            let pk_bytes = key_file.key_bytes()?;
            let pk = crate::keyfile::parse_hybrid_kem_pk_from_bytes(&pk_bytes, alg)?;
            let encrypted =
                latticearc::encrypt(plaintext, latticearc::EncryptKey::Hybrid(&pk), config)
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;
            latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
                .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
        }
        _ => bail!(
            "Expected symmetric or public key file for encryption, got {:?}",
            key_file.key_type
        ),
    }
}

fn encrypt_symmetric(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Symmetric {
        bail!("Expected symmetric key file, got {:?}", key_file.key_type);
    }

    let key_bytes = key_file.key_bytes()?;
    if key_bytes.len() != 32 {
        bail!("AES-256 requires a 32-byte key, got {} bytes", key_bytes.len());
    }

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new().force_scheme(latticearc::CryptoScheme::Symmetric),
    )
    .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn encrypt_chacha20(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Symmetric {
        bail!("Expected symmetric key file for ChaCha20 encryption, got {:?}", key_file.key_type);
    }
    let key_bytes = key_file.key_bytes()?;

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Symmetric(&key_bytes),
        latticearc::CryptoConfig::new().force_scheme(latticearc::CryptoScheme::SymmetricChaCha20),
    )
    .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn encrypt_hybrid(plaintext: &[u8], key_file: &KeyFile) -> Result<String> {
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for hybrid encryption, got {:?}", key_file.key_type);
    }

    let pk_bytes = key_file.key_bytes()?;
    // The legacy `--algorithm hybrid` path historically wrote ML-KEM-768
    // public keys, so the algorithm is fixed here. If the key file's
    // algorithm tag is one of the typed hybrid variants, prefer that;
    // otherwise fall back to the historic 768.
    let alg = key_file.portable_key().algorithm();
    let resolved_alg = if matches!(
        alg,
        latticearc::unified_api::key_format::KeyAlgorithm::HybridMlKem512X25519
            | latticearc::unified_api::key_format::KeyAlgorithm::HybridMlKem768X25519
            | latticearc::unified_api::key_format::KeyAlgorithm::HybridMlKem1024X25519
    ) {
        alg
    } else {
        latticearc::unified_api::key_format::KeyAlgorithm::HybridMlKem768X25519
    };
    let pk = crate::keyfile::parse_hybrid_kem_pk_from_bytes(&pk_bytes, resolved_alg)?;

    let encrypted = latticearc::encrypt(
        plaintext,
        latticearc::EncryptKey::Hybrid(&pk),
        latticearc::CryptoConfig::new(),
    )
    .map_err(|e| anyhow::anyhow!("Hybrid encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn encrypt_pq_only_mode(
    plaintext: &[u8],
    key_file: &KeyFile,
    args: &EncryptArgs,
) -> Result<String> {
    if key_file.key_type != KeyType::Public {
        bail!("Expected public key file for PQ-only encryption, got {:?}", key_file.key_type);
    }

    let pk_bytes = key_file.key_bytes()?;
    let level =
        super::common::resolve_ml_kem_level(key_file.portable_key().algorithm()).map_err(|e| {
            anyhow::anyhow!("{e}. Generate one with: latticearc-cli keygen --algorithm ml-kem768")
        })?;

    let pq_pk = latticearc::PqOnlyPublicKey::from_bytes(level, &pk_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid PQ-only public key: {e}"))?;

    let security_level = super::common::ml_kem_to_security_level(level);
    let mut config = latticearc::CryptoConfig::new()
        .crypto_mode(latticearc::CryptoMode::PqOnly)
        .security_level(args.security_level.unwrap_or(security_level));
    if let Some(ref compliance) = args.compliance {
        config = config.compliance(compliance.clone());
    }

    let encrypted = latticearc::encrypt(plaintext, latticearc::EncryptKey::PqOnly(&pq_pk), config)
        .map_err(|e| anyhow::anyhow!("PQ-only encryption failed: {e}"))?;

    latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e}"))
}

fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>> {
    // route through the shared helper.
    super::common::read_file_or_stdin(
        path.as_deref(),
        super::common::CLI_MAX_ENCRYPTION_INPUT_BYTES,
        "encrypt",
    )
}

fn write_output(path: &Option<PathBuf>, data: &str, force: bool) -> Result<()> {
    match path {
        Some(p) => {
            // Atomic write — closes the partial-file confidentiality
            // window for decrypted material at rest. Same helper the
            // keyfile writer uses (round-7 audit fix #18).
            // only overwrite when --force is
            // passed; otherwise refuse to clobber, matching keygen's
            // default-safe behavior.
            // LINT-OK: public-write-ciphertext (encrypted data is not secret)
            latticearc::unified_api::atomic_write::AtomicWrite::new(data.as_bytes())
                .overwrite_existing(force)
                .write(p)
                .with_context(|| {
                    format!("Failed to write {} (use --force to overwrite)", p.display())
                })?;
            eprintln!("Encrypted data written to: {}", p.display());
        }
        None => {
            // `print!` (not `println!`) — byte-exact stdout for
            // pipelines that hash or chain into other tools (round-7
            // audit fix #14). Callers that want a trailing newline can
            // redirect through `cat` or append themselves.
            print!("{data}");
        }
    }
    Ok(())
}
