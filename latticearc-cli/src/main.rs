// Binary crate: must print to stdout/stderr
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! # LatticeArc CLI
//!
//! Post-quantum cryptography from the command line.
//!
//! This binary provides 8 subcommands for everyday cryptographic operations
//! using NIST-standardized post-quantum algorithms:
//!
//! | Command   | Purpose                                        |
//! |-----------|------------------------------------------------|
//! | `keygen`  | Generate signing, encryption, or symmetric keys |
//! | `sign`    | Create a digital signature over a file          |
//! | `verify`  | Check a signature against a public key          |
//! | `encrypt` | Encrypt a file (AES-256-GCM or hybrid PQ)       |
//! | `decrypt` | Decrypt a previously encrypted file              |
//! | `hash`    | Compute a cryptographic hash (SHA3, SHA2, BLAKE2)|
//! | `kdf`     | Derive a key from a password or key material     |
//! | `info`    | Show version, FIPS status, supported algorithms  |
//!
//! ## Supported Algorithms
//!
//! - **Signatures:** ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205),
//!   FN-DSA-512 (FIPS 206 draft), Ed25519 (RFC 8032), Hybrid ML-DSA+Ed25519
//! - **Encryption:** AES-256-GCM (FIPS 197), Hybrid ML-KEM+X25519+AES-256-GCM
//! - **Hashing:** SHA3-256 (FIPS 202), SHA-256/512 (FIPS 180-4), BLAKE2b (RFC 7693)
//! - **KDF:** HKDF-SHA256 (SP 800-56C), PBKDF2-HMAC-SHA256 (SP 800-132)
//!
//! ## Architecture
//!
//! ```text
//! main.rs          Entry point, CLI argument parsing (clap)
//! ├── keyfile.rs   JSON key file format, serialization, permissions
//! └── commands/
//!     ├── keygen   Key generation for all 12 algorithm variants
//!     ├── sign     Digital signature creation (7 algorithms)
//!     ├── verify   Signature verification with auto-detection
//!     ├── encrypt  Authenticated encryption (symmetric + hybrid)
//!     ├── decrypt  Decryption with integrity verification
//!     ├── hash     Cryptographic hashing (4 algorithms)
//!     ├── kdf      Key derivation (HKDF + PBKDF2)
//!     └── info     Version and capability reporting
//! ```
//!
//! All cryptographic operations are delegated to the `latticearc` library crate.
//! The CLI handles file I/O, key serialization, argument parsing, and user output.

mod commands;
mod keyfile;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// LatticeArc — Post-quantum cryptography from the command line.
///
/// Generate keys, encrypt, decrypt, sign, verify, hash, and derive keys
/// using NIST-standard post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
/// and classical algorithms (AES-256-GCM, Ed25519, X25519).
#[derive(Parser)]
#[command(name = "latticearc-cli", version, about, long_about = None)]
#[command(propagate_version = true)]
// showing the full help when invoked with no args
// is more discoverable than the default 2-line "USAGE:" stub for
// first-time users. Costs nothing for scripted callers (they always
// supply a subcommand) and pays back the discoverability for
// `latticearc-cli` typed at a fresh shell.
#[command(arg_required_else_help = true)]
struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Generate a cryptographic keypair or symmetric key.
    Keygen(commands::keygen::KeygenArgs),
    /// Encrypt data using symmetric or hybrid post-quantum encryption.
    Encrypt(commands::encrypt::EncryptArgs),
    /// Decrypt data.
    Decrypt(commands::decrypt::DecryptArgs),
    /// Sign data with a signing key.
    Sign(commands::sign::SignArgs),
    /// Verify a signature.
    Verify(commands::verify::VerifyArgs),
    /// Hash data (SHA3-256, SHA-256, SHA-512, BLAKE2b).
    Hash(commands::hash::HashArgs),
    /// Derive a key from a password using HKDF or PBKDF2.
    Kdf(commands::kdf::KdfArgs),
    /// Show version, supported algorithms, build info, and FIPS status.
    Info(commands::info::InfoArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Wire up the `tracing` subscriber so `tracing::{debug,info,warn,error}!`
    // events from the library reach stderr. The `tracing-init` Cargo
    // feature on our `latticearc` dep pulls in the `tracing-subscriber`
    // and `tracing-appender` crates that back this helper. Subscriber
    // wiring is the binary's job (see DESIGN_PATTERNS Pattern 6 +
    // SECURITY.md observability section); a library that calls this
    // would `panic!` the next downstream consumer.
    //
    // Filter defaults to `latticearc=info`; override at runtime with
    // `RUST_LOG=latticearc=debug` (or `=trace` to see per-stage
    // crypto-error tags).
    //
    // Best-effort: if a subscriber is somehow already installed (e.g., the
    // CLI is being driven from a test harness that wired its own), we
    // swallow the error rather than aborting the user's command.
    let _ = latticearc::unified_api::logging::init_tracing();

    // Initialize LatticeArc (runs FIPS power-up self-tests)
    latticearc::init().map_err(|e| anyhow::anyhow!("Library initialization failed: {e}"))?;

    match cli.command {
        Commands::Keygen(args) => commands::keygen::run(args),
        Commands::Encrypt(args) => commands::encrypt::run(args),
        Commands::Decrypt(args) => commands::decrypt::run(args),
        Commands::Sign(args) => commands::sign::run(args),
        // verify returns Ok(true)=VALID,
        // Ok(false)=INVALID. Translate INVALID into exit 1 here so
        // destructors on the per-command state inside `verify::run`
        // (KeyFile, Vec<u8>, etc.) all get to run before the process
        // dies. The earlier in-function `process::exit(1)` skipped
        // them — currently benign because verify's per-command state
        // only holds public material, but a regression copying the
        // pattern to sign/decrypt would skip secret zeroization.
        Commands::Verify(args) => {
            let valid = commands::verify::run(args)?;
            if !valid {
                // `clippy::exit` allowed: deterministic exit 1 is the
                // documented INVALID-signature signal in our exit-code
                // contract (0/1/≥2 — see QUICK_REFERENCE.md). Pattern
                // 12 wants the rationale adjacent to the `#[allow]`;
                // moved it from 11 lines above.
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Hash(args) => commands::hash::run(args),
        Commands::Kdf(args) => commands::kdf::run(args),
        Commands::Info(args) => commands::info::run(args),
    }
}
