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

    // Initialize LatticeArc (runs FIPS power-up self-tests)
    latticearc::init().map_err(|e| anyhow::anyhow!("Library initialization failed: {e}"))?;

    match cli.command {
        Commands::Keygen(args) => commands::keygen::run(args),
        Commands::Encrypt(args) => commands::encrypt::run(args),
        Commands::Decrypt(args) => commands::decrypt::run(args),
        Commands::Sign(args) => commands::sign::run(args),
        Commands::Verify(args) => commands::verify::run(args),
        Commands::Hash(args) => commands::hash::run(args),
        Commands::Kdf(args) => commands::kdf::run(args),
        Commands::Info(args) => commands::info::run(args),
    }
}
