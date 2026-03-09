// Binary crate: must print to stdout/stderr
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! LatticeArc CLI - Post-Quantum Cryptography Command Line Tool
//!
//! Provides keygen, encrypt, decrypt, sign, verify, hash, and KDF operations
//! using the LatticeArc post-quantum cryptography library.

mod commands;
mod keyfile;
mod keystore;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// LatticeArc — Post-quantum cryptography from the command line.
///
/// Generate keys, encrypt, decrypt, sign, verify, hash, and derive keys
/// using NIST-standard post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, FN-DSA)
/// and classical algorithms (AES-256-GCM, Ed25519, X25519).
#[derive(Parser)]
#[command(name = "latticearc", version, about, long_about = None)]
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
    /// Manage an encrypted keystore (store, load, rotate, delete keys).
    Keystore(commands::keystore::KeystoreArgs),
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
        Commands::Keystore(args) => commands::keystore::run(args),
    }
}
