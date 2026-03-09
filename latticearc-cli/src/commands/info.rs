//! Info/version command.

use anyhow::Result;
use clap::Args;

/// Arguments for the `info` subcommand.
#[derive(Args)]
pub(crate) struct InfoArgs;

/// Execute the info command.
///
/// Returns `Result<()>` for consistency with other command handlers,
/// even though this function is infallible.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn run(_args: InfoArgs) -> Result<()> {
    println!("LatticeArc CLI v{}", env!("CARGO_PKG_VERSION"));
    println!("Library:  latticearc v{}", latticearc::VERSION);
    println!();
    println!(
        "FIPS 140-3 backend: {}",
        if latticearc::fips_available() { "available (aws-lc-rs)" } else { "not available" }
    );
    println!("Self-tests passed:  {}", latticearc::unified_api::self_tests_passed());
    println!();
    println!("Supported Algorithms:");
    println!("  Encryption:");
    println!("    AES-256-GCM             (FIPS validated via aws-lc-rs)");
    println!("    ChaCha20-Poly1305       (RFC 8439, non-FIPS)");
    println!("    ML-KEM-512/768/1024     (FIPS 203, key encapsulation)");
    println!("    Hybrid ML-KEM+X25519    (ML-KEM + ECDH + HKDF + AES-256-GCM)");
    println!();
    println!("  Signatures:");
    println!("    ML-DSA-44/65/87         (FIPS 204, lattice-based)");
    println!("    SLH-DSA-SHAKE-128s      (FIPS 205, hash-based, stateless)");
    println!("    FN-DSA-512              (FIPS 206 draft, compact lattice)");
    println!("    Ed25519                 (RFC 8032, classical)");
    println!("    Hybrid ML-DSA+Ed25519   (combined PQ + classical)");
    println!();
    println!("  Hashing:");
    println!("    SHA3-256                (FIPS 202, default)");
    println!("    SHA-256                 (FIPS 180-4)");
    println!("    SHA-512                 (FIPS 180-4)");
    println!("    BLAKE2b-256             (RFC 7693)");
    println!();
    println!("  Key Derivation:");
    println!("    HKDF-SHA256             (SP 800-56C)");
    println!("    PBKDF2-HMAC-SHA256      (SP 800-132)");
    Ok(())
}
