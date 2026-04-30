//! Info command — display version, FIPS status, and supported algorithms.
//!
//! Shows a human-readable summary of the CLI and library versions, whether
//! the FIPS 140-3 backend (aws-lc-rs) is linked and operational, and a
//! complete list of every algorithm available across all command categories
//! (encryption, signatures, hashing, key derivation).
//!
//! **Self-tests:** The output includes a `Self-tests passed` line that
//! reports whether the library's power-on self-tests (KAT vectors) passed.
//! This is a FIPS 140-3 requirement for validated modules.

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
        if latticearc::fips_available() {
            // Round-21 audit fix #11: distinguish "validated backend"
            // (aws-lc-rs is FIPS 140-3 validated as a stand-alone
            // module) from "validated module" (this binary linking
            // aws-lc-rs is NOT itself certified). The previous
            // "available (aws-lc-rs)" wording read like a FIPS-
            // certified-product claim to operators glancing at
            // `--info`.
            "validated backend (aws-lc-rs); this binary links the validated backend but is NOT itself a FIPS 140-3 certified module — see docs/NIST_COMPLIANCE.md and docs/FIPS_SECURITY_POLICY.md"
        } else {
            "not available"
        }
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
    println!("    FN-DSA-512              (FIPS 206, compact lattice)");
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
