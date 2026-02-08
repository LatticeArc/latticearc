//! Post-Quantum Signatures Example
//!
//! Demonstrates ML-DSA (FIPS 204) signature generation and verification
//! through the unified API at different security levels.
//!
//! Note: SLH-DSA is very slow in debug mode — always run with `--release`.
//!
//! Run with: `cargo run --package latticearc --example post_quantum_signatures --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::expect_used)]

use latticearc::{CryptoConfig, SecurityLevel, generate_signing_keypair, sign_with_key, verify};
use std::time::Instant;

fn main() {
    println!("=== LatticeArc: Post-Quantum Signatures ===\n");

    let message = b"Critical infrastructure firmware update v3.7.2";

    // --- ML-DSA-65 (SecurityLevel::High, NIST Level 3) ---
    println!("--- ML-DSA at SecurityLevel::High (NIST Level 3) ---");
    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    let keygen_time = start.elapsed();
    println!("  Scheme: {}", scheme);
    println!("  Keygen: {:?}", keygen_time);
    println!("  PK: {} bytes, SK: {} bytes", pk.len(), sk.len());

    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("sign failed");
    let sign_time = start.elapsed();
    println!("  Sign:   {:?}, signature data: {} bytes", sign_time, signed.data.len());

    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let valid = verify(&signed, config).expect("verify failed");
    let verify_time = start.elapsed();
    assert!(valid);
    println!("  Verify: {:?}, result: VALID", verify_time);

    // --- ML-DSA-87 (SecurityLevel::Maximum, NIST Level 5) ---
    println!("\n--- ML-DSA at SecurityLevel::Maximum (NIST Level 5) ---");
    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let (pk5, sk5, scheme5) = generate_signing_keypair(config).expect("keygen failed");
    let keygen_time = start.elapsed();
    println!("  Scheme: {}", scheme5);
    println!("  Keygen: {:?}", keygen_time);
    println!("  PK: {} bytes, SK: {} bytes", pk5.len(), sk5.len());

    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let signed5 = sign_with_key(message, &sk5, &pk5, config).expect("sign failed");
    let sign_time = start.elapsed();
    println!("  Sign:   {:?}, signature data: {} bytes", sign_time, signed5.data.len());

    let start = Instant::now();
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    let valid5 = verify(&signed5, config).expect("verify failed");
    let verify_time = start.elapsed();
    assert!(valid5);
    println!("  Verify: {:?}, result: VALID", verify_time);

    // --- Comparison ---
    println!("\n--- Size Comparison ---");
    println!("  Level 3 PK: {} bytes | Level 5 PK: {} bytes", pk.len(), pk5.len());
    println!(
        "  Level 3 signed: {} bytes | Level 5 signed: {} bytes",
        signed.data.len(),
        signed5.data.len()
    );

    println!("\nAll post-quantum signature tests passed!");
}
