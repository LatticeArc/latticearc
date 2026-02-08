//! Digital Signatures Example
//!
//! Demonstrates persistent-key signing with `generate_signing_keypair` + `sign_with_key` + `verify`.
//!
//! Run with: `cargo run --package latticearc --example digital_signatures --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::panic)]

use latticearc::{CryptoConfig, SecurityLevel, generate_signing_keypair, sign_with_key, verify};

fn main() {
    println!("=== LatticeArc: Digital Signatures (Persistent Identity) ===\n");

    // --- Generate a persistent signing keypair ---
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (pk, sk, scheme) = generate_signing_keypair(config).expect("keygen failed");
    println!("Generated keypair using scheme: {}", scheme);
    println!("  Public key:  {} bytes", pk.len());
    println!("  Secret key:  {} bytes", sk.len());

    // --- Sign a message ---
    let message = b"I authorize the transfer of $1,000,000 to account XYZ.";
    println!("\nSigning message ({} bytes)...", message.len());

    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(message, &sk, &pk, config).expect("signing failed");
    println!("  Signature scheme: {}", signed.scheme);
    println!("  Signed data size: {} bytes", signed.data.len());

    // --- Verify ---
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&signed, config).expect("verification failed");
    assert!(is_valid, "Signature should be valid");
    println!("  Verification: VALID\n");

    // --- Sign 5 messages with the same key ---
    println!("--- Signing 5 messages with same keypair ---");
    for i in 0..5u32 {
        let msg = format!("Document #{}: approval granted", i);
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let signed = sign_with_key(msg.as_bytes(), &sk, &pk, config).expect("signing failed");
        let config = CryptoConfig::new().security_level(SecurityLevel::High);
        let valid = verify(&signed, config).expect("verify failed");
        assert!(valid);
        println!("  Message {}: signed and verified OK", i);
    }

    // --- Tamper detection ---
    println!("\n--- Tamper Detection ---");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let mut signed = sign_with_key(b"original", &sk, &pk, config).expect("signing failed");
    signed.data = b"tampered".to_vec();
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&signed, config);
    match result {
        Ok(false) | Err(_) => println!("  Tampered message correctly rejected"),
        Ok(true) => panic!("Tampered message should not verify"),
    }

    // --- Cross-key rejection ---
    println!("\n--- Cross-Key Rejection ---");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (_pk2, sk2, _scheme2) = generate_signing_keypair(config).expect("keygen2 failed");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed_by_other =
        sign_with_key(b"signed by key 2", &sk2, &pk, config).expect("sign failed");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let result = verify(&signed_by_other, config);
    match result {
        Ok(false) | Err(_) => println!("  Cross-key signature correctly rejected"),
        Ok(true) => panic!("Cross-key verification should fail"),
    }

    println!("\nAll digital signature tests passed!");
}
