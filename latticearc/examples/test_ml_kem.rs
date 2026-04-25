#![deny(unsafe_code)]
#![allow(missing_docs)]
// Example files use println! for demonstration purposes
#![allow(clippy::print_stdout)]
// Example files use expect! for simplicity
#![allow(clippy::expect_used)]

// Example file for ML-KEM implementation
// This file tests all ML-KEM operations

use latticearc::primitives::kem::ml_kem::*;

fn main() {
    println!("Testing ML-KEM Implementation...\n");

    // Test ML-KEM-512
    println!("1. Testing ML-KEM-512...");
    test_ml_kem_succeeds(MlKemSecurityLevel::MlKem512);

    // Test ML-KEM-768
    println!("\n2. Testing ML-KEM-768...");
    test_ml_kem_succeeds(MlKemSecurityLevel::MlKem768);

    // Test ML-KEM-1024
    println!("\n3. Testing ML-KEM-1024...");
    test_ml_kem_succeeds(MlKemSecurityLevel::MlKem1024);

    println!("\nAll ML-KEM tests passed!");
}

fn test_ml_kem_succeeds(security_level: MlKemSecurityLevel) {
    // Key generation
    println!("   - Generating keypair...");
    let (pk, sk) = MlKem::generate_keypair(security_level).expect("Key generation failed");

    println!("   - Public key size: {} bytes", pk.as_bytes().len());
    println!("   - Secret key size: {} bytes", sk.expose_secret().len());

    // Verify key sizes match specification
    assert_eq!(pk.as_bytes().len(), security_level.public_key_size());
    assert_eq!(sk.expose_secret().len(), security_level.secret_key_size());

    // Encapsulation
    println!("   - Encapsulating shared secret...");
    let (ss1, ct) = MlKem::encapsulate(&pk).expect("Encapsulation failed");

    println!("   - Ciphertext size: {} bytes", ct.as_bytes().len());
    println!("   - Shared secret size: {} bytes", ss1.expose_secret().len());

    // Verify ciphertext and shared secret sizes
    assert_eq!(ct.as_bytes().len(), security_level.ciphertext_size());
    assert_eq!(ss1.expose_secret().len(), 32);

    // Decapsulation
    println!("   - Decapsulating shared secret...");
    let ss2 = MlKem::decapsulate(&sk, &ct).expect("Decapsulation failed");

    // Verify shared secrets match
    assert_eq!(ss1.expose_secret(), ss2.expose_secret());

    println!(
        "   - ML-KEM-{}: All operations successful!",
        match security_level {
            MlKemSecurityLevel::MlKem512 => "512",
            MlKemSecurityLevel::MlKem768 => "768",
            MlKemSecurityLevel::MlKem1024 => "1024",
            _ => "unknown",
        }
    );
}
