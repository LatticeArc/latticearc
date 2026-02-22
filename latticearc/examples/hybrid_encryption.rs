//! Hybrid Encryption Example (ML-KEM-768 + X25519)
//!
//! Demonstrates hybrid post-quantum + classical encryption using the unified API
//! where security holds if EITHER algorithm remains secure.
//!
//! Run with: `cargo run --package latticearc --example hybrid_encryption --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]

use latticearc::{CryptoConfig, DecryptKey, EncryptKey, generate_hybrid_keypair};

fn main() {
    println!("=== LatticeArc: Hybrid Encryption (ML-KEM-768 + X25519) ===\n");

    // --- Generate hybrid keypair ---
    let (pk, sk) = generate_hybrid_keypair().expect("keypair generation failed");
    println!("Generated hybrid keypair:");
    println!("  ML-KEM-768 PK: {} bytes", pk.ml_kem_pk.len());
    println!("  X25519 PK:     {} bytes", pk.ecdh_pk.len());

    // --- Encrypt ---
    let plaintext = b"Top secret: quantum-resistant message";
    println!(
        "\nPlaintext ({} bytes): {:?}",
        plaintext.len(),
        std::str::from_utf8(plaintext).unwrap()
    );

    let encrypted = latticearc::encrypt(plaintext, EncryptKey::Hybrid(&pk), CryptoConfig::new())
        .expect("encryption failed");
    println!("Encrypted:");
    println!("  Scheme:     {}", encrypted.scheme);
    println!("  Ciphertext: {} bytes", encrypted.ciphertext.len());
    println!("  Nonce:      {} bytes", encrypted.nonce.len());
    println!("  Tag:        {} bytes", encrypted.tag.len());
    if let Some(ref hd) = encrypted.hybrid_data {
        println!("  ML-KEM CT:  {} bytes", hd.ml_kem_ciphertext.len());
        println!("  ECDH ePK:   {} bytes", hd.ecdh_ephemeral_pk.len());
    }

    // --- Decrypt ---
    let decrypted = latticearc::decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())
        .expect("decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext);
    println!("\nDecrypted: {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("  Roundtrip OK!");

    // --- Multiple messages with same keypair ---
    println!("\n--- Multiple messages with same keypair ---");
    for i in 0..5u32 {
        let msg = format!("Hybrid message #{}", i);
        let enc = latticearc::encrypt(msg.as_bytes(), EncryptKey::Hybrid(&pk), CryptoConfig::new())
            .expect("encrypt failed");
        let dec = latticearc::decrypt(&enc, DecryptKey::Hybrid(&sk), CryptoConfig::new())
            .expect("decrypt failed");
        assert_eq!(dec, msg.as_bytes());
        println!("  Message {}: {} bytes -> encrypt -> decrypt OK", i, msg.len());
    }

    println!("\nAll hybrid encryption tests passed!");
}
