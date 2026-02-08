//! Hybrid Encryption Example (ML-KEM-768 + X25519)
//!
//! Demonstrates hybrid post-quantum + classical encryption where security
//! holds if EITHER algorithm remains secure.
//!
//! Run with: `cargo run --package latticearc --example hybrid_encryption --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]

use latticearc::{SecurityMode, decrypt_hybrid, encrypt_hybrid, generate_hybrid_keypair};

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

    let encrypted =
        encrypt_hybrid(plaintext, &pk, SecurityMode::Unverified).expect("encryption failed");
    println!("Encrypted:");
    println!("  KEM ciphertext:   {} bytes", encrypted.kem_ciphertext.len());
    println!("  ECDH ephemeral:   {} bytes", encrypted.ecdh_ephemeral_pk.len());
    println!("  Symmetric CT:     {} bytes", encrypted.symmetric_ciphertext.len());
    println!("  Nonce:            {} bytes", encrypted.nonce.len());
    println!("  Tag:              {} bytes", encrypted.tag.len());

    // --- Decrypt ---
    let decrypted =
        decrypt_hybrid(&encrypted, &sk, SecurityMode::Unverified).expect("decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext);
    println!("\nDecrypted: {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("  Roundtrip OK!");

    // --- Multiple messages with same keypair ---
    println!("\n--- Multiple messages with same keypair ---");
    for i in 0..5u32 {
        let msg = format!("Hybrid message #{}", i);
        let enc =
            encrypt_hybrid(msg.as_bytes(), &pk, SecurityMode::Unverified).expect("encrypt failed");
        let dec = decrypt_hybrid(&enc, &sk, SecurityMode::Unverified).expect("decrypt failed");
        assert_eq!(dec, msg.as_bytes());
        println!("  Message {}: {} bytes -> encrypt -> decrypt OK", i, msg.len());
    }

    println!("\nAll hybrid encryption tests passed!");
}
