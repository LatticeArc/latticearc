//! Basic AES-256-GCM Encryption Example
//!
//! Demonstrates encrypt→decrypt through the unified API.
//!
//! Run with: `cargo run --package latticearc --example basic_encryption --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
#![allow(clippy::indexing_slicing)]

fn main() {
    println!("=== LatticeArc: Basic AES-256-GCM Encryption ===\n");

    let key = [0x42u8; 32]; // 256-bit key

    // --- Encrypt and decrypt ---
    let plaintext = b"Confidential: quarterly earnings exceed projections.";
    println!(
        "Plaintext ({} bytes): {:?}",
        plaintext.len(),
        std::str::from_utf8(plaintext).unwrap()
    );

    let ciphertext =
        latticearc::encrypt_aes_gcm(plaintext, &key, latticearc::SecurityMode::Unverified)
            .expect("encryption failed");
    println!(
        "Ciphertext ({} bytes): {:02x?}...",
        ciphertext.len(),
        &ciphertext[..16.min(ciphertext.len())]
    );

    let decrypted =
        latticearc::decrypt_aes_gcm(&ciphertext, &key, latticearc::SecurityMode::Unverified)
            .expect("decryption failed");
    assert_eq!(decrypted.as_slice(), plaintext);
    println!("Decrypted: {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("  Roundtrip OK!\n");

    // --- Tamper detection ---
    println!("--- Tamper Detection ---");
    let mut tampered = ciphertext.clone();
    if tampered.len() > 12 {
        tampered[12] ^= 0xFF;
    }
    let result = latticearc::decrypt_aes_gcm(&tampered, &key, latticearc::SecurityMode::Unverified);
    assert!(result.is_err());
    println!("  Tampered ciphertext correctly rejected: {:?}", result.err().unwrap());

    // --- Wrong key detection ---
    println!("\n--- Wrong Key Detection ---");
    let wrong_key = [0x99u8; 32];
    let result =
        latticearc::decrypt_aes_gcm(&ciphertext, &wrong_key, latticearc::SecurityMode::Unverified);
    assert!(result.is_err());
    println!("  Wrong key correctly rejected: {:?}", result.err().unwrap());

    println!("\nAll basic encryption tests passed!");
}
