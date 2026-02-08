//! Complete Secure Workflow Example
//!
//! Full end-to-end lifecycle demonstrating:
//! 1. Key generation (persistent signing identity)
//! 2. Key derivation from password
//! 3. Encryption of sensitive data
//! 4. Signing the encrypted data (non-repudiation)
//! 5. Serialization for storage/transmission
//! 6. Deserialization
//! 7. Signature verification
//! 8. Decryption
//! 9. Verification that plaintext matches original
//!
//! Run with: `cargo run --package latticearc --example complete_secure_workflow --release`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]

use latticearc::{
    CryptoConfig, SecurityLevel, SecurityMode, decrypt_aes_gcm, derive_key,
    deserialize_signed_data, encrypt_aes_gcm, generate_signing_keypair, hash_data,
    serialize_signed_data, sign_with_key, verify,
};

fn main() {
    println!("=== LatticeArc: Complete Secure Workflow ===\n");

    // -----------------------------------------------------------------------
    // Step 1: Generate a persistent signing keypair
    // -----------------------------------------------------------------------
    println!("Step 1: Generate signing keypair...");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let (sign_pk, sign_sk, scheme) =
        generate_signing_keypair(config).expect("signing keypair generation failed");
    println!("  Scheme: {}, PK: {} bytes", scheme, sign_pk.len());

    // -----------------------------------------------------------------------
    // Step 2: Derive encryption key from password using HKDF
    // -----------------------------------------------------------------------
    println!("\nStep 2: Derive encryption key from password...");
    let password = b"correct horse battery staple";
    let salt = b"unique-application-salt-v1";
    let enc_key =
        derive_key(password, salt, 32, SecurityMode::Unverified).expect("key derivation failed");
    println!("  Derived {} byte encryption key", enc_key.len());

    // Verify determinism: same inputs → same key
    let enc_key2 = derive_key(password, salt, 32, SecurityMode::Unverified).unwrap();
    assert_eq!(enc_key, enc_key2, "KDF must be deterministic");
    println!("  Determinism verified: same inputs produce same key");

    // -----------------------------------------------------------------------
    // Step 3: Encrypt sensitive data
    // -----------------------------------------------------------------------
    println!("\nStep 3: Encrypt sensitive data...");
    let original_data = b"Patient ID: 12345\nDiagnosis: Healthy\nSSN: 123-45-6789";
    let original_hash = hash_data(original_data);
    println!(
        "  Original: {} bytes, SHA3-256: {:02x?}...",
        original_data.len(),
        &original_hash[..8]
    );

    let ciphertext = encrypt_aes_gcm(original_data, &enc_key, SecurityMode::Unverified)
        .expect("encryption failed");
    println!("  Ciphertext: {} bytes", ciphertext.len());

    // -----------------------------------------------------------------------
    // Step 4: Sign the encrypted data (non-repudiation)
    // -----------------------------------------------------------------------
    println!("\nStep 4: Sign the ciphertext...");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let signed = sign_with_key(&ciphertext, &sign_sk, &sign_pk, config).expect("signing failed");
    println!("  Signed data: {} bytes, scheme: {}", signed.data.len(), signed.scheme);

    // -----------------------------------------------------------------------
    // Step 5: Serialize for storage/transmission
    // -----------------------------------------------------------------------
    println!("\nStep 5: Serialize for storage...");
    let serialized = serialize_signed_data(&signed).expect("serialization failed");
    println!("  Serialized: {} bytes (wire format)", serialized.len());

    // -----------------------------------------------------------------------
    // Step 6: Deserialize (simulates loading from disk/network)
    // -----------------------------------------------------------------------
    println!("\nStep 6: Deserialize...");
    let loaded = deserialize_signed_data(&serialized).expect("deserialization failed");
    println!("  Deserialized: scheme={}, data={} bytes", loaded.scheme, loaded.data.len());

    // -----------------------------------------------------------------------
    // Step 7: Verify signature
    // -----------------------------------------------------------------------
    println!("\nStep 7: Verify signature...");
    let config = CryptoConfig::new().security_level(SecurityLevel::High);
    let is_valid = verify(&loaded, config).expect("verification failed");
    assert!(is_valid, "Signature must be valid");
    println!("  Signature: VALID");

    // -----------------------------------------------------------------------
    // Step 8: Decrypt data
    // -----------------------------------------------------------------------
    println!("\nStep 8: Decrypt data...");
    let decrypted = decrypt_aes_gcm(&loaded.data, &enc_key, SecurityMode::Unverified)
        .expect("decryption failed");
    println!("  Decrypted: {} bytes", decrypted.len());

    // -----------------------------------------------------------------------
    // Step 9: Verify plaintext matches original
    // -----------------------------------------------------------------------
    println!("\nStep 9: Verify integrity...");
    assert_eq!(decrypted.as_slice(), original_data);
    let decrypted_hash = hash_data(&decrypted);
    assert_eq!(original_hash, decrypted_hash, "Hash mismatch");
    println!("  Content: {:?}", std::str::from_utf8(&decrypted).unwrap());
    println!("  SHA3-256 match: OK");

    println!("\n=== Complete secure workflow passed! ===");
}
