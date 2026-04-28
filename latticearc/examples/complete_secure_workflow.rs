//! Complete Secure Workflow Example
//!
//! Full end-to-end lifecycle demonstrating:
//! 1. Key generation (persistent signing identity)
//! 2. Password-based key derivation via PBKDF2 with a per-use random salt
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

use latticearc::primitives::kdf::pbkdf2::{Pbkdf2Params, pbkdf2};
use latticearc::primitives::rand::csprng::random_bytes;
use latticearc::{
    CryptoConfig, SecurityLevel, SecurityMode, decrypt_aes_gcm, deserialize_signed_data,
    encrypt_aes_gcm, generate_signing_keypair, hash_data, serialize_signed_data, sign_with_key,
    verify,
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
    // Step 2: Derive encryption key from a password using PBKDF2
    // -----------------------------------------------------------------------
    //
    // Password-based key derivation MUST use a slow, memory-or-cpu-hard KDF
    // to make brute-force attacks expensive. Using HKDF directly on a
    // password is a security antipattern: HKDF assumes high-entropy input
    // keying material (DH shared secrets, raw random bytes) and provides
    // zero work factor, so an attacker who steals the ciphertext can try
    // passwords at line rate.
    //
    // This example uses PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP
    // 2023 recommendation) with a fresh 16-byte random salt. The salt is
    // stored alongside the ciphertext so the same password + salt produces
    // the same key on decrypt, but different salts on other encryptions
    // prevent rainbow-table attacks across users.
    println!("\nStep 2: Derive encryption key from password via PBKDF2...");
    let password = b"correct horse battery staple";
    let salt = random_bytes(16);
    let params = Pbkdf2Params::with_salt(&salt).iterations(600_000).key_length(32);
    let derived = pbkdf2(password, &params).expect("PBKDF2 derivation failed");
    let enc_key: Vec<u8> = derived.expose_secret().to_vec();
    println!("  Derived {}-byte encryption key (PBKDF2, 600k iters)", enc_key.len());

    // Verify determinism: same password + same salt → same key.
    let derived2 = pbkdf2(password, &params).expect("PBKDF2 re-derivation failed");
    assert_eq!(
        enc_key,
        derived2.expose_secret(),
        "PBKDF2 must be deterministic for fixed salt + iters"
    );
    println!("  Determinism verified: same password + salt produce same key");

    // -----------------------------------------------------------------------
    // Step 3: Encrypt sensitive data
    // -----------------------------------------------------------------------
    println!("\nStep 3: Encrypt sensitive data...");
    // Example fixture — not real patient data.
    let original_data = b"Record-ID: RCRD-0001\nCategory: Example\nNotes: fixture data";
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
