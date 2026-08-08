//! Integration tests for the `hash` and `kdf` commands, including determinism and security-property checks.
// Test code legitimately uses unwrap/expect, indexing, and println for proof output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod support;
use support::*;

// ============================================================================
// S08: Hash command — all algorithms
// ============================================================================
#[test]
fn test_hash_all_algorithms_succeeds() {
    let dir = temp_dir();
    let msg_path = dir.path().join("data.bin");
    std::fs::write(&msg_path, b"hash me").unwrap();
    let msg = msg_path.to_str().unwrap();

    let sha3 = run_ok(&["hash", "--algorithm", "sha3-256", "--input", msg]);
    assert!(sha3.starts_with("SHA3-256: "));
    assert_eq!(sha3.trim().len(), "SHA3-256: ".len() + 64); // 32 bytes = 64 hex

    let sha256 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg]);
    assert!(sha256.starts_with("SHA-256: "));

    let sha512 = run_ok(&["hash", "--algorithm", "sha-512", "--input", msg]);
    assert!(sha512.starts_with("SHA-512: "));
    assert_eq!(sha512.trim().len(), "SHA-512: ".len() + 128); // 64 bytes = 128 hex

    let blake2 = run_ok(&["hash", "--algorithm", "blake2b", "--input", msg]);
    assert!(blake2.starts_with("BLAKE2b-256: "));

    // All should produce different hashes
    assert_ne!(sha3.trim(), sha256.trim());
    assert_ne!(sha256.trim(), sha512.trim());
    assert_ne!(sha256.trim(), blake2.trim());

    // Extract actual hash values for proof
    let sha3_hash = sha3.trim().strip_prefix("SHA3-256: ").unwrap();
    let sha256_hash = sha256.trim().strip_prefix("SHA-256: ").unwrap();
    let sha512_hash = sha512.trim().strip_prefix("SHA-512: ").unwrap();
    let blake2_hash = blake2.trim().strip_prefix("BLAKE2b-256: ").unwrap();

    println!(
        "[PROOF] {{\"test\": \"hash_all_algorithms\", \"category\": \"cli-hash\", \"input\": \"hash me\", \"sha3_256\": \"{sha3_hash}\", \"sha256\": \"{sha256_hash}\", \"sha512_prefix\": \"{}...\", \"blake2b\": \"{blake2_hash}\", \"all_distinct\": true}}",
        &sha512_hash[..32]
    );
}
#[test]
fn test_hash_base64_output_succeeds() {
    let dir = temp_dir();
    let msg_path = dir.path().join("data.bin");
    std::fs::write(&msg_path, b"base64 test").unwrap();

    let out = run_ok(&[
        "hash",
        "--algorithm",
        "sha-256",
        "--input",
        msg_path.to_str().unwrap(),
        "--format",
        "base64",
    ]);
    assert!(out.starts_with("SHA-256: "));
    // Base64 of 32 bytes = 44 characters
    let hash_part = out.trim().strip_prefix("SHA-256: ").unwrap();
    assert_eq!(hash_part.len(), 44);
    assert!(hash_part.ends_with('='));

    println!(
        "[PROOF] {{\"test\": \"hash_base64_output\", \"category\": \"cli-hash\", \"format\": \"base64\", \"length\": 44}}"
    );
}
// ============================================================================
// S09: KDF command
// ============================================================================
#[test]
fn test_kdf_hkdf_derivation_succeeds() {
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c0d0e0f",
        "--length",
        "42",
        "--info",
        "test-context",
    ]);
    let hex_key = out.trim();
    assert_eq!(hex_key.len(), 84); // 42 bytes = 84 hex chars

    println!(
        "[PROOF] {{\"test\": \"kdf_hkdf_derivation\", \"category\": \"cli-kdf\", \"algorithm\": \"HKDF-SHA256\", \"output_length\": 42}}"
    );
}
#[test]
fn test_kdf_pbkdf2_derivation_succeeds() {
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "mypassword",
        "--salt",
        "73616c7473616c7473616c7473616c74", // "saltsalt" in hex
        "--length",
        "32",
        "--iterations",
        "1000", // low for test speed
        // CLI enforces OWASP 600k floor (#62); test fixture uses small count.
        "--allow-weak-iterations",
        "--allow-argv-secret",
    ]);
    let hex_key = out.trim();
    assert_eq!(hex_key.len(), 64); // 32 bytes = 64 hex chars

    println!(
        "[PROOF] {{\"test\": \"kdf_pbkdf2_derivation\", \"category\": \"cli-kdf\", \"algorithm\": \"PBKDF2-HMAC-SHA256\", \"iterations\": 1000, \"output_length\": 32}}"
    );
}
// ============================================================================
// S21: KDF determinism — same inputs produce same output
// ============================================================================
#[test]
fn test_kdf_deterministic_output_is_deterministic() {
    let args = &[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "password123",
        "--salt",
        "aabbccddaabbccddaabbccddaabbccdd",
        "--length",
        "32",
        "--iterations",
        "1000",
        // CLI enforces OWASP 600k floor (#62); test fixture uses small count.
        "--allow-weak-iterations",
        // KAT bypass for argv-passed PBKDF2 password.
        "--allow-argv-secret",
    ];

    let out1 = run_ok(args);
    let out2 = run_ok(args);
    assert_eq!(out1, out2, "Same KDF inputs must produce same output");

    println!(
        "[PROOF] {{\"test\": \"kdf_deterministic\", \"category\": \"cli-kdf\", \"deterministic\": true}}"
    );
}
// ============================================================================
// S22: Hash determinism
// ============================================================================
#[test]
fn test_hash_deterministic_output_is_deterministic() {
    let dir = temp_dir();
    let msg_path = dir.path().join("data.bin");
    std::fs::write(&msg_path, b"determinism test").unwrap();

    let out1 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg_path.to_str().unwrap()]);
    let out2 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg_path.to_str().unwrap()]);
    assert_eq!(out1, out2, "Same input must produce same hash");

    println!(
        "[PROOF] {{\"test\": \"hash_deterministic\", \"category\": \"cli-hash\", \"deterministic\": true}}"
    );
}
#[test]
fn test_hash_empty_input_fails() {
    let dir = temp_dir();
    let msg_path = dir.path().join("empty.txt");
    std::fs::write(&msg_path, b"").unwrap();
    let msg = msg_path.to_str().unwrap();

    // SHA-256 of empty string is a well-known constant:
    // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let sha256 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg]);
    let hash_hex = sha256.trim().strip_prefix("SHA-256: ").unwrap();
    assert_eq!(
        hash_hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 of empty input must match NIST known-answer value"
    );

    println!(
        "[PROOF] {{\"test\": \"hash_empty_input\", \"category\": \"edge-case\", \"input_bytes\": 0, \"sha256_empty\": \"{hash_hex}\", \"matches_known_answer\": true}}"
    );
}
// ============================================================================
// S38: Non-Existent File Handling
// ============================================================================
#[test]
fn test_nonexistent_input_file_succeeds() {
    let nonexistent_path = std::env::temp_dir().join("latticearc_does_not_exist_ever.txt");
    let nonexistent_str = nonexistent_path.to_string_lossy().into_owned();
    let stderr = run_fail(&["hash", "--algorithm", "sha-256", "--input", &nonexistent_str]);
    assert!(
        stderr.contains("Failed to read")
            || stderr.contains("No such file")
            || stderr.contains("error"),
        "Non-existent input file must produce clear error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"nonexistent_input_file\", \"category\": \"negative\", \"file\": \"nonexistent\", \"error_reported\": true}}"
    );
}
// ============================================================================
// S40: KDF Invalid Inputs
// ============================================================================
#[test]
fn test_kdf_invalid_hex_salt_fails() {
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "not-hex-data!!!",
        "--length",
        "32",
        "--info",
        "test",
    ]);
    assert!(
        stderr.contains("hex") || stderr.contains("Invalid") || stderr.contains("error"),
        "Invalid hex salt must be rejected: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"kdf_invalid_hex_salt\", \"category\": \"negative\", \"invalid_field\": \"salt\", \"rejected\": true}}"
    );
}
#[test]
fn test_kdf_invalid_hex_input_fails() {
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "zzz-not-hex",
        "--salt",
        "000102030405060708090a0b0c0d0e0f",
        "--length",
        "32",
        "--info",
        "test",
    ]);
    assert!(
        stderr.contains("hex") || stderr.contains("Invalid") || stderr.contains("error"),
        "Invalid hex input must be rejected: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"kdf_invalid_hex_input\", \"category\": \"negative\", \"invalid_field\": \"input\", \"rejected\": true}}"
    );
}
#[test]
fn test_kdf_zero_length_rejected_fails() {
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c0d0e0f",
        "--length",
        "0",
        "--info",
        "test",
    ]);
    assert!(
        stderr.contains("length") || stderr.contains("0") || stderr.contains("error"),
        "Zero-length KDF output must be rejected: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"kdf_zero_length_rejected\", \"category\": \"negative\", \"length\": 0, \"rejected\": true}}"
    );
}
// ============================================================================
// S48: HKDF Domain Separation — Different Info Strings Produce Different Keys
// ============================================================================
//
// RFC 5869 §3.2: The "info" parameter enables domain separation.
// Same IKM + salt but different info MUST produce different derived keys.
// This is a critical security property for multi-purpose key derivation.
#[test]
fn test_hkdf_domain_separation_succeeds() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let salt = "000102030405060708090a0b0c0d0e0f";

    // Derive with info="encryption"
    let key_enc = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        ikm,
        "--salt",
        salt,
        "--length",
        "32",
        "--info",
        "encryption",
    ]);

    // Derive with info="authentication"
    let key_auth = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        ikm,
        "--salt",
        salt,
        "--length",
        "32",
        "--info",
        "authentication",
    ]);

    // Derive with different info
    let key_signing = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        ikm,
        "--salt",
        salt,
        "--length",
        "32",
        "--info",
        "signing",
    ]);

    assert_ne!(
        key_enc.trim(),
        key_auth.trim(),
        "HKDF with different info strings MUST produce different keys"
    );
    assert_ne!(
        key_enc.trim(),
        key_signing.trim(),
        "HKDF info='encryption' vs info='signing' MUST differ"
    );
    assert_ne!(
        key_auth.trim(),
        key_signing.trim(),
        "HKDF info='authentication' vs info='signing' MUST differ"
    );

    println!(
        "[PROOF] {{\"test\": \"hkdf_domain_separation\", \"category\": \"security\", \"standard\": \"RFC 5869 §3.2\", \"info_values\": [\"encryption\", \"authentication\", \"signing\"], \"all_keys_unique\": true, \"domain_separation_enforced\": true}}"
    );
}
// ============================================================================
// S49: PBKDF2 Salt Influence
// ============================================================================
//
// SP 800-132: The salt directly affects the derived key.
// Different salts with the same password MUST produce different keys.
// This prevents rainbow table attacks.
#[test]
fn test_pbkdf2_salt_influence_succeeds() {
    let password = "test-password-for-salt-check";

    let key_salt1 = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        password,
        "--salt",
        "000102030405060708090a0b0c0d0e0f",
        "--length",
        "32",
        "--allow-argv-secret",
    ]);

    let key_salt2 = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        password,
        "--salt",
        "ff0102030405060708090a0b0c0d0e0f",
        "--length",
        "32",
        "--allow-argv-secret",
    ]);

    assert_ne!(
        key_salt1.trim(),
        key_salt2.trim(),
        "PBKDF2 with different salts MUST produce different keys"
    );

    // Both must be valid 32-byte hex strings (64 hex chars)
    assert_eq!(key_salt1.trim().len(), 64, "PBKDF2 salt1: 32 bytes = 64 hex chars");
    assert_eq!(key_salt2.trim().len(), 64, "PBKDF2 salt2: 32 bytes = 64 hex chars");

    println!(
        "[PROOF] {{\"test\": \"pbkdf2_salt_influence\", \"category\": \"security\", \"standard\": \"SP 800-132\", \"salts_differ\": true, \"keys_differ\": true, \"rainbow_table_defense\": true}}"
    );
}
// ============================================================================
// S50: PBKDF2 Password Sensitivity
// ============================================================================
//
// Different passwords with the same salt and iterations MUST produce different keys.
#[test]
fn test_pbkdf2_password_sensitivity_succeeds() {
    let salt = "000102030405060708090a0b0c0d0e0f";

    let key_a = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "password-alpha",
        "--salt",
        salt,
        "--length",
        "32",
        "--iterations",
        "100000",
        // CLI enforces OWASP 600k floor (#62); test fixture uses small count.
        "--allow-weak-iterations",
        "--allow-argv-secret",
    ]);

    let key_b = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "password-beta",
        "--salt",
        salt,
        "--length",
        "32",
        "--iterations",
        "100000",
        "--allow-weak-iterations",
        "--allow-argv-secret",
    ]);

    assert_ne!(
        key_a.trim(),
        key_b.trim(),
        "PBKDF2 with different passwords MUST produce different keys"
    );

    println!(
        "[PROOF] {{\"test\": \"pbkdf2_password_sensitivity\", \"category\": \"security\", \"passwords\": [\"password-alpha\", \"password-beta\"], \"keys_differ\": true, \"password_sensitivity_verified\": true}}"
    );
}
// ============================================================================
// S61: Hash Algorithm Cross-Validation — Same Input, Different Algorithms
// ============================================================================
//
// Different hash algorithms applied to the same input MUST produce
// different outputs (unless there's a collision, which is astronomically unlikely).
#[test]
fn test_hash_cross_algorithm_divergence_succeeds() {
    let dir = temp_dir();
    let msg_path = dir.path().join("data.txt");
    std::fs::write(&msg_path, b"cross-algorithm hash divergence test data").unwrap();
    let msg = msg_path.to_str().unwrap();

    let sha3 = run_ok(&["hash", "--algorithm", "sha3-256", "--input", msg]);
    let sha256 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg]);
    let sha512 = run_ok(&["hash", "--algorithm", "sha-512", "--input", msg]);
    let blake2 = run_ok(&["hash", "--algorithm", "blake2b", "--input", msg]);

    // Extract hex values (strip algorithm prefix)
    let sha3_hex = sha3.trim().strip_prefix("SHA3-256: ").unwrap();
    let sha256_hex = sha256.trim().strip_prefix("SHA-256: ").unwrap();
    let blake2_hex = blake2.trim().strip_prefix("BLAKE2b-256: ").unwrap();

    // All 32-byte hashes must be different from each other
    assert_ne!(sha3_hex, sha256_hex, "SHA3-256 and SHA-256 must produce different outputs");
    assert_ne!(sha3_hex, blake2_hex, "SHA3-256 and BLAKE2b must produce different outputs");
    assert_ne!(sha256_hex, blake2_hex, "SHA-256 and BLAKE2b must produce different outputs");

    // SHA-512 is 64 bytes, can't collide with 32-byte hashes by length alone
    let sha512_hex = sha512.trim().strip_prefix("SHA-512: ").unwrap();
    assert_eq!(sha512_hex.len(), 128, "SHA-512 output = 64 bytes = 128 hex chars");

    println!(
        "[PROOF] {{\"test\": \"hash_cross_algorithm_divergence\", \"category\": \"correctness\", \"algorithms\": [\"SHA3-256\", \"SHA-256\", \"SHA-512\", \"BLAKE2b-256\"], \"all_outputs_unique\": true, \"no_cross_algorithm_collisions\": true}}"
    );
}
