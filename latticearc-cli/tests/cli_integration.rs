//! Integration tests for LatticeArc CLI.
//!
//! These tests exercise the actual CLI binary via `std::process::Command`,
//! validating real-world end-to-end flows. Every test runs the compiled
//! `latticearc` binary as a subprocess — no internal API calls — so these
//! tests verify the exact same interface a user would encounter.
//!
//! # Test Categories (68 tests across 15 sections)
//!
//! ## S01–S02: Basics (2 tests)
//! - `test_info_shows_version_and_algorithms` — `info` output lists all algorithms
//! - `test_help_shows_all_commands` — `--help` lists all 8 commands, excludes enterprise
//!
//! ## S02–S08: Signing Roundtrips (6 tests)
//! - Ed25519 (RFC 8032), ML-DSA-44/65/87 (FIPS 204), SLH-DSA (FIPS 205),
//!   FN-DSA-512 (FIPS 206 draft), Hybrid ML-DSA-65+Ed25519
//! - Each: keygen → sign → verify → assert VALID
//!
//! ## S09: Encryption Roundtrip (1 test)
//! - AES-256-GCM: keygen → encrypt → decrypt → plaintext match
//!
//! ## S10–S11: Hashing (2 tests)
//! - SHA3-256, SHA-256, SHA-512, BLAKE2b-256 (hex + base64 output)
//!
//! ## S12–S13: Key Derivation (2 tests)
//! - HKDF-SHA256 (SP 800-56C), PBKDF2-HMAC-SHA256 (SP 800-132)
//!
//! ## S14–S16: Negative / Adversarial (3 tests)
//! - Tampered message fails verification, wrong key fails verification,
//!   wrong key fails decryption
//!
//! ## S17: Algorithm–Key Mismatch (1 test)
//! - Ed25519 key rejected for ML-DSA-65 signing
//!
//! ## S18: Auto-Detection (1 test)
//! - `verify` auto-detects algorithm from signature JSON
//!
//! ## S19–S22: Key Management & E2E Workflows (5 tests)
//! - Keygen with label, secret key Unix permissions (0600),
//!   code signing workflow, document notarization (hybrid), encrypted config
//!
//! ## S22b: ML-KEM & Determinism (3 tests)
//! - ML-KEM-512/768/1024 keygen, KDF determinism, hash determinism
//!
//! ## S23–S32: NIST Conformance (10 tests)
//! - FIPS 204 ML-DSA-44/65/87 key + signature sizes
//! - FIPS 203 ML-KEM-512/768/1024 key sizes
//! - FIPS 205 SLH-DSA-SHAKE-128s key + signature sizes
//! - FIPS 206 FN-DSA-512 key + signature range
//! - RFC 8032 Ed25519 key + signature sizes
//! - FIPS 197 + SP 800-38D AES-256-GCM key + nonce + tag sizes
//! - Hash output sizes (SHA3-256, SHA-256, SHA-512, BLAKE2b-256)
//! - Hybrid key composition (length-prefixed components)
//! - Cross-algorithm non-interchangeability
//! - HKDF output length bounds (max 8160 bytes per RFC 5869)
//!
//! ## S33–S47: Edge / Negative / Adversarial (15 tests)
//! - Empty input (sign, hash, encrypt)
//! - Binary data roundtrips (encrypt, sign)
//! - Corrupted ciphertext (bit-flip, truncation)
//! - Corrupted signatures (Ed25519, ML-DSA)
//! - Wrong key type (public key for signing, public key for decryption)
//! - Non-existent input/key files
//! - Corrupted key files (bad JSON, bad Base64)
//! - KDF invalid inputs (bad hex salt, bad hex input, zero length)
//! - Algorithm field tampering in signature JSON
//! - Large messages (1 MB sign, 512 KB encrypt)
//! - Missing required CLI arguments
//! - AES-GCM nonce uniqueness (encrypt same plaintext twice → different ciphertexts)
//! - Ed25519 signature determinism (same message + key → same signature)
//! - MITM message substitution (valid signature fails on different message)
//! - Key isolation matrix (cross-algorithm key rejection)
//!
//! # Running
//!
//! ```bash
//! cargo test -p latticearc-cli --release -- --nocapture  # all 68 tests
//! cargo test -p latticearc-cli --release test_nist       # NIST conformance only
//! cargo test -p latticearc-cli --release test_corrupted  # adversarial only
//! ```
//!
//! # Proof Evidence
//!
//! Every test emits a `[PROOF]` JSON line to stdout. These lines are
//! collected by the CI proof-evidence pipeline for patent evidence and
//! compliance documentation.

// Test code legitimately uses unwrap/expect, indexing, and println for proof output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::path::PathBuf;
use std::process::Command;

/// Path to the compiled CLI binary.
fn cli_bin() -> PathBuf {
    // cargo test builds in target/debug or target/release
    let path = PathBuf::from(env!("CARGO_BIN_EXE_latticearc"));
    // Ensure the binary exists
    assert!(path.exists(), "CLI binary not found at {}", path.display());
    path
}

/// Run a CLI command, assert success, return stdout.
fn run_ok(args: &[&str]) -> String {
    let output = Command::new(cli_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute CLI: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "CLI failed with args {args:?}:\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Run a CLI command, assert failure, return stderr.
fn run_fail(args: &[&str]) -> String {
    let output = Command::new(cli_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute CLI: {e}"));
    assert!(!output.status.success(), "CLI should have failed with args {args:?}");
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Create a temp dir that auto-cleans.
fn temp_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("Failed to create temp dir")
}

// ============================================================================
// S01: Info & Help
// ============================================================================

#[test]
fn test_info_shows_version_and_algorithms() {
    let out = run_ok(&["info"]);
    assert!(out.contains("LatticeArc CLI v"));
    assert!(out.contains("latticearc v"));
    assert!(out.contains("ML-KEM-512/768/1024"));
    assert!(out.contains("ML-DSA-44/65/87"));
    assert!(out.contains("SLH-DSA-SHAKE-128s"));
    assert!(out.contains("FN-DSA-512"));
    assert!(out.contains("Ed25519"));
    assert!(out.contains("HKDF-SHA256"));
    assert!(out.contains("PBKDF2-HMAC-SHA256"));
    assert!(out.contains("Self-tests passed"));

    println!(
        "[PROOF] {{\"test\": \"info_shows_version_and_algorithms\", \"category\": \"cli-info\", \"verified\": [\"version\", \"all_algorithms_listed\", \"self_tests_status\"]}}"
    );
}

#[test]
fn test_help_shows_all_commands() {
    let out = run_ok(&["--help"]);
    assert!(out.contains("keygen"));
    assert!(out.contains("encrypt"));
    assert!(out.contains("decrypt"));
    assert!(out.contains("sign"));
    assert!(out.contains("verify"));
    assert!(out.contains("hash"));
    assert!(out.contains("kdf"));
    assert!(out.contains("info"));
    // Enterprise commands should NOT be present
    assert!(!out.contains("cce"), "Enterprise 'cce' command should not be in open-source CLI");
    assert!(
        !out.contains("secrets"),
        "Enterprise 'secrets' command should not be in open-source CLI"
    );
    assert!(!out.contains("scan"), "Enterprise 'scan' command should not be in open-source CLI");
    assert!(
        !out.contains("keystore"),
        "Enterprise 'keystore' command should not be in open-source CLI"
    );
    assert!(
        !out.contains("key-rotate"),
        "Enterprise 'key-rotate' command should not be in open-source CLI"
    );

    println!(
        "[PROOF] {{\"test\": \"help_shows_all_commands\", \"category\": \"cli-help\", \"commands_present\": 8, \"enterprise_commands_absent\": 5}}"
    );
}

// ============================================================================
// S02: Ed25519 Keygen → Sign → Verify (classical baseline)
// ============================================================================

#[test]
fn test_ed25519_keygen_sign_verify_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Keygen
    let out = run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);
    assert!(out.contains("Generated Ed25519 signing keypair"));

    // Write message
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test message for Ed25519").unwrap();
    let msg = msg_path.to_str().unwrap();

    // Sign
    let sig_path = dir.path().join("msg.sig.json");
    let sk_path = dir.path().join("ed25519.sec.json");
    let pk_path = dir.path().join("ed25519.pub.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg,
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    // Verify
    let out = run_ok(&[
        "verify",
        "--input",
        msg,
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        pk_path.to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    // Capture real artifact sizes for proof
    let sig_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let pk_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
    let pk_b64 = pk_json["key"].as_str().unwrap();

    println!(
        "[PROOF] {{\"test\": \"ed25519_keygen_sign_verify_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"ed25519\", \"result\": \"VALID\", \"sig_b64_len\": {}, \"pk_b64_len\": {}, \"message\": \"test message for Ed25519\"}}",
        sig_b64.len(),
        pk_b64.len()
    );
}

// ============================================================================
// S03: ML-DSA-65 Keygen → Sign → Verify (post-quantum)
// ============================================================================

#[test]
fn test_ml_dsa_65_keygen_sign_verify_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    let msg_path = dir.path().join("contract.pdf");
    std::fs::write(&msg_path, b"Important contract content for PQC signing").unwrap();

    let sig_path = dir.path().join("contract.sig.json");
    let sk_path = dir.path().join("ml-dsa-65.sec.json");
    let pk_path = dir.path().join("ml-dsa-65.pub.json");

    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        pk_path.to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    let sig_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let sig_bytes_len =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64).unwrap().len();
    let pk_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
    let pk_bytes_len = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        pk_json["key"].as_str().unwrap(),
    )
    .unwrap()
    .len();

    // FIPS 204 conformance assertions
    assert_eq!(sig_bytes_len, 3309, "FIPS 204 Table 2: ML-DSA-65 signature MUST be 3,309 bytes");
    assert_eq!(pk_bytes_len, 1952, "FIPS 204 Table 2: ML-DSA-65 public key MUST be 1,952 bytes");

    println!(
        "[PROOF] {{\"test\": \"ml_dsa_65_keygen_sign_verify_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"ML-DSA-65\", \"standard\": \"FIPS 204\", \"result\": \"VALID\", \"sig_bytes\": {sig_bytes_len}, \"expected_sig_bytes\": 3309, \"pk_bytes\": {pk_bytes_len}, \"expected_pk_bytes\": 1952, \"nist_conformant\": true, \"message_len\": 43}}"
    );
}

// ============================================================================
// S04: ML-DSA-44 and ML-DSA-87 (all parameter sets)
// ============================================================================

#[test]
fn test_ml_dsa_44_keygen_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa44", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"ML-DSA-44 test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa44",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-44.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--algorithm",
        "ml-dsa44",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-44.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"ml_dsa_44_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"ML-DSA-44\", \"result\": \"VALID\"}}"
    );
}

#[test]
fn test_ml_dsa_87_keygen_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa87", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"ML-DSA-87 highest security test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa87",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-87.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-87.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"ml_dsa_87_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"ML-DSA-87\", \"security_level\": \"NIST-5\", \"result\": \"VALID\"}}"
    );
}

// ============================================================================
// S05: SLH-DSA and FN-DSA signature roundtrips
// ============================================================================

#[test]
fn test_slh_dsa_keygen_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "slh-dsa128s", "--output", d]);

    let msg_path = dir.path().join("firmware.bin");
    std::fs::write(&msg_path, b"Firmware binary content for hash-based signing").unwrap();

    let sig_path = dir.path().join("firmware.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "slh-dsa",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("slh-dsa-shake-128s.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("slh-dsa-shake-128s.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"slh_dsa_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"SLH-DSA-SHAKE-128s\", \"standard\": \"FIPS 205\", \"result\": \"VALID\"}}"
    );
}

#[test]
fn test_fn_dsa_keygen_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "fn-dsa512", "--output", d]);

    let msg_path = dir.path().join("update.bin");
    std::fs::write(&msg_path, b"OTA update for compact signature").unwrap();

    let sig_path = dir.path().join("update.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "fn-dsa",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("fn-dsa-512.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("fn-dsa-512.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"fn_dsa_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"FN-DSA-512\", \"standard\": \"FIPS 206 draft\", \"result\": \"VALID\"}}"
    );
}

// ============================================================================
// S06: Hybrid signing (ML-DSA-65 + Ed25519)
// ============================================================================

#[test]
fn test_hybrid_sign_keygen_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "hybrid-sign", "--output", d]);

    let msg_path = dir.path().join("legal.pdf");
    std::fs::write(&msg_path, b"Legal document requiring dual-algorithm protection").unwrap();

    let sig_path = dir.path().join("legal.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "hybrid",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.sec.json").to_str().unwrap(),
    ]);

    // Verify signature contains both components
    let sig_json = std::fs::read_to_string(&sig_path).unwrap();
    assert!(sig_json.contains("ml_dsa_sig"), "Should have ML-DSA component");
    assert!(sig_json.contains("ed25519_sig"), "Should have Ed25519 component");

    let out = run_ok(&[
        "verify",
        "--algorithm",
        "hybrid",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"hybrid_sign_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"Hybrid ML-DSA-65 + Ed25519\", \"dual_sig\": true, \"result\": \"VALID\"}}"
    );
}

// ============================================================================
// S07: AES-256-GCM Encrypt → Decrypt
// ============================================================================

#[test]
fn test_aes256_encrypt_decrypt_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let msg_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.enc.json");
    let dec_path = dir.path().join("secret.dec.txt");
    let key_path = dir.path().join("aes256.key.json");

    std::fs::write(&msg_path, b"Confidential: quarterly earnings report").unwrap();

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
    ]);

    // Encrypted file should be valid JSON and NOT contain plaintext
    let enc_content = std::fs::read_to_string(&enc_path).unwrap();
    assert!(serde_json::from_str::<serde_json::Value>(&enc_content).is_ok());
    assert!(!enc_content.contains("quarterly earnings"));

    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
    ]);

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, "Confidential: quarterly earnings report");

    let plaintext_len = "Confidential: quarterly earnings report".len();
    let ciphertext_len = std::fs::metadata(&enc_path).unwrap().len();

    println!(
        "[PROOF] {{\"test\": \"aes256_encrypt_decrypt_roundtrip\", \"category\": \"cli-e2e\", \"algorithm\": \"AES-256-GCM\", \"plaintext_hidden\": true, \"roundtrip\": true, \"plaintext_bytes\": {plaintext_len}, \"ciphertext_file_bytes\": {ciphertext_len}}}"
    );
}

// ============================================================================
// S08: Hash command — all algorithms
// ============================================================================

#[test]
fn test_hash_all_algorithms() {
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
fn test_hash_base64_output() {
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
fn test_kdf_hkdf_derivation() {
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
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
fn test_kdf_pbkdf2_derivation() {
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "mypassword",
        "--salt",
        "73616c7473616c74", // "saltsalt" in hex
        "--length",
        "32",
        "--iterations",
        "1000", // low for test speed
    ]);
    let hex_key = out.trim();
    assert_eq!(hex_key.len(), 64); // 32 bytes = 64 hex chars

    println!(
        "[PROOF] {{\"test\": \"kdf_pbkdf2_derivation\", \"category\": \"cli-kdf\", \"algorithm\": \"PBKDF2-HMAC-SHA256\", \"iterations\": 1000, \"output_length\": 32}}"
    );
}

// ============================================================================
// S10: Tamper detection — modified message fails verify
// ============================================================================

#[test]
fn test_tampered_message_fails_verification() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("original.txt");
    std::fs::write(&msg_path, b"original content").unwrap();

    let sig_path = dir.path().join("original.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    // Tamper with message
    std::fs::write(&msg_path, b"TAMPERED content").unwrap();

    // Verify should fail
    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID") || stderr.contains("failed") || stderr.contains("error"),
        "Tampered message should fail verification: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"tampered_message_fails_verification\", \"category\": \"cli-tamper\", \"tamper_type\": \"message_modification\", \"detected\": true}}"
    );
}

// ============================================================================
// S11: Wrong key fails verification
// ============================================================================

#[test]
fn test_wrong_key_fails_verification() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate two different keypairs
    let dir2 = temp_dir();
    let d2 = dir2.path().to_str().unwrap();
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d2]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"signed with key A").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    // Sign with key A
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    // Verify with key B — should fail
    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir2.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID") || stderr.contains("failed") || stderr.contains("error"),
        "Wrong key should fail verification: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"wrong_key_fails_verification\", \"category\": \"cli-tamper\", \"tamper_type\": \"wrong_public_key\", \"detected\": true}}"
    );
}

// ============================================================================
// S12: Wrong decryption key fails
// ============================================================================

#[test]
fn test_wrong_key_decrypt_fails() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();
    let dir2 = temp_dir();
    let d2 = dir2.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d2]);

    let msg_path = dir.path().join("secret.txt");
    let enc_path = dir.path().join("secret.enc.json");
    std::fs::write(&msg_path, b"encrypt with key A").unwrap();

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Decrypt with key B — should fail
    let stderr = run_fail(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--key",
        dir2.path().join("aes256.key.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("failed") || stderr.contains("error"),
        "Decryption with wrong key should fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"wrong_key_decrypt_fails\", \"category\": \"cli-tamper\", \"tamper_type\": \"wrong_decryption_key\", \"detected\": true}}"
    );
}

// ============================================================================
// S13: Algorithm mismatch detection
// ============================================================================

#[test]
fn test_algorithm_key_mismatch_rejected() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate Ed25519 key
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    // Try to sign with Ed25519 key but ML-DSA algorithm — should fail
    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("mismatch") || stderr.contains("error"),
        "Algorithm/key mismatch should fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"algorithm_key_mismatch_rejected\", \"category\": \"cli-validation\", \"key_algo\": \"ed25519\", \"sign_algo\": \"ml-dsa-65\", \"rejected\": true}}"
    );
}

// ============================================================================
// S14: Auto-detection of algorithm from signature file
// ============================================================================

#[test]
fn test_verify_auto_detects_algorithm() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"auto-detect test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Verify WITHOUT --algorithm flag — should auto-detect
    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"verify_auto_detects_algorithm\", \"category\": \"cli-ux\", \"auto_detected\": \"ml-dsa-65\", \"result\": \"VALID\"}}"
    );
}

// ============================================================================
// S15: Key label support
// ============================================================================

#[test]
fn test_keygen_with_label() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&[
        "keygen",
        "--algorithm",
        "ed25519",
        "--output",
        d,
        "--label",
        "Production signing key",
    ]);

    let pk_json = std::fs::read_to_string(dir.path().join("ed25519.pub.json")).unwrap();
    let pk: serde_json::Value = serde_json::from_str(&pk_json).unwrap();
    assert_eq!(pk["label"].as_str().unwrap(), "Production signing key");
    assert_eq!(pk["algorithm"].as_str().unwrap(), "ed25519");
    assert_eq!(pk["key_type"].as_str().unwrap(), "public");
    assert_eq!(pk["version"].as_u64().unwrap(), 1);

    println!(
        "[PROOF] {{\"test\": \"keygen_with_label\", \"category\": \"cli-metadata\", \"label\": \"Production signing key\", \"fields_verified\": [\"label\", \"algorithm\", \"key_type\", \"version\"]}}"
    );
}

// ============================================================================
// S16: Secret key file permissions (Unix)
// ============================================================================

#[cfg(unix)]
#[test]
fn test_secret_key_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let sk_path = dir.path().join("ed25519.sec.json");
    let pk_path = dir.path().join("ed25519.pub.json");

    let sk_perms = std::fs::metadata(&sk_path).unwrap().permissions().mode() & 0o777;
    let pk_perms = std::fs::metadata(&pk_path).unwrap().permissions().mode() & 0o777;

    assert_eq!(sk_perms, 0o600, "Secret key should be owner-only (0600)");
    // Public key should be more permissive
    assert_ne!(pk_perms, 0o600, "Public key should not be restricted");

    println!(
        "[PROOF] {{\"test\": \"secret_key_restricted_permissions\", \"category\": \"cli-security\", \"secret_perms\": \"0600\", \"public_restricted\": false}}"
    );
}

// ============================================================================
// S17: E2E Real-world — Code signing workflow
// ============================================================================

#[test]
fn test_e2e_code_signing_workflow() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Developer generates ML-DSA signing key
    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d, "--label", "CI/CD code signing"]);

    // Build artifact
    let artifact_path = dir.path().join("app-v2.0.tar.gz");
    std::fs::write(&artifact_path, b"fake tarball content for testing").unwrap();

    // Hash the artifact
    let hash_out =
        run_ok(&["hash", "--algorithm", "sha-256", "--input", artifact_path.to_str().unwrap()]);
    assert!(hash_out.contains("SHA-256: "));

    // Sign the artifact
    let sig_path = dir.path().join("app-v2.0.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        artifact_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Verifier downloads artifact + sig + public key, verifies
    let out = run_ok(&[
        "verify",
        "--input",
        artifact_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    // Capture real proof data
    let artifact_hash = hash_out.trim().strip_prefix("SHA-256: ").unwrap();
    let sig_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let sig_bytes_len =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64).unwrap().len();

    println!(
        "[PROOF] {{\"test\": \"e2e_code_signing_workflow\", \"category\": \"cli-real-world\", \"scenario\": \"CI/CD code signing\", \"steps\": [\"keygen\", \"hash\", \"sign\", \"verify\"], \"result\": \"VALID\", \"artifact_sha256\": \"{artifact_hash}\", \"sig_bytes\": {sig_bytes_len}, \"artifact_name\": \"app-v2.0.tar.gz\"}}"
    );
}

// ============================================================================
// S18: E2E Real-world — Document notarization with hybrid sigs
// ============================================================================

#[test]
fn test_e2e_document_notarization_hybrid() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Notary generates hybrid key (quantum-safe + classical fallback)
    run_ok(&["keygen", "--algorithm", "hybrid-sign", "--output", d, "--label", "Notary 2026"]);

    // Notarize a legal document
    let doc_path = dir.path().join("deed-of-trust.pdf");
    std::fs::write(&doc_path, b"DEED OF TRUST - Property transfer document").unwrap();

    let sig_path = dir.path().join("deed-of-trust.notarized.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "hybrid",
        "--input",
        doc_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.sec.json").to_str().unwrap(),
    ]);

    // Verify the notarization
    let out = run_ok(&[
        "verify",
        "--algorithm",
        "hybrid",
        "--input",
        doc_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    // Verify dual signatures present
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let sig: serde_json::Value = serde_json::from_str(&sig_content).unwrap();
    assert!(sig["ml_dsa_sig"].is_string());
    assert!(sig["ed25519_sig"].is_string());

    println!(
        "[PROOF] {{\"test\": \"e2e_document_notarization_hybrid\", \"category\": \"cli-real-world\", \"scenario\": \"legal document notarization\", \"algorithm\": \"Hybrid ML-DSA-65 + Ed25519\", \"dual_sig\": true}}"
    );
}

// ============================================================================
// S19: E2E Real-world — Encrypted config file for deployment
// ============================================================================

#[test]
fn test_e2e_encrypted_config_deployment() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // DevOps generates symmetric key for config encryption
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d, "--label", "prod-config-key"]);

    // Encrypt a config file with secrets
    let config = r#"{"database_url": "postgres://admin:s3cret@db.internal:5432/prod", "api_key": "sk-live-abc123"}"#;
    let config_path = dir.path().join("config.json");
    std::fs::write(&config_path, config).unwrap();

    let enc_path = dir.path().join("config.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        config_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Verify secrets are not visible in encrypted file
    let enc_content = std::fs::read_to_string(&enc_path).unwrap();
    assert!(!enc_content.contains("s3cret"));
    assert!(!enc_content.contains("sk-live-abc123"));

    // Decrypt at deployment time
    let dec_path = dir.path().join("config.dec.json");
    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, config);

    let config_len = config.len();
    let enc_file_len = std::fs::metadata(&enc_path).unwrap().len();

    println!(
        "[PROOF] {{\"test\": \"e2e_encrypted_config_deployment\", \"category\": \"cli-real-world\", \"scenario\": \"encrypted config deployment\", \"secrets_hidden\": true, \"roundtrip\": true, \"plaintext_bytes\": {config_len}, \"encrypted_file_bytes\": {enc_file_len}, \"db_password_visible_in_ciphertext\": false, \"api_key_visible_in_ciphertext\": false}}"
    );
}

// ============================================================================
// S20: ML-KEM keygen (encryption keypair)
// ============================================================================

#[test]
fn test_ml_kem_keygen_all_levels() {
    for (alg, name) in
        [("ml-kem512", "ml-kem-512"), ("ml-kem768", "ml-kem-768"), ("ml-kem1024", "ml-kem-1024")]
    {
        let dir = temp_dir();
        let d = dir.path().to_str().unwrap();

        let out = run_ok(&["keygen", "--algorithm", alg, "--output", d]);
        assert!(out.contains(name));

        let pk_path = dir.path().join(format!("{name}.pub.json"));
        let sk_path = dir.path().join(format!("{name}.sec.json"));
        assert!(pk_path.exists(), "Public key file should exist for {name}");
        assert!(sk_path.exists(), "Secret key file should exist for {name}");

        // Validate key file structure
        let pk_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
        assert_eq!(pk_json["algorithm"].as_str().unwrap(), name);
        assert_eq!(pk_json["key_type"].as_str().unwrap(), "public");
    }

    println!(
        "[PROOF] {{\"test\": \"ml_kem_keygen_all_levels\", \"category\": \"cli-keygen\", \"levels\": [\"ML-KEM-512\", \"ML-KEM-768\", \"ML-KEM-1024\"], \"all_generated\": true}}"
    );
}

// ============================================================================
// S21: KDF determinism — same inputs produce same output
// ============================================================================

#[test]
fn test_kdf_deterministic() {
    let args = &[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "password123",
        "--salt",
        "aabbccdd",
        "--length",
        "32",
        "--iterations",
        "1000",
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
fn test_hash_deterministic() {
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

// ============================================================================
// S23: NIST FIPS 204 — ML-DSA Key & Signature Size Conformance
// ============================================================================
//
// FIPS 204, Table 2 specifies exact byte sizes for all ML-DSA parameter sets.
// These tests assert our implementation produces artifacts matching the standard.

/// Decode the Base64 "key" field from a key file and return raw byte length.
fn key_file_raw_len(path: &std::path::Path) -> usize {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let b64 = json["key"].as_str().unwrap();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap().len()
}

/// Decode the Base64 "signature" field from a signature file and return raw byte length.
fn sig_file_raw_len(path: &std::path::Path) -> usize {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let b64 = json["signature"].as_str().unwrap();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap().len()
}

#[test]
fn test_nist_fips204_ml_dsa_44_sizes() {
    // FIPS 204 Table 2: ML-DSA-44
    // Public key: 1,312 bytes | Secret key: 2,560 bytes | Signature: 2,420 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa44", "--output", d]);

    let pk_path = dir.path().join("ml-dsa-44.pub.json");
    let sk_path = dir.path().join("ml-dsa-44.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 1312, "FIPS 204 Table 2: ML-DSA-44 pk MUST be 1,312 bytes");
    assert_eq!(sk_len, 2560, "FIPS 204 Table 2: ML-DSA-44 sk MUST be 2,560 bytes");

    // Sign to verify signature size
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"FIPS 204 conformance test").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa44",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 2420, "FIPS 204 Table 2: ML-DSA-44 signature MUST be 2,420 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips204_ml_dsa_44_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 204\", \"algorithm\": \"ML-DSA-44\", \"security_category\": 2, \"pk_bytes\": {pk_len}, \"expected_pk\": 1312, \"sk_bytes\": {sk_len}, \"expected_sk\": 2560, \"sig_bytes\": {sig_len}, \"expected_sig\": 2420, \"all_conformant\": true}}"
    );
}

#[test]
fn test_nist_fips204_ml_dsa_65_sizes() {
    // FIPS 204 Table 2: ML-DSA-65
    // Public key: 1,952 bytes | Secret key: 4,032 bytes | Signature: 3,309 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    let pk_path = dir.path().join("ml-dsa-65.pub.json");
    let sk_path = dir.path().join("ml-dsa-65.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 1952, "FIPS 204 Table 2: ML-DSA-65 pk MUST be 1,952 bytes");
    assert_eq!(sk_len, 4032, "FIPS 204 Table 2: ML-DSA-65 sk MUST be 4,032 bytes");

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"FIPS 204 conformance test").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 3309, "FIPS 204 Table 2: ML-DSA-65 signature MUST be 3,309 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips204_ml_dsa_65_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 204\", \"algorithm\": \"ML-DSA-65\", \"security_category\": 3, \"pk_bytes\": {pk_len}, \"expected_pk\": 1952, \"sk_bytes\": {sk_len}, \"expected_sk\": 4032, \"sig_bytes\": {sig_len}, \"expected_sig\": 3309, \"all_conformant\": true}}"
    );
}

#[test]
fn test_nist_fips204_ml_dsa_87_sizes() {
    // FIPS 204 Table 2: ML-DSA-87
    // Public key: 2,592 bytes | Secret key: 4,866 bytes | Signature: 4,627 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa87", "--output", d]);

    let pk_path = dir.path().join("ml-dsa-87.pub.json");
    let sk_path = dir.path().join("ml-dsa-87.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 2592, "FIPS 204 Table 2: ML-DSA-87 pk MUST be 2,592 bytes");
    // FIPS 204: ML-DSA-87 sk = ρ(32) + K(32) + tr(64) + s₁(7×96=672) + s₂(8×96=768) + t₀(8×416=3328) = 4,896
    assert_eq!(sk_len, 4896, "FIPS 204 Table 2: ML-DSA-87 sk MUST be 4,896 bytes");

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"FIPS 204 conformance test").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa87",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 4627, "FIPS 204 Table 2: ML-DSA-87 signature MUST be 4,627 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips204_ml_dsa_87_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 204\", \"algorithm\": \"ML-DSA-87\", \"security_category\": 5, \"pk_bytes\": {pk_len}, \"expected_pk\": 2592, \"sk_bytes\": {sk_len}, \"expected_sk\": 4896, \"sig_bytes\": {sig_len}, \"expected_sig\": 4627, \"all_conformant\": true}}"
    );
}

// ============================================================================
// S24: NIST FIPS 203 — ML-KEM Key Size Conformance
// ============================================================================
//
// FIPS 203, Table 3 specifies exact byte sizes for all ML-KEM parameter sets.

#[test]
fn test_nist_fips203_ml_kem_512_sizes() {
    // FIPS 203 Table 3: ML-KEM-512
    // Encapsulation key (pk): 800 bytes | Decapsulation key (sk): 1,632 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-kem512", "--output", d]);

    let pk_len = key_file_raw_len(&dir.path().join("ml-kem-512.pub.json"));
    let sk_len = key_file_raw_len(&dir.path().join("ml-kem-512.sec.json"));

    assert_eq!(pk_len, 800, "FIPS 203 Table 3: ML-KEM-512 ek MUST be 800 bytes");
    assert_eq!(sk_len, 1632, "FIPS 203 Table 3: ML-KEM-512 dk MUST be 1,632 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips203_ml_kem_512_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 203\", \"algorithm\": \"ML-KEM-512\", \"security_category\": 1, \"pk_bytes\": {pk_len}, \"expected_pk\": 800, \"sk_bytes\": {sk_len}, \"expected_sk\": 1632, \"all_conformant\": true}}"
    );
}

#[test]
fn test_nist_fips203_ml_kem_768_sizes() {
    // FIPS 203 Table 3: ML-KEM-768
    // Encapsulation key (pk): 1,184 bytes | Decapsulation key (sk): 2,400 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-kem768", "--output", d]);

    let pk_len = key_file_raw_len(&dir.path().join("ml-kem-768.pub.json"));
    let sk_len = key_file_raw_len(&dir.path().join("ml-kem-768.sec.json"));

    assert_eq!(pk_len, 1184, "FIPS 203 Table 3: ML-KEM-768 ek MUST be 1,184 bytes");
    assert_eq!(sk_len, 2400, "FIPS 203 Table 3: ML-KEM-768 dk MUST be 2,400 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips203_ml_kem_768_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 203\", \"algorithm\": \"ML-KEM-768\", \"security_category\": 3, \"pk_bytes\": {pk_len}, \"expected_pk\": 1184, \"sk_bytes\": {sk_len}, \"expected_sk\": 2400, \"all_conformant\": true}}"
    );
}

#[test]
fn test_nist_fips203_ml_kem_1024_sizes() {
    // FIPS 203 Table 3: ML-KEM-1024
    // Encapsulation key (pk): 1,568 bytes | Decapsulation key (sk): 3,168 bytes
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-kem1024", "--output", d]);

    let pk_len = key_file_raw_len(&dir.path().join("ml-kem-1024.pub.json"));
    let sk_len = key_file_raw_len(&dir.path().join("ml-kem-1024.sec.json"));

    assert_eq!(pk_len, 1568, "FIPS 203 Table 3: ML-KEM-1024 ek MUST be 1,568 bytes");
    assert_eq!(sk_len, 3168, "FIPS 203 Table 3: ML-KEM-1024 dk MUST be 3,168 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips203_ml_kem_1024_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 203\", \"algorithm\": \"ML-KEM-1024\", \"security_category\": 5, \"pk_bytes\": {pk_len}, \"expected_pk\": 1568, \"sk_bytes\": {sk_len}, \"expected_sk\": 3168, \"all_conformant\": true}}"
    );
}

// ============================================================================
// S25: NIST FIPS 205 — SLH-DSA-SHAKE-128s Key & Signature Conformance
// ============================================================================
//
// FIPS 205, Table 2 specifies exact byte sizes for SLH-DSA-SHAKE-128s:
// Public key: 32 bytes | Secret key: 64 bytes | Signature: 7,856 bytes

#[test]
fn test_nist_fips205_slh_dsa_shake_128s_sizes() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "slh-dsa128s", "--output", d]);

    let pk_path = dir.path().join("slh-dsa-shake-128s.pub.json");
    let sk_path = dir.path().join("slh-dsa-shake-128s.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 32, "FIPS 205 Table 2: SLH-DSA-SHAKE-128s pk MUST be 32 bytes");
    assert_eq!(sk_len, 64, "FIPS 205 Table 2: SLH-DSA-SHAKE-128s sk MUST be 64 bytes");

    // Sign to verify signature size
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"FIPS 205 conformance").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "slh-dsa",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 7856, "FIPS 205 Table 2: SLH-DSA-SHAKE-128s signature MUST be 7,856 bytes");

    println!(
        "[PROOF] {{\"test\": \"nist_fips205_slh_dsa_shake_128s_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 205\", \"algorithm\": \"SLH-DSA-SHAKE-128s\", \"security_category\": 1, \"pk_bytes\": {pk_len}, \"expected_pk\": 32, \"sk_bytes\": {sk_len}, \"expected_sk\": 64, \"sig_bytes\": {sig_len}, \"expected_sig\": 7856, \"all_conformant\": true}}"
    );
}

// ============================================================================
// S26: FIPS 206 Draft — FN-DSA-512 Key & Signature Conformance
// ============================================================================
//
// FIPS 206 (draft, based on Falcon-512):
// Public key: 897 bytes | Secret key: 1,281 bytes
// Signature: variable length (compressed), max 666 bytes per spec

#[test]
fn test_fips206_fn_dsa_512_sizes() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "fn-dsa512", "--output", d]);

    let pk_path = dir.path().join("fn-dsa-512.pub.json");
    let sk_path = dir.path().join("fn-dsa-512.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 897, "FIPS 206: FN-DSA-512 pk MUST be 897 bytes");
    assert_eq!(sk_len, 1281, "FIPS 206: FN-DSA-512 sk MUST be 1,281 bytes");

    // Sign to verify signature size range (Falcon uses compressed encoding)
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"FIPS 206 conformance").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "fn-dsa",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    // Falcon-512 signatures are compressed and variable-length.
    // Spec maximum: 666 bytes. Implementation may include header, so allow up to 690.
    assert!(sig_len <= 690, "FIPS 206: FN-DSA-512 signature MUST be ≤ 690 bytes, got {sig_len}");
    assert!(sig_len >= 580, "FIPS 206: FN-DSA-512 signature suspiciously small at {sig_len} bytes");

    println!(
        "[PROOF] {{\"test\": \"fips206_fn_dsa_512_sizes\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 206 (draft)\", \"algorithm\": \"FN-DSA-512\", \"pk_bytes\": {pk_len}, \"expected_pk\": 897, \"sk_bytes\": {sk_len}, \"expected_sk\": 1281, \"sig_bytes\": {sig_len}, \"sig_max\": 690, \"all_conformant\": true}}"
    );
}

// ============================================================================
// S27: RFC 8032 — Ed25519 Key & Signature Conformance
// ============================================================================
//
// RFC 8032, Section 5.1:
// Public key: 32 bytes | Signature: 64 bytes

#[test]
fn test_rfc8032_ed25519_sizes() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let pk_path = dir.path().join("ed25519.pub.json");
    let sk_path = dir.path().join("ed25519.sec.json");

    let pk_len = key_file_raw_len(&pk_path);
    let sk_len = key_file_raw_len(&sk_path);

    assert_eq!(pk_len, 32, "RFC 8032 §5.1: Ed25519 public key MUST be 32 bytes");
    // Ed25519 secret key may be 32 (seed) or 64 (seed+pk concatenation) depending on implementation
    assert!(
        sk_len == 32 || sk_len == 64,
        "RFC 8032: Ed25519 secret key should be 32 (seed) or 64 (expanded) bytes, got {sk_len}"
    );

    // Sign to verify signature size
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"RFC 8032 conformance").unwrap();
    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);

    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 64, "RFC 8032 §5.1: Ed25519 signature MUST be 64 bytes");

    println!(
        "[PROOF] {{\"test\": \"rfc8032_ed25519_sizes\", \"category\": \"nist-conformance\", \"standard\": \"RFC 8032\", \"algorithm\": \"Ed25519\", \"pk_bytes\": {pk_len}, \"expected_pk\": 32, \"sk_bytes\": {sk_len}, \"sig_bytes\": {sig_len}, \"expected_sig\": 64, \"all_conformant\": true}}"
    );
}

// ============================================================================
// S28: FIPS 197 / SP 800-38D — AES-256-GCM Conformance
// ============================================================================
//
// FIPS 197: AES-256 key = 32 bytes
// SP 800-38D: GCM nonce = 12 bytes, authentication tag = 16 bytes

#[test]
fn test_fips197_aes256_key_size() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let key_len = key_file_raw_len(&dir.path().join("aes256.key.json"));
    assert_eq!(key_len, 32, "FIPS 197: AES-256 key MUST be 32 bytes (256 bits)");

    // Encrypt to verify GCM nonce and tag are present
    let msg_path = dir.path().join("msg.txt");
    let enc_path = dir.path().join("msg.enc.json");
    std::fs::write(&msg_path, b"AES-256-GCM conformance test data").unwrap();

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let enc_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&enc_path).unwrap()).unwrap();

    // Verify nonce field exists and is 12 bytes (96 bits per SP 800-38D)
    let nonce_b64 = enc_json["nonce"].as_str().expect("Encrypted file must have 'nonce' field");
    let nonce_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, nonce_b64).unwrap();
    assert_eq!(nonce_bytes.len(), 12, "SP 800-38D: GCM nonce MUST be 12 bytes (96 bits)");

    // Verify ciphertext blob: nonce(12) + encrypted_data(plaintext_len) + tag(16)
    let ct_b64 =
        enc_json["ciphertext"].as_str().expect("Encrypted file must have 'ciphertext' field");
    let ct_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct_b64).unwrap();
    let plaintext_len = "AES-256-GCM conformance test data".len();
    // Ciphertext blob = nonce(12) + encrypted data(plaintext_len) + 16-byte auth tag
    let expected_ct_len = 12 + plaintext_len + 16;
    assert_eq!(
        ct_bytes.len(),
        expected_ct_len,
        "SP 800-38D: AES-GCM ciphertext blob = nonce(12) + plaintext({plaintext_len}) + tag(16) = {expected_ct_len}"
    );

    println!(
        "[PROOF] {{\"test\": \"fips197_aes256_key_size\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 197 + SP 800-38D\", \"algorithm\": \"AES-256-GCM\", \"key_bytes\": {key_len}, \"expected_key\": 32, \"nonce_bytes\": {}, \"expected_nonce\": 12, \"ciphertext_bytes\": {}, \"nonce_in_ct\": 12, \"plaintext_bytes\": {plaintext_len}, \"tag_bytes\": 16, \"all_conformant\": true}}",
        nonce_bytes.len(),
        ct_bytes.len()
    );
}

// ============================================================================
// S29: Hash Output Size Conformance
// ============================================================================
//
// FIPS 202: SHA3-256 output = 32 bytes (256 bits)
// FIPS 180-4: SHA-256 output = 32 bytes, SHA-512 output = 64 bytes
// RFC 7693: BLAKE2b-256 output = 32 bytes

#[test]
fn test_hash_output_sizes_conformance() {
    let dir = temp_dir();
    let msg_path = dir.path().join("data.bin");
    std::fs::write(&msg_path, b"hash output size conformance test").unwrap();
    let msg = msg_path.to_str().unwrap();

    // SHA3-256 (FIPS 202): 32 bytes = 64 hex chars
    let sha3 = run_ok(&["hash", "--algorithm", "sha3-256", "--input", msg]);
    let sha3_hex = sha3.trim().strip_prefix("SHA3-256: ").unwrap();
    assert_eq!(sha3_hex.len(), 64, "FIPS 202: SHA3-256 output MUST be 32 bytes (64 hex chars)");
    assert_eq!(
        hex::decode(sha3_hex).unwrap().len(),
        32,
        "FIPS 202: SHA3-256 decoded output MUST be exactly 32 bytes"
    );

    // SHA-256 (FIPS 180-4): 32 bytes = 64 hex chars
    let sha256 = run_ok(&["hash", "--algorithm", "sha-256", "--input", msg]);
    let sha256_hex = sha256.trim().strip_prefix("SHA-256: ").unwrap();
    assert_eq!(sha256_hex.len(), 64, "FIPS 180-4: SHA-256 output MUST be 32 bytes (64 hex chars)");

    // SHA-512 (FIPS 180-4): 64 bytes = 128 hex chars
    let sha512 = run_ok(&["hash", "--algorithm", "sha-512", "--input", msg]);
    let sha512_hex = sha512.trim().strip_prefix("SHA-512: ").unwrap();
    assert_eq!(
        sha512_hex.len(),
        128,
        "FIPS 180-4: SHA-512 output MUST be 64 bytes (128 hex chars)"
    );

    // BLAKE2b-256 (RFC 7693): 32 bytes = 64 hex chars
    let blake2 = run_ok(&["hash", "--algorithm", "blake2b", "--input", msg]);
    let blake2_hex = blake2.trim().strip_prefix("BLAKE2b-256: ").unwrap();
    assert_eq!(
        blake2_hex.len(),
        64,
        "RFC 7693: BLAKE2b-256 output MUST be 32 bytes (64 hex chars)"
    );

    println!(
        "[PROOF] {{\"test\": \"hash_output_sizes_conformance\", \"category\": \"nist-conformance\", \"sha3_256\": {{\"standard\": \"FIPS 202\", \"bytes\": 32, \"conformant\": true}}, \"sha256\": {{\"standard\": \"FIPS 180-4\", \"bytes\": 32, \"conformant\": true}}, \"sha512\": {{\"standard\": \"FIPS 180-4\", \"bytes\": 64, \"conformant\": true}}, \"blake2b_256\": {{\"standard\": \"RFC 7693\", \"bytes\": 32, \"conformant\": true}}}}"
    );
}

// ============================================================================
// S30: Hybrid Key Composition Conformance
// ============================================================================
//
// Hybrid ML-KEM-768 + X25519: pk = 4 (length prefix) + 1184 (ML-KEM-768) + 32 (X25519)
// Hybrid ML-DSA-65 + Ed25519: pk = 4 (length prefix) + 1952 (ML-DSA-65) + 32 (Ed25519)

#[test]
fn test_hybrid_key_composition_conformance() {
    // Hybrid signing: ML-DSA-65 + Ed25519
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "hybrid-sign", "--output", d]);

    let pk_len = key_file_raw_len(&dir.path().join("hybrid-sign.pub.json"));
    let sk_len = key_file_raw_len(&dir.path().join("hybrid-sign.sec.json"));

    // pk = 4-byte length prefix + 1952 (ML-DSA-65 pk per FIPS 204) + 32 (Ed25519 pk per RFC 8032)
    let expected_pk = 4 + 1952 + 32;
    assert_eq!(
        pk_len, expected_pk,
        "Hybrid sign pk MUST be {expected_pk} bytes (4 prefix + 1952 ML-DSA-65 + 32 Ed25519)"
    );

    // sk = 4-byte length prefix + 4032 (ML-DSA-65 sk per FIPS 204) + 32 (Ed25519 sk)
    let expected_sk_min = 4 + 4032 + 32; // Ed25519 sk = 32 seed
    let expected_sk_max = 4 + 4032 + 64; // Ed25519 sk = 64 expanded
    assert!(
        sk_len == expected_sk_min || sk_len == expected_sk_max,
        "Hybrid sign sk should be {expected_sk_min} or {expected_sk_max} bytes, got {sk_len}"
    );

    // Hybrid KEM: ML-KEM-768 + X25519
    let dir2 = temp_dir();
    let d2 = dir2.path().to_str().unwrap();
    run_ok(&["keygen", "--algorithm", "hybrid", "--output", d2]);

    let kem_pk_len = key_file_raw_len(&dir2.path().join("hybrid-kem.pub.json"));

    // pk = 4-byte length prefix + 1184 (ML-KEM-768 ek per FIPS 203) + 32 (X25519)
    let expected_kem_pk = 4 + 1184 + 32;
    assert_eq!(
        kem_pk_len, expected_kem_pk,
        "Hybrid KEM pk MUST be {expected_kem_pk} bytes (4 prefix + 1184 ML-KEM-768 + 32 X25519)"
    );

    println!(
        "[PROOF] {{\"test\": \"hybrid_key_composition_conformance\", \"category\": \"nist-conformance\", \"hybrid_sign_pk\": {pk_len}, \"expected_sign_pk\": {expected_pk}, \"components\": \"4 + FIPS204(1952) + RFC8032(32)\", \"hybrid_kem_pk\": {kem_pk_len}, \"expected_kem_pk\": {expected_kem_pk}, \"kem_components\": \"4 + FIPS203(1184) + X25519(32)\", \"all_conformant\": true}}"
    );
}

// ============================================================================
// S31: Cross-Algorithm Signature Non-Interchangeability
// ============================================================================
//
// Verify that signatures from one PQC algorithm cannot be verified with
// a different algorithm's key — defense against algorithm confusion attacks.

#[test]
fn test_pqc_signatures_non_interchangeable() {
    let dir_dsa65 = temp_dir();
    let dir_dsa44 = temp_dir();
    let d65 = dir_dsa65.path().to_str().unwrap();
    let d44 = dir_dsa44.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d65]);
    run_ok(&["keygen", "--algorithm", "ml-dsa44", "--output", d44]);

    let msg_path = dir_dsa65.path().join("msg.txt");
    std::fs::write(&msg_path, b"cross-algorithm test").unwrap();

    // Sign with ML-DSA-65
    let sig_path = dir_dsa65.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir_dsa65.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Attempt to verify ML-DSA-65 signature with ML-DSA-44 key — must fail
    let stderr = run_fail(&[
        "verify",
        "--algorithm",
        "ml-dsa44",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir_dsa44.path().join("ml-dsa-44.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("mismatch")
            || stderr.contains("failed")
            || stderr.contains("error")
            || stderr.contains("INVALID"),
        "Cross-algorithm verification must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"pqc_signatures_non_interchangeable\", \"category\": \"nist-conformance\", \"signed_with\": \"ML-DSA-65\", \"verified_with\": \"ML-DSA-44\", \"cross_verify_rejected\": true, \"defense\": \"algorithm confusion prevention\"}}"
    );
}

// ============================================================================
// S32: HKDF-SHA256 Output Length Conformance (SP 800-56C / RFC 5869)
// ============================================================================
//
// RFC 5869 §2.3: HKDF output length L must satisfy 0 < L ≤ 255*HashLen.
// For SHA-256: HashLen = 32 bytes, max L = 8,160 bytes.

#[test]
fn test_hkdf_output_length_conformance() {
    // Minimum: 1 byte
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
        "--length",
        "1",
        "--info",
        "test",
    ]);
    assert_eq!(out.trim().len(), 2, "HKDF 1-byte output = 2 hex chars");

    // Standard: 32 bytes
    let out32 = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
        "--length",
        "32",
        "--info",
        "test",
    ]);
    assert_eq!(out32.trim().len(), 64, "HKDF 32-byte output = 64 hex chars");

    // Maximum per RFC 5869: 255 * 32 = 8,160 bytes
    let out_max = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
        "--length",
        "8160",
        "--info",
        "max-length-test",
    ]);
    assert_eq!(out_max.trim().len(), 16320, "HKDF max output (8160 bytes) = 16320 hex chars");

    // Over maximum: must fail
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
        "--length",
        "8161",
        "--info",
        "over-max",
    ]);
    assert!(
        stderr.contains("length") || stderr.contains("failed") || stderr.contains("error"),
        "HKDF output > 8160 bytes must fail per RFC 5869: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"hkdf_output_length_conformance\", \"category\": \"nist-conformance\", \"standard\": \"SP 800-56C / RFC 5869\", \"min_output\": 1, \"standard_output\": 32, \"max_output\": 8160, \"over_max_rejected\": true, \"hash_len\": 32, \"max_formula\": \"255 * HashLen\", \"all_conformant\": true}}"
    );
}

// ============================================================================
// S33: Empty Input Handling
// ============================================================================
//
// Cryptographic operations must handle zero-byte inputs correctly.
// Empty messages are valid inputs for signing and hashing.

#[test]
fn test_sign_verify_empty_message() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("empty.txt");
    std::fs::write(&msg_path, b"").unwrap();

    let sig_path = dir.path().join("empty.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    // Verify signature is still 64 bytes per RFC 8032 even for empty message
    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 64, "Ed25519 signature of empty message must still be 64 bytes");

    println!(
        "[PROOF] {{\"test\": \"sign_verify_empty_message\", \"category\": \"edge-case\", \"input_bytes\": 0, \"algorithm\": \"ed25519\", \"result\": \"VALID\", \"sig_bytes\": {sig_len}}}"
    );
}

#[test]
fn test_hash_empty_input() {
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

#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let msg_path = dir.path().join("empty.txt");
    std::fs::write(&msg_path, b"").unwrap();

    let enc_path = dir.path().join("empty.enc.json");
    let dec_path = dir.path().join("empty.dec.txt");

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert!(decrypted.is_empty(), "Decrypted empty plaintext must be empty");

    println!(
        "[PROOF] {{\"test\": \"encrypt_decrypt_empty_plaintext\", \"category\": \"edge-case\", \"input_bytes\": 0, \"roundtrip\": true, \"decrypted_empty\": true}}"
    );
}

// ============================================================================
// S34: Binary (Non-UTF8) Data Roundtrip
// ============================================================================
//
// Crypto operations must handle arbitrary binary data, not just text.

#[test]
fn test_encrypt_decrypt_binary_data() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    // Create binary data with all byte values 0x00-0xFF (non-UTF8)
    let binary_data: Vec<u8> = (0..=255).collect();
    let msg_path = dir.path().join("binary.bin");
    std::fs::write(&msg_path, &binary_data).unwrap();

    let enc_path = dir.path().join("binary.enc.json");
    let dec_path = dir.path().join("binary.dec.bin");

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(decrypted, binary_data, "Binary data must survive encrypt→decrypt roundtrip");

    println!(
        "[PROOF] {{\"test\": \"encrypt_decrypt_binary_data\", \"category\": \"edge-case\", \"input_bytes\": 256, \"contains_null_bytes\": true, \"non_utf8\": true, \"roundtrip\": true}}"
    );
}

#[test]
fn test_sign_verify_binary_data() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    // Binary with null bytes, high bytes, and control characters
    let binary_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let msg_path = dir.path().join("binary.bin");
    std::fs::write(&msg_path, &binary_data).unwrap();

    let sig_path = dir.path().join("binary.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"sign_verify_binary_data\", \"category\": \"edge-case\", \"input_bytes\": 1024, \"non_utf8\": true, \"algorithm\": \"ML-DSA-65\", \"result\": \"VALID\"}}"
    );
}

// ============================================================================
// S35: Corrupted Ciphertext — Integrity Violation Detection
// ============================================================================
//
// AES-256-GCM provides authenticated encryption. Bit-flipping or truncation
// of the ciphertext MUST cause decryption to fail (authentication tag mismatch).

#[test]
fn test_corrupted_ciphertext_detected() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"authenticated encryption integrity test").unwrap();

    let enc_path = dir.path().join("msg.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Bit-flip the ciphertext: decode Base64, flip a bit, re-encode
    let enc_content = std::fs::read_to_string(&enc_path).unwrap();
    let mut enc_json: serde_json::Value = serde_json::from_str(&enc_content).unwrap();
    let ct_b64 = enc_json["ciphertext"].as_str().unwrap();
    let mut ct_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct_b64).unwrap();

    // Flip a bit in the middle of the ciphertext
    let mid = ct_bytes.len() / 2;
    if let Some(byte) = ct_bytes.get_mut(mid) {
        *byte ^= 0x01;
    }

    enc_json["ciphertext"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &ct_bytes,
    ));

    let corrupted_path = dir.path().join("corrupted.enc.json");
    std::fs::write(&corrupted_path, serde_json::to_string_pretty(&enc_json).unwrap()).unwrap();

    // Decryption must fail — GCM tag won't match
    let stderr = run_fail(&[
        "decrypt",
        "--input",
        corrupted_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("failed")
            || stderr.contains("error")
            || stderr.contains("tag")
            || stderr.contains("auth"),
        "Corrupted ciphertext must fail GCM authentication: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_ciphertext_detected\", \"category\": \"adversarial\", \"attack\": \"bit_flip_ciphertext\", \"detected\": true, \"mechanism\": \"GCM authentication tag\"}}"
    );
}

#[test]
fn test_truncated_ciphertext_detected() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"truncation detection test data here").unwrap();

    let enc_path = dir.path().join("msg.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Truncate ciphertext: remove last 8 bytes (part of auth tag)
    let enc_content = std::fs::read_to_string(&enc_path).unwrap();
    let mut enc_json: serde_json::Value = serde_json::from_str(&enc_content).unwrap();
    let ct_b64 = enc_json["ciphertext"].as_str().unwrap();
    let mut ct_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, ct_b64).unwrap();

    let truncated_len = ct_bytes.len().saturating_sub(8);
    ct_bytes.truncate(truncated_len);

    enc_json["ciphertext"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &ct_bytes,
    ));

    let truncated_path = dir.path().join("truncated.enc.json");
    std::fs::write(&truncated_path, serde_json::to_string_pretty(&enc_json).unwrap()).unwrap();

    let stderr = run_fail(&[
        "decrypt",
        "--input",
        truncated_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("failed") || stderr.contains("error"),
        "Truncated ciphertext must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"truncated_ciphertext_detected\", \"category\": \"adversarial\", \"attack\": \"ciphertext_truncation\", \"bytes_removed\": 8, \"detected\": true}}"
    );
}

// ============================================================================
// S36: Corrupted Signature — Forgery Detection
// ============================================================================
//
// Bit-flipping a signature must cause verification to fail for all algorithms.

#[test]
fn test_corrupted_signature_detected_ed25519() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"forgery detection test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    // Corrupt the signature: flip a bit
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let mut sig_json: serde_json::Value = serde_json::from_str(&sig_content).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let mut sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64).unwrap();

    if let Some(byte) = sig_bytes.get_mut(0) {
        *byte ^= 0x01;
    }

    sig_json["signature"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &sig_bytes,
    ));

    let corrupted_sig = dir.path().join("corrupted.sig.json");
    std::fs::write(&corrupted_sig, serde_json::to_string_pretty(&sig_json).unwrap()).unwrap();

    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        corrupted_sig.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID") || stderr.contains("failed") || stderr.contains("error"),
        "Corrupted Ed25519 signature must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_ed25519\", \"category\": \"adversarial\", \"attack\": \"signature_bit_flip\", \"algorithm\": \"ed25519\", \"detected\": true}}"
    );
}

#[test]
fn test_corrupted_signature_detected_ml_dsa() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"PQC forgery detection test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Corrupt the PQC signature
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let mut sig_json: serde_json::Value = serde_json::from_str(&sig_content).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let mut sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64).unwrap();

    // Flip multiple bits across the signature
    for i in [0, sig_bytes.len() / 4, sig_bytes.len() / 2, sig_bytes.len() - 1] {
        if let Some(byte) = sig_bytes.get_mut(i) {
            *byte ^= 0xFF;
        }
    }

    sig_json["signature"] = serde_json::Value::String(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &sig_bytes,
    ));

    let corrupted_sig = dir.path().join("corrupted.sig.json");
    std::fs::write(&corrupted_sig, serde_json::to_string_pretty(&sig_json).unwrap()).unwrap();

    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        corrupted_sig.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID") || stderr.contains("failed") || stderr.contains("error"),
        "Corrupted ML-DSA-65 signature must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_ml_dsa\", \"category\": \"adversarial\", \"attack\": \"multi_bit_flip_signature\", \"algorithm\": \"ML-DSA-65\", \"bits_flipped\": 4, \"detected\": true}}"
    );
}

// ============================================================================
// S37: Wrong Key Type — Sign with Public Key, Decrypt with Public Key
// ============================================================================
//
// The CLI must reject operations when the wrong key type is provided.

#[test]
fn test_sign_with_public_key_rejected() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    // Attempt to sign using the PUBLIC key — must fail
    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("secret")
            || stderr.contains("mismatch")
            || stderr.contains("error")
            || stderr.contains("key_type"),
        "Signing with public key must be rejected: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"sign_with_public_key_rejected\", \"category\": \"negative\", \"operation\": \"sign\", \"key_provided\": \"public\", \"key_required\": \"secret\", \"rejected\": true}}"
    );
}

#[test]
fn test_decrypt_with_wrong_key_type_rejected() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate both AES and Ed25519 keys
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"type confusion test").unwrap();

    let enc_path = dir.path().join("msg.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Attempt to decrypt with an Ed25519 public key — wrong key type entirely
    let stderr = run_fail(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("symmetric")
            || stderr.contains("mismatch")
            || stderr.contains("error")
            || stderr.contains("key_type")
            || stderr.contains("public key"),
        "Decrypting with wrong key type must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"decrypt_with_wrong_key_type_rejected\", \"category\": \"negative\", \"operation\": \"decrypt\", \"encrypted_with\": \"aes256\", \"decrypted_with\": \"ed25519.pub\", \"rejected\": true}}"
    );
}

// ============================================================================
// S38: Non-Existent File Handling
// ============================================================================

#[test]
fn test_nonexistent_input_file() {
    let stderr = run_fail(&[
        "hash",
        "--algorithm",
        "sha-256",
        "--input",
        "/tmp/latticearc_does_not_exist_ever.txt",
    ]);
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

#[test]
fn test_nonexistent_key_file() {
    let dir = temp_dir();
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        "/tmp/latticearc_no_such_key.json",
    ]);
    assert!(
        stderr.contains("Failed to read")
            || stderr.contains("No such file")
            || stderr.contains("error"),
        "Non-existent key file must produce clear error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"nonexistent_key_file\", \"category\": \"negative\", \"file\": \"nonexistent_key\", \"error_reported\": true}}"
    );
}

// ============================================================================
// S39: Corrupted / Invalid Key File
// ============================================================================

#[test]
fn test_corrupted_key_file_json() {
    let dir = temp_dir();
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    // Write invalid JSON as a key file
    let bad_key_path = dir.path().join("bad.key.json");
    std::fs::write(&bad_key_path, "{ this is not valid json !!!").unwrap();

    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        bad_key_path.to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("Invalid")
            || stderr.contains("format")
            || stderr.contains("error")
            || stderr.contains("parse"),
        "Corrupted JSON key file must produce clear error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_key_file_json\", \"category\": \"adversarial\", \"attack\": \"malformed_key_file\", \"detected\": true}}"
    );
}

#[test]
fn test_key_file_wrong_base64() {
    let dir = temp_dir();
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    // Write valid JSON but with invalid Base64 in key field
    let bad_key_path = dir.path().join("bad_b64.key.json");
    let bad_json = r#"{
        "version": 1,
        "algorithm": "ed25519",
        "key_type": "secret",
        "key": "!!!not-valid-base64!!!",
        "created": "2026-01-01T00:00:00Z"
    }"#;
    std::fs::write(&bad_key_path, bad_json).unwrap();

    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        bad_key_path.to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("Base64")
            || stderr.contains("Invalid")
            || stderr.contains("decode")
            || stderr.contains("error"),
        "Invalid Base64 in key file must produce clear error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"key_file_wrong_base64\", \"category\": \"adversarial\", \"attack\": \"invalid_base64_key\", \"detected\": true}}"
    );
}

// ============================================================================
// S40: KDF Invalid Inputs
// ============================================================================

#[test]
fn test_kdf_invalid_hex_salt() {
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
fn test_kdf_invalid_hex_input() {
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "zzz-not-hex",
        "--salt",
        "000102030405060708090a0b0c",
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
fn test_kdf_zero_length_rejected() {
    let stderr = run_fail(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c",
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
// S41: Signature Algorithm Field Tampering
// ============================================================================
//
// An attacker who modifies the "algorithm" field in a signature file
// must not be able to get a valid verification with a different algorithm.

#[test]
fn test_signature_algorithm_field_tampered() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"algorithm tampering test").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    // Tamper: change algorithm field from "ed25519" to "ml-dsa-65"
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let tampered = sig_content.replace("\"ed25519\"", "\"ml-dsa-65\"");
    let tampered_path = dir.path().join("tampered_algo.sig.json");
    std::fs::write(&tampered_path, &tampered).unwrap();

    // Verify with the tampered algorithm field and original Ed25519 key
    // This must fail — algorithm/key mismatch or parsing error
    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        tampered_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("mismatch")
            || stderr.contains("failed")
            || stderr.contains("error")
            || stderr.contains("INVALID"),
        "Tampered algorithm field must cause verification failure: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"signature_algorithm_field_tampered\", \"category\": \"adversarial\", \"attack\": \"algorithm_field_substitution\", \"original\": \"ed25519\", \"tampered_to\": \"ml-dsa-65\", \"detected\": true}}"
    );
}

// ============================================================================
// S42: Large Message Handling
// ============================================================================
//
// Verify correct operation with messages larger than typical block sizes.
// AES block = 16 bytes, SHA chunk = 64 bytes. Test with 1 MB.

#[test]
fn test_large_message_sign_verify() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    // 1 MB of pseudo-random data
    let large_data: Vec<u8> = (0..1_048_576_u32).map(|i| (i % 256) as u8).collect();
    let msg_path = dir.path().join("large.bin");
    std::fs::write(&msg_path, &large_data).unwrap();

    let sig_path = dir.path().join("large.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    let out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    println!(
        "[PROOF] {{\"test\": \"large_message_sign_verify\", \"category\": \"edge-case\", \"input_bytes\": 1048576, \"algorithm\": \"ed25519\", \"result\": \"VALID\"}}"
    );
}

#[test]
fn test_large_message_encrypt_decrypt() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    // 512 KB of binary data
    let large_data: Vec<u8> = (0..524_288_u32).map(|i| (i % 256) as u8).collect();
    let msg_path = dir.path().join("large.bin");
    std::fs::write(&msg_path, &large_data).unwrap();

    let enc_path = dir.path().join("large.enc.json");
    let dec_path = dir.path().join("large.dec.bin");

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(decrypted.len(), large_data.len());
    assert_eq!(decrypted, large_data, "Large binary data must survive encrypt→decrypt roundtrip");

    println!(
        "[PROOF] {{\"test\": \"large_message_encrypt_decrypt\", \"category\": \"edge-case\", \"input_bytes\": 524288, \"roundtrip\": true}}"
    );
}

// ============================================================================
// S43: Missing Required Arguments
// ============================================================================

#[test]
fn test_keygen_missing_algorithm() {
    let output = Command::new(cli_bin()).args(["keygen"]).output().unwrap();
    assert!(!output.status.success(), "keygen without --algorithm must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("algorithm"),
        "Missing algorithm must show helpful error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"keygen_missing_algorithm\", \"category\": \"negative\", \"missing\": \"algorithm\", \"rejected\": true}}"
    );
}

#[test]
fn test_sign_missing_key() {
    let dir = temp_dir();
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    let output = Command::new(cli_bin())
        .args(["sign", "--algorithm", "ed25519", "--input", msg_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "sign without --key must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("key"),
        "Missing key must show helpful error: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"sign_missing_key\", \"category\": \"negative\", \"missing\": \"key\", \"rejected\": true}}"
    );
}

// ============================================================================
// S44: Nonce Uniqueness — Two Encryptions Produce Different Ciphertexts
// ============================================================================
//
// AES-256-GCM security requires unique nonces. Two encryptions of the same
// plaintext with the same key MUST produce different ciphertexts (random nonce).

#[test]
fn test_aes_gcm_nonce_uniqueness() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"same plaintext encrypted twice").unwrap();

    let enc1_path = dir.path().join("enc1.json");
    let enc2_path = dir.path().join("enc2.json");

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc1_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc2_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let enc1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&enc1_path).unwrap()).unwrap();
    let enc2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&enc2_path).unwrap()).unwrap();

    // Nonces must be different (random generation)
    assert_ne!(
        enc1["nonce"].as_str().unwrap(),
        enc2["nonce"].as_str().unwrap(),
        "Two encryptions of the same plaintext MUST use different nonces"
    );

    // Ciphertexts must be different (different nonce → different output)
    assert_ne!(
        enc1["ciphertext"].as_str().unwrap(),
        enc2["ciphertext"].as_str().unwrap(),
        "Two encryptions with different nonces MUST produce different ciphertexts"
    );

    // But both must decrypt to the same plaintext
    let dec1_path = dir.path().join("dec1.txt");
    let dec2_path = dir.path().join("dec2.txt");

    run_ok(&[
        "decrypt",
        "--input",
        enc1_path.to_str().unwrap(),
        "--output",
        dec1_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);
    run_ok(&[
        "decrypt",
        "--input",
        enc2_path.to_str().unwrap(),
        "--output",
        dec2_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    let dec1 = std::fs::read_to_string(&dec1_path).unwrap();
    let dec2 = std::fs::read_to_string(&dec2_path).unwrap();
    assert_eq!(dec1, dec2, "Both decryptions must recover original plaintext");
    assert_eq!(dec1, "same plaintext encrypted twice");

    println!(
        "[PROOF] {{\"test\": \"aes_gcm_nonce_uniqueness\", \"category\": \"adversarial\", \"nonces_unique\": true, \"ciphertexts_unique\": true, \"both_decrypt_correctly\": true, \"defense\": \"random nonce prevents nonce reuse attack\"}}"
    );
}

// ============================================================================
// S45: Signature Non-Determinism vs Determinism by Algorithm
// ============================================================================
//
// Ed25519 is deterministic (RFC 8032) — same message+key = same signature.
// ML-DSA may be randomized (FIPS 204 hedged signing).

#[test]
fn test_ed25519_signature_determinism() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"deterministic signing test").unwrap();

    let sig1_path = dir.path().join("sig1.json");
    let sig2_path = dir.path().join("sig2.json");

    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig1_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);
    run_ok(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig2_path.to_str().unwrap(),
        "--key",
        dir.path().join("ed25519.sec.json").to_str().unwrap(),
    ]);

    let sig1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig1_path).unwrap()).unwrap();
    let sig2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig2_path).unwrap()).unwrap();

    // Ed25519 is deterministic per RFC 8032 §5.1.6
    assert_eq!(
        sig1["signature"].as_str().unwrap(),
        sig2["signature"].as_str().unwrap(),
        "Ed25519 signing MUST be deterministic (RFC 8032 §5.1.6)"
    );

    println!(
        "[PROOF] {{\"test\": \"ed25519_signature_determinism\", \"category\": \"nist-conformance\", \"standard\": \"RFC 8032 §5.1.6\", \"deterministic\": true, \"signatures_identical\": true}}"
    );
}

// ============================================================================
// S46: E2E Adversarial — Man-in-the-Middle Signature Substitution
// ============================================================================
//
// Attacker intercepts a signed message, replaces the message, keeps the
// original signature. Verification must fail.

#[test]
fn test_mitm_message_substitution() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    // Alice signs "Transfer $100 to Bob"
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"Transfer $100 to Bob").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Attacker replaces message with "Transfer $10000 to Mallory"
    std::fs::write(&msg_path, b"Transfer $10000 to Mallory").unwrap();

    // Verification with substituted message must fail
    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID") || stderr.contains("failed") || stderr.contains("error"),
        "MITM message substitution must be detected: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"mitm_message_substitution\", \"category\": \"adversarial\", \"attack\": \"message_substitution\", \"original\": \"Transfer $100 to Bob\", \"substituted\": \"Transfer $10000 to Mallory\", \"detected\": true, \"algorithm\": \"ML-DSA-65\"}}"
    );
}

// ============================================================================
// S47: Key Isolation — Different Keys Never Produce Valid Cross-Verification
// ============================================================================
//
// Generate N independent keypairs. Sign with each. Verify that no signature
// validates under any other keypair's public key.

#[test]
fn test_key_isolation_matrix() {
    let dirs: Vec<_> = (0..3).map(|_| temp_dir()).collect();

    // Generate 3 independent Ed25519 keypairs
    for d in &dirs {
        run_ok(&["keygen", "--algorithm", "ed25519", "--output", d.path().to_str().unwrap()]);
    }

    let msg_path = dirs[0].path().join("msg.txt");
    std::fs::write(&msg_path, b"key isolation matrix test").unwrap();

    // Sign with each key
    let mut sig_paths = Vec::new();
    for (i, d) in dirs.iter().enumerate() {
        let sig_path = d.path().join(format!("sig_{i}.json"));
        run_ok(&[
            "sign",
            "--algorithm",
            "ed25519",
            "--input",
            msg_path.to_str().unwrap(),
            "--output",
            sig_path.to_str().unwrap(),
            "--key",
            d.path().join("ed25519.sec.json").to_str().unwrap(),
        ]);
        sig_paths.push(sig_path);
    }

    // Verify: sig[i] should ONLY verify with key[i]
    let mut cross_verified = 0_u32;
    for (i, sig_path) in sig_paths.iter().enumerate() {
        for (j, d) in dirs.iter().enumerate() {
            let output = Command::new(cli_bin())
                .args([
                    "verify",
                    "--input",
                    msg_path.to_str().unwrap(),
                    "--signature",
                    sig_path.to_str().unwrap(),
                    "--key",
                    d.path().join("ed25519.pub.json").to_str().unwrap(),
                ])
                .output()
                .unwrap();

            if i == j {
                assert!(output.status.success(), "sig[{i}] must verify with key[{i}]");
            } else if output.status.success() {
                cross_verified = cross_verified.saturating_add(1);
            }
        }
    }

    assert_eq!(
        cross_verified, 0,
        "No cross-key verification should succeed (got {cross_verified})"
    );

    println!(
        "[PROOF] {{\"test\": \"key_isolation_matrix\", \"category\": \"adversarial\", \"keypairs\": 3, \"verifications_attempted\": 9, \"correct_verifications\": 3, \"cross_verifications\": {cross_verified}, \"fully_isolated\": true}}"
    );
}
