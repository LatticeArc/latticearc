//! End-to-end, multi-command CLI workflows plus basics and miscellaneous regression tests.
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
// S01: Info & Help
// ============================================================================
#[test]
fn test_info_shows_version_and_algorithms_succeeds() {
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
fn test_help_shows_all_commands_succeeds() {
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
// S17: E2E Real-world — Code signing workflow
// ============================================================================
#[test]
fn test_e2e_code_signing_workflow_succeeds() {
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
    let out = run_ok_combined(&[
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
    let sig_json: serde_json::Value = read_json_file(&sig_path);
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
fn test_e2e_document_notarization_hybrid_is_documented() {
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
    let out = run_ok_combined(&[
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
fn test_e2e_encrypted_config_deployment_succeeds() {
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
// S57: E2E Multi-Step Crypto Pipeline
// ============================================================================
//
// Complete pipeline: generate keys → sign document → hash signature → encrypt
// → decrypt → verify signature. Proves all CLI commands compose correctly.
#[test]
fn test_e2e_multi_step_crypto_pipeline_succeeds() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Step 1: Generate signing and encryption keys
    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);

    // Step 2: Create document
    let doc_path = dir.path().join("document.txt");
    std::fs::write(&doc_path, b"Critical infrastructure deployment manifest v2.1").unwrap();

    // Step 3: Sign the document with ML-DSA-65
    let sig_path = dir.path().join("document.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        doc_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Step 4: Hash the document for audit trail
    let hash_out =
        run_ok(&["hash", "--algorithm", "sha3-256", "--input", doc_path.to_str().unwrap()]);
    assert!(hash_out.contains("SHA3-256:"), "Hash output must contain algorithm prefix");

    // Step 5: Encrypt the signed document
    let enc_path = dir.path().join("document.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        doc_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Step 6: Decrypt the document
    let dec_path = dir.path().join("document.dec.txt");
    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Step 7: Verify the decrypted document matches original
    let original = std::fs::read(&doc_path).unwrap();
    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(original, decrypted, "Decrypted document must match original");

    // Step 8: Verify signature against decrypted document (proves integrity end-to-end)
    let out = run_ok_combined(&[
        "verify",
        "--input",
        dec_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"), "Signature must verify against decrypted document");

    // Step 9: Hash the decrypted document — must match original hash
    let hash_dec =
        run_ok(&["hash", "--algorithm", "sha3-256", "--input", dec_path.to_str().unwrap()]);
    assert_eq!(
        hash_out.trim(),
        hash_dec.trim(),
        "Hash of original and decrypted documents MUST match"
    );

    println!(
        "[PROOF] {{\"test\": \"e2e_multi_step_crypto_pipeline\", \"category\": \"e2e\", \"steps\": [\"keygen\", \"sign\", \"hash\", \"encrypt\", \"decrypt\", \"verify\", \"hash-compare\"], \"algorithms\": {{\"signing\": \"ML-DSA-65\", \"encryption\": \"AES-256-GCM\", \"hashing\": \"SHA3-256\"}}, \"all_steps_passed\": true, \"integrity_preserved\": true}}"
    );
}
// ============================================================================
// S58: E2E PQC Document Custody Chain
// ============================================================================
//
// Simulates a document custody chain: author signs → custodian encrypts
// → recipient decrypts → recipient verifies author's signature.
// Uses PQC (ML-DSA-87) for quantum-resistant non-repudiation.
#[test]
fn test_e2e_pqc_document_custody_chain_is_documented() {
    let author_dir = temp_dir();
    let custodian_dir = temp_dir();

    // Author generates PQC signing keys (strongest level)
    run_ok(&["keygen", "--algorithm", "ml-dsa87", "--output", author_dir.path().to_str().unwrap()]);

    // Custodian generates encryption keys
    run_ok(&[
        "keygen",
        "--algorithm",
        "aes256",
        "--output",
        custodian_dir.path().to_str().unwrap(),
    ]);

    // Author creates and signs document
    let doc_path = author_dir.path().join("evidence.txt");
    std::fs::write(&doc_path, b"Chain of custody record: Item #2026-0314, logged 09:00 UTC")
        .unwrap();

    let sig_path = author_dir.path().join("evidence.sig.json");
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa87",
        "--input",
        doc_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        author_dir.path().join("ml-dsa-87.sec.json").to_str().unwrap(),
    ]);

    // Custodian encrypts document for secure transport
    let enc_path = custodian_dir.path().join("evidence.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        doc_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        custodian_dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Recipient decrypts
    let dec_path = custodian_dir.path().join("evidence.dec.txt");
    run_ok(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        custodian_dir.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Recipient verifies author's signature on decrypted document
    let out = run_ok_combined(&[
        "verify",
        "--input",
        dec_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        author_dir.path().join("ml-dsa-87.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"), "Author's PQC signature must verify after decrypt");

    // Verify content integrity
    let original = std::fs::read_to_string(&doc_path).unwrap();
    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(original, decrypted, "Document content must survive custody chain");

    println!(
        "[PROOF] {{\"test\": \"e2e_pqc_document_custody_chain\", \"category\": \"e2e\", \"workflow\": \"custody_chain\", \"signing\": \"ML-DSA-87 (FIPS 204 Category 5)\", \"encryption\": \"AES-256-GCM (SP 800-38D)\", \"non_repudiation\": true, \"content_integrity\": true, \"quantum_resistant\": true}}"
    );
}
// ============================================================================
// S59: E2E Key Derivation for Encryption
// ============================================================================
//
// Derive an encryption key from a password via PBKDF2, then use it
// for AES-256-GCM encryption/decryption. Proves KDF→encrypt→decrypt pipeline.
#[test]
fn test_e2e_derived_key_encrypt_decrypt_roundtrip() {
    let dir = temp_dir();

    // Step 1: Derive a 32-byte key from password via PBKDF2
    let derived_hex = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "user-passphrase-2026",
        "--salt",
        "e3b0c44298fc1c14e3b0c44298fc1c14",
        "--length",
        "32",
        "--iterations",
        "100000",
        // CLI enforces OWASP 600k floor (#62); test fixture uses small count.
        "--allow-weak-iterations",
        "--allow-argv-secret",
    ]);
    let derived_key = derived_hex.trim();
    assert_eq!(derived_key.len(), 64, "Derived key must be 32 bytes (64 hex chars)");

    // Step 2: Write derived key as an AES key file
    let key_path = dir.path().join("derived.key.json");
    let key_json = format!(
        r#"{{"version": 1, "algorithm": "aes256", "key_type": "symmetric", "key": "{}", "created": "2026-03-14T00:00:00Z"}}"#,
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            hex::decode(derived_key).unwrap()
        )
    );
    std::fs::write(&key_path, &key_json).unwrap();

    // Step 3: Encrypt with derived key
    let msg_path = dir.path().join("secret.txt");
    std::fs::write(&msg_path, b"Password-derived encryption test").unwrap();

    let enc_path = dir.path().join("secret.enc.json");
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

    // Step 4: Decrypt with same derived key
    let dec_path = dir.path().join("secret.dec.txt");
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
    assert_eq!(decrypted, "Password-derived encryption test");

    // Step 5: Re-derive the same key and verify it matches
    let derived_again = run_ok(&[
        "kdf",
        "--algorithm",
        "pbkdf2",
        "--input",
        "user-passphrase-2026",
        "--salt",
        "e3b0c44298fc1c14e3b0c44298fc1c14",
        "--length",
        "32",
        "--iterations",
        "100000",
        "--allow-weak-iterations",
        "--allow-argv-secret",
    ]);
    assert_eq!(
        derived_key,
        derived_again.trim(),
        "PBKDF2 must be deterministic: same password + salt + iterations = same key"
    );

    println!(
        "[PROOF] {{\"test\": \"e2e_derived_key_encrypt_decrypt\", \"category\": \"e2e\", \"workflow\": \"password_to_encryption\", \"kdf\": \"PBKDF2-HMAC-SHA256\", \"iterations\": 100000, \"encryption\": \"AES-256-GCM\", \"roundtrip\": true, \"key_determinism\": true}}"
    );
}
#[test]
fn test_cli_reads_cbor_encoded_symmetric_key() {
    // The CLI `keygen` command writes JSON, but `read_from` must accept
    // CBOR-encoded LPK files produced by the library API (or any other
    // LPK-compatible tool). Regression guard: a prior version of the CLI
    // only parsed JSON and silently rejected CBOR files despite the
    // CLI README claiming CBOR was supported.
    use latticearc::PortableKey;
    use latticearc::unified_api::key_format::{KeyAlgorithm, KeyData, KeyType};

    let dir = temp_dir();

    // Build a valid AES-256 PortableKey via the library and serialize to CBOR.
    let raw = [0x55u8; 32];
    let key = PortableKey::new(KeyAlgorithm::Aes256, KeyType::Symmetric, KeyData::from_raw(&raw));
    let cbor_bytes = key.to_cbor().expect("CBOR serialization");
    let cbor_path = dir.path().join("aes256-cbor.key");
    std::fs::write(&cbor_path, &cbor_bytes).unwrap();

    // Use the CBOR-encoded key to encrypt and decrypt a message through the CLI.
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"cbor cli smoke test").unwrap();
    let ct_path = dir.path().join("msg.ct");
    run_ok(&[
        "encrypt",
        "--key",
        cbor_path.to_str().unwrap(),
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        ct_path.to_str().unwrap(),
    ]);
    let dec_path = dir.path().join("msg.out");
    run_ok(&[
        "decrypt",
        "--key",
        cbor_path.to_str().unwrap(),
        "--input",
        ct_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ]);

    // Sanity: confirm the file is actually CBOR, not JSON. `to_cbor` emits
    // a CBOR map, which starts with a byte in the range 0xa0..=0xb7 (short
    // map header, RFC 8949 §3.1). This range is NOT valid as the first
    // byte of JSON (`{` = 0x7b, whitespace, etc.), so a read of this file
    // as JSON would fail at byte 0.
    let first = cbor_bytes[0];
    assert!(
        (0xa0..=0xb7).contains(&first),
        "expected CBOR short map header (0xa0..=0xb7), got 0x{first:02x}",
    );

    let decrypted = std::fs::read(&dec_path).unwrap();
    assert_eq!(decrypted, b"cbor cli smoke test");
}
// ============================================================================
// Security-fix behavioral regression tests.
//
// Each test asserts a user-visible property the corresponding fix
// is supposed to provide. To be a genuine regression blocker, each test
// must (a) PASS against the fixed code, and (b) FAIL when the fix is
// reverted. The second property is what makes these tests useful — coverage
// that still passes after the fix is gone is theatre.
// ============================================================================
/// `KeyFile::read_from` must reject files larger
/// than `MAX_KEYFILE_BYTES` (1 MiB). Before this fix, an oversized key file
/// (e.g., a symlink to /dev/zero, a sparse file, or a malicious 2 GiB
/// file at a path the user thought was a key) was read into memory in
/// full, causing OOM.
///
/// This test:
///   1. Writes a 2 MiB file at `<tmp>/oversized.json`.
///   2. Invokes any CLI command that reads a key — `verify --key`.
///   3. Asserts the CLI fails with a "maximum supported size" error,
///      not an OOM and not a JSON-parse error.
#[test]
fn round20_fix14_keyfile_size_cap_rejects_oversized_input() {
    let dir = temp_dir();
    let big_path = dir.path().join("oversized.json");
    // 2 MiB > MAX_KEYFILE_BYTES (1 MiB)
    let big_data = vec![b'A'; 2 * 1024 * 1024];
    std::fs::write(&big_path, &big_data).unwrap();

    // We need a CLI invocation that reads the key file. `verify --key`
    // is the cleanest because it doesn't depend on prior keygen state.
    // Use a dummy signature input; the CLI should reject the key file
    // BEFORE attempting to parse the signature.
    let dummy_sig = dir.path().join("sig.json");
    std::fs::write(&dummy_sig, b"{}").unwrap();
    let dummy_input = dir.path().join("data.txt");
    std::fs::write(&dummy_input, b"data").unwrap();

    let stderr = run_fail(&[
        "verify",
        "--algorithm",
        "ed25519",
        "--input",
        dummy_input.to_str().unwrap(),
        "--signature",
        dummy_sig.to_str().unwrap(),
        "--key",
        big_path.to_str().unwrap(),
    ]);

    // Either the CLI's own `MAX_KEYFILE_BYTES` (1 MiB) gate fires,
    // OR (without the fix) the library's downstream JSON-parser size
    // limit fires. Both reject the oversized input — but only the
    // CLI gate is the fix under test. We assert on the CLI's specific
    // error string so reverting the fix actually fails this test
    // (the library message is "exceeds limit", the CLI's is
    // "maximum supported size").
    assert!(
        stderr.contains("maximum supported size"),
        "oversized key file must be rejected by the CLI's \
         MAX_KEYFILE_BYTES gate (which produces 'maximum supported size') BEFORE \
         std::fs::read attempts to load it. Got stderr:\n{stderr}"
    );
}
/// `decrypt --output <path>` must
/// write the decrypted plaintext with mode 0o600 — owner read+write
/// only, never world-readable.
///
/// Note: the original finding stated the file would inherit umask
/// (typically 0o644). In practice `tempfile::NamedTempFile::new_in`
/// already creates files with mode 0o600 and `persist()` preserves
/// that, so that stated risk doesn't materialize. Our fix
/// added an explicit `.secret_mode()` call as defense-in-depth in
/// case tempfile's default ever changes; this test pins the
/// **resulting file mode** as a regression blocker for either path
/// of the contract (explicit chmod OR tempfile default).
///
/// If tempfile changes its default to 0o644 AND someone removes
/// `.secret_mode()` from decrypt, this test fails. That's the
/// intended trap.
#[cfg(unix)]
#[test]
fn round20_fix5_decrypt_output_is_chmod_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate an AES-256 key.
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);
    let key_path = dir.path().join("aes256.key.json");

    // Plaintext + roundtrip.
    let pt_path = dir.path().join("plaintext.txt");
    std::fs::write(&pt_path, b"sample plaintext").unwrap();
    let ct_path = dir.path().join("ciphertext.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        pt_path.to_str().unwrap(),
        "--output",
        ct_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
    ]);

    // Decrypt → output file. THIS is the path the fix gates.
    let dec_path = dir.path().join("decrypted.txt");
    run_ok(&[
        "decrypt",
        "--input",
        ct_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
        "--key",
        key_path.to_str().unwrap(),
    ]);

    // The decrypted file must be 0o600 — owner read+write only.
    let meta = std::fs::metadata(&dec_path).expect("stat decrypted file");
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "decrypted plaintext file must be chmod 0o600 (got 0o{mode:o}). \
         The decrypt path must call AtomicWrite::secret_mode() so plaintext at rest is \
         not world-readable."
    );
}
