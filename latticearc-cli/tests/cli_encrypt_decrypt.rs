//! Integration tests for the `encrypt` and `decrypt` commands, including PQ-only and adversarial ciphertext scenarios.
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

fn pure_pq_kem_encrypt_decrypt_roundtrip(algorithm: &str, expected_scheme: &str) {
    let dir = temp_dir();
    run_ok(&["keygen", "--algorithm", algorithm, "--output", dir.path().to_str().unwrap()]);

    let sk_path = dir.path().join(format!("{expected_scheme}.sec.json"));
    let pk_path = dir.path().join(format!("{expected_scheme}.pub.json"));
    assert!(sk_path.exists(), "secret key not written for {algorithm}: {}", sk_path.display());
    assert!(pk_path.exists(), "public key not written for {algorithm}: {}", pk_path.display());

    let msg_path = dir.path().join("plaintext.bin");
    let plaintext = format!("pure-pq regression fixture for {algorithm}");
    std::fs::write(&msg_path, &plaintext).unwrap();

    let ct_path = dir.path().join("ciphertext.json");
    // --use-case routes through encrypt_with_config; with a pure-PQ key this
    // used to hit the hybrid-parse bug. The fix auto-routes to PqOnly.
    run_ok(&[
        "encrypt",
        "--use-case",
        "file-storage",
        "--key",
        pk_path.to_str().unwrap(),
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        ct_path.to_str().unwrap(),
    ]);

    let pt_path = dir.path().join("decrypted.bin");
    run_ok(&[
        "decrypt",
        "--key",
        sk_path.to_str().unwrap(),
        "--input",
        ct_path.to_str().unwrap(),
        "--output",
        pt_path.to_str().unwrap(),
    ]);

    let decrypted = std::fs::read(&pt_path).unwrap();
    assert_eq!(
        decrypted,
        plaintext.as_bytes(),
        "decrypted plaintext did not match original for pure-PQ {algorithm}"
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
#[test]
fn test_encrypt_decrypt_empty_plaintext_roundtrip() {
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
fn test_encrypt_decrypt_binary_data_roundtrip() {
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
// ============================================================================
// S35: Corrupted Ciphertext — Integrity Violation Detection
// ============================================================================
//
// AES-256-GCM provides authenticated encryption. Bit-flipping or truncation
// of the ciphertext MUST cause decryption to fail (authentication tag mismatch).
#[test]
fn test_corrupted_ciphertext_detected_fails() {
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
fn test_truncated_ciphertext_detected_succeeds() {
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
#[test]
fn test_decrypt_with_wrong_key_type_rejected_fails() {
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
#[test]
fn test_large_message_encrypt_decrypt_roundtrip() {
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
// S44: Nonce Uniqueness — Two Encryptions Produce Different Ciphertexts
// ============================================================================
//
// AES-256-GCM security requires unique nonces. Two encryptions of the same
// plaintext with the same key MUST produce different ciphertexts (random nonce).
#[test]
fn test_aes_gcm_nonce_uniqueness_are_unique() {
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

    let enc1: serde_json::Value = read_json_file(&enc1_path);
    let enc2: serde_json::Value = read_json_file(&enc2_path);

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
// S56: Decrypt with Mismatched AES Key
// ============================================================================
//
// Encrypting with key A and decrypting with key B MUST fail.
// AES-256-GCM authentication tag prevents silent wrong-key decryption.
#[test]
fn test_decrypt_with_different_aes_key_fails() {
    let dir1 = temp_dir();
    let dir2 = temp_dir();

    run_ok(&["keygen", "--algorithm", "aes256", "--output", dir1.path().to_str().unwrap()]);
    run_ok(&["keygen", "--algorithm", "aes256", "--output", dir2.path().to_str().unwrap()]);

    let msg_path = dir1.path().join("secret.txt");
    std::fs::write(&msg_path, b"confidential data for key A only").unwrap();

    let enc_path = dir1.path().join("secret.enc.json");
    run_ok(&[
        "encrypt",
        "--mode",
        "aes256-gcm",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
        "--key",
        dir1.path().join("aes256.key.json").to_str().unwrap(),
    ]);

    // Attempt to decrypt with key B — must fail
    let stderr = run_fail(&[
        "decrypt",
        "--input",
        enc_path.to_str().unwrap(),
        "--key",
        dir2.path().join("aes256.key.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("failed")
            || stderr.contains("error")
            || stderr.contains("tag")
            || stderr.contains("auth"),
        "Decrypting with wrong AES key must fail: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"decrypt_with_different_aes_key_fails\", \"category\": \"adversarial\", \"attack\": \"wrong_symmetric_key\", \"mechanism\": \"GCM authentication tag\", \"detected\": true, \"silent_decryption_prevented\": true}}"
    );
}
// ============================================================================
// S33: PQ-Only Encryption CLI Tests
// ============================================================================
/// PQ-only encrypt/decrypt roundtrip at ML-KEM-768 via CLI.
#[test]
fn test_cli_pq_only_encrypt_decrypt_roundtrip_succeeds() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate ML-KEM-768 keypair (PQ-only, no hybrid)
    run_ok(&["keygen", "--algorithm", "ml-kem768", "--output", d]);

    let pk_path = dir.path().join("ml-kem-768.pub.json");
    let sk_path = dir.path().join("ml-kem-768.sec.json");
    assert!(pk_path.exists(), "ML-KEM-768 public key should exist");
    assert!(sk_path.exists(), "ML-KEM-768 secret key should exist");

    // Write plaintext
    let plaintext = "PQ-only CLI encryption test data";
    let input_path = dir.path().join("input.txt");
    std::fs::write(&input_path, plaintext).unwrap();

    let enc_path = dir.path().join("encrypted.json");

    // Encrypt with --mode pq-only
    run_ok(&[
        "encrypt",
        "--mode",
        "pq-only",
        "--key",
        pk_path.to_str().unwrap(),
        "--input",
        input_path.to_str().unwrap(),
        "--output",
        enc_path.to_str().unwrap(),
    ]);
    assert!(enc_path.exists(), "Encrypted file should exist");

    let dec_path = dir.path().join("decrypted.txt");

    // Decrypt
    run_ok(&[
        "decrypt",
        "--key",
        sk_path.to_str().unwrap(),
        "--input",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ]);

    let decrypted = std::fs::read_to_string(&dec_path).unwrap();
    assert_eq!(decrypted, plaintext, "Decrypted data must match original");

    println!(
        "[PROOF] {{\"test\": \"cli_pq_only_roundtrip\", \"category\": \"cli-e2e\", \
         \"algorithm\": \"ML-KEM-768\", \"mode\": \"pq-only\", \"result\": \"MATCH\"}}"
    );
}
/// PQ-only encrypt with symmetric key file should fail.
#[test]
fn test_cli_pq_only_wrong_key_type_fails() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate symmetric key
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);
    let sym_key = dir.path().join("aes256.key.json");

    let input_path = dir.path().join("input.txt");
    std::fs::write(&input_path, "test").unwrap();

    // Try PQ-only encrypt with symmetric key — should fail
    let stderr = run_fail(&[
        "encrypt",
        "--mode",
        "pq-only",
        "--key",
        sym_key.to_str().unwrap(),
        "--input",
        input_path.to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("public key") || stderr.contains("Public"),
        "Error should mention needing a public key, got: {stderr}"
    );
}
/// PQ-only encrypt at all 3 ML-KEM levels.
#[test]
fn test_cli_pq_only_all_levels_roundtrip_succeeds() {
    for (algo, pk_name, sk_name) in [
        ("ml-kem512", "ml-kem-512.pub.json", "ml-kem-512.sec.json"),
        ("ml-kem768", "ml-kem-768.pub.json", "ml-kem-768.sec.json"),
        ("ml-kem1024", "ml-kem-1024.pub.json", "ml-kem-1024.sec.json"),
    ] {
        let dir = temp_dir();
        let d = dir.path().to_str().unwrap();

        run_ok(&["keygen", "--algorithm", algo, "--output", d]);

        let pk_path = dir.path().join(pk_name);
        let sk_path = dir.path().join(sk_name);

        let input_path = dir.path().join("input.txt");
        std::fs::write(&input_path, format!("PQ-only {algo} test")).unwrap();

        let enc_path = dir.path().join("enc.json");
        run_ok(&[
            "encrypt",
            "--mode",
            "pq-only",
            "--key",
            pk_path.to_str().unwrap(),
            "--input",
            input_path.to_str().unwrap(),
            "--output",
            enc_path.to_str().unwrap(),
        ]);

        let dec_path = dir.path().join("dec.txt");
        run_ok(&[
            "decrypt",
            "--key",
            sk_path.to_str().unwrap(),
            "--input",
            enc_path.to_str().unwrap(),
            "--output",
            dec_path.to_str().unwrap(),
        ]);

        let decrypted = std::fs::read_to_string(&dec_path).unwrap();
        assert_eq!(decrypted, format!("PQ-only {algo} test"));

        println!(
            "[PROOF] {{\"test\": \"cli_pq_only_{algo}\", \"category\": \"cli-e2e\", \
             \"result\": \"MATCH\"}}"
        );
    }
}
// ============================================================================
// Regression: pure-PQ ML-KEM keygen → `encrypt --use-case ...` must auto-route
// ============================================================================
//
// Sibling bug to the sign-path issue: `encrypt_with_config` (the `--use-case`
// path) unconditionally parsed a public key as hybrid. If the user supplied
// a pure-PQ ML-KEM public key, it failed with a hybrid length mismatch.
// The fix auto-detects pure-PQ ML-KEM algorithms and delegates to
// `encrypt_pq_only_mode`, which sets `CryptoMode::PqOnly` and uses
// `EncryptKey::PqOnly`.
#[test]
fn test_pure_pq_ml_kem_512_encrypt_decrypt_via_use_case_flag() {
    pure_pq_kem_encrypt_decrypt_roundtrip("ml-kem512", "ml-kem-512");
}
#[test]
fn test_pure_pq_ml_kem_768_encrypt_decrypt_via_use_case_flag() {
    pure_pq_kem_encrypt_decrypt_roundtrip("ml-kem768", "ml-kem-768");
}
#[test]
fn test_pure_pq_ml_kem_1024_encrypt_decrypt_via_use_case_flag() {
    pure_pq_kem_encrypt_decrypt_roundtrip("ml-kem1024", "ml-kem-1024");
}
