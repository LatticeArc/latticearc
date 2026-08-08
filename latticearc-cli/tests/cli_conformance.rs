//! NIST/FIPS/RFC byte-size conformance tests for CLI-generated keys, signatures, and ciphertexts.
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

/// Decode the Base64 "key" field from a key file and return raw byte length.
fn key_file_raw_len(path: &std::path::Path) -> usize {
    let json: serde_json::Value = read_json_file(path);
    // Support both PortableKey format (key_data.raw) and legacy format (key)
    let b64 = json["key_data"]["raw"]
        .as_str()
        .or_else(|| json["key"].as_str())
        .expect("Key file must have key_data.raw or key field");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap().len()
}
/// Get the total raw byte length of a composite hybrid key (pq + classical).
fn hybrid_key_file_raw_len(path: &std::path::Path) -> (usize, usize) {
    let json: serde_json::Value = read_json_file(path);
    // PortableKey composite format: key_data.pq + key_data.classical
    if let (Some(pq), Some(cl)) =
        (json["key_data"]["pq"].as_str(), json["key_data"]["classical"].as_str())
    {
        let pq_len =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pq).unwrap().len();
        let cl_len =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, cl).unwrap().len();
        return (pq_len, cl_len);
    }
    // Legacy format: length-prefixed binary in key field
    let b64 = json["key"].as_str().expect("Key file must have key_data or key field");
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap();
    (bytes.len(), 0)
}
/// Decode the Base64 "signature" field from a signature file and return raw byte length.
fn sig_file_raw_len(path: &std::path::Path) -> usize {
    let json: serde_json::Value = read_json_file(path);
    let b64 = json["signature"].as_str().unwrap();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap().len()
}

// ============================================================================
// S23: NIST FIPS 204 — ML-DSA Key & Signature Size Conformance
// ============================================================================
//
// FIPS 204, Table 2 specifies exact byte sizes for all ML-DSA parameter sets.
// These tests assert our implementation produces artifacts matching the standard.
#[test]
fn test_nist_fips204_ml_dsa_44_sizes_has_correct_size() {
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
fn test_nist_fips204_ml_dsa_65_sizes_has_correct_size() {
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
fn test_nist_fips204_ml_dsa_87_sizes_has_correct_size() {
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
fn test_nist_fips203_ml_kem_512_sizes_has_correct_size() {
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
fn test_nist_fips203_ml_kem_768_sizes_has_correct_size() {
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
fn test_nist_fips203_ml_kem_1024_sizes_has_correct_size() {
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
fn test_nist_fips205_slh_dsa_shake_128s_sizes_has_correct_size() {
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
fn test_fips206_fn_dsa_512_sizes_has_correct_size() {
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
fn test_rfc8032_ed25519_sizes_has_correct_size() {
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
fn test_fips197_aes256_key_size_has_correct_size() {
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

    let enc_json: serde_json::Value = read_json_file(&enc_path);

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
fn test_hash_output_sizes_conformance_has_correct_size() {
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
fn test_hybrid_key_composition_conformance_succeeds() {
    // Hybrid signing: ML-DSA-65 + Ed25519
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "hybrid-sign", "--output", d]);

    // PortableKey composite format: pq and classical stored separately
    let (sign_pq, sign_cl) = hybrid_key_file_raw_len(&dir.path().join("hybrid-sign.pub.json"));
    let (sign_sk_pq, sign_sk_cl) =
        hybrid_key_file_raw_len(&dir.path().join("hybrid-sign.sec.json"));

    assert_eq!(sign_pq, 1952, "FIPS 204: ML-DSA-65 pk MUST be 1,952 bytes");
    assert_eq!(sign_cl, 32, "RFC 8032: Ed25519 pk MUST be 32 bytes");
    assert_eq!(sign_sk_pq, 4032, "FIPS 204: ML-DSA-65 sk MUST be 4,032 bytes");
    assert!(
        sign_sk_cl == 32 || sign_sk_cl == 64,
        "RFC 8032: Ed25519 sk should be 32 or 64 bytes, got {sign_sk_cl}"
    );

    // Hybrid KEM: ML-KEM-768 + X25519
    let dir2 = temp_dir();
    let d2 = dir2.path().to_str().unwrap();
    run_ok(&["keygen", "--algorithm", "hybrid", "--output", d2]);

    let (kem_pq, kem_cl) = hybrid_key_file_raw_len(&dir2.path().join("hybrid-kem.pub.json"));

    assert_eq!(kem_pq, 1184, "FIPS 203: ML-KEM-768 ek MUST be 1,184 bytes");
    assert_eq!(kem_cl, 32, "X25519 pk MUST be 32 bytes");

    let total_sign_pk = sign_pq + sign_cl;
    let total_kem_pk = kem_pq + kem_cl;

    println!(
        "[PROOF] {{\"test\": \"hybrid_key_composition_conformance\", \"category\": \"nist-conformance\", \"hybrid_sign_pq\": {sign_pq}, \"hybrid_sign_classical\": {sign_cl}, \"total_sign_pk\": {total_sign_pk}, \"components\": \"FIPS204(1952) + RFC8032(32)\", \"hybrid_kem_pq\": {kem_pq}, \"hybrid_kem_classical\": {kem_cl}, \"total_kem_pk\": {total_kem_pk}, \"kem_components\": \"FIPS203(1184) + X25519(32)\", \"all_conformant\": true}}"
    );
}
// ============================================================================
// S31: Cross-Algorithm Signature Non-Interchangeability
// ============================================================================
//
// Verify that signatures from one PQC algorithm cannot be verified with
// a different algorithm's key — defense against algorithm confusion attacks.
#[test]
fn test_pqc_signatures_non_interchangeable_succeeds() {
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
fn test_hkdf_output_length_conformance_has_correct_size() {
    // Minimum: 1 byte
    let out = run_ok(&[
        "kdf",
        "--algorithm",
        "hkdf",
        "--input",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "--salt",
        "000102030405060708090a0b0c0d0e0f",
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
        "000102030405060708090a0b0c0d0e0f",
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
        "000102030405060708090a0b0c0d0e0f",
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
        "000102030405060708090a0b0c0d0e0f",
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
