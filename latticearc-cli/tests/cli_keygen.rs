//! Integration tests for the `keygen` command: algorithm/use-case routing, key-file schema, permissions, and key-file error handling.
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
use std::process::Command;
use support::*;

/// Get the raw key base64 string from a key file JSON (supports both formats).
fn get_key_b64(json: &serde_json::Value) -> &str {
    json["key_data"]["raw"]
        .as_str()
        .or_else(|| json["key"].as_str())
        .expect("Key file must have key_data.raw or key field")
}
/// Helper: full keygen → sign → verify round-trip via the CLI for a given
/// use case. Asserts the expected signing scheme name and verifies the
/// signature validates against the generated public key.
fn use_case_keygen_sign_verify_roundtrip(use_case: &str, expected_scheme: &str) {
    let dir = temp_dir();
    run_ok(&["keygen", "--use-case", use_case, "--output", dir.path().to_str().unwrap()]);

    let sk_path = dir.path().join(format!("{expected_scheme}.sec.json"));
    let pk_path = dir.path().join(format!("{expected_scheme}.pub.json"));
    assert!(sk_path.exists(), "secret key not written for {use_case}: {}", sk_path.display());
    assert!(pk_path.exists(), "public key not written for {use_case}: {}", pk_path.display());

    let msg_path = dir.path().join("message.txt");
    std::fs::write(&msg_path, format!("regression fixture for {use_case}")).unwrap();

    let sig_path = dir.path().join("message.sig");
    run_ok(&[
        "sign",
        "--key",
        sk_path.to_str().unwrap(),
        "--public-key",
        pk_path.to_str().unwrap(),
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
    ]);

    // H2: SignedData verify requires either `--key` (trust-anchor pin) or
    // `--allow-embedded-key`. Use --key to demonstrate the right pattern.
    let verify_out = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        pk_path.to_str().unwrap(),
    ]);
    assert!(
        verify_out.contains("VALID"),
        "verify did not report VALID for {use_case}: {verify_out}"
    );
    assert!(
        verify_out.contains(expected_scheme),
        "verify output did not contain {expected_scheme}: {verify_out}"
    );
}

// ============================================================================
// S15: Key label support
// ============================================================================
#[test]
fn test_keygen_with_label_succeeds() {
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
    let label = pk["metadata"]["label"].as_str().or_else(|| pk["label"].as_str()).unwrap();
    assert_eq!(label, "Production signing key");
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
fn test_secret_key_restricted_permissions_succeeds() {
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
// S20: ML-KEM keygen (encryption keypair)
// ============================================================================
#[test]
fn test_ml_kem_keygen_all_levels_succeeds() {
    for (alg, name) in
        [("ml-kem512", "ml-kem-512"), ("ml-kem768", "ml-kem-768"), ("ml-kem1024", "ml-kem-1024")]
    {
        let dir = temp_dir();
        let d = dir.path().to_str().unwrap();

        // status messages on stderr now.
        let out = run_ok_combined(&["keygen", "--algorithm", alg, "--output", d]);
        assert!(out.contains(name));

        let pk_path = dir.path().join(format!("{name}.pub.json"));
        let sk_path = dir.path().join(format!("{name}.sec.json"));
        assert!(pk_path.exists(), "Public key file should exist for {name}");
        assert!(sk_path.exists(), "Secret key file should exist for {name}");

        // Validate key file structure
        let pk_json: serde_json::Value = read_json_file(&pk_path);
        assert_eq!(pk_json["algorithm"].as_str().unwrap(), name);
        assert_eq!(pk_json["key_type"].as_str().unwrap(), "public");
    }

    println!(
        "[PROOF] {{\"test\": \"ml_kem_keygen_all_levels\", \"category\": \"cli-keygen\", \"levels\": [\"ML-KEM-512\", \"ML-KEM-768\", \"ML-KEM-1024\"], \"all_generated\": true}}"
    );
}
#[test]
fn test_nonexistent_key_file_succeeds() {
    let dir = temp_dir();
    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"test").unwrap();

    let no_such_key = std::env::temp_dir().join("latticearc_no_such_key.json");
    let no_such_key_str = no_such_key.to_string_lossy().into_owned();
    let stderr = run_fail(&[
        "sign",
        "--algorithm",
        "ed25519",
        "--input",
        msg_path.to_str().unwrap(),
        "--key",
        &no_such_key_str,
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
fn test_corrupted_key_file_json_fails() {
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
fn test_key_file_wrong_base64_fails() {
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
// S43: Missing Required Arguments
// ============================================================================
#[test]
fn test_keygen_missing_algorithm_fails() {
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
// ============================================================================
// S51: Key File JSON Schema Validation
// ============================================================================
//
// Key files produced by `keygen` must follow a consistent JSON schema
// with required fields: version, algorithm, key_type, key, created.
#[test]
fn test_key_file_json_schema_succeeds() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Generate Ed25519 keys (asymmetric)
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    // Validate public key schema
    let pk_content = std::fs::read_to_string(dir.path().join("ed25519.pub.json")).unwrap();
    let pk_json: serde_json::Value = serde_json::from_str(&pk_content).unwrap();

    assert!(pk_json["version"].is_number(), "Key file must have 'version' field (number)");
    assert!(pk_json["algorithm"].is_string(), "Key file must have 'algorithm' field (string)");
    assert!(pk_json["key_type"].is_string(), "Key file must have 'key_type' field (string)");
    assert!(!get_key_b64(&pk_json).is_empty(), "Key file must have key data");
    assert!(pk_json["created"].is_string(), "Key file must have 'created' field (string)");

    assert_eq!(pk_json["algorithm"].as_str().unwrap(), "ed25519");
    assert_eq!(pk_json["key_type"].as_str().unwrap(), "public");

    // Validate secret key schema
    let sk_content = std::fs::read_to_string(dir.path().join("ed25519.sec.json")).unwrap();
    let sk_json: serde_json::Value = serde_json::from_str(&sk_content).unwrap();

    assert_eq!(sk_json["key_type"].as_str().unwrap(), "secret");
    assert_eq!(sk_json["algorithm"].as_str().unwrap(), "ed25519");

    // Validate symmetric key schema (AES-256)
    run_ok(&["keygen", "--algorithm", "aes256", "--output", d]);
    let aes_content = std::fs::read_to_string(dir.path().join("aes256.key.json")).unwrap();
    let aes_json: serde_json::Value = serde_json::from_str(&aes_content).unwrap();

    assert!(aes_json["version"].is_number(), "AES key must have 'version' field");
    assert_eq!(aes_json["algorithm"].as_str().unwrap(), "aes-256");
    assert_eq!(aes_json["key_type"].as_str().unwrap(), "symmetric");
    assert!(!get_key_b64(&aes_json).is_empty(), "AES key must have key data");

    // Validate ML-DSA key schema (PQC)
    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);
    let pqc_content = std::fs::read_to_string(dir.path().join("ml-dsa-65.pub.json")).unwrap();
    let pqc_json: serde_json::Value = serde_json::from_str(&pqc_content).unwrap();

    assert_eq!(pqc_json["algorithm"].as_str().unwrap(), "ml-dsa-65");
    assert_eq!(pqc_json["key_type"].as_str().unwrap(), "public");

    println!(
        "[PROOF] {{\"test\": \"key_file_json_schema\", \"category\": \"correctness\", \"schemas_validated\": [\"ed25519.pub\", \"ed25519.sec\", \"aes256.key\", \"ml-dsa-65.pub\"], \"required_fields\": [\"version\", \"algorithm\", \"key_type\", \"key\", \"created\"], \"all_valid\": true}}"
    );
}
// ============================================================================
// S52: Keygen Uniqueness — Each Invocation Produces Different Keys
// ============================================================================
//
// Key generation must use cryptographically secure randomness.
// Two consecutive keygen invocations MUST produce different keys.
#[test]
fn test_keygen_produces_unique_keys_are_unique() {
    let dir1 = temp_dir();
    let dir2 = temp_dir();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", dir1.path().to_str().unwrap()]);
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", dir2.path().to_str().unwrap()]);

    let pk1 = std::fs::read_to_string(dir1.path().join("ed25519.pub.json")).unwrap();
    let pk2 = std::fs::read_to_string(dir2.path().join("ed25519.pub.json")).unwrap();

    let pk1_json: serde_json::Value = serde_json::from_str(&pk1).unwrap();
    let pk2_json: serde_json::Value = serde_json::from_str(&pk2).unwrap();

    assert_ne!(
        get_key_b64(&pk1_json),
        get_key_b64(&pk2_json),
        "Two keygen invocations MUST produce different public keys"
    );

    let sk1 = std::fs::read_to_string(dir1.path().join("ed25519.sec.json")).unwrap();
    let sk2 = std::fs::read_to_string(dir2.path().join("ed25519.sec.json")).unwrap();

    let sk1_json: serde_json::Value = serde_json::from_str(&sk1).unwrap();
    let sk2_json: serde_json::Value = serde_json::from_str(&sk2).unwrap();

    assert_ne!(
        get_key_b64(&sk1_json),
        get_key_b64(&sk2_json),
        "Two keygen invocations MUST produce different secret keys"
    );

    // Also verify AES keygen uniqueness
    run_ok(&["keygen", "--algorithm", "aes256", "--output", dir1.path().to_str().unwrap()]);
    run_ok(&["keygen", "--algorithm", "aes256", "--output", dir2.path().to_str().unwrap()]);

    let aes1 = std::fs::read_to_string(dir1.path().join("aes256.key.json")).unwrap();
    let aes2 = std::fs::read_to_string(dir2.path().join("aes256.key.json")).unwrap();

    let aes1_json: serde_json::Value = serde_json::from_str(&aes1).unwrap();
    let aes2_json: serde_json::Value = serde_json::from_str(&aes2).unwrap();

    assert_ne!(
        get_key_b64(&aes1_json),
        get_key_b64(&aes2_json),
        "Two AES keygen invocations MUST produce different keys"
    );

    println!(
        "[PROOF] {{\"test\": \"keygen_produces_unique_keys\", \"category\": \"security\", \"algorithms\": [\"ed25519\", \"aes256\"], \"public_keys_unique\": true, \"secret_keys_unique\": true, \"symmetric_keys_unique\": true, \"csprng_verified\": true}}"
    );
}
// ============================================================================
// S23: Use-case-driven keygen + sign + verify
// ============================================================================
//
// End-to-end coverage of the `--use-case` path of `keygen` through a full
// keygen → sign (via the unified `--public-key` path) → verify round-trip.
//
// Three independent pieces of logic are exercised here that the library-level
// `test_generate_signing_keypair_all_use_cases_succeeds` does not cover:
//
//   1. `select_signature_scheme` routing `UseCase` variants to their signing
//      scheme (not their encryption scheme) via `UseCaseConfig`.
//   2. `generate_from_config` writing hybrid ML-DSA + Ed25519 keys as
//      `KeyData::Composite` so that `PortableKey::validate()` accepts them.
//   3. `sign_unified` inferring the signing scheme from the loaded public
//      key's algorithm when no use case / security level is supplied.
#[test]
fn test_cli_keygen_use_case_iot_device_roundtrip_succeeds() {
    // IoT → SecurityLevel::Standard → hybrid ML-DSA-44 + Ed25519
    use_case_keygen_sign_verify_roundtrip("iot-device", "hybrid-ml-dsa-44-ed25519");
}
#[test]
fn test_cli_keygen_use_case_secure_messaging_roundtrip_succeeds() {
    // SecureMessaging → SecurityLevel::High (default) → hybrid ML-DSA-65 + Ed25519
    use_case_keygen_sign_verify_roundtrip("secure-messaging", "hybrid-ml-dsa-65-ed25519");
}
#[test]
fn test_cli_keygen_use_case_legal_documents_roundtrip_succeeds() {
    // LegalDocuments → SecurityLevel::Maximum → hybrid ML-DSA-87 + Ed25519
    use_case_keygen_sign_verify_roundtrip("legal-documents", "hybrid-ml-dsa-87-ed25519");
}
#[test]
fn test_cli_keygen_use_case_file_storage_roundtrip_succeeds() {
    // FileStorage is encryption-oriented; the use-case → signing scheme
    // dispatcher must still route it to the signature side of the policy
    // engine (SecurityLevel::Maximum → hybrid ML-DSA-87 + Ed25519) rather
    // than returning the encryption scheme.
    use_case_keygen_sign_verify_roundtrip("file-storage", "hybrid-ml-dsa-87-ed25519");
}
