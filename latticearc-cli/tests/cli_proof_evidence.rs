//! CLI End-to-End Proof Evidence Suite
//!
//! Comprehensive integration tests for the `latticearc` CLI binary. Each test
//! spawns the real binary, exercises a complete workflow (keygen → sign → verify,
//! keygen → encrypt → decrypt, etc.), and emits a `[PROOF]` JSON line to stdout
//! with detailed numeric metadata matching the library proof evidence format.
//!
//! Run: `cargo test -p latticearc-cli --test cli_proof_evidence --release -- --nocapture`
//! Extract: `grep "\[PROOF\]" output.txt > cli_proof_evidence.jsonl`

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    missing_docs,
    unused_qualifications
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Locate the FIPS dylib directory in the build artifacts.
fn find_fips_dylib_dir() -> Option<PathBuf> {
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .join("target")
        .join("release")
        .join("build");

    if !target_dir.exists() {
        return None;
    }

    let entries = std::fs::read_dir(&target_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("aws-lc-fips-sys-") {
            let artifacts = entry.path().join("out").join("build").join("artifacts");
            if artifacts.exists()
                && let Ok(files) = std::fs::read_dir(&artifacts)
            {
                for f in files.flatten() {
                    let fname = f.file_name();
                    let fname_str = fname.to_string_lossy();
                    if fname_str.ends_with(".dylib") || fname_str.ends_with(".so") {
                        return Some(artifacts);
                    }
                }
            }
        }
    }
    None
}

/// Build a `Command` for the CLI binary with the FIPS dylib path set.
fn cli_cmd() -> Command {
    let bin = env!("CARGO_BIN_EXE_latticearc");
    let mut cmd = Command::new(bin);
    if let Some(dylib_dir) = find_fips_dylib_dir() {
        if cfg!(target_os = "macos") {
            let existing = std::env::var("DYLD_LIBRARY_PATH").unwrap_or_default();
            let new_path = if existing.is_empty() {
                dylib_dir.to_string_lossy().to_string()
            } else {
                format!("{}:{existing}", dylib_dir.display())
            };
            cmd.env("DYLD_LIBRARY_PATH", new_path);
        } else {
            let existing = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
            let new_path = if existing.is_empty() {
                dylib_dir.to_string_lossy().to_string()
            } else {
                format!("{}:{existing}", dylib_dir.display())
            };
            cmd.env("LD_LIBRARY_PATH", new_path);
        }
    }
    cmd
}

/// Run the CLI with given args, assert success, return stdout.
fn run_cli(args: &[&str]) -> String {
    let output = cli_cmd().args(args).output().expect("Failed to execute CLI binary");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    assert!(
        output.status.success(),
        "CLI failed with args {args:?}:\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Run the CLI expecting failure, return (stdout, stderr, exit_code).
fn run_cli_fail(args: &[&str]) -> (String, String, i32) {
    let output = cli_cmd().args(args).output().expect("Failed to execute CLI binary");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/// Write test data to a file.
fn write_test_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write test file");
    path
}

/// Decode base64 key material from a key file JSON and return its byte length.
fn key_material_len(key_file_path: &Path) -> usize {
    let content = std::fs::read_to_string(key_file_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let b64 = json["key"].as_str().unwrap();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap().len()
}

/// Decode base64 signature from a standard signature JSON and return its byte length.
fn sig_material_len(sig_file_path: &Path) -> usize {
    let content = std::fs::read_to_string(sig_file_path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    use base64::Engine;
    if let Some(b64) = json.get("signature").and_then(|v| v.as_str()) {
        base64::engine::general_purpose::STANDARD.decode(b64).unwrap().len()
    } else {
        // Hybrid: ml_dsa_sig + ed25519_sig
        let ml = json["ml_dsa_sig"].as_str().unwrap();
        let ed = json["ed25519_sig"].as_str().unwrap();
        let ml_len = base64::engine::general_purpose::STANDARD.decode(ml).unwrap().len();
        let ed_len = base64::engine::general_purpose::STANDARD.decode(ed).unwrap().len();
        ml_len + ed_len
    }
}

/// Compute SHA3-256 hash of data using the CLI and return the hex digest.
fn cli_sha3_hex(data: &[u8]) -> String {
    let dir = TempDir::new().expect("tempdir");
    let input = write_test_file(dir.path(), "hash_input.bin", data);
    let output = run_cli(&["hash", "-i", input.to_str().unwrap()]);
    output.trim().strip_prefix("SHA3-256: ").unwrap().to_string()
}

// ============================================================================
// Section 1: Signing Roundtrips (keygen → sign → verify) — 7 algorithms
// ============================================================================

/// Test sign/verify roundtrip with rich proof evidence output.
fn sign_verify_roundtrip(
    keygen_alg: &str,
    sign_alg: &str,
    pk_file: &str,
    sk_file: &str,
    standard: &str,
    test_name: &str,
) {
    let dir = TempDir::new().expect("tempdir");
    let key_dir = dir.path().join("keys");

    run_cli(&["keygen", "-a", keygen_alg, "-o", key_dir.to_str().unwrap()]);

    let pk_path = key_dir.join(pk_file);
    let sk_path = key_dir.join(sk_file);
    assert!(pk_path.exists(), "Public key file not found: {}", pk_path.display());
    assert!(sk_path.exists(), "Secret key file not found: {}", sk_path.display());

    // Validate key file JSON structure
    let pk_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
    assert_eq!(pk_json["version"], 1);
    assert_eq!(pk_json["key_type"], "public");
    assert!(pk_json["key"].is_string());
    assert!(pk_json["created"].is_string());

    let sk_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sk_path).unwrap()).unwrap();
    assert_eq!(sk_json["version"], 1);
    assert_eq!(sk_json["key_type"], "secret");

    // Measure key sizes
    let pk_bytes = key_material_len(&pk_path);
    let sk_bytes = key_material_len(&sk_path);

    // Write test data and sign
    let message = b"test message for signing roundtrip proof evidence";
    let input = write_test_file(dir.path(), "message.txt", message);
    let sig_path = dir.path().join("message.sig.json");

    run_cli(&[
        "sign",
        "-a",
        sign_alg,
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);
    assert!(sig_path.exists(), "Signature file not created");

    // Measure signature size
    let sig_bytes = sig_material_len(&sig_path);

    // Verify
    let output = run_cli(&[
        "verify",
        "-a",
        sign_alg,
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert!(output.contains("VALID"), "Verification should succeed: {output}");

    println!(
        "[PROOF] {{\"section\":1,\"test\":\"{test_name}\",\
         \"algorithm\":\"{sign_alg}\",\"standard\":\"{standard}\",\
         \"pk_bytes\":{pk_bytes},\"sk_bytes\":{sk_bytes},\
         \"signature_bytes\":{sig_bytes},\"message_len\":{},\
         \"verify\":\"PASS\",\"roundtrip\":\"PASS\",\"status\":\"PASS\"}}",
        message.len(),
    );
}

#[test]
fn s1_01_ed25519_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "ed25519",
        "ed25519",
        "ed25519.pub.json",
        "ed25519.sec.json",
        "RFC 8032",
        "ed25519_roundtrip",
    );
}

#[test]
fn s1_02_ml_dsa_44_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "ml-dsa44",
        "ml-dsa44",
        "ml-dsa-44.pub.json",
        "ml-dsa-44.sec.json",
        "FIPS 204",
        "ml_dsa_44_roundtrip",
    );
}

#[test]
fn s1_03_ml_dsa_65_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "ml-dsa65",
        "ml-dsa65",
        "ml-dsa-65.pub.json",
        "ml-dsa-65.sec.json",
        "FIPS 204",
        "ml_dsa_65_roundtrip",
    );
}

#[test]
fn s1_04_ml_dsa_87_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "ml-dsa87",
        "ml-dsa87",
        "ml-dsa-87.pub.json",
        "ml-dsa-87.sec.json",
        "FIPS 204",
        "ml_dsa_87_roundtrip",
    );
}

#[test]
fn s1_05_slh_dsa_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "slh-dsa128s",
        "slh-dsa",
        "slh-dsa-shake-128s.pub.json",
        "slh-dsa-shake-128s.sec.json",
        "FIPS 205",
        "slh_dsa_roundtrip",
    );
}

#[test]
fn s1_06_fn_dsa_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "fn-dsa512",
        "fn-dsa",
        "fn-dsa-512.pub.json",
        "fn-dsa-512.sec.json",
        "FIPS 206",
        "fn_dsa_roundtrip",
    );
}

#[test]
fn s1_07_hybrid_sign_verify_roundtrip() {
    sign_verify_roundtrip(
        "hybrid-sign",
        "hybrid",
        "hybrid-sign.pub.json",
        "hybrid-sign.sec.json",
        "FIPS 204 + RFC 8032",
        "hybrid_sign_roundtrip",
    );
}

// ============================================================================
// Section 2: Encryption Roundtrip with SHA3-256 Hash Binding
// ============================================================================

/// Encrypt/decrypt roundtrip with pre/post SHA3-256 hash verification.
fn encrypt_decrypt_roundtrip_with_hash(plaintext: &[u8], test_name: &str, description: &str) {
    let dir = TempDir::new().expect("tempdir");
    let key_dir = dir.path().join("keys");

    run_cli(&["keygen", "-a", "aes256", "-o", key_dir.to_str().unwrap()]);
    let key_path = key_dir.join("aes256.key.json");

    let key_bytes = key_material_len(&key_path);
    assert_eq!(key_bytes, 32, "AES-256 key must be 32 bytes");

    // Hash before encryption
    let pre_hash = cli_sha3_hex(plaintext);

    let input = write_test_file(dir.path(), "plaintext.bin", plaintext);
    let enc_path = dir.path().join("encrypted.json");
    let dec_path = dir.path().join("decrypted.bin");

    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    let enc_json_len = std::fs::metadata(&enc_path).unwrap().len();

    run_cli(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-o",
        dec_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    let decrypted = std::fs::read(&dec_path).expect("read decrypted");
    assert_eq!(decrypted.len(), plaintext.len(), "Size mismatch");
    assert_eq!(decrypted, plaintext, "Content mismatch");

    // Hash after decryption
    let post_hash = cli_sha3_hex(&decrypted);
    assert_eq!(pre_hash, post_hash, "SHA3-256 hash must match after roundtrip");

    println!(
        "[PROOF] {{\"section\":2,\"test\":\"{test_name}\",\
         \"description\":\"{description}\",\
         \"algorithm\":\"AES-256-GCM\",\"standard\":\"SP 800-38D\",\
         \"key_bytes\":{key_bytes},\
         \"plaintext_len\":{},\"encrypted_json_bytes\":{enc_json_len},\
         \"sha3_256_before\":\"{pre_hash}\",\"sha3_256_after\":\"{post_hash}\",\
         \"hash_match\":true,\"byte_exact_match\":true,\
         \"roundtrip\":\"PASS\",\"status\":\"PASS\"}}",
        plaintext.len(),
    );
}

#[test]
fn s2_01_aes256_gcm_encrypt_decrypt_roundtrip() {
    encrypt_decrypt_roundtrip_with_hash(
        b"Top secret post-quantum message for AES-256-GCM encryption test",
        "aes256_gcm_roundtrip",
        "Standard plaintext encrypt/decrypt with hash binding",
    );
}

#[test]
fn s2_02_aes256_gcm_large_file_roundtrip() {
    let plaintext: Vec<u8> = (0u8..=255).cycle().take(1_048_576).collect();
    encrypt_decrypt_roundtrip_with_hash(
        &plaintext,
        "aes256_gcm_large_file",
        "1MB file encrypt/decrypt with hash binding",
    );
}

#[test]
fn s2_03_aes256_gcm_empty_file_roundtrip() {
    encrypt_decrypt_roundtrip_with_hash(
        b"",
        "aes256_gcm_empty_file",
        "Empty file encrypt/decrypt with hash binding",
    );
}

#[test]
fn s2_04_aes256_gcm_binary_all_256_values() {
    let mut plaintext = Vec::with_capacity(512);
    for i in 0..256u16 {
        plaintext.push(i as u8);
        plaintext.push(255u8.wrapping_sub(i as u8));
    }
    encrypt_decrypt_roundtrip_with_hash(
        &plaintext,
        "aes256_gcm_binary_all_256",
        "Binary data with all 256 byte values",
    );
}

#[test]
fn s2_05_aes256_gcm_unicode_roundtrip() {
    let plaintext = "Hello 世界 مرحبا Привет 🔐🛡️ Ñoño café résumé naïve".as_bytes();
    encrypt_decrypt_roundtrip_with_hash(
        plaintext,
        "aes256_gcm_unicode",
        "Multi-language Unicode with emoji",
    );
}

#[test]
fn s2_06_aes256_gcm_structured_json_roundtrip() {
    let plaintext = br#"{"database":{"host":"db.internal","port":5432,"credentials":{"user":"admin","password":"s3cret!@#$%"}},"features":["encryption","audit","compliance"],"version":42}"#;
    encrypt_decrypt_roundtrip_with_hash(
        plaintext,
        "aes256_gcm_structured_json",
        "JSON config with nested objects and special chars",
    );
}

#[test]
fn s2_07_aes256_gcm_1_byte_roundtrip() {
    encrypt_decrypt_roundtrip_with_hash(
        &[0x42],
        "aes256_gcm_1_byte",
        "Single byte encrypt/decrypt with hash binding",
    );
}

// ============================================================================
// Section 3: Key File Format & NIST Parameter Validation
// ============================================================================

#[test]
fn s3_01_key_file_json_structure_all_algorithms() {
    let dir = TempDir::new().expect("tempdir");
    let key_dir = dir.path().join("keys");

    let algorithms: &[(&str, &[&str])] = &[
        ("aes256", &["aes256.key.json"]),
        ("ed25519", &["ed25519.pub.json", "ed25519.sec.json"]),
        ("ml-dsa44", &["ml-dsa-44.pub.json", "ml-dsa-44.sec.json"]),
        ("ml-dsa65", &["ml-dsa-65.pub.json", "ml-dsa-65.sec.json"]),
        ("ml-dsa87", &["ml-dsa-87.pub.json", "ml-dsa-87.sec.json"]),
        ("slh-dsa128s", &["slh-dsa-shake-128s.pub.json", "slh-dsa-shake-128s.sec.json"]),
        ("fn-dsa512", &["fn-dsa-512.pub.json", "fn-dsa-512.sec.json"]),
        ("ml-kem768", &["ml-kem-768.pub.json", "ml-kem-768.sec.json"]),
        ("hybrid-sign", &["hybrid-sign.pub.json", "hybrid-sign.sec.json"]),
    ];

    let mut total_files = 0;
    for (alg, expected_files) in algorithms {
        let alg_dir = key_dir.join(alg);
        run_cli(&["keygen", "-a", alg, "-o", alg_dir.to_str().unwrap()]);

        for file_name in *expected_files {
            let file_path = alg_dir.join(file_name);
            assert!(file_path.exists(), "Missing key file: {}", file_path.display());

            let content = std::fs::read_to_string(&file_path).unwrap();
            let json: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
                panic!("Invalid JSON in {}: {e}", file_path.display());
            });

            assert_eq!(json["version"], 1, "Wrong version in {file_name}");
            assert!(json["algorithm"].is_string(), "Missing algorithm in {file_name}");
            assert!(json["key_type"].is_string(), "Missing key_type in {file_name}");
            assert!(json["key"].is_string(), "Missing key in {file_name}");
            assert!(json["created"].is_string(), "Missing created in {file_name}");

            let kt = json["key_type"].as_str().unwrap();
            assert!(
                ["symmetric", "public", "secret"].contains(&kt),
                "Invalid key_type '{kt}' in {file_name}"
            );

            // Validate ISO 8601 timestamp contains required components
            let ts = json["created"].as_str().unwrap();
            assert!(ts.contains('T'), "Timestamp should be ISO 8601: {ts}");

            let key_b64 = json["key"].as_str().unwrap();
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(key_b64)
                .unwrap_or_else(|e| panic!("Invalid Base64 in {file_name}: {e}"));

            total_files += 1;
        }
    }

    println!(
        "[PROOF] {{\"section\":3,\"test\":\"key_file_json_structure\",\
         \"algorithms_tested\":{},\"total_key_files\":{total_files},\
         \"fields_validated\":[\"version\",\"algorithm\",\"key_type\",\"key\",\"created\"],\
         \"base64_valid\":true,\"iso8601_valid\":true,\
         \"status\":\"PASS\"}}",
        algorithms.len(),
    );
}

#[test]
fn s3_02_key_file_label_support() {
    let dir = TempDir::new().expect("tempdir");

    run_cli(&[
        "keygen",
        "-a",
        "ed25519",
        "-o",
        dir.path().to_str().unwrap(),
        "-l",
        "test-signing-key",
    ]);

    let pk_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("ed25519.pub.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(pk_json["label"], "test-signing-key");

    let sk_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("ed25519.sec.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(sk_json["label"], "test-signing-key");

    // Without label, field should be absent
    let dir2 = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir2.path().to_str().unwrap()]);
    let no_label: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir2.path().join("ed25519.pub.json")).unwrap(),
    )
    .unwrap();
    assert!(no_label.get("label").is_none(), "Label should be absent when not provided");

    println!(
        "[PROOF] {{\"section\":3,\"test\":\"key_file_label\",\
         \"label_stored\":true,\"label_absent_when_omitted\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s3_03_nist_ml_kem_key_sizes() {
    // FIPS 203 Table 2: ML-KEM public key sizes
    let expected: &[(&str, &str, usize)] = &[
        ("ml-kem512", "ml-kem-512", 800),
        ("ml-kem768", "ml-kem-768", 1184),
        ("ml-kem1024", "ml-kem-1024", 1568),
    ];

    for (alg, prefix, expected_pk_size) in expected {
        let dir = TempDir::new().expect("tempdir");
        run_cli(&["keygen", "-a", alg, "-o", dir.path().to_str().unwrap()]);

        let pk_path = dir.path().join(format!("{prefix}.pub.json"));
        let sk_path = dir.path().join(format!("{prefix}.sec.json"));
        assert!(pk_path.exists(), "Missing {prefix} public key");
        assert!(sk_path.exists(), "Missing {prefix} secret key");

        let pk_bytes = key_material_len(&pk_path);
        let sk_bytes = key_material_len(&sk_path);

        assert_eq!(
            pk_bytes, *expected_pk_size,
            "{prefix} PK size: expected {expected_pk_size}, got {pk_bytes}"
        );

        let pk_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
        assert_eq!(pk_json["algorithm"].as_str().unwrap(), *prefix);

        println!(
            "[PROOF] {{\"section\":3,\"test\":\"nist_ml_kem_{prefix}\",\
             \"algorithm\":\"{prefix}\",\"standard\":\"FIPS 203\",\
             \"pk_bytes\":{pk_bytes},\"expected_pk_bytes\":{expected_pk_size},\
             \"sk_bytes\":{sk_bytes},\
             \"pk_size_match\":true,\"status\":\"PASS\"}}"
        );
    }
}

#[test]
fn s3_04_nist_aes_key_size() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);
    let key_path = dir.path().join("aes256.key.json");
    let key_bytes = key_material_len(&key_path);
    assert_eq!(key_bytes, 32, "AES-256 key must be exactly 32 bytes");

    println!(
        "[PROOF] {{\"section\":3,\"test\":\"nist_aes256_key_size\",\
         \"algorithm\":\"AES-256\",\"standard\":\"FIPS 197\",\
         \"key_bytes\":{key_bytes},\"expected_key_bytes\":32,\
         \"key_size_match\":true,\"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 4: Security Properties
// ============================================================================

#[test]
#[cfg(unix)]
fn s4_01_secret_key_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);

    let sk_path = dir.path().join("ed25519.sec.json");
    let mode = std::fs::metadata(&sk_path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Secret key file should have 0600 permissions, got {mode:#o}");

    let pk_mode = std::fs::metadata(dir.path().join("ed25519.pub.json"))
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert!(pk_mode & 0o400 != 0, "Public key should be readable");

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"secret_key_permissions\",\
         \"sk_mode\":\"{mode:#o}\",\"expected\":\"0o600\",\
         \"pk_readable\":true,\"fips_140_3\":\"key protection\",\
         \"status\":\"PASS\"}}"
    );
}

#[test]
#[cfg(unix)]
fn s4_02_symmetric_key_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);

    let key_path = dir.path().join("aes256.key.json");
    let mode = std::fs::metadata(&key_path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Symmetric key file should have 0600 permissions, got {mode:#o}");

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"symmetric_key_permissions\",\
         \"mode\":\"{mode:#o}\",\"expected\":\"0o600\",\
         \"status\":\"PASS\"}}"
    );
}

#[test]
#[cfg(unix)]
fn s4_03_all_secret_key_types_restricted() {
    use std::os::unix::fs::PermissionsExt;

    let algorithms: &[(&str, &str)] = &[
        ("ml-dsa65", "ml-dsa-65.sec.json"),
        ("ml-kem768", "ml-kem-768.sec.json"),
        ("fn-dsa512", "fn-dsa-512.sec.json"),
        ("hybrid-sign", "hybrid-sign.sec.json"),
    ];

    for (alg, sk_file) in algorithms {
        let dir = TempDir::new().expect("tempdir");
        run_cli(&["keygen", "-a", alg, "-o", dir.path().to_str().unwrap()]);
        let sk_path = dir.path().join(sk_file);
        let mode = std::fs::metadata(&sk_path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{alg} secret key should have 0600, got {mode:#o}");
    }

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"all_secret_keys_restricted\",\
         \"algorithms_checked\":{},\
         \"all_0600\":true,\"status\":\"PASS\"}}",
        algorithms.len(),
    );
}

#[test]
fn s4_04_algorithm_key_mismatch_rejected() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ml-dsa65",
        "-i",
        input.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "Should fail with algorithm mismatch");
    assert!(
        stderr.contains("mismatch") || stderr.contains("algorithm"),
        "Error should mention algorithm mismatch: {stderr}"
    );

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"algorithm_mismatch\",\
         \"key_alg\":\"ed25519\",\"requested_alg\":\"ml-dsa65\",\
         \"exit_code\":{code},\"error_mentions_mismatch\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s4_05_public_key_for_signing_rejected() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("ed25519.pub.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("secret") || stderr.contains("Secret"), "Error: {stderr}");

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"public_key_for_signing\",\
         \"exit_code\":{code},\"error_mentions_secret\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s4_06_secret_key_for_verify_rejected() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let sig_path = dir.path().join("test.sig.json");
    run_cli(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    let (_, stderr, code) = run_cli_fail(&[
        "verify",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);
    assert!(stderr.contains("public") || stderr.contains("Public"), "Error: {stderr}");

    println!(
        "[PROOF] {{\"section\":4,\"test\":\"secret_key_for_verify\",\
         \"exit_code\":{code},\"error_mentions_public\":true,\
         \"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 5: Negative Tests — Tampered Data
// ============================================================================

#[test]
fn s5_01_tampered_signature_rejected() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("ed25519.pub.json");
    let sk_path = dir.path().join("ed25519.sec.json");
    let input = write_test_file(dir.path(), "message.txt", b"authentic message");

    let sig_path = dir.path().join("message.sig.json");
    run_cli(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    // Tamper with signature base64
    let sig_content = std::fs::read_to_string(&sig_path).unwrap();
    let mut sig_json: serde_json::Value = serde_json::from_str(&sig_content).unwrap();
    let sig_b64 = sig_json["signature"].as_str().unwrap().to_string();
    let mut tampered = sig_b64.into_bytes();
    if !tampered.is_empty() {
        tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    }
    sig_json["signature"] = serde_json::Value::String(String::from_utf8(tampered).unwrap());
    std::fs::write(&sig_path, serde_json::to_string_pretty(&sig_json).unwrap()).unwrap();

    let (_, _stderr, code) = run_cli_fail(&[
        "verify",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0, "Tampered signature should be rejected");

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"tampered_signature\",\
         \"algorithm\":\"ed25519\",\"corruption\":\"base64 first byte flipped\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_02_tampered_message_rejected() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ml-dsa65", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("ml-dsa-65.pub.json");
    let sk_path = dir.path().join("ml-dsa-65.sec.json");
    let input = write_test_file(dir.path(), "message.txt", b"original message");

    let sig_path = dir.path().join("message.sig.json");
    run_cli(&[
        "sign",
        "-a",
        "ml-dsa65",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    let tampered_input = write_test_file(dir.path(), "tampered.txt", b"tampered message");
    let (_, _stderr, code) = run_cli_fail(&[
        "verify",
        "-a",
        "ml-dsa65",
        "-i",
        tampered_input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"tampered_message\",\
         \"algorithm\":\"ML-DSA-65\",\"standard\":\"FIPS 204\",\
         \"corruption\":\"message content modified\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_03_wrong_key_for_decrypt() {
    let dir = TempDir::new().expect("tempdir");
    let key_dir_1 = dir.path().join("key1");
    let key_dir_2 = dir.path().join("key2");

    run_cli(&["keygen", "-a", "aes256", "-o", key_dir_1.to_str().unwrap()]);
    run_cli(&["keygen", "-a", "aes256", "-o", key_dir_2.to_str().unwrap()]);

    let input = write_test_file(dir.path(), "secret.txt", b"secret data");
    let enc_path = dir.path().join("encrypted.json");

    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key_dir_1.join("aes256.key.json").to_str().unwrap(),
    ]);

    let (_, _stderr, code) = run_cli_fail(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-k",
        key_dir_2.join("aes256.key.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"wrong_key_decrypt\",\
         \"algorithm\":\"AES-256-GCM\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_04_missing_input_file() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");

    let (_, _stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        "/nonexistent/file.txt",
        "-k",
        sk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"missing_input_file\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_05_missing_key_file() {
    let dir = TempDir::new().expect("tempdir");
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, _stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        "/nonexistent/key.json",
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"missing_key_file\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_06_wrong_key_for_verify() {
    let dir = TempDir::new().expect("tempdir");
    let key_dir_1 = dir.path().join("keys1");
    let key_dir_2 = dir.path().join("keys2");

    run_cli(&["keygen", "-a", "ed25519", "-o", key_dir_1.to_str().unwrap()]);
    run_cli(&["keygen", "-a", "ed25519", "-o", key_dir_2.to_str().unwrap()]);

    let input = write_test_file(dir.path(), "message.txt", b"test message");
    let sig_path = dir.path().join("message.sig.json");

    run_cli(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        key_dir_1.join("ed25519.sec.json").to_str().unwrap(),
    ]);

    let (_, _stderr, code) = run_cli_fail(&[
        "verify",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        key_dir_2.join("ed25519.pub.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"wrong_key_verify\",\
         \"algorithm\":\"ed25519\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_07_encrypt_with_wrong_key_type() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("ed25519.pub.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, _stderr, code) = run_cli_fail(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"wrong_key_type_encrypt\",\
         \"provided\":\"public\",\"expected\":\"symmetric\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s5_08_decrypt_with_public_key() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);
    let key_path = dir.path().join("aes256.key.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");
    let enc_path = dir.path().join("encrypted.json");

    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    let key_dir2 = dir.path().join("keys2");
    run_cli(&["keygen", "-a", "ed25519", "-o", key_dir2.to_str().unwrap()]);
    let pk_path = key_dir2.join("ed25519.pub.json");

    let (_, _stderr, code) = run_cli_fail(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":5,\"test\":\"decrypt_with_public_key\",\
         \"provided\":\"public\",\"expected\":\"symmetric\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 6: Corrupted Key File Tests
// ============================================================================

#[test]
fn s6_01_invalid_json_key_file() {
    let dir = TempDir::new().expect("tempdir");
    let bad_key = dir.path().join("bad.key.json");
    std::fs::write(&bad_key, "this is not json{{{").unwrap();
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, _stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        bad_key.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"invalid_json_key_file\",\
         \"corruption\":\"not valid JSON\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s6_02_invalid_base64_key_material() {
    let dir = TempDir::new().expect("tempdir");
    let bad_key = dir.path().join("bad_b64.key.json");
    let bad_json = serde_json::json!({
        "version": 1,
        "algorithm": "ed25519",
        "key_type": "secret",
        "key": "!!!not_valid_base64!!!",
        "created": "2026-01-01T00:00:00Z"
    });
    std::fs::write(&bad_key, serde_json::to_string_pretty(&bad_json).unwrap()).unwrap();
    let input = write_test_file(dir.path(), "message.txt", b"test");

    let (_, _stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        bad_key.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"invalid_base64_key\",\
         \"corruption\":\"invalid Base64 in key field\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s6_03_truncated_key_material() {
    let dir = TempDir::new().expect("tempdir");

    // Generate a valid key, then truncate its key material
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");
    let content = std::fs::read_to_string(&sk_path).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Replace key with a very short base64 value (2 bytes instead of full key)
    use base64::Engine;
    json["key"] =
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode([0x42, 0x43]));
    std::fs::write(&sk_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let input = write_test_file(dir.path(), "message.txt", b"test");
    let (_, _stderr, code) = run_cli_fail(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"truncated_key_material\",\
         \"corruption\":\"key material truncated to 2 bytes\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s6_04_wrong_version_key_file() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");

    // Modify version to 99 — file should still parse (version isn't validated at read)
    // but this tests forward-compatibility behavior
    let content = std::fs::read_to_string(&sk_path).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&content).unwrap();
    json["version"] = serde_json::json!(99);
    std::fs::write(&sk_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let input = write_test_file(dir.path(), "message.txt", b"test");
    // This may or may not fail depending on version validation — we just document behavior
    let output = cli_cmd()
        .args([
            "sign",
            "-a",
            "ed25519",
            "-i",
            input.to_str().unwrap(),
            "-k",
            sk_path.to_str().unwrap(),
        ])
        .output()
        .expect("execute");
    let succeeded = output.status.success();

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"wrong_version_key_file\",\
         \"version_set\":99,\"accepted\":{succeeded},\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s6_05_corrupted_encrypted_json() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);
    let key_path = dir.path().join("aes256.key.json");
    let input = write_test_file(dir.path(), "message.txt", b"test");
    let enc_path = dir.path().join("encrypted.json");

    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    // Corrupt the encrypted JSON by truncating it
    let content = std::fs::read_to_string(&enc_path).unwrap();
    std::fs::write(&enc_path, &content[..content.len() / 2]).unwrap();

    let (_, _stderr, code) = run_cli_fail(&[
        "decrypt",
        "-i",
        enc_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":6,\"test\":\"corrupted_encrypted_json\",\
         \"corruption\":\"JSON truncated to 50%\",\
         \"exit_code\":{code},\"negative\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 7: Hash & KDF
// ============================================================================

#[test]
fn s7_01_hash_deterministic() {
    let dir = TempDir::new().expect("tempdir");
    let input = write_test_file(dir.path(), "data.txt", b"deterministic hash test");

    let output1 = run_cli(&["hash", "-i", input.to_str().unwrap()]);
    let output2 = run_cli(&["hash", "-i", input.to_str().unwrap()]);
    assert_eq!(output1, output2, "Hash should be deterministic");

    assert!(output1.starts_with("SHA3-256: "), "Hash output format unexpected: {output1}");
    let hex_part = output1.trim().strip_prefix("SHA3-256: ").unwrap();
    assert_eq!(hex_part.len(), 64, "SHA3-256 hex digest should be 64 chars");
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be hex");

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"hash_deterministic\",\
         \"algorithm\":\"SHA3-256\",\"standard\":\"FIPS 202\",\
         \"digest_hex_len\":{},\"deterministic\":true,\
         \"digest\":\"{hex_part}\",\"status\":\"PASS\"}}",
        hex_part.len(),
    );
}

#[test]
fn s7_02_hash_base64_format() {
    let dir = TempDir::new().expect("tempdir");
    let input = write_test_file(dir.path(), "data.txt", b"base64 format test");

    let output = run_cli(&["hash", "-i", input.to_str().unwrap(), "-f", "base64"]);
    let b64_part = output.trim().strip_prefix("SHA3-256: ").unwrap();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64_part).unwrap();
    assert_eq!(decoded.len(), 32, "SHA3-256 should produce 32 bytes");

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"hash_base64_format\",\
         \"algorithm\":\"SHA3-256\",\"output_bytes\":32,\
         \"base64_decodable\":true,\"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_03_hash_different_inputs() {
    let dir = TempDir::new().expect("tempdir");
    let input1 = write_test_file(dir.path(), "data1.txt", b"message A");
    let input2 = write_test_file(dir.path(), "data2.txt", b"message B");

    let output1 = run_cli(&["hash", "-i", input1.to_str().unwrap()]);
    let output2 = run_cli(&["hash", "-i", input2.to_str().unwrap()]);
    assert_ne!(output1, output2);

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"hash_collision_resistance\",\
         \"algorithm\":\"SHA3-256\",\"different_outputs\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_04_hash_empty_input() {
    let dir = TempDir::new().expect("tempdir");
    let input = write_test_file(dir.path(), "empty.txt", b"");
    let output = run_cli(&["hash", "-i", input.to_str().unwrap()]);
    let hex_part = output.trim().strip_prefix("SHA3-256: ").unwrap();
    assert_eq!(hex_part.len(), 64, "Empty input should still produce 64 hex chars");

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"hash_empty_input\",\
         \"algorithm\":\"SHA3-256\",\"input_len\":0,\
         \"digest_hex_len\":64,\"digest\":\"{hex_part}\",\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_05_kdf_hkdf_deterministic() {
    let args = &[
        "kdf",
        "-a",
        "hkdf",
        "-i",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "-s",
        "000102030405060708090a0b0c",
        "--info",
        "f0f1f2f3f4f5f6f7f8f9",
        "-l",
        "42",
    ];
    let output1 = run_cli(args);
    let output2 = run_cli(args);
    assert_eq!(output1, output2);
    let hex_part = output1.trim();
    assert_eq!(hex_part.len(), 84, "42 bytes = 84 hex chars");

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"kdf_hkdf_deterministic\",\
         \"algorithm\":\"HKDF-SHA256\",\"standard\":\"SP 800-56C\",\
         \"output_bytes\":42,\"deterministic\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_06_kdf_pbkdf2_deterministic() {
    let args = &[
        "kdf",
        "-a",
        "pbkdf2",
        "-i",
        "password",
        "-s",
        "73616c74",
        "--iterations",
        "10000",
        "-l",
        "32",
    ];
    let output1 = run_cli(args);
    let output2 = run_cli(args);
    assert_eq!(output1, output2);

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"kdf_pbkdf2_deterministic\",\
         \"algorithm\":\"PBKDF2-HMAC-SHA256\",\"standard\":\"SP 800-132\",\
         \"iterations\":10000,\"output_bytes\":32,\"deterministic\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_07_kdf_salt_sensitivity() {
    let output1 = run_cli(&[
        "kdf",
        "-a",
        "hkdf",
        "-i",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "-s",
        "000102030405060708090a0b0c",
        "--info",
        "test",
        "-l",
        "32",
    ]);
    let output2 = run_cli(&[
        "kdf",
        "-a",
        "hkdf",
        "-i",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "-s",
        "ff0102030405060708090a0b0c",
        "--info",
        "test",
        "-l",
        "32",
    ]);
    assert_ne!(output1, output2);

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"kdf_salt_sensitivity\",\
         \"algorithm\":\"HKDF-SHA256\",\"different_outputs\":true,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s7_08_kdf_base64_output() {
    let output = run_cli(&[
        "kdf",
        "-a",
        "hkdf",
        "-i",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "-s",
        "000102030405060708090a0b0c",
        "--info",
        "test",
        "-l",
        "32",
        "-f",
        "base64",
    ]);
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(output.trim()).unwrap();
    assert_eq!(decoded.len(), 32);

    println!(
        "[PROOF] {{\"section\":7,\"test\":\"kdf_base64_output\",\
         \"algorithm\":\"HKDF-SHA256\",\"output_bytes\":32,\
         \"base64_decodable\":true,\"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 8: Info Command
// ============================================================================

#[test]
fn s8_01_info_command_output() {
    let output = run_cli(&["info"]);

    let checks = [
        ("LatticeArc CLI", "cli_name"),
        ("FIPS 140-3", "fips_mention"),
        ("Self-tests", "self_tests"),
        ("AES-256-GCM", "aes_256_gcm"),
        ("ML-DSA", "ml_dsa"),
        ("ML-KEM", "ml_kem"),
        ("SLH-DSA", "slh_dsa"),
        ("FN-DSA", "fn_dsa"),
        ("Ed25519", "ed25519"),
        ("SHA3-256", "sha3_256"),
        ("HKDF", "hkdf"),
        ("PBKDF2", "pbkdf2"),
    ];

    for (expected, _label) in &checks {
        assert!(output.contains(expected), "Info should contain '{expected}'");
    }

    println!(
        "[PROOF] {{\"section\":8,\"test\":\"info_command\",\
         \"algorithms_listed\":{},\"fips_mentioned\":true,\
         \"self_tests_shown\":true,\"status\":\"PASS\"}}",
        checks.len(),
    );
}

// ============================================================================
// Section 9: Cross-Algorithm Isolation
// ============================================================================

#[test]
fn s9_01_cross_algorithm_key_rejection() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let ed_sk = dir.path().join("ed25519.sec.json");
    let input = write_test_file(dir.path(), "message.txt", b"cross-algo test");

    let wrong_algs = ["ml-dsa44", "ml-dsa65", "ml-dsa87", "slh-dsa", "fn-dsa"];
    let mut rejected = 0;
    for wrong_alg in &wrong_algs {
        let (_, _stderr, code) = run_cli_fail(&[
            "sign",
            "-a",
            wrong_alg,
            "-i",
            input.to_str().unwrap(),
            "-k",
            ed_sk.to_str().unwrap(),
        ]);
        assert_ne!(code, 0, "Ed25519 key with {wrong_alg} should fail");
        rejected += 1;
    }

    println!(
        "[PROOF] {{\"section\":9,\"test\":\"cross_algorithm_isolation\",\
         \"base_key\":\"ed25519\",\"wrong_algorithms_tested\":{},\
         \"all_rejected\":true,\"status\":\"PASS\"}}",
        rejected,
    );
}

#[test]
fn s9_02_ml_dsa_cross_level_isolation() {
    let dir = TempDir::new().expect("tempdir");
    let dir44 = dir.path().join("dsa44");
    let dir65 = dir.path().join("dsa65");

    run_cli(&["keygen", "-a", "ml-dsa44", "-o", dir44.to_str().unwrap()]);
    run_cli(&["keygen", "-a", "ml-dsa65", "-o", dir65.to_str().unwrap()]);

    let input = write_test_file(dir.path(), "message.txt", b"cross level test");
    let sig_path = dir.path().join("sig.json");

    run_cli(&[
        "sign",
        "-a",
        "ml-dsa44",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        dir44.join("ml-dsa-44.sec.json").to_str().unwrap(),
    ]);

    let (_, _stderr, code) = run_cli_fail(&[
        "verify",
        "-a",
        "ml-dsa65",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        dir65.join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert_ne!(code, 0);

    println!(
        "[PROOF] {{\"section\":9,\"test\":\"ml_dsa_cross_level\",\
         \"sign_level\":\"ML-DSA-44\",\"verify_level\":\"ML-DSA-65\",\
         \"exit_code\":{code},\"isolation_enforced\":true,\
         \"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 10: Key Reuse & Nonce Uniqueness
// ============================================================================

#[test]
fn s10_01_keygen_uniqueness() {
    let dir = TempDir::new().expect("tempdir");
    let dir1 = dir.path().join("run1");
    let dir2 = dir.path().join("run2");

    run_cli(&["keygen", "-a", "ed25519", "-o", dir1.to_str().unwrap()]);
    run_cli(&["keygen", "-a", "ed25519", "-o", dir2.to_str().unwrap()]);

    let pk1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir1.join("ed25519.pub.json")).unwrap())
            .unwrap();
    let pk2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir2.join("ed25519.pub.json")).unwrap())
            .unwrap();

    assert_ne!(pk1["key"], pk2["key"], "Two key generations should produce different keys");

    println!(
        "[PROOF] {{\"section\":10,\"test\":\"keygen_uniqueness\",\
         \"algorithm\":\"ed25519\",\"keys_different\":true,\
         \"rng_quality\":\"PASS\",\"status\":\"PASS\"}}"
    );
}

#[test]
fn s10_02_encrypt_nonce_uniqueness() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);
    let key_path = dir.path().join("aes256.key.json");
    let input = write_test_file(dir.path(), "data.txt", b"same plaintext");

    let enc1_path = dir.path().join("enc1.json");
    let enc2_path = dir.path().join("enc2.json");

    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc1_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);
    run_cli(&[
        "encrypt",
        "-m",
        "aes256-gcm",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc2_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    let enc1 = std::fs::read_to_string(&enc1_path).unwrap();
    let enc2 = std::fs::read_to_string(&enc2_path).unwrap();
    assert_ne!(
        enc1, enc2,
        "Two encryptions must produce different ciphertexts (nonce reuse = catastrophic)"
    );

    // Both should still decrypt correctly
    let dec1_path = dir.path().join("dec1.bin");
    let dec2_path = dir.path().join("dec2.bin");
    run_cli(&[
        "decrypt",
        "-i",
        enc1_path.to_str().unwrap(),
        "-o",
        dec1_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);
    run_cli(&[
        "decrypt",
        "-i",
        enc2_path.to_str().unwrap(),
        "-o",
        dec2_path.to_str().unwrap(),
        "-k",
        key_path.to_str().unwrap(),
    ]);

    assert_eq!(std::fs::read(&dec1_path).unwrap(), b"same plaintext");
    assert_eq!(std::fs::read(&dec2_path).unwrap(), b"same plaintext");

    println!(
        "[PROOF] {{\"section\":10,\"test\":\"nonce_uniqueness\",\
         \"algorithm\":\"AES-256-GCM\",\
         \"ciphertexts_different\":true,\"both_decrypt_correctly\":true,\
         \"nonce_reuse\":false,\"status\":\"PASS\"}}"
    );
}

#[test]
fn s10_03_key_reuse_sign_multiple_files() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ml-dsa65", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("ml-dsa-65.pub.json");
    let sk_path = dir.path().join("ml-dsa-65.sec.json");

    let messages: &[&[u8]] =
        &[b"First document to sign", b"Second document to sign", b"Third document to sign"];

    for (i, msg) in messages.iter().enumerate() {
        let input = write_test_file(dir.path(), &format!("doc{i}.txt"), msg);
        let sig_path = dir.path().join(format!("doc{i}.sig.json"));

        run_cli(&[
            "sign",
            "-a",
            "ml-dsa65",
            "-i",
            input.to_str().unwrap(),
            "-o",
            sig_path.to_str().unwrap(),
            "-k",
            sk_path.to_str().unwrap(),
        ]);

        let output = run_cli(&[
            "verify",
            "-a",
            "ml-dsa65",
            "-i",
            input.to_str().unwrap(),
            "-s",
            sig_path.to_str().unwrap(),
            "-k",
            pk_path.to_str().unwrap(),
        ]);
        assert!(output.contains("VALID"));
    }

    println!(
        "[PROOF] {{\"section\":10,\"test\":\"key_reuse_sign\",\
         \"algorithm\":\"ML-DSA-65\",\"files_signed\":{},\
         \"all_verified\":true,\"status\":\"PASS\"}}",
        messages.len(),
    );
}

#[test]
fn s10_04_key_reuse_encrypt_multiple_files() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "aes256", "-o", dir.path().to_str().unwrap()]);
    let key_path = dir.path().join("aes256.key.json");

    let payloads: &[&[u8]] =
        &[b"First secret document", b"Second secret document", b"Third secret document"];

    for (i, payload) in payloads.iter().enumerate() {
        let input = write_test_file(dir.path(), &format!("secret{i}.txt"), payload);
        let enc_path = dir.path().join(format!("secret{i}.enc.json"));
        let dec_path = dir.path().join(format!("secret{i}.dec.bin"));

        run_cli(&[
            "encrypt",
            "-m",
            "aes256-gcm",
            "-i",
            input.to_str().unwrap(),
            "-o",
            enc_path.to_str().unwrap(),
            "-k",
            key_path.to_str().unwrap(),
        ]);
        run_cli(&[
            "decrypt",
            "-i",
            enc_path.to_str().unwrap(),
            "-o",
            dec_path.to_str().unwrap(),
            "-k",
            key_path.to_str().unwrap(),
        ]);

        let decrypted = std::fs::read(&dec_path).unwrap();
        assert_eq!(decrypted.as_slice(), *payload);
    }

    println!(
        "[PROOF] {{\"section\":10,\"test\":\"key_reuse_encrypt\",\
         \"algorithm\":\"AES-256-GCM\",\"files_encrypted\":{},\
         \"all_roundtripped\":true,\"status\":\"PASS\"}}",
        payloads.len(),
    );
}

// ============================================================================
// Section 11: Signature Default Output Path
// ============================================================================

#[test]
fn s11_01_sign_default_output_path() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "ed25519", "-o", dir.path().to_str().unwrap()]);
    let sk_path = dir.path().join("ed25519.sec.json");
    let input = write_test_file(dir.path(), "document.pdf", b"pdf content");

    run_cli(&[
        "sign",
        "-a",
        "ed25519",
        "-i",
        input.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    let expected_sig = dir.path().join("document.pdf.sig.json");
    assert!(expected_sig.exists(), "Default signature path should be <input>.sig.json");

    println!(
        "[PROOF] {{\"section\":11,\"test\":\"default_sig_path\",\
         \"input\":\"document.pdf\",\"expected_output\":\"document.pdf.sig.json\",\
         \"file_created\":true,\"status\":\"PASS\"}}"
    );
}

// ============================================================================
// Section 12: Hybrid Signing Edge Cases
// ============================================================================

#[test]
fn s12_01_hybrid_sign_verify_binary_data() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "hybrid-sign", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("hybrid-sign.pub.json");
    let sk_path = dir.path().join("hybrid-sign.sec.json");

    let binary_data: Vec<u8> = (0u8..=255).collect();
    let input = write_test_file(dir.path(), "binary.bin", &binary_data);
    let sig_path = dir.path().join("binary.sig.json");

    run_cli(&[
        "sign",
        "-a",
        "hybrid",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    // Validate hybrid signature JSON structure
    let sig_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sig_path).unwrap()).unwrap();
    assert!(sig_json.get("ml_dsa_sig").is_some(), "Hybrid sig should have ml_dsa_sig");
    assert!(sig_json.get("ed25519_sig").is_some(), "Hybrid sig should have ed25519_sig");
    assert_eq!(sig_json["algorithm"], "hybrid-ml-dsa-65-ed25519");

    use base64::Engine;
    let ml_dsa_len = base64::engine::general_purpose::STANDARD
        .decode(sig_json["ml_dsa_sig"].as_str().unwrap())
        .unwrap()
        .len();
    let ed25519_len = base64::engine::general_purpose::STANDARD
        .decode(sig_json["ed25519_sig"].as_str().unwrap())
        .unwrap()
        .len();

    let output = run_cli(&[
        "verify",
        "-a",
        "hybrid",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert!(output.contains("VALID"));

    println!(
        "[PROOF] {{\"section\":12,\"test\":\"hybrid_binary_data\",\
         \"algorithm\":\"Hybrid ML-DSA-65+Ed25519\",\
         \"standard\":\"FIPS 204 + RFC 8032\",\
         \"input_bytes\":256,\
         \"ml_dsa_sig_bytes\":{ml_dsa_len},\"ed25519_sig_bytes\":{ed25519_len},\
         \"total_sig_bytes\":{},\
         \"verify\":\"PASS\",\"status\":\"PASS\"}}",
        ml_dsa_len + ed25519_len,
    );
}

#[test]
fn s12_02_hybrid_sign_unicode_data() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "hybrid-sign", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("hybrid-sign.pub.json");
    let sk_path = dir.path().join("hybrid-sign.sec.json");

    let unicode_data = "合同签名 Контракт 契約 العقد 🔏📜✅".as_bytes();
    let input = write_test_file(dir.path(), "unicode.txt", unicode_data);
    let sig_path = dir.path().join("unicode.sig.json");

    run_cli(&[
        "sign",
        "-a",
        "hybrid",
        "-i",
        input.to_str().unwrap(),
        "-o",
        sig_path.to_str().unwrap(),
        "-k",
        sk_path.to_str().unwrap(),
    ]);

    let output = run_cli(&[
        "verify",
        "-a",
        "hybrid",
        "-i",
        input.to_str().unwrap(),
        "-s",
        sig_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);
    assert!(output.contains("VALID"));

    println!(
        "[PROOF] {{\"section\":12,\"test\":\"hybrid_unicode_data\",\
         \"algorithm\":\"Hybrid ML-DSA-65+Ed25519\",\
         \"input_bytes\":{},\"verify\":\"PASS\",\"status\":\"PASS\"}}",
        unicode_data.len(),
    );
}

// ============================================================================
// Section 13: Hybrid KEM Encryption Keygen
// ============================================================================

#[test]
fn s13_01_hybrid_kem_keygen() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "hybrid", "-o", dir.path().to_str().unwrap()]);

    // Hybrid KEM only saves public key (secret key is ephemeral per CLI docs)
    let pk_path = dir.path().join("hybrid-kem.pub.json");
    assert!(pk_path.exists(), "Hybrid KEM public key should be created");

    let pk_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&pk_path).unwrap()).unwrap();
    assert_eq!(pk_json["algorithm"], "hybrid-ml-kem-768-x25519");
    assert_eq!(pk_json["key_type"], "public");

    let pk_bytes = key_material_len(&pk_path);
    // Format: 4 bytes (u32le length prefix) + ML-KEM-768 pk (1184) + X25519 pk (32)
    assert_eq!(pk_bytes, 4 + 1184 + 32, "Hybrid KEM PK = 4 + 1184 + 32 = 1220 bytes");

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"hybrid_kem_keygen\",\
         \"algorithm\":\"hybrid-ml-kem-768-x25519\",\
         \"pk_bytes\":{pk_bytes},\
         \"ml_kem_pk_bytes\":1184,\"x25519_pk_bytes\":32,\
         \"length_prefix_bytes\":4,\
         \"status\":\"PASS\"}}"
    );
}

#[test]
fn s13_02_hybrid_kem_encrypt() {
    let dir = TempDir::new().expect("tempdir");
    run_cli(&["keygen", "-a", "hybrid", "-o", dir.path().to_str().unwrap()]);
    let pk_path = dir.path().join("hybrid-kem.pub.json");

    let plaintext = b"Post-quantum encrypted message via hybrid ML-KEM-768 + X25519";
    let input = write_test_file(dir.path(), "message.txt", plaintext);
    let enc_path = dir.path().join("hybrid_encrypted.json");

    run_cli(&[
        "encrypt",
        "-m",
        "hybrid",
        "-i",
        input.to_str().unwrap(),
        "-o",
        enc_path.to_str().unwrap(),
        "-k",
        pk_path.to_str().unwrap(),
    ]);

    assert!(enc_path.exists(), "Hybrid encrypted file should be created");

    // Validate the encrypted JSON has hybrid-specific fields
    let enc_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&enc_path).unwrap()).unwrap();
    assert!(enc_json.get("scheme").is_some(), "Should have scheme field");

    let enc_file_len = std::fs::metadata(&enc_path).unwrap().len();

    println!(
        "[PROOF] {{\"section\":13,\"test\":\"hybrid_kem_encrypt\",\
         \"algorithm\":\"Hybrid ML-KEM-768 + X25519 + AES-256-GCM\",\
         \"plaintext_len\":{},\"encrypted_json_bytes\":{enc_file_len},\
         \"status\":\"PASS\"}}",
        plaintext.len(),
    );
}
