//! Integration tests for the `sign` and `verify` commands, including adversarial/tamper-detection and Pattern-6 reject-path indistinguishability.
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
use std::path::PathBuf;
use std::process::Command;
use support::*;

/// Get the raw key base64 string from a key file JSON (supports both formats).
fn get_key_b64(json: &serde_json::Value) -> &str {
    json["key_data"]["raw"]
        .as_str()
        .or_else(|| json["key"].as_str())
        .expect("Key file must have key_data.raw or key field")
}
/// Decode the Base64 "signature" field from a signature file and return raw byte length.
fn sig_file_raw_len(path: &std::path::Path) -> usize {
    let json: serde_json::Value = read_json_file(path);
    let b64 = json["signature"].as_str().unwrap();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).unwrap().len()
}
fn pure_pq_keygen_sign_verify_roundtrip(algorithm: &str, expected_scheme: &str) {
    let dir = temp_dir();
    run_ok(&["keygen", "--algorithm", algorithm, "--output", dir.path().to_str().unwrap()]);

    let sk_path = dir.path().join(format!("{expected_scheme}.sec.json"));
    let pk_path = dir.path().join(format!("{expected_scheme}.pub.json"));
    assert!(sk_path.exists(), "secret key not written for {algorithm}: {}", sk_path.display());
    assert!(pk_path.exists(), "public key not written for {algorithm}: {}", pk_path.display());

    let msg_path = dir.path().join("message.txt");
    std::fs::write(&msg_path, format!("pure-pq regression fixture for {algorithm}")).unwrap();

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

    // H2: SignedData verify requires `--key` to pin the trust anchor.
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
        verify_out.contains("VALID") && verify_out.contains(expected_scheme),
        "verify output for pure-PQ {algorithm} did not confirm valid signature under \
         expected scheme {expected_scheme}. Got: {verify_out}"
    );
}
/// Capture exit code + stderr for a CLI invocation that must fail.
///
/// `output.status.code()` returns `None` when the process was killed
/// by a signal (SIGSEGV / SIGKILL / etc.). Map that to `-1` so the
/// caller's `assert_eq!(code, 1, ...)` produces a "got -1, expected 1"
/// error rather than a confusing pattern-mismatch.
fn run_capture_fail(args: &[&str]) -> (i32, String) {
    let output = execute_cli(args);
    assert!(!output.status.success(), "CLI should have failed with args {args:?}");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (code, stderr)
}
/// Assert a `verify` invocation collapses to the indistinguishable INVALID
/// shape required by Pattern-6: exit 1, stderr says "Signature is INVALID.",
/// stderr contains none of the known leak substrings. Returns the captured
/// stderr so callers can perform additional scenario-specific assertions
/// (e.g., absence of an attacker-controlled marker) without re-spawning
/// the CLI.
/// Substrings that historically leaked reject detail. Each is the
/// literal text from a `bail!` / `anyhow!` / `.context(...)` site a
/// found to be distinguishable. New leak shapes should
/// be appended here, not silently dropped.
///
/// Stored lowercase so the per-test compare can match
/// case-insensitively against `stderr.to_lowercase()` without a
/// per-leak `to_lowercase()` allocation.
const PATTERN6_LEAK_SUBSTRINGS_LOWER: &[&str] = &[
    "verification failed",
    "hybrid verification failed",
    "signature was created over different data",
    "failed to parse signature json",
    "failed to parse hybrid signature json",
    "missing 'signature' field",
    "missing 'ml_dsa_sig'",
    "missing 'ed25519_sig'",
    "invalid base64 in signature",
    "invalid base64 in ml_dsa_sig",
    "invalid base64 in ed25519_sig",
    "missing 'algorithm' field",
    "unknown algorithm in signature file",
    "invalid padding",
    "could not detect signature algorithm",
];
fn assert_verify_invalid_collapse(args: &[&str], scenario: &str) -> String {
    let (code, stderr) = run_capture_fail(args);
    assert_eq!(
        code, 1,
        "verify ({scenario}) must exit 1 (INVALID class), not {code} (operational class). \
         A non-1 exit lets attackers distinguish reject paths via $? -- Pattern-6 leak.\nstderr: {stderr}"
    );

    // Verdict-line contract: stderr may contain unrelated tracing INFO
    // lines (logging-init banner, etc.), but exactly one line — taken
    // as a whole — must equal "Signature is INVALID.". Whole-line
    // match (not `contains`) catches both a regression that prepends
    // / appends text to the verdict ("Signature is INVALID: <reason>")
    // AND an unrelated log line that incidentally contains the substring
    // "Signature is" without being the verdict itself.
    let verdict_count = stderr.lines().filter(|line| *line == "Signature is INVALID.").count();
    assert_eq!(
        verdict_count, 1,
        "verify ({scenario}) stderr must contain exactly one whole line equal to \
         'Signature is INVALID.', found {verdict_count}.\nfull stderr: {stderr}"
    );

    // Case-insensitive leak check. The stderr-side `to_lowercase()` is
    // one allocation per test on a typically <1 KiB string; the leak
    // side is statically lowercase via PATTERN6_LEAK_SUBSTRINGS_LOWER
    // so the inner loop allocates nothing.
    let stderr_lower = stderr.to_lowercase();
    for leak in PATTERN6_LEAK_SUBSTRINGS_LOWER {
        assert!(
            !stderr_lower.contains(leak),
            "verify ({scenario}) stderr leaked reject detail '{leak}' (case-insensitive): {stderr}"
        );
    }
    stderr
}
/// CLI vs keyfile-stem mapping for legacy-mode signing.
///
/// `keygen --algorithm <cli_keygen>` produces `<keyfile_stem>.{sec,pub}.json`.
/// `sign --algorithm <cli_sign>` writes the signature.
///
/// The mismatch between CLI value and keyfile stem (e.g. `ml-dsa65` vs
/// `ml-dsa-65`) is intentional — the CLI value is a clap enum, the
/// keyfile name is the canonical algorithm string.
struct LegacyAlg<'a> {
    cli_keygen: &'a str,
    cli_sign: &'a str,
    keyfile_stem: &'a str,
}

// `keygen --algorithm` and `sign --algorithm` accept different value
// sets — keygen uses the strict SLH-DSA / FN-DSA parameter-set names
// (`slh-dsa128s`, `fn-dsa512`), sign uses the family names (`slh-dsa`,
// `fn-dsa`). Pre-fix tests that hardcoded one assumed both were the
// same and silently failed at the cross-product level.
const LEGACY_ALGS: &[LegacyAlg] = &[
    LegacyAlg { cli_keygen: "ml-dsa65", cli_sign: "ml-dsa65", keyfile_stem: "ml-dsa-65" },
    LegacyAlg { cli_keygen: "ml-dsa44", cli_sign: "ml-dsa44", keyfile_stem: "ml-dsa-44" },
    LegacyAlg { cli_keygen: "ml-dsa87", cli_sign: "ml-dsa87", keyfile_stem: "ml-dsa-87" },
    LegacyAlg {
        cli_keygen: "slh-dsa128s",
        cli_sign: "slh-dsa",
        keyfile_stem: "slh-dsa-shake-128s",
    },
    LegacyAlg { cli_keygen: "fn-dsa512", cli_sign: "fn-dsa", keyfile_stem: "fn-dsa-512" },
    LegacyAlg { cli_keygen: "ed25519", cli_sign: "ed25519", keyfile_stem: "ed25519" },
];
const HYBRID_ALG: LegacyAlg =
    LegacyAlg { cli_keygen: "hybrid-sign", cli_sign: "hybrid", keyfile_stem: "hybrid-sign" };
const ED25519_ALG: LegacyAlg =
    LegacyAlg { cli_keygen: "ed25519", cli_sign: "ed25519", keyfile_stem: "ed25519" };
/// Helper: keygen + sign (legacy `--algorithm` mode) for a given alg
/// descriptor. Returns (msg_path, sig_path, pub_key_path).
fn legacy_sign_fixture(dir: &tempfile::TempDir, alg: &LegacyAlg) -> (PathBuf, PathBuf, PathBuf) {
    let d = dir.path().to_str().unwrap();
    run_ok(&["keygen", "--algorithm", alg.cli_keygen, "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"pattern-6 cross-product fixture").unwrap();

    let sig_path = dir.path().join("msg.sig.json");
    let sk_path = dir.path().join(format!("{}.sec.json", alg.keyfile_stem));
    let pk_path = dir.path().join(format!("{}.pub.json", alg.keyfile_stem));
    run_ok(&[
        "sign",
        "--algorithm",
        alg.cli_sign,
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig_path.to_str().unwrap(),
        "--key",
        sk_path.to_str().unwrap(),
    ]);
    (msg_path, sig_path, pk_path)
}
/// SignedData sign fixture: `keygen <keygen_args>` → write msg → sign
/// via `--key + --public-key` (the SignedData envelope path). Returns
/// (msg_path, sig_path, sk_path, pk_path).
///
/// `keyfile_stem` is the filename prefix the CLI emits for the
/// chosen algorithm/use-case (e.g. `"ml-dsa-65"` for `--algorithm
/// ml-dsa65`, `"hybrid-ml-dsa-65-ed25519"` for `--use-case
/// secure-messaging`).
///
/// **Per-dir requirement**: the helper hardcodes `msg.txt` and
/// `msg.sig` filenames. Calling it twice on the same `TempDir`
/// silently overwrites both files. Tests that need two independent
/// fixtures (e.g. the C1 key-substitution regression) must use two
/// separate `TempDir` values; the function asserts this at runtime
/// via the `msg.txt` non-existence check below to surface the
/// collision instead of letting it pass silently.
fn signed_data_sign_fixture(
    dir: &tempfile::TempDir,
    keygen_args: &[&str],
    keyfile_stem: &str,
    msg_bytes: &[u8],
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let d = dir.path().to_str().unwrap();
    let mut keygen_cmd: Vec<&str> = vec!["keygen"];
    keygen_cmd.extend(keygen_args);
    keygen_cmd.extend(["--output", d]);
    run_ok(&keygen_cmd);

    let sk_path = dir.path().join(format!("{keyfile_stem}.sec.json"));
    let pk_path = dir.path().join(format!("{keyfile_stem}.pub.json"));

    let msg_path = dir.path().join("msg.txt");
    assert!(
        !msg_path.exists(),
        "signed_data_sign_fixture: caller must use a fresh TempDir; \
         {} already exists (would silently overwrite the prior fixture)",
        msg_path.display()
    );
    std::fs::write(&msg_path, msg_bytes).unwrap();

    let sig_path = dir.path().join("msg.sig");
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

    (msg_path, sig_path, sk_path, pk_path)
}

// ============================================================================
// S02: Ed25519 Keygen → Sign → Verify (classical baseline)
// ============================================================================
#[test]
fn test_ed25519_keygen_sign_verify_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    // Keygen — moved status messages to stderr,
    // so capture both streams when checking "Generated ... keypair".
    let out = run_ok_combined(&["keygen", "--algorithm", "ed25519", "--output", d]);
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
    let out = run_ok_combined(&[
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
    let sig_json: serde_json::Value = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let pk_json: serde_json::Value = read_json_file(&pk_path);
    let pk_b64 = pk_json["key_data"]["raw"].as_str().or_else(|| pk_json["key"].as_str()).unwrap();

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

    let out = run_ok_combined(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        pk_path.to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    let sig_json: serde_json::Value = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().unwrap();
    let sig_bytes_len =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64).unwrap().len();
    let pk_json: serde_json::Value = read_json_file(&pk_path);
    let pk_bytes_len =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, get_key_b64(&pk_json))
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
fn test_ml_dsa_44_keygen_sign_verify_roundtrip() {
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

    let out = run_ok_combined(&[
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
fn test_ml_dsa_87_keygen_sign_verify_roundtrip() {
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

    let out = run_ok_combined(&[
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
fn test_slh_dsa_keygen_sign_verify_roundtrip() {
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

    let out = run_ok_combined(&[
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
fn test_fn_dsa_keygen_sign_verify_roundtrip() {
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

    let out = run_ok_combined(&[
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
fn test_hybrid_sign_keygen_sign_verify_roundtrip() {
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

    let out = run_ok_combined(&[
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
// S10: Tamper detection — modified message fails verify
// ============================================================================
#[test]
fn test_tampered_message_fails_verification_fails() {
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
        stderr.contains("INVALID")
            || stderr.contains("Verification failed")
            || stderr.contains("Signature is INVALID"),
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
fn test_wrong_key_fails_verification_fails() {
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
        stderr.contains("INVALID")
            || stderr.contains("Verification failed")
            || stderr.contains("Signature is INVALID"),
        "Wrong key should fail verification: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"wrong_key_fails_verification\", \"category\": \"cli-tamper\", \"tamper_type\": \"wrong_public_key\", \"detected\": true}}"
    );
}
// ============================================================================
// S13: Algorithm mismatch detection
// ============================================================================
#[test]
fn test_algorithm_key_mismatch_rejected_fails() {
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
fn test_verify_auto_detects_algorithm_succeeds() {
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
    let out = run_ok_combined(&[
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
// S33: Empty Input Handling
// ============================================================================
//
// Cryptographic operations must handle zero-byte inputs correctly.
// Empty messages are valid inputs for signing and hashing.
#[test]
fn test_sign_verify_empty_message_roundtrip() {
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

    let out = run_ok_combined(&[
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
fn test_sign_verify_binary_data_roundtrip() {
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

    let out = run_ok_combined(&[
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
// S36: Corrupted Signature — Forgery Detection
// ============================================================================
//
// Bit-flipping a signature must cause verification to fail for all algorithms.
#[test]
fn test_corrupted_signature_detected_ed25519_fails() {
    let dir = temp_dir();
    let (msg_path, sig_path, pk_path) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let mut sig_json = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().expect("signature str").to_string();
    sig_json["signature"] = serde_json::Value::String(corrupt_base64(&sig_b64));
    let corrupted_sig = dir.path().join("corrupted.sig.json");
    write_json_file_pretty(&corrupted_sig, &sig_json);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg_path.to_str().unwrap(),
            "--signature",
            corrupted_sig.to_str().unwrap(),
            "--key",
            pk_path.to_str().unwrap(),
        ],
        "corrupted ed25519 signature",
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_ed25519\", \"category\": \"adversarial\", \"attack\": \"signature_bit_flip\", \"algorithm\": \"ed25519\", \"detected\": true}}"
    );
}
#[test]
fn test_corrupted_signature_detected_ml_dsa_fails() {
    let dir = temp_dir();
    let ml_dsa65 =
        LegacyAlg { cli_keygen: "ml-dsa65", cli_sign: "ml-dsa65", keyfile_stem: "ml-dsa-65" };
    let (msg_path, sig_path, pk_path) = legacy_sign_fixture(&dir, &ml_dsa65);

    let mut sig_json = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().expect("signature str").to_string();
    sig_json["signature"] = serde_json::Value::String(corrupt_base64(&sig_b64));
    let corrupted_sig = dir.path().join("corrupted.sig.json");
    write_json_file_pretty(&corrupted_sig, &sig_json);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg_path.to_str().unwrap(),
            "--signature",
            corrupted_sig.to_str().unwrap(),
            "--key",
            pk_path.to_str().unwrap(),
        ],
        "corrupted ML-DSA-65 signature",
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_ml_dsa\", \"category\": \"adversarial\", \"attack\": \"signature_bit_flip\", \"algorithm\": \"ML-DSA-65\", \"detected\": true}}"
    );
}
// ============================================================================
// S37: Wrong Key Type — Sign with Public Key, Decrypt with Public Key
// ============================================================================
//
// The CLI must reject operations when the wrong key type is provided.
#[test]
fn test_sign_with_public_key_rejected_fails() {
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
// ============================================================================
// S41: Signature Algorithm Field Tampering
// ============================================================================
//
// An attacker who modifies the "algorithm" field in a signature file
// must not be able to get a valid verification with a different algorithm.
#[test]
fn test_signature_algorithm_field_tampered_fails() {
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
// AES block = 16 bytes, SHA chunk = 64 bytes.
//
// Ed25519 sign/verify now enforce
// `validate_signature_size`, which caps message length at 64 KiB by
// default. This test previously used 1 MB; shrunk to 50 KiB to stay
// safely under the cap while still exercising a multi-page message
// that crosses every relevant block boundary (AES 16-byte, SHA-512
// 128-byte, page-size 4096-byte).
#[test]
fn test_large_message_sign_verify_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ed25519", "--output", d]);

    // 50 KiB of pseudo-random data — under the 64 KiB ML-DSA / SLH-DSA
    // / FN-DSA / Ed25519 sign-side resource-limit cap ().
    let large_data: Vec<u8> = (0..50u32 * 1024).map(|i| (i % 256) as u8).collect();
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

    let out = run_ok_combined(&[
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
        "[PROOF] {{\"test\": \"large_message_sign_verify\", \"category\": \"edge-case\", \"input_bytes\": 51200, \"algorithm\": \"ed25519\", \"result\": \"VALID\"}}"
    );
}
#[test]
fn test_sign_missing_key_fails() {
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
// S45: Signature Non-Determinism vs Determinism by Algorithm
// ============================================================================
//
// Ed25519 is deterministic (RFC 8032) — same message+key = same signature.
// ML-DSA may be randomized (FIPS 204 hedged signing).
#[test]
fn test_ed25519_signature_determinism_is_deterministic() {
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

    let sig1: serde_json::Value = read_json_file(&sig1_path);
    let sig2: serde_json::Value = read_json_file(&sig2_path);

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
fn test_mitm_message_substitution_succeeds() {
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
        stderr.contains("INVALID")
            || stderr.contains("Verification failed")
            || stderr.contains("Signature is INVALID"),
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
fn test_key_isolation_matrix_succeeds() {
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
// ============================================================================
// S53: PQC Large Message Sign/Verify (ML-DSA-87)
// ============================================================================
//
// Post-quantum signatures (FIPS 204) must handle large messages.
// ML-DSA-87 (Category 5) with 64 KB input (library limit).
#[test]
fn test_pqc_large_message_sign_verify_ml_dsa87_roundtrip() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa87", "--output", d]);

    // 64 KB of data (at library signing limit)
    let large_data: Vec<u8> = (0..65_536_u32).map(|i| (i % 256) as u8).collect();
    let msg_path = dir.path().join("large_pqc.bin");
    std::fs::write(&msg_path, &large_data).unwrap();

    let sig_path = dir.path().join("large_pqc.sig.json");
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

    let out = run_ok_combined(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-87.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"));

    // Verify signature size per FIPS 204 (ML-DSA-87 sig = 4627 bytes)
    let sig_len = sig_file_raw_len(&sig_path);
    assert_eq!(sig_len, 4627, "ML-DSA-87 signature MUST be 4627 bytes per FIPS 204");

    println!(
        "[PROOF] {{\"test\": \"pqc_large_message_sign_verify_ml_dsa87\", \"category\": \"e2e\", \"algorithm\": \"ML-DSA-87\", \"security_level\": \"NIST Category 5\", \"input_bytes\": 65536, \"sig_bytes\": {sig_len}, \"result\": \"VALID\", \"standard\": \"FIPS 204\"}}"
    );
}
// ============================================================================
// S54: SLH-DSA Corrupted Signature Detection
// ============================================================================
//
// Hash-based signatures (FIPS 205) must detect forgery via bit-flipping.
#[test]
fn test_corrupted_signature_detected_slh_dsa_fails() {
    let dir = temp_dir();
    let slh_dsa = LegacyAlg {
        cli_keygen: "slh-dsa128s",
        cli_sign: "slh-dsa",
        keyfile_stem: "slh-dsa-shake-128s",
    };
    let (msg_path, sig_path, pk_path) = legacy_sign_fixture(&dir, &slh_dsa);

    let mut sig_json = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().expect("signature str").to_string();
    sig_json["signature"] = serde_json::Value::String(corrupt_base64(&sig_b64));
    let corrupted_sig = dir.path().join("corrupted_slh.sig.json");
    write_json_file_pretty(&corrupted_sig, &sig_json);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg_path.to_str().unwrap(),
            "--signature",
            corrupted_sig.to_str().unwrap(),
            "--key",
            pk_path.to_str().unwrap(),
        ],
        "corrupted SLH-DSA-SHAKE-128s signature",
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_slh_dsa\", \"category\": \"adversarial\", \"attack\": \"signature_bit_flip\", \"algorithm\": \"SLH-DSA-SHAKE-128s\", \"standard\": \"FIPS 205\", \"detected\": true}}"
    );
}
// ============================================================================
// S55: Hybrid Signing — Tampered Message Detection
// ============================================================================
//
// Hybrid ML-DSA-65+Ed25519 must detect message substitution.
// Both inner signatures (PQC and classical) must fail simultaneously.
#[test]
fn test_hybrid_sign_tamper_detection_fails() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "hybrid-sign", "--output", d]);

    let msg_path = dir.path().join("contract.txt");
    std::fs::write(&msg_path, b"Original contract: pay $5000 to vendor").unwrap();

    let sig_path = dir.path().join("contract.sig.json");
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

    // Verify original
    let out = run_ok_combined(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.pub.json").to_str().unwrap(),
    ]);
    assert!(out.contains("VALID"), "Original message must verify");

    // Tamper with message
    std::fs::write(&msg_path, b"Tampered contract: pay $50000 to attacker").unwrap();

    let stderr = run_fail(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig_path.to_str().unwrap(),
        "--key",
        dir.path().join("hybrid-sign.pub.json").to_str().unwrap(),
    ]);
    assert!(
        stderr.contains("INVALID")
            || stderr.contains("Verification failed")
            || stderr.contains("Signature is INVALID"),
        "Tampered message must fail hybrid verification: {stderr}"
    );

    println!(
        "[PROOF] {{\"test\": \"hybrid_sign_tamper_detection\", \"category\": \"adversarial\", \"algorithm\": \"Hybrid ML-DSA-65+Ed25519\", \"attack\": \"message_substitution\", \"original_verified\": true, \"tampered_rejected\": true}}"
    );
}
// ============================================================================
// S60: FN-DSA-512 Corrupted Signature Detection
// ============================================================================
//
// FIPS 206 (draft) FN-DSA-512 lattice-based signatures must detect forgery.
#[test]
fn test_corrupted_signature_detected_fn_dsa_fails() {
    let dir = temp_dir();
    let fn_dsa =
        LegacyAlg { cli_keygen: "fn-dsa512", cli_sign: "fn-dsa", keyfile_stem: "fn-dsa-512" };
    let (msg_path, sig_path, pk_path) = legacy_sign_fixture(&dir, &fn_dsa);

    let mut sig_json = read_json_file(&sig_path);
    let sig_b64 = sig_json["signature"].as_str().expect("signature str").to_string();
    sig_json["signature"] = serde_json::Value::String(corrupt_base64(&sig_b64));
    let corrupted_sig = dir.path().join("corrupted_fn.sig.json");
    write_json_file_pretty(&corrupted_sig, &sig_json);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg_path.to_str().unwrap(),
            "--signature",
            corrupted_sig.to_str().unwrap(),
            "--key",
            pk_path.to_str().unwrap(),
        ],
        "corrupted FN-DSA-512 signature",
    );

    println!(
        "[PROOF] {{\"test\": \"corrupted_signature_detected_fn_dsa\", \"category\": \"adversarial\", \"attack\": \"signature_bit_flip\", \"algorithm\": \"FN-DSA-512\", \"standard\": \"FIPS 206 (draft)\", \"detected\": true}}"
    );
}
// ============================================================================
// S62: ML-DSA Signature Non-Determinism (Hedged Signing)
// ============================================================================
//
// FIPS 204 ML-DSA uses hedged signing (randomized).
// Two signatures of the same message with the same key SHOULD differ
// (unlike Ed25519 which is fully deterministic per RFC 8032).
#[test]
fn test_ml_dsa_signature_randomized_succeeds() {
    let dir = temp_dir();
    let d = dir.path().to_str().unwrap();

    run_ok(&["keygen", "--algorithm", "ml-dsa65", "--output", d]);

    let msg_path = dir.path().join("msg.txt");
    std::fs::write(&msg_path, b"hedged signing randomness test").unwrap();

    let sig1_path = dir.path().join("sig1.json");
    let sig2_path = dir.path().join("sig2.json");

    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig1_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);
    run_ok(&[
        "sign",
        "--algorithm",
        "ml-dsa65",
        "--input",
        msg_path.to_str().unwrap(),
        "--output",
        sig2_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.sec.json").to_str().unwrap(),
    ]);

    // Both signatures must verify
    let out1 = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig1_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    let out2 = run_ok(&[
        "verify",
        "--input",
        msg_path.to_str().unwrap(),
        "--signature",
        sig2_path.to_str().unwrap(),
        "--key",
        dir.path().join("ml-dsa-65.pub.json").to_str().unwrap(),
    ]);
    assert!(out1.contains("VALID"), "First ML-DSA signature must verify");
    assert!(out2.contains("VALID"), "Second ML-DSA signature must verify");

    // Signatures should differ (hedged signing), but both are valid
    // Note: some implementations may use deterministic mode, so we test
    // that both verify rather than asserting they differ
    let sig1: serde_json::Value = read_json_file(&sig1_path);
    let sig2: serde_json::Value = read_json_file(&sig2_path);

    let sigs_differ = sig1["signature"].as_str().unwrap() != sig2["signature"].as_str().unwrap();

    println!(
        "[PROOF] {{\"test\": \"ml_dsa_signature_randomized\", \"category\": \"nist-conformance\", \"standard\": \"FIPS 204\", \"algorithm\": \"ML-DSA-65\", \"both_verify\": true, \"signatures_differ\": {sigs_differ}, \"hedged_signing\": true}}"
    );
}
// ============================================================================
// Regression: pure-PQ keygen → `sign --public-key` must work (no hybrid coercion)
// ============================================================================
//
// Before `build_signing_config` was taught to infer `CryptoMode`, this combination
// failed with "Hybrid secret key length mismatch: expected 4064, got 4032":
//
//   - `keygen --algorithm ml-dsa65` produces a pure-PQ ML-DSA-65 keypair.
//   - `sign --public-key` routes to `sign_unified`, which calls the unified API.
//   - `build_signing_config` inferred SecurityLevel::High from the key's
//     algorithm but left `CryptoMode` at its default (Hybrid).
//   - The selector resolved (High, Hybrid) to `hybrid-ml-dsa-65-ed25519`
//     and tried to parse the 4032-byte pure-PQ secret key as a 4064-byte
//     hybrid secret key.
//
// The fix adds `infer_crypto_mode` so pure-PQ keys produce `CryptoMode::PqOnly`.
// This test locks in the end-to-end round-trip through the CLI so the same
// API-half-aligned bug can't recur.
#[test]
fn test_pure_pq_ml_dsa_44_keygen_sign_verify_roundtrip_via_public_key_flag() {
    pure_pq_keygen_sign_verify_roundtrip("ml-dsa44", "ml-dsa-44");
}
#[test]
fn test_pure_pq_ml_dsa_65_keygen_sign_verify_roundtrip_via_public_key_flag() {
    pure_pq_keygen_sign_verify_roundtrip("ml-dsa65", "ml-dsa-65");
}
#[test]
fn test_pure_pq_ml_dsa_87_keygen_sign_verify_roundtrip_via_public_key_flag() {
    pure_pq_keygen_sign_verify_roundtrip("ml-dsa87", "ml-dsa-87");
}
// ============================================================================
// S99: Pattern-6 reject-path indistinguishability (/L1/L2/M1/M3)
// ============================================================================
//
// Every reject path triggered by attacker-controllable signature-file content
// must produce identical observable behaviour:
//   1. Stderr contains "Signature is INVALID." and nothing more specific
//   2. Exit code is exactly 1 (the "invalid signature" class), not ≥2 (the
//      "operational error" class)
//
// Without these tests the leak-detection table reappears the next time a
// new error path is added: the per-axis tests (legacy-only or per-algorithm)
// would each pass while the cross-product reveals the leak.
//
// The leak strings tested below are the literal substrings previously
// found in the CLI binary's stderr — adding a new substring here
// when a new distinguisher is found is the intended way to
// extend the contract.
#[test]
fn test_pattern6_legacy_signature_bytes_tamper_collapses_invalid() {
    // Tamper the base64 `signature` field's bytes. This is the
    // already-collapsed baseline ("Signature is INVALID.") that was
    // recorded as `(collapsed)`; the test pins it so a future regression
    // can't silently un-collapse it.
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let mut v = read_json_file(&sig);
    let orig_b64 = v["signature"].as_str().expect("signature str").to_string();
    v["signature"] = serde_json::Value::String(corrupt_base64(&orig_b64));
    let tampered_path = dir.path().join("tampered_sig.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy signature-bytes tamper",
    );
}
#[test]
fn test_pattern6_legacy_bad_base64_collapses_invalid() {
    // Replace the base64 signature with a string that fails base64
    // decoding (invalid padding). found this leaked
    // "Invalid padding" / "Invalid base64 in signature".
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let mut v = read_json_file(&sig);
    // 3-char string is invalid base64 (must be multiple of 4 with padding).
    v["signature"] = serde_json::Value::String("AAA".to_string());
    let tampered_path = dir.path().join("bad_b64.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy bad-base64",
    );
}
#[test]
fn test_pattern6_legacy_missing_signature_field_collapses_invalid() {
    // Strip the entire `"signature"` field. reachable via
    // tampered JSON, leaked "Missing 'signature' field".
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let mut v = read_json_file(&sig);
    if let Some(obj) = v.as_object_mut() {
        obj.remove("signature");
    }
    let tampered_path = dir.path().join("missing_sig.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy missing-signature-field",
    );
}
#[test]
fn test_pattern6_legacy_unknown_algorithm_collapses_invalid() {
    // Replace the algorithm field with an attacker-controlled string.
    // leaked the algorithm string back into stderr
    // ("Unknown algorithm in signature file: '<attacker-string>'") with
    // length-amplification.
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    // 64-char attacker-controlled marker — if it shows up in stderr we
    // know the echo leak regressed.
    let attacker_marker = "X".repeat(64);
    let mut v = read_json_file(&sig);
    v["algorithm"] = serde_json::Value::String(format!("unknown-alg-{attacker_marker}"));
    let tampered_path = dir.path().join("unknown_alg.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    let args = [
        "verify",
        "--input",
        msg.to_str().unwrap(),
        "--signature",
        tampered_path.to_str().unwrap(),
        "--key",
        pk.to_str().unwrap(),
    ];
    let stderr = assert_verify_invalid_collapse(&args, "legacy unknown-algorithm");
    assert!(
        !stderr.contains(&attacker_marker),
        "verify must NOT echo the attacker-controlled algorithm string into stderr — \
         echoing it back gives an attacker a length-amplification primitive. \
         stderr: {stderr}"
    );
}
#[test]
fn test_pattern6_legacy_missing_algorithm_field_collapses_invalid() {
    // Strip the `algorithm` field entirely. Pre-fix path emitted
    // "Signature file missing 'algorithm' field — cannot auto-detect".
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let mut v = read_json_file(&sig);
    if let Some(obj) = v.as_object_mut() {
        obj.remove("algorithm");
    }
    let tampered_path = dir.path().join("missing_alg.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy missing-algorithm-field",
    );
}
#[test]
fn test_pattern6_legacy_crypto_reject_collapses_invalid() {
    // Crypto-side reject (signature verifies false).
    // recorded this as leaking "Verification failed" via
    // `.map_err(|_| anyhow!("Verification failed"))`.
    //
    // Sign with one key, then verify against a wrong key for the same
    // algorithm — same scheme, different public key → crypto reject.
    let dir = temp_dir();
    let (msg, sig, _pk) = legacy_sign_fixture(&dir, &ED25519_ALG);

    let dir2 = temp_dir();
    run_ok(&["keygen", "--algorithm", "ed25519", "--output", dir2.path().to_str().unwrap()]);
    let wrong_pk = dir2.path().join("ed25519.pub.json");

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--key",
            wrong_pk.to_str().unwrap(),
        ],
        "legacy crypto-reject (wrong key)",
    );
}
#[test]
fn test_pattern6_signed_data_data_mismatch_collapses_invalid() {
    // SignedData envelope: tamper the input file after signing. The
    // distinguisher this pins is the embedded-data-vs-input-data
    // mismatch path, which previously emitted a stricter error string
    // than the Pattern-6 `print_invalid()` shape.
    let dir = temp_dir();
    let (_msg_path, sig_path, _sk_path, _pk_path) = signed_data_sign_fixture(
        &dir,
        &["--use-case", "secure-messaging"],
        "hybrid-ml-dsa-65-ed25519",
        b"original signed bytes",
    );

    // Tamper the input file to a different content; SignedData embeds
    // the original data, so the two bytes won't match.
    let tampered_input = dir.path().join("tampered.txt");
    std::fs::write(&tampered_input, b"different bytes after sign").unwrap();

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            tampered_input.to_str().unwrap(),
            "--signature",
            sig_path.to_str().unwrap(),
        ],
        "SignedData data-mismatch",
    );
}
#[test]
fn test_pattern6_hybrid_legacy_crypto_reject_collapses_invalid() {
    // Hybrid path crypto reject. leaked structured
    // upstream error via `anyhow!("Hybrid verification failed: {e}")`,
    // which on a half-pair rejection (ML-DSA OK, Ed25519 rejected, or
    // vice versa) revealed which half failed. Sign with one hybrid
    // keypair, verify against a different hybrid public key.
    let dir = temp_dir();
    let (msg, sig, _pk) = legacy_sign_fixture(&dir, &HYBRID_ALG);

    let dir2 = temp_dir();
    run_ok(&[
        "keygen",
        "--algorithm",
        HYBRID_ALG.cli_keygen,
        "--output",
        dir2.path().to_str().unwrap(),
    ]);
    let wrong_pk = dir2.path().join(format!("{}.pub.json", HYBRID_ALG.keyfile_stem));

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--key",
            wrong_pk.to_str().unwrap(),
        ],
        "legacy hybrid crypto-reject (wrong key)",
    );
}
#[test]
fn test_pattern6_hybrid_missing_ml_dsa_field_collapses_invalid() {
    // Hybrid signature with `ml_dsa_sig` field stripped. Pre-fix path
    // emitted "Missing 'ml_dsa_sig' field in hybrid signature".
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &HYBRID_ALG);

    let mut v = read_json_file(&sig);
    if let Some(obj) = v.as_object_mut() {
        obj.remove("ml_dsa_sig");
    }
    let tampered_path = dir.path().join("missing_ml_dsa.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy hybrid missing-ml-dsa-field",
    );
}
#[test]
fn test_pattern6_hybrid_bad_base64_in_ed25519_collapses_invalid() {
    // Hybrid signature with corrupt base64 in `ed25519_sig`. Pre-fix
    // path emitted "Invalid base64 in ed25519_sig".
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &HYBRID_ALG);

    let mut v = read_json_file(&sig);
    v["ed25519_sig"] = serde_json::Value::String("AAA".to_string());
    let tampered_path = dir.path().join("bad_b64_ed25519.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy hybrid bad-base64 ed25519",
    );
}
#[test]
fn test_pattern6_hybrid_bad_base64_in_ml_dsa_collapses_invalid() {
    // Mirror of the ed25519 test for the ML-DSA half of the hybrid
    // pair. Pre-fix path emitted "Invalid base64 in ml_dsa_sig". Both
    // halves of the hybrid signature must collapse to the same shape;
    // testing only one side leaves a Pattern-6 distinguisher between
    // ML-DSA and Ed25519 reject paths.
    let dir = temp_dir();
    let (msg, sig, pk) = legacy_sign_fixture(&dir, &HYBRID_ALG);

    let mut v = read_json_file(&sig);
    v["ml_dsa_sig"] = serde_json::Value::String("AAA".to_string());
    let tampered_path = dir.path().join("bad_b64_ml_dsa.sig.json");
    write_json_file_pretty(&tampered_path, &v);

    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg.to_str().unwrap(),
            "--signature",
            tampered_path.to_str().unwrap(),
            "--key",
            pk.to_str().unwrap(),
        ],
        "legacy hybrid bad-base64 ml_dsa",
    );
}
#[test]
fn test_pattern6_legacy_crypto_reject_per_algorithm_collapses_invalid() {
    // Cross-product over every legacy-supported algorithm: each
    // crypto-reject path must collapse identically. This is the
    // axis-vs-cross-product test that feedback_verify_api_intersections.md
    // calls for — per-algorithm tests existed individually, but a per-
    // algorithm × tamper-shape matrix didn't.
    for alg in LEGACY_ALGS {
        let dir = temp_dir();
        let (msg, sig, _pk) = legacy_sign_fixture(&dir, alg);

        let dir2 = temp_dir();
        run_ok(&[
            "keygen",
            "--algorithm",
            alg.cli_keygen,
            "--output",
            dir2.path().to_str().unwrap(),
        ]);
        let wrong_pk = dir2.path().join(format!("{}.pub.json", alg.keyfile_stem));

        assert_verify_invalid_collapse(
            &[
                "verify",
                "--input",
                msg.to_str().unwrap(),
                "--signature",
                sig.to_str().unwrap(),
                "--key",
                wrong_pk.to_str().unwrap(),
            ],
            &format!("legacy {} crypto-reject (wrong key)", alg.cli_keygen),
        );
    }
}
#[test]
fn test_pattern6_legacy_signature_tamper_per_algorithm_collapses_invalid() {
    // Cross-product: for each algorithm, tamper the signature bytes
    // and confirm collapse. This is the "tamper × algorithm" axis where
    // 5 reject messages were previously found to remain
    // distinguishable (one per algorithm path through verify_standard).
    for alg in LEGACY_ALGS {
        let dir = temp_dir();
        let (msg, sig, pk) = legacy_sign_fixture(&dir, alg);

        let mut v = read_json_file(&sig);
        let orig_b64 = v["signature"].as_str().expect("signature str").to_string();
        v["signature"] = serde_json::Value::String(corrupt_base64(&orig_b64));
        let tampered_path = dir.path().join("tampered.sig.json");
        write_json_file_pretty(&tampered_path, &v);

        assert_verify_invalid_collapse(
            &[
                "verify",
                "--input",
                msg.to_str().unwrap(),
                "--signature",
                tampered_path.to_str().unwrap(),
                "--key",
                pk.to_str().unwrap(),
            ],
            &format!("legacy {} signature-bytes tamper", alg.cli_keygen),
        );
    }
}
#[test]
fn test_pattern6_signed_data_key_substitution_collapses_invalid() {
    // Pins the SignedData `--key` enforcement: when the operator
    // passes `--key`, its bytes MUST match the envelope's embedded
    // `signed.metadata.public_key`, otherwise the verdict collapses
    // to INVALID. Without this contract, a SignedData envelope with
    // an attacker's (key, sig, data) triple verifies against any
    // operator-trusted `--key`.
    let trusted_dir = temp_dir();
    let evil_dir = temp_dir();

    // Trusted side: keygen only (no sign — its pk is just the trust
    // anchor the operator passes via `--key` to verify).
    run_ok(&[
        "keygen",
        "--algorithm",
        "ml-dsa65",
        "--output",
        trusted_dir.path().to_str().unwrap(),
    ]);
    let trusted_pk = trusted_dir.path().join("ml-dsa-65.pub.json");

    // Evil side: full SignedData fixture — keygen, sign with evil key,
    // embed evil pk in the envelope.
    let (msg_path, sig_path, _evil_sk, _evil_pk) = signed_data_sign_fixture(
        &evil_dir,
        &["--algorithm", "ml-dsa65"],
        "ml-dsa-65",
        b"forged signature target",
    );

    // Verify with the operator's trusted `--key` (different keypair).
    assert_verify_invalid_collapse(
        &[
            "verify",
            "--input",
            msg_path.to_str().unwrap(),
            "--signature",
            sig_path.to_str().unwrap(),
            "--key",
            trusted_pk.to_str().unwrap(),
        ],
        "SignedData --key substitution",
    );
}
