//! Shared CLI-invocation and JSON-fixture helpers for the `latticearc-cli` integration tests.
//!
//! This is a `tests/support/mod.rs` directory module (not a `tests/support.rs` file), so cargo
//! does NOT treat it as its own test target. Each topic test file pulls it in via `mod support;`
//! and is compiled as a separate integration-test binary, so this module is compiled once per
//! consumer. Not every consumer test file calls every helper below — `dead_code` is allowed here
//! for that reason (shared test-helper module, not production code).

// Test code legitimately uses unwrap/expect, indexing, and println for proof output.
// `dead_code` is allowed because this module is shared across several independently-compiled
// integration-test binaries and not every binary calls every helper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::panic,
    clippy::cast_possible_truncation,
    dead_code
)]

use std::path::PathBuf;
use std::process::Command;

/// Path to the compiled CLI binary.
pub fn cli_bin() -> PathBuf {
    // cargo test builds in target/debug or target/release
    let path = PathBuf::from(env!("CARGO_BIN_EXE_latticearc-cli"));
    // Ensure the binary exists
    assert!(path.exists(), "CLI binary not found at {}", path.display());
    path
}

/// Spawn the CLI with `args`, wait for completion, return raw `Output`.
///
/// Sets `LATTICEARC_ALLOW_UNSAFE_CLI=1` so the L8 env-gate doesn't reject
/// tests that exercise `--allow-weak-iterations` / `--allow-argv-secret`
/// for KAT-replay / reproducibility (which is the documented purpose of
/// those flags). Also sets `--print-to-tty` semantics via flag: child
/// stdout is not a TTY when captured by `.output()`, so the L9 hard-fail
/// doesn't fire and no extra opt-in is needed.
pub fn execute_cli(args: &[&str]) -> std::process::Output {
    Command::new(cli_bin())
        .args(args)
        .env("LATTICEARC_ALLOW_UNSAFE_CLI", "1")
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute CLI: {e}"))
}

/// Run a CLI command, assert success, return stdout.
pub fn run_ok(args: &[&str]) -> String {
    let output = execute_cli(args);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "CLI failed with args {args:?}:\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// Run a CLI command, assert success, return stdout + stderr concatenated.
///
/// Use this for tests that check status messages —
/// moved keygen / encrypt / decrypt / sign "Written to: ..." style
/// messages from stdout to stderr (UNIX convention: data on stdout,
/// status on stderr). Tests that pre-date that move and assert on
/// "Generated ... keypair" should switch to this helper.
pub fn run_ok_combined(args: &[&str]) -> String {
    let output = execute_cli(args);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "CLI failed with args {args:?}:\nstdout: {stdout}\nstderr: {stderr}"
    );
    format!("{stdout}{stderr}")
}

/// Run a CLI command, assert failure, return stderr.
pub fn run_fail(args: &[&str]) -> String {
    let output = execute_cli(args);
    assert!(!output.status.success(), "CLI should have failed with args {args:?}");
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// Create a temp dir that auto-cleans.
pub fn temp_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("Failed to create temp dir")
}

/// Read a JSON file from disk as `serde_json::Value`. Generic helper
/// for tests that load sig / pk / encrypted-blob JSON.
pub fn read_json_file(path: impl AsRef<std::path::Path>) -> serde_json::Value {
    let s = std::fs::read_to_string(path).expect("read JSON file");
    serde_json::from_str(&s).expect("parse JSON file")
}

/// Tamper a base64-encoded payload such that the decoded bytes are
/// guaranteed to differ in at least one bit from the original.
///
/// A naïve "swap the first two characters" approach is fragile: when
/// the underlying bytes encode to two consecutive identical base64
/// chars (observed in SLH-DSA-SHAKE-128s), swapping is a no-op and
/// the test silently fails to actually tamper. Decode, flip the low
/// bit of the first byte AND the entire last byte, re-encode — this
/// always changes the binary content at both ends so the test
/// exercises a structurally meaningful corruption pattern (single-
/// bit AND multi-bit, head AND tail) regardless of signature length.
pub fn corrupt_base64(b64: &str) -> String {
    use base64::Engine;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("input should be valid base64");
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
    }
    if bytes.len() > 1
        && let Some(last) = bytes.last_mut()
    {
        *last ^= 0xFF;
    }
    base64::engine::general_purpose::STANDARD.encode(&bytes)
}

/// Pretty-print a `serde_json::Value` to disk. Used by the Pattern-6
/// tampering tests to write back a modified JSON tree.
pub fn write_json_file_pretty(path: impl AsRef<std::path::Path>, v: &serde_json::Value) {
    let s = serde_json::to_string_pretty(v).expect("serialize JSON");
    std::fs::write(path, s).expect("write JSON file");
}
