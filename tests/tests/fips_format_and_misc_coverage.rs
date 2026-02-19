//! Coverage tests for format.rs, validation_summary.rs, and other small coverage gaps.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss
)]

use latticearc_tests::validation::format::{FormatError, validate_key_format};

// ============================================================
// format.rs — 0% coverage (6 lines)
// ============================================================

#[test]
fn test_validate_key_format_correct_size() {
    let key = vec![0u8; 32];
    assert!(
        validate_key_format(&key, 32).is_ok(),
        "32-byte key should pass validation for expected size 32"
    );
}

#[test]
fn test_validate_key_format_wrong_size() {
    let key = vec![0u8; 16];
    let result = validate_key_format(&key, 32);
    assert!(result.is_err(), "16-byte key should fail validation for expected size 32");
    match result.unwrap_err() {
        FormatError::InvalidKeySize(actual, expected) => {
            assert_eq!(actual, 16, "actual key size should be 16");
            assert_eq!(expected, 32, "expected key size should be 32");
        }
    }
}

#[test]
fn test_validate_key_format_empty() {
    let key: Vec<u8> = Vec::new();
    assert!(
        validate_key_format(&key, 0).is_ok(),
        "empty key should pass validation for expected size 0"
    );
    assert!(
        validate_key_format(&key, 1).is_err(),
        "empty key should fail validation for expected size 1"
    );
}

#[test]
fn test_format_error_display() {
    let err = FormatError::InvalidKeySize(16, 32);
    let msg = format!("{}", err);
    assert!(msg.contains("16"), "error message should contain actual size 16");
    assert!(msg.contains("32"), "error message should contain expected size 32");
}

// ============================================================
// validation_summary.rs — ComplianceReporter coverage
// ============================================================

use latticearc_tests::validation::validation_summary::ComplianceReporter;

#[test]
fn test_compliance_reporter_new() {
    let reporter = ComplianceReporter::new(0.05);
    let report = reporter.generate_full_compliance_report(&[], &None);
    assert!(report.is_ok(), "empty compliance report should generate successfully");
}

#[test]
fn test_compliance_reporter_json_export() {
    let reporter = ComplianceReporter::new(0.01);
    let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
    let json = reporter.generate_json_report(&report);
    assert!(json.is_ok(), "JSON report generation should succeed");
    let json_str = json.unwrap();
    assert!(
        json_str.contains("overall_compliance"),
        "JSON report should contain overall_compliance field"
    );
}

#[test]
fn test_compliance_reporter_html_export() {
    let reporter = ComplianceReporter::new(0.05);
    let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
    let html = reporter.generate_html_report(&report);
    assert!(html.is_ok(), "HTML report generation should succeed");
    let html_str = html.unwrap();
    assert!(
        html_str.contains("html") || html_str.contains("Compliance"),
        "HTML report should contain markup or compliance content"
    );
}

// ============================================================
// nist_functions.rs — RandomizedHasher coverage
// ============================================================

use latticearc_tests::validation::nist_functions::{
    RandomizedHashConfig, RandomizedHashMode, RandomizedHasher, RandomizedHashing,
};

#[test]
fn test_randomized_hasher_default() {
    let hasher = RandomizedHasher::default();
    let hash = hasher.hash(b"test message");
    assert!(hash.is_ok(), "default hasher should hash successfully");
    let hash_result = hash.unwrap();
    assert!(!hash_result.hash_hex().is_empty(), "hash hex should not be empty");
    assert!(!hash_result.salt_hex().is_empty(), "salt hex should not be empty");
}

#[test]
fn test_randomized_hasher_verify() {
    let hasher = RandomizedHasher::default();
    let message = b"verify this message";
    let hash = hasher.hash(message).unwrap();
    let valid = hasher.verify(message, &hash);
    assert!(valid.is_ok(), "verification should not return error");
    assert!(valid.unwrap(), "hash should verify against same message");
}

#[test]
fn test_randomized_hasher_verify_wrong_message() {
    let hasher = RandomizedHasher::default();
    let hash = hasher.hash(b"original message").unwrap();
    let valid = hasher.verify(b"different message", &hash);
    assert!(valid.is_ok(), "verification of wrong message should not error");
    assert!(!valid.unwrap(), "hash should not verify against different message");
}

#[test]
fn test_randomized_hasher_custom_config() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-256".to_string(),
        mode: RandomizedHashMode::SaltSuffix,
        salt_length: 32,
        salt_insertions: 1,
    };
    let hasher = RandomizedHasher::new(config);
    let hash = hasher.hash(b"test");
    assert!(hash.is_ok(), "custom config hasher should hash successfully");
}

#[test]
fn test_nist_functions_hash_message() {
    let hash = RandomizedHashing::hash_message(b"hello world");
    assert!(hash.is_ok(), "static hash_message should succeed");
}

#[test]
fn test_nist_functions_verify_hash() {
    let message = b"test message for static API";
    let hash = RandomizedHashing::hash_message(message).unwrap();
    let valid = RandomizedHashing::verify_hash(message, &hash);
    assert!(valid.is_ok(), "static verify_hash should not error");
    assert!(valid.unwrap(), "static API hash should verify against same message");
}

#[test]
fn test_nist_functions_recommended_config() {
    let config_128 = RandomizedHashing::recommended_config(128);
    assert!(config_128.salt_length > 0, "128-bit config should have positive salt length");

    let config_256 = RandomizedHashing::recommended_config(256);
    assert!(
        config_256.salt_length >= config_128.salt_length,
        "256-bit config salt should be >= 128-bit config salt"
    );
}

#[test]
fn test_nist_functions_hash_with_config() {
    let config = RandomizedHashing::recommended_config(192);
    let hash = RandomizedHashing::hash_message_with_config(b"test", config);
    assert!(hash.is_ok(), "hash_message_with_config should succeed with 192-bit config");
}
