//! Coverage tests for format.rs, validation_summary.rs, and other small coverage gaps.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    deprecated
)]

use arc_validation::format::{FormatError, validate_key_format};

// ============================================================
// format.rs — 0% coverage (6 lines)
// ============================================================

#[test]
fn test_validate_key_format_correct_size() {
    let key = vec![0u8; 32];
    assert!(validate_key_format(&key, 32).is_ok());
}

#[test]
fn test_validate_key_format_wrong_size() {
    let key = vec![0u8; 16];
    let result = validate_key_format(&key, 32);
    assert!(result.is_err());
    match result.unwrap_err() {
        FormatError::InvalidKeySize(actual, expected) => {
            assert_eq!(actual, 16);
            assert_eq!(expected, 32);
        }
    }
}

#[test]
fn test_validate_key_format_empty() {
    let key: Vec<u8> = Vec::new();
    assert!(validate_key_format(&key, 0).is_ok());
    assert!(validate_key_format(&key, 1).is_err());
}

#[test]
fn test_format_error_display() {
    let err = FormatError::InvalidKeySize(16, 32);
    let msg = format!("{}", err);
    assert!(msg.contains("16"));
    assert!(msg.contains("32"));
}

// ============================================================
// validation_summary.rs — ComplianceReporter coverage
// ============================================================

use arc_validation::validation_summary::ComplianceReporter;

#[test]
fn test_compliance_reporter_new() {
    let reporter = ComplianceReporter::new(0.05);
    let report = reporter.generate_full_compliance_report(&[], &None);
    assert!(report.is_ok());
}

#[test]
fn test_compliance_reporter_json_export() {
    let reporter = ComplianceReporter::new(0.01);
    let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
    let json = reporter.generate_json_report(&report);
    assert!(json.is_ok());
    let json_str = json.unwrap();
    assert!(json_str.contains("overall_compliance"));
}

#[test]
fn test_compliance_reporter_html_export() {
    let reporter = ComplianceReporter::new(0.05);
    let report = reporter.generate_full_compliance_report(&[], &None).unwrap();
    let html = reporter.generate_html_report(&report);
    assert!(html.is_ok());
    let html_str = html.unwrap();
    assert!(html_str.contains("html") || html_str.contains("Compliance"));
}

// ============================================================
// nist_functions.rs — RandomizedHasher coverage
// ============================================================

use arc_validation::nist_functions::{
    RandomizedHashConfig, RandomizedHashMode, RandomizedHasher, RandomizedHashing,
};

#[test]
fn test_randomized_hasher_default() {
    let hasher = RandomizedHasher::default();
    let hash = hasher.hash(b"test message");
    assert!(hash.is_ok());
    let hash_result = hash.unwrap();
    assert!(!hash_result.hash_hex().is_empty());
    assert!(!hash_result.salt_hex().is_empty());
}

#[test]
fn test_randomized_hasher_verify() {
    let hasher = RandomizedHasher::default();
    let message = b"verify this message";
    let hash = hasher.hash(message).unwrap();
    let valid = hasher.verify(message, &hash);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[test]
fn test_randomized_hasher_verify_wrong_message() {
    let hasher = RandomizedHasher::default();
    let hash = hasher.hash(b"original message").unwrap();
    let valid = hasher.verify(b"different message", &hash);
    assert!(valid.is_ok());
    assert!(!valid.unwrap());
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
    assert!(hash.is_ok());
}

#[test]
fn test_nist_functions_hash_message() {
    let hash = RandomizedHashing::hash_message(b"hello world");
    assert!(hash.is_ok());
}

#[test]
fn test_nist_functions_verify_hash() {
    let message = b"test message for static API";
    let hash = RandomizedHashing::hash_message(message).unwrap();
    let valid = RandomizedHashing::verify_hash(message, &hash);
    assert!(valid.is_ok());
    assert!(valid.unwrap());
}

#[test]
fn test_nist_functions_recommended_config() {
    let config_128 = RandomizedHashing::recommended_config(128);
    assert!(config_128.salt_length > 0);

    let config_256 = RandomizedHashing::recommended_config(256);
    assert!(config_256.salt_length >= config_128.salt_length);
}

#[test]
fn test_nist_functions_hash_with_config() {
    let config = RandomizedHashing::recommended_config(192);
    let hash = RandomizedHashing::hash_message_with_config(b"test", config);
    assert!(hash.is_ok());
}
