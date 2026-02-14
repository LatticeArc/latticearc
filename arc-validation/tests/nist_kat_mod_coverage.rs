//! Coverage tests for arc-validation/src/nist_kat/mod.rs
//! Targets: KatTestResult factory methods, NistKatError display, decode_hex

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use arc_validation::nist_kat::{KatTestResult, NistKatError, decode_hex};

#[test]
fn test_kat_test_result_passed() {
    let result = KatTestResult::passed("test-1".to_string(), "AES-GCM".to_string(), 42);
    assert!(result.passed);
    assert_eq!(result.test_case, "test-1");
    assert_eq!(result.algorithm, "AES-GCM");
    assert!(result.error_message.is_none());
    assert_eq!(result.execution_time_us, 42);
}

#[test]
fn test_kat_test_result_failed() {
    let result = KatTestResult::failed(
        "test-2".to_string(),
        "ML-KEM".to_string(),
        "mismatch".to_string(),
        100,
    );
    assert!(!result.passed);
    assert_eq!(result.test_case, "test-2");
    assert_eq!(result.algorithm, "ML-KEM");
    assert_eq!(result.error_message.as_deref(), Some("mismatch"));
    assert_eq!(result.execution_time_us, 100);
}

#[test]
fn test_kat_test_result_clone_debug() {
    let result = KatTestResult::passed("tc".to_string(), "SHA-256".to_string(), 10);
    let cloned = result.clone();
    assert_eq!(cloned.test_case, result.test_case);
    let debug = format!("{:?}", result);
    assert!(debug.contains("SHA-256"));
}

#[test]
fn test_decode_hex_valid() {
    let bytes = decode_hex("48656c6c6f").unwrap();
    assert_eq!(bytes, b"Hello");
}

#[test]
fn test_decode_hex_empty() {
    let bytes = decode_hex("").unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn test_decode_hex_invalid() {
    let result = decode_hex("xyz");
    assert!(result.is_err());
}

#[test]
fn test_nist_kat_error_display() {
    let e1 = NistKatError::TestFailed {
        algorithm: "AES".to_string(),
        test_name: "tc1".to_string(),
        message: "fail".to_string(),
    };
    let s = e1.to_string();
    assert!(s.contains("AES"));
    assert!(s.contains("tc1"));
    assert!(s.contains("fail"));

    let e2 = NistKatError::HexError("bad hex".to_string());
    assert!(e2.to_string().contains("bad hex"));

    let e3 = NistKatError::ImplementationError("impl error".to_string());
    assert!(e3.to_string().contains("impl error"));

    let e4 = NistKatError::UnsupportedAlgorithm("FooAlg".to_string());
    assert!(e4.to_string().contains("FooAlg"));

    // Debug
    let debug = format!("{:?}", e1);
    assert!(debug.contains("TestFailed"));
}
