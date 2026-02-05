//! Comprehensive tests for RFC test vectors module
//!
//! This module tests the public APIs of arc_validation::rfc_vectors including:
//! - RfcTestError error types and formatting
//! - RfcTestResults tracking and reporting
//! - Additional RFC test vector validation scenarios
//! - Edge cases and error handling paths

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

use arc_validation::rfc_vectors::{RfcTestError, RfcTestResults};

// =============================================================================
// RfcTestResults Tests
// =============================================================================

#[test]
fn test_rfc_test_results_new() {
    let results = RfcTestResults::new();
    assert_eq!(results.total, 0);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 0);
    assert!(results.failures.is_empty());
}

#[test]
fn test_rfc_test_results_default() {
    let results = RfcTestResults::default();
    assert_eq!(results.total, 0);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 0);
    assert!(results.failures.is_empty());
}

#[test]
fn test_rfc_test_results_add_pass() {
    let mut results = RfcTestResults::new();
    results.add_pass();

    assert_eq!(results.total, 1);
    assert_eq!(results.passed, 1);
    assert_eq!(results.failed, 0);
    assert!(results.failures.is_empty());
}

#[test]
fn test_rfc_test_results_add_multiple_passes() {
    let mut results = RfcTestResults::new();

    for _ in 0..10 {
        results.add_pass();
    }

    assert_eq!(results.total, 10);
    assert_eq!(results.passed, 10);
    assert_eq!(results.failed, 0);
    assert!(results.failures.is_empty());
}

#[test]
fn test_rfc_test_results_add_failure() {
    let mut results = RfcTestResults::new();
    results.add_failure("Test failure message".to_string());

    assert_eq!(results.total, 1);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 1);
    assert_eq!(results.failures.len(), 1);
    assert_eq!(results.failures[0], "Test failure message");
}

#[test]
fn test_rfc_test_results_add_multiple_failures() {
    let mut results = RfcTestResults::new();

    results.add_failure("Failure 1".to_string());
    results.add_failure("Failure 2".to_string());
    results.add_failure("Failure 3".to_string());

    assert_eq!(results.total, 3);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 3);
    assert_eq!(results.failures.len(), 3);
    assert_eq!(results.failures[0], "Failure 1");
    assert_eq!(results.failures[1], "Failure 2");
    assert_eq!(results.failures[2], "Failure 3");
}

#[test]
fn test_rfc_test_results_mixed_pass_and_fail() {
    let mut results = RfcTestResults::new();

    results.add_pass();
    results.add_pass();
    results.add_failure("Failure A".to_string());
    results.add_pass();
    results.add_failure("Failure B".to_string());

    assert_eq!(results.total, 5);
    assert_eq!(results.passed, 3);
    assert_eq!(results.failed, 2);
    assert_eq!(results.failures.len(), 2);
}

#[test]
fn test_rfc_test_results_all_passed_true() {
    let mut results = RfcTestResults::new();
    results.add_pass();
    results.add_pass();
    results.add_pass();

    assert!(results.all_passed());
}

#[test]
fn test_rfc_test_results_all_passed_false() {
    let mut results = RfcTestResults::new();
    results.add_pass();
    results.add_failure("failure".to_string());
    results.add_pass();

    assert!(!results.all_passed());
}

#[test]
fn test_rfc_test_results_all_passed_empty() {
    let results = RfcTestResults::new();
    // Empty results technically have no failures
    assert!(results.all_passed());
}

#[test]
fn test_rfc_test_results_debug_format() {
    let mut results = RfcTestResults::new();
    results.add_pass();
    results.add_failure("test failure".to_string());

    let debug_str = format!("{:?}", results);
    assert!(debug_str.contains("RfcTestResults"));
    assert!(debug_str.contains("total"));
    assert!(debug_str.contains("passed"));
    assert!(debug_str.contains("failed"));
    assert!(debug_str.contains("failures"));
}

#[test]
fn test_rfc_test_results_failure_messages_preserved() {
    let mut results = RfcTestResults::new();

    let messages = vec![
        "RFC 8439: encryption failed".to_string(),
        "RFC 8032: signature mismatch".to_string(),
        "RFC 7748: key derivation error".to_string(),
        "RFC 5869: HKDF expansion failed".to_string(),
    ];

    for msg in &messages {
        results.add_failure(msg.clone());
    }

    assert_eq!(results.failures, messages);
}

#[test]
fn test_rfc_test_results_empty_failure_message() {
    let mut results = RfcTestResults::new();
    results.add_failure(String::new());

    assert_eq!(results.failed, 1);
    assert_eq!(results.failures[0], "");
}

#[test]
fn test_rfc_test_results_unicode_failure_message() {
    let mut results = RfcTestResults::new();
    results.add_failure("Test failed: \u{2718} validation error \u{1F512}".to_string());

    assert_eq!(results.failed, 1);
    assert!(results.failures[0].contains("\u{2718}"));
}

#[test]
fn test_rfc_test_results_large_number_of_tests() {
    let mut results = RfcTestResults::new();

    for i in 0..1000 {
        if i % 10 == 0 {
            results.add_failure(format!("Failure at test {}", i));
        } else {
            results.add_pass();
        }
    }

    assert_eq!(results.total, 1000);
    assert_eq!(results.passed, 900);
    assert_eq!(results.failed, 100);
    assert_eq!(results.failures.len(), 100);
}

// =============================================================================
// RfcTestError Tests
// =============================================================================

#[test]
fn test_rfc_test_error_test_failed_display() {
    let error = RfcTestError::TestFailed {
        rfc: "RFC 8439".to_string(),
        test_name: "ChaCha20-Poly1305 AEAD".to_string(),
        message: "ciphertext mismatch".to_string(),
    };

    let display = format!("{}", error);
    assert!(display.contains("RFC 8439"));
    assert!(display.contains("ChaCha20-Poly1305 AEAD"));
    assert!(display.contains("ciphertext mismatch"));
}

#[test]
fn test_rfc_test_error_hex_error_display() {
    let error = RfcTestError::HexError("invalid hex character 'g'".to_string());

    let display = format!("{}", error);
    assert!(display.contains("Hex decode error"));
    assert!(display.contains("invalid hex character 'g'"));
}

#[test]
fn test_rfc_test_error_debug_format() {
    let error = RfcTestError::TestFailed {
        rfc: "RFC 8032".to_string(),
        test_name: "Ed25519".to_string(),
        message: "signature verification failed".to_string(),
    };

    let debug = format!("{:?}", error);
    assert!(debug.contains("TestFailed"));
    assert!(debug.contains("RFC 8032"));
    assert!(debug.contains("Ed25519"));
    assert!(debug.contains("signature verification failed"));
}

#[test]
fn test_rfc_test_error_hex_error_debug() {
    let error = RfcTestError::HexError("odd length".to_string());

    let debug = format!("{:?}", error);
    assert!(debug.contains("HexError"));
    assert!(debug.contains("odd length"));
}

#[test]
fn test_rfc_test_error_test_failed_empty_fields() {
    let error = RfcTestError::TestFailed {
        rfc: String::new(),
        test_name: String::new(),
        message: String::new(),
    };

    let display = format!("{}", error);
    assert!(display.contains("RFC test failed"));
}

#[test]
fn test_rfc_test_error_test_failed_special_characters() {
    let error = RfcTestError::TestFailed {
        rfc: "RFC-8439 (ChaCha20)".to_string(),
        test_name: "Test <vector> #1".to_string(),
        message: "Expected 0x00 but got 0xff".to_string(),
    };

    let display = format!("{}", error);
    assert!(display.contains("RFC-8439 (ChaCha20)"));
    assert!(display.contains("Test <vector> #1"));
    assert!(display.contains("Expected 0x00 but got 0xff"));
}

#[test]
fn test_rfc_test_error_hex_error_empty() {
    let error = RfcTestError::HexError(String::new());

    let display = format!("{}", error);
    assert!(display.contains("Hex decode error"));
}

#[test]
fn test_rfc_test_error_is_std_error() {
    let error: Box<dyn std::error::Error> = Box::new(RfcTestError::TestFailed {
        rfc: "RFC 7748".to_string(),
        test_name: "X25519".to_string(),
        message: "shared secret mismatch".to_string(),
    });

    // Verify we can use it as a std::error::Error
    let _description = error.to_string();
    assert!(error.source().is_none()); // RfcTestError has no source error
}

#[test]
fn test_rfc_test_error_hex_is_std_error() {
    let error: Box<dyn std::error::Error> =
        Box::new(RfcTestError::HexError("invalid character at position 5".to_string()));

    let _description = error.to_string();
    assert!(error.source().is_none());
}

// =============================================================================
// Integration-style tests using RfcTestResults
// =============================================================================

#[test]
fn test_rfc_test_results_typical_workflow() {
    let mut results = RfcTestResults::new();

    // Simulate running a test suite
    // Test 1: passes
    let test1_result: Result<(), &str> = Ok(());
    if test1_result.is_ok() {
        results.add_pass();
    } else {
        results.add_failure("Test 1 failed".to_string());
    }

    // Test 2: passes
    let test2_result: Result<(), &str> = Ok(());
    if test2_result.is_ok() {
        results.add_pass();
    } else {
        results.add_failure("Test 2 failed".to_string());
    }

    // Test 3: fails
    let test3_result: Result<(), &str> = Err("validation error");
    if test3_result.is_ok() {
        results.add_pass();
    } else {
        results.add_failure(format!("Test 3 failed: {:?}", test3_result.err()));
    }

    assert_eq!(results.total, 3);
    assert_eq!(results.passed, 2);
    assert_eq!(results.failed, 1);
    assert!(!results.all_passed());
}

#[test]
fn test_rfc_test_results_report_generation() {
    let mut results = RfcTestResults::new();

    // Add some test results
    results.add_pass();
    results.add_pass();
    results.add_failure("ChaCha20: tag mismatch".to_string());
    results.add_pass();
    results.add_failure("HKDF: expansion too long".to_string());

    // Generate a summary report
    let pass_rate = if results.total > 0 {
        (results.passed as f64 / results.total as f64) * 100.0
    } else {
        0.0
    };

    assert_eq!(results.total, 5);
    assert!((pass_rate - 60.0).abs() < 0.001);
    assert_eq!(results.failures.len(), 2);
}

// =============================================================================
// Additional RFC Vector Validation Tests
// =============================================================================

/// Test hex decoding scenarios that could trigger HexError
#[test]
fn test_hex_decoding_valid() {
    let valid_hex = "0123456789abcdef";
    let result = hex::decode(valid_hex);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
}

#[test]
fn test_hex_decoding_uppercase() {
    let valid_hex = "0123456789ABCDEF";
    let result = hex::decode(valid_hex);
    assert!(result.is_ok());
}

#[test]
fn test_hex_decoding_mixed_case() {
    let valid_hex = "0123456789AbCdEf";
    let result = hex::decode(valid_hex);
    assert!(result.is_ok());
}

#[test]
fn test_hex_decoding_empty() {
    let empty_hex = "";
    let result = hex::decode(empty_hex);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_hex_decoding_invalid_char() {
    let invalid_hex = "0123456789abcdeg";
    let result = hex::decode(invalid_hex);
    assert!(result.is_err());
}

#[test]
fn test_hex_decoding_odd_length() {
    let odd_hex = "0123456789abcde";
    let result = hex::decode(odd_hex);
    assert!(result.is_err());
}

#[test]
fn test_hex_decoding_whitespace() {
    let hex_with_space = "01 23 45";
    let result = hex::decode(hex_with_space);
    assert!(result.is_err());
}

// =============================================================================
// Edge Cases for Test Results
// =============================================================================

#[test]
fn test_rfc_test_results_consistency() {
    let mut results = RfcTestResults::new();

    // Track independently
    let mut expected_total = 0usize;
    let mut expected_passed = 0usize;
    let mut expected_failed = 0usize;

    for i in 0..50 {
        if i % 3 == 0 {
            results.add_failure(format!("fail {}", i));
            expected_total += 1;
            expected_failed += 1;
        } else {
            results.add_pass();
            expected_total += 1;
            expected_passed += 1;
        }
    }

    // Verify consistency: total == passed + failed
    assert_eq!(results.total, results.passed + results.failed);
    assert_eq!(results.total, expected_total);
    assert_eq!(results.passed, expected_passed);
    assert_eq!(results.failed, expected_failed);
}

#[test]
fn test_rfc_test_results_failure_order_preserved() {
    let mut results = RfcTestResults::new();

    let failures = vec!["first", "second", "third", "fourth", "fifth"];
    for (i, f) in failures.iter().enumerate() {
        if i % 2 == 0 {
            results.add_pass();
        }
        results.add_failure(f.to_string());
    }

    // Verify failures are in insertion order
    for (i, f) in failures.iter().enumerate() {
        assert_eq!(results.failures[i], *f);
    }
}

#[test]
fn test_rfc_test_results_long_failure_message() {
    let mut results = RfcTestResults::new();

    let long_message = "A".repeat(10000);
    results.add_failure(long_message.clone());

    assert_eq!(results.failures[0], long_message);
    assert_eq!(results.failures[0].len(), 10000);
}

// =============================================================================
// Error Variant Coverage Tests
// =============================================================================

#[test]
fn test_all_rfc_error_variants() {
    // Test TestFailed variant
    let test_failed = RfcTestError::TestFailed {
        rfc: "RFC 5869".to_string(),
        test_name: "HKDF-SHA256 Test 1".to_string(),
        message: "PRK mismatch".to_string(),
    };

    // Test HexError variant
    let hex_error = RfcTestError::HexError("invalid input".to_string());

    // Both should implement Display
    let _ = format!("{}", test_failed);
    let _ = format!("{}", hex_error);

    // Both should implement Debug
    let _ = format!("{:?}", test_failed);
    let _ = format!("{:?}", hex_error);
}

#[test]
fn test_rfc_test_error_field_access() {
    // Create error and verify fields via pattern matching
    let error = RfcTestError::TestFailed {
        rfc: "RFC 8032".to_string(),
        test_name: "Test Vector 1".to_string(),
        message: "Signature mismatch at byte 32".to_string(),
    };

    match error {
        RfcTestError::TestFailed { rfc, test_name, message } => {
            assert_eq!(rfc, "RFC 8032");
            assert_eq!(test_name, "Test Vector 1");
            assert_eq!(message, "Signature mismatch at byte 32");
        }
        _ => panic!("Expected TestFailed variant"),
    }
}

#[test]
fn test_rfc_test_error_hex_error_field_access() {
    let error = RfcTestError::HexError("position 42: invalid digit".to_string());

    match error {
        RfcTestError::HexError(msg) => {
            assert!(msg.contains("position 42"));
            assert!(msg.contains("invalid digit"));
        }
        _ => panic!("Expected HexError variant"),
    }
}

// =============================================================================
// Simulated RFC Test Workflow Tests
// =============================================================================

#[test]
fn test_simulated_chacha20_poly1305_workflow() {
    use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut results = RfcTestResults::new();

    // Generate a test key and nonce
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"test message for RFC 8439";
    let aad = b"additional data";

    let cipher = ChaCha20Poly1305::new(&key.into());

    // Test encryption
    match cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad }) {
        Ok(ciphertext) => {
            results.add_pass();

            // Test decryption
            match cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad }) {
                Ok(decrypted) => {
                    if decrypted == plaintext {
                        results.add_pass();
                    } else {
                        results.add_failure("Decrypted text doesn't match original".to_string());
                    }
                }
                Err(e) => {
                    results.add_failure(format!("Decryption failed: {:?}", e));
                }
            }
        }
        Err(e) => {
            results.add_failure(format!("Encryption failed: {:?}", e));
        }
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

#[test]
fn test_simulated_x25519_workflow() {
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut results = RfcTestResults::new();

    // Alice generates key pair
    let alice_secret = StaticSecret::from([1u8; 32]);
    let alice_public = PublicKey::from(&alice_secret);

    // Bob generates key pair
    let bob_secret = StaticSecret::from([2u8; 32]);
    let bob_public = PublicKey::from(&bob_secret);

    // Both compute shared secret
    let shared_alice = alice_secret.diffie_hellman(&bob_public);
    let shared_bob = bob_secret.diffie_hellman(&alice_public);

    if shared_alice.as_bytes() == shared_bob.as_bytes() {
        results.add_pass();
    } else {
        results.add_failure("X25519 shared secrets don't match".to_string());
    }

    // Verify public key derivation is deterministic
    let alice_secret_2 = StaticSecret::from([1u8; 32]);
    let alice_public_2 = PublicKey::from(&alice_secret_2);

    if alice_public.as_bytes() == alice_public_2.as_bytes() {
        results.add_pass();
    } else {
        results.add_failure("X25519 key derivation not deterministic".to_string());
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

#[test]
fn test_simulated_ed25519_workflow() {
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    let mut results = RfcTestResults::new();

    // Generate key pair from fixed seed
    let secret_key = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&secret_key);
    let verifying_key = signing_key.verifying_key();

    // Sign a message
    let message = b"Test message for Ed25519";
    let signature = signing_key.sign(message);

    // Verify signature
    if verifying_key.verify(message, &signature).is_ok() {
        results.add_pass();
    } else {
        results.add_failure("Ed25519 signature verification failed".to_string());
    }

    // Verify signature fails for wrong message
    let wrong_message = b"Wrong message";
    if verifying_key.verify(wrong_message, &signature).is_err() {
        results.add_pass();
    } else {
        results.add_failure("Ed25519 verification should fail for wrong message".to_string());
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

#[test]
fn test_simulated_hkdf_workflow() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut results = RfcTestResults::new();

    let ikm = b"input keying material";
    let salt = b"optional salt";
    let info = b"context info";

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    // Test expansion to various lengths
    let lengths = [16, 32, 64, 128];

    for &len in &lengths {
        let mut okm = vec![0u8; len];
        if hk.expand(info, &mut okm).is_ok() {
            results.add_pass();
        } else {
            results.add_failure(format!("HKDF expansion to {} bytes failed", len));
        }
    }

    // Test determinism
    let mut okm1 = vec![0u8; 32];
    let mut okm2 = vec![0u8; 32];

    let hk1 = Hkdf::<Sha256>::new(Some(salt), ikm);
    let hk2 = Hkdf::<Sha256>::new(Some(salt), ikm);

    let _ = hk1.expand(info, &mut okm1);
    let _ = hk2.expand(info, &mut okm2);

    if okm1 == okm2 {
        results.add_pass();
    } else {
        results.add_failure("HKDF not deterministic".to_string());
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

#[test]
fn test_simulated_sha256_workflow() {
    use sha2::{Digest, Sha256};

    let mut results = RfcTestResults::new();

    // Test empty input
    let mut hasher = Sha256::new();
    hasher.update(b"");
    let result = hasher.finalize();

    // Known SHA-256 of empty string
    let expected =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();

    if result.as_slice() == expected.as_slice() {
        results.add_pass();
    } else {
        results.add_failure("SHA-256 of empty string mismatch".to_string());
    }

    // Test "abc"
    let mut hasher = Sha256::new();
    hasher.update(b"abc");
    let result = hasher.finalize();

    let expected =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();

    if result.as_slice() == expected.as_slice() {
        results.add_pass();
    } else {
        results.add_failure("SHA-256 of 'abc' mismatch".to_string());
    }

    // Test incremental hashing
    let mut hasher1 = Sha256::new();
    hasher1.update(b"hello ");
    hasher1.update(b"world");
    let result1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(b"hello world");
    let result2 = hasher2.finalize();

    if result1 == result2 {
        results.add_pass();
    } else {
        results.add_failure("SHA-256 incremental hashing mismatch".to_string());
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

// =============================================================================
// AES-GCM Tests
// =============================================================================

#[test]
fn test_simulated_aes_gcm_workflow() {
    use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

    let mut results = RfcTestResults::new();

    let key = [0x42u8; 32];
    let nonce_bytes = [0u8; 12];
    let plaintext = b"test plaintext for AES-GCM";
    let aad = b"additional authenticated data";

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("key creation");
    let sealing_key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    if sealing_key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out).is_ok() {
        results.add_pass();

        // Test decryption
        let unbound_key2 = UnboundKey::new(&AES_256_GCM, &key).expect("key creation");
        let opening_key = LessSafeKey::new(unbound_key2);
        let nonce2 = Nonce::assume_unique_for_key(nonce_bytes);

        if let Ok(decrypted) = opening_key.open_in_place(nonce2, Aad::from(aad), &mut in_out) {
            if decrypted == plaintext {
                results.add_pass();
            } else {
                results.add_failure("AES-GCM decryption mismatch".to_string());
            }
        } else {
            results.add_failure("AES-GCM decryption failed".to_string());
        }
    } else {
        results.add_failure("AES-GCM encryption failed".to_string());
    }

    assert!(results.all_passed(), "Failures: {:?}", results.failures);
}

// =============================================================================
// Boundary and Stress Tests
// =============================================================================

#[test]
fn test_rfc_test_results_stress() {
    let mut results = RfcTestResults::new();

    // Simulate a large test suite
    for i in 0..10000 {
        if i % 100 == 99 {
            results.add_failure(format!("Test {} failed", i));
        } else {
            results.add_pass();
        }
    }

    assert_eq!(results.total, 10000);
    assert_eq!(results.passed, 9900);
    assert_eq!(results.failed, 100);
    assert_eq!(results.failures.len(), 100);
    assert!(!results.all_passed());
}

#[test]
fn test_rfc_test_results_many_failures() {
    let mut results = RfcTestResults::new();

    // All failures
    for i in 0..1000 {
        results.add_failure(format!("All tests fail: {}", i));
    }

    assert_eq!(results.total, 1000);
    assert_eq!(results.passed, 0);
    assert_eq!(results.failed, 1000);
    assert!(!results.all_passed());
}

#[test]
fn test_rfc_test_results_all_passes() {
    let mut results = RfcTestResults::new();

    // All passes
    for _ in 0..1000 {
        results.add_pass();
    }

    assert_eq!(results.total, 1000);
    assert_eq!(results.passed, 1000);
    assert_eq!(results.failed, 0);
    assert!(results.all_passed());
}
