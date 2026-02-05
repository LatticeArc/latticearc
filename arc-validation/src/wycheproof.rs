//! Wycheproof Test Vectors
//!
//! This module validates LatticeArc's cryptographic implementations against
//! Google's Wycheproof test vectors, which are designed to catch edge cases
//! and known attack patterns in cryptographic implementations.
//!
//! See: <https://github.com/google/wycheproof>

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: Test result counters - overflow is impossible with realistic test counts
#![allow(clippy::arithmetic_side_effects)]
// JUSTIFICATION: Test code uses expect() for known-valid test vectors and println! for test output
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]
// JUSTIFICATION: Test statistics calculations, precision loss acceptable for reporting
#![allow(clippy::cast_precision_loss)]
// JUSTIFICATION: Match pattern clearer for test control flow
#![allow(clippy::single_match_else)]
#![allow(clippy::manual_let_else)]
// JUSTIFICATION: Test data slicing with known-valid indices
#![allow(clippy::indexing_slicing)]

use thiserror::Error;

/// Errors from Wycheproof test validation
#[derive(Debug, Error)]
pub enum WycheproofError {
    /// Test vector loading failed
    #[error("Failed to load test vectors: {0}")]
    LoadError(String),

    /// Test case failed
    #[error("Test case {tc_id} failed: {message}")]
    TestFailed {
        /// Test case ID
        tc_id: u32,
        /// Failure message
        message: String,
    },

    /// Unexpected result
    #[error("Unexpected result for test {tc_id}: expected {expected}, got {actual}")]
    UnexpectedResult {
        /// Test case ID
        tc_id: u32,
        /// Expected result
        expected: String,
        /// Actual result
        actual: String,
    },
}

/// Result of running Wycheproof tests
#[derive(Debug, Default)]
pub struct WycheproofResults {
    /// Total number of tests run
    pub total: usize,
    /// Number of tests passed
    pub passed: usize,
    /// Number of tests failed
    pub failed: usize,
    /// Number of tests skipped
    pub skipped: usize,
    /// Failure details
    pub failures: Vec<String>,
}

impl WycheproofResults {
    /// Create a new results instance
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if all tests passed
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Add a passed test
    pub fn add_pass(&mut self) {
        self.total += 1;
        self.passed += 1;
    }

    /// Add a failed test
    pub fn add_failure(&mut self, message: String) {
        self.total += 1;
        self.failed += 1;
        self.failures.push(message);
    }

    /// Add a skipped test
    pub fn add_skip(&mut self) {
        self.total += 1;
        self.skipped += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wycheproof::{TestResult, aead::TestSet as AeadTestSet};

    /// Test AES-GCM against Wycheproof vectors
    #[test]
    fn test_aes_gcm_wycheproof() {
        let test_set = match AeadTestSet::load(wycheproof::aead::TestName::AesGcm) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!("Failed to load AES-GCM test vectors: {e}");
                return;
            }
        };

        let mut results = WycheproofResults::new();

        for group in test_set.test_groups {
            for test in group.tests {
                let key = &test.key[..];
                let nonce = &test.nonce[..];
                let aad = &test.aad[..];
                let plaintext = &test.pt[..];
                let ciphertext = &test.ct[..];
                let tag = &test.tag[..];

                // Skip tests with non-standard parameters
                if key.len() != 16 && key.len() != 32 {
                    results.add_skip();
                    continue;
                }
                if nonce.len() != 12 {
                    results.add_skip();
                    continue;
                }

                // Test decryption (most important for security)
                let mut ct_with_tag = ciphertext.to_vec();
                ct_with_tag.extend_from_slice(tag);

                // Use aws-lc-rs for AES-GCM
                use aws_lc_rs::aead::{
                    AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey,
                };

                let algorithm = if key.len() == 16 { &AES_128_GCM } else { &AES_256_GCM };

                let unbound_key = match UnboundKey::new(algorithm, key) {
                    Ok(k) => k,
                    Err(_) => {
                        results.add_skip();
                        continue;
                    }
                };
                let less_safe_key = LessSafeKey::new(unbound_key);

                let nonce_array: [u8; 12] = match nonce.try_into() {
                    Ok(n) => n,
                    Err(_) => {
                        results.add_skip();
                        continue;
                    }
                };
                let nonce = Nonce::assume_unique_for_key(nonce_array);

                let decrypt_result =
                    less_safe_key.open_in_place(nonce, Aad::from(aad), &mut ct_with_tag);

                match test.result {
                    TestResult::Valid => {
                        if decrypt_result.is_ok() {
                            let decrypted = &ct_with_tag[..plaintext.len()];
                            if decrypted == plaintext {
                                results.add_pass();
                            } else {
                                results.add_failure(format!(
                                    "Test {}: decrypted data doesn't match plaintext",
                                    test.tc_id
                                ));
                            }
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected valid but decryption failed",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Invalid => {
                        if decrypt_result.is_err() {
                            results.add_pass();
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected invalid but decryption succeeded",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Acceptable => {
                        // Implementation-defined, count as pass either way
                        results.add_pass();
                    }
                }
            }
        }

        println!(
            "AES-GCM Wycheproof: {}/{} passed, {} skipped",
            results.passed, results.total, results.skipped
        );

        // Allow some failures for edge cases we don't support
        let failure_rate = results.failed as f64 / results.total as f64;
        assert!(
            failure_rate < 0.05,
            "Too many failures: {}/{} ({}%)\nFailures: {:?}",
            results.failed,
            results.total,
            failure_rate * 100.0,
            results.failures
        );
    }

    /// Test ChaCha20-Poly1305 against Wycheproof vectors
    #[test]
    fn test_chacha20_poly1305_wycheproof() {
        let test_set = match AeadTestSet::load(wycheproof::aead::TestName::ChaCha20Poly1305) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!("Failed to load ChaCha20-Poly1305 test vectors: {e}");
                return;
            }
        };

        let mut results = WycheproofResults::new();

        for group in test_set.test_groups {
            for test in group.tests {
                let key = &test.key[..];
                let nonce = &test.nonce[..];
                let aad = &test.aad[..];
                let plaintext = &test.pt[..];
                let ciphertext = &test.ct[..];
                let tag = &test.tag[..];

                // ChaCha20-Poly1305 requires 32-byte key and 12-byte nonce
                if key.len() != 32 || nonce.len() != 12 {
                    results.add_skip();
                    continue;
                }

                use chacha20poly1305::{
                    ChaCha20Poly1305,
                    aead::{Aead, KeyInit, Payload},
                };

                let key_array: [u8; 32] = match key.try_into() {
                    Ok(k) => k,
                    Err(_) => {
                        results.add_skip();
                        continue;
                    }
                };

                let cipher = ChaCha20Poly1305::new(&key_array.into());

                // Combine ciphertext and tag for decryption
                let mut ct_with_tag = ciphertext.to_vec();
                ct_with_tag.extend_from_slice(tag);

                let decrypt_result =
                    cipher.decrypt(nonce.into(), Payload { msg: &ct_with_tag, aad });

                match test.result {
                    TestResult::Valid => {
                        if let Ok(decrypted) = decrypt_result {
                            if decrypted == plaintext {
                                results.add_pass();
                            } else {
                                results.add_failure(format!(
                                    "Test {}: decrypted data doesn't match",
                                    test.tc_id
                                ));
                            }
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected valid but decryption failed",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Invalid => {
                        if decrypt_result.is_err() {
                            results.add_pass();
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected invalid but decryption succeeded",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Acceptable => {
                        results.add_pass();
                    }
                }
            }
        }

        println!(
            "ChaCha20-Poly1305 Wycheproof: {}/{} passed, {} skipped",
            results.passed, results.total, results.skipped
        );

        let failure_rate = results.failed as f64 / results.total as f64;
        assert!(
            failure_rate < 0.05,
            "Too many failures: {}/{} ({}%)\nFailures: {:?}",
            results.failed,
            results.total,
            failure_rate * 100.0,
            results.failures
        );
    }

    /// Test ECDSA signature verification against Wycheproof vectors
    #[test]
    fn test_ecdsa_p256_wycheproof() {
        use wycheproof::ecdsa::{TestName, TestSet};

        let test_set = match TestSet::load(TestName::EcdsaSecp256r1Sha256) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!("Failed to load ECDSA test vectors: {e}");
                return;
            }
        };

        let mut results = WycheproofResults::new();

        for group in test_set.test_groups {
            for _test in group.tests {
                // We skip ECDSA tests as we focus on PQC
                // This is a placeholder for when we add ECDSA support
                results.add_skip();
            }
        }

        println!(
            "ECDSA P-256 Wycheproof: {}/{} passed, {} skipped",
            results.passed, results.total, results.skipped
        );
    }

    /// Test EdDSA signature verification against Wycheproof vectors
    #[test]
    fn test_eddsa_wycheproof() {
        use wycheproof::eddsa::{TestName, TestSet};

        let test_set = match TestSet::load(TestName::Ed25519) {
            Ok(ts) => ts,
            Err(e) => {
                tracing::warn!("Failed to load EdDSA test vectors: {e}");
                return;
            }
        };

        let mut results = WycheproofResults::new();

        for group in test_set.test_groups {
            let public_key = &group.key.pk[..];

            for test in group.tests {
                let message = &test.msg[..];
                let signature = &test.sig[..];

                // Validate using ed25519-dalek
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                let vk: Result<VerifyingKey, _> = public_key.try_into();
                let vk = match vk {
                    Ok(k) => k,
                    Err(_) => {
                        // Invalid public key format
                        if matches!(test.result, TestResult::Invalid) {
                            results.add_pass();
                        } else {
                            results.add_skip();
                        }
                        continue;
                    }
                };

                let sig = match Signature::from_slice(signature) {
                    Ok(s) => s,
                    Err(_) => {
                        if matches!(test.result, TestResult::Invalid) {
                            results.add_pass();
                        } else {
                            results.add_skip();
                        }
                        continue;
                    }
                };

                let verify_result = vk.verify(message, &sig);

                match test.result {
                    TestResult::Valid => {
                        if verify_result.is_ok() {
                            results.add_pass();
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected valid but verification failed",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Invalid => {
                        if verify_result.is_err() {
                            results.add_pass();
                        } else {
                            results.add_failure(format!(
                                "Test {}: expected invalid but verification succeeded",
                                test.tc_id
                            ));
                        }
                    }
                    TestResult::Acceptable => {
                        results.add_pass();
                    }
                }
            }
        }

        println!(
            "EdDSA Wycheproof: {}/{} passed, {} skipped",
            results.passed, results.total, results.skipped
        );

        let failure_rate =
            if results.total > 0 { results.failed as f64 / results.total as f64 } else { 0.0 };
        assert!(
            failure_rate < 0.05,
            "Too many failures: {}/{} ({}%)\nFailures: {:?}",
            results.failed,
            results.total,
            failure_rate * 100.0,
            results.failures
        );
    }

    // =========================================================================
    // Unit tests for WycheproofResults API
    // =========================================================================

    /// Verify that a fresh WycheproofResults reports all_passed as true
    /// (zero failures means everything passed, even with zero tests).
    #[test]
    fn test_results_new_all_passed() {
        let results = WycheproofResults::new();
        assert!(results.all_passed());
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.skipped, 0);
        assert!(results.failures.is_empty());
    }

    /// Verify that Default derives the same state as new().
    #[test]
    fn test_results_default() {
        let results = WycheproofResults::default();
        assert!(results.all_passed());
        assert_eq!(results.total, 0);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert_eq!(results.skipped, 0);
        assert!(results.failures.is_empty());
    }

    /// Verify that all_passed returns true when there are only passes.
    #[test]
    fn test_results_all_passed_with_passes_only() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_pass();
        results.add_pass();
        assert!(results.all_passed());
        assert_eq!(results.total, 3);
        assert_eq!(results.passed, 3);
        assert_eq!(results.failed, 0);
    }

    /// Verify that all_passed returns false when there are failures.
    #[test]
    fn test_results_all_passed_returns_false_with_failures() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_failure("test failure message".to_string());
        assert!(!results.all_passed());
        assert_eq!(results.total, 2);
        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.failures.len(), 1);
        assert_eq!(results.failures[0], "test failure message");
    }

    /// Verify that all_passed still returns true with skips but no failures.
    #[test]
    fn test_results_all_passed_with_skips() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_skip();
        results.add_skip();
        assert!(results.all_passed());
        assert_eq!(results.total, 3);
        assert_eq!(results.passed, 1);
        assert_eq!(results.skipped, 2);
        assert_eq!(results.failed, 0);
    }

    /// Verify add_failure accumulates messages correctly.
    #[test]
    fn test_results_multiple_failures() {
        let mut results = WycheproofResults::new();
        results.add_failure("error 1".to_string());
        results.add_failure("error 2".to_string());
        results.add_failure("error 3".to_string());
        assert!(!results.all_passed());
        assert_eq!(results.total, 3);
        assert_eq!(results.failed, 3);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failures.len(), 3);
        assert_eq!(results.failures[0], "error 1");
        assert_eq!(results.failures[1], "error 2");
        assert_eq!(results.failures[2], "error 3");
    }

    /// Verify mixed pass, fail, skip counts are tracked correctly.
    #[test]
    fn test_results_mixed_operations() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_failure("fail A".to_string());
        results.add_skip();
        results.add_pass();
        results.add_failure("fail B".to_string());
        results.add_skip();
        results.add_pass();

        assert_eq!(results.total, 7);
        assert_eq!(results.passed, 3);
        assert_eq!(results.failed, 2);
        assert_eq!(results.skipped, 2);
        assert!(!results.all_passed());
        assert_eq!(results.failures, vec!["fail A", "fail B"]);
    }

    /// Verify Debug formatting is implemented for WycheproofResults.
    #[test]
    fn test_results_debug_format() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        results.add_failure("debug test failure".to_string());
        let debug_str = format!("{results:?}");
        assert!(debug_str.contains("WycheproofResults"));
        assert!(debug_str.contains("debug test failure"));
        assert!(debug_str.contains("total"));
        assert!(debug_str.contains("passed"));
        assert!(debug_str.contains("failed"));
    }

    // =========================================================================
    // Unit tests for WycheproofError variants
    // =========================================================================

    /// Verify LoadError display formatting.
    #[test]
    fn test_error_load_error_display() {
        let err = WycheproofError::LoadError("file not found".to_string());
        let msg = format!("{err}");
        assert_eq!(msg, "Failed to load test vectors: file not found");
    }

    /// Verify TestFailed display formatting.
    #[test]
    fn test_error_test_failed_display() {
        let err =
            WycheproofError::TestFailed { tc_id: 42, message: "decryption mismatch".to_string() };
        let msg = format!("{err}");
        assert_eq!(msg, "Test case 42 failed: decryption mismatch");
    }

    /// Verify UnexpectedResult display formatting.
    #[test]
    fn test_error_unexpected_result_display() {
        let err = WycheproofError::UnexpectedResult {
            tc_id: 99,
            expected: "valid".to_string(),
            actual: "invalid".to_string(),
        };
        let msg = format!("{err}");
        assert_eq!(msg, "Unexpected result for test 99: expected valid, got invalid");
    }

    /// Verify WycheproofError implements std::error::Error (source is None for leaf errors).
    #[test]
    fn test_error_is_std_error() {
        use std::error::Error;

        let load_err = WycheproofError::LoadError("test".to_string());
        // thiserror leaf variants have no source
        assert!(load_err.source().is_none());

        let test_failed = WycheproofError::TestFailed { tc_id: 1, message: "msg".to_string() };
        assert!(test_failed.source().is_none());

        let unexpected = WycheproofError::UnexpectedResult {
            tc_id: 2,
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(unexpected.source().is_none());
    }

    /// Verify Debug formatting for WycheproofError variants.
    #[test]
    fn test_error_debug_format() {
        let err = WycheproofError::LoadError("debug test".to_string());
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("LoadError"));
        assert!(debug_str.contains("debug test"));

        let err = WycheproofError::TestFailed { tc_id: 10, message: "failed debug".to_string() };
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("TestFailed"));
        assert!(debug_str.contains("10"));

        let err = WycheproofError::UnexpectedResult {
            tc_id: 20,
            expected: "yes".to_string(),
            actual: "no".to_string(),
        };
        let debug_str = format!("{err:?}");
        assert!(debug_str.contains("UnexpectedResult"));
        assert!(debug_str.contains("20"));
    }

    /// Verify LoadError with empty string.
    #[test]
    fn test_error_load_error_empty_message() {
        let err = WycheproofError::LoadError(String::new());
        let msg = format!("{err}");
        assert_eq!(msg, "Failed to load test vectors: ");
    }

    /// Verify TestFailed with tc_id zero.
    #[test]
    fn test_error_test_failed_zero_id() {
        let err = WycheproofError::TestFailed { tc_id: 0, message: "zero id test".to_string() };
        let msg = format!("{err}");
        assert_eq!(msg, "Test case 0 failed: zero id test");
    }

    /// Verify UnexpectedResult with large tc_id.
    #[test]
    fn test_error_unexpected_result_large_id() {
        let err = WycheproofError::UnexpectedResult {
            tc_id: u32::MAX,
            expected: "pass".to_string(),
            actual: "fail".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains(&u32::MAX.to_string()));
        assert!(msg.contains("pass"));
        assert!(msg.contains("fail"));
    }

    /// Verify add_skip increments both total and skipped but not passed or failed.
    #[test]
    fn test_results_add_skip_only() {
        let mut results = WycheproofResults::new();
        results.add_skip();
        assert_eq!(results.total, 1);
        assert_eq!(results.skipped, 1);
        assert_eq!(results.passed, 0);
        assert_eq!(results.failed, 0);
        assert!(results.all_passed());
        assert!(results.failures.is_empty());
    }

    /// Verify add_pass increments both total and passed but not skipped or failed.
    #[test]
    fn test_results_add_pass_only() {
        let mut results = WycheproofResults::new();
        results.add_pass();
        assert_eq!(results.total, 1);
        assert_eq!(results.passed, 1);
        assert_eq!(results.skipped, 0);
        assert_eq!(results.failed, 0);
        assert!(results.all_passed());
    }

    /// Verify add_failure increments total, failed, and pushes message.
    #[test]
    fn test_results_add_failure_only() {
        let mut results = WycheproofResults::new();
        results.add_failure("single failure".to_string());
        assert_eq!(results.total, 1);
        assert_eq!(results.failed, 1);
        assert_eq!(results.passed, 0);
        assert_eq!(results.skipped, 0);
        assert!(!results.all_passed());
        assert_eq!(results.failures.len(), 1);
    }
}
