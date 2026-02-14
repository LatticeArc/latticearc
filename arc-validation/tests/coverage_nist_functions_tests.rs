//! Coverage tests for nist_functions.rs (RandomizedHasher)
//!
//! Targets uncovered paths in RandomizedHasher: different modes, verify, edge cases.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::print_stdout,
    clippy::redundant_clone,
    clippy::cast_precision_loss
)]

use arc_validation::nist_functions::{RandomizedHashConfig, RandomizedHashMode, RandomizedHasher};

// ============================================================================
// Construction and defaults
// ============================================================================

#[test]
fn test_randomized_hasher_default() {
    let hasher = RandomizedHasher::default();
    let result = hasher.hash(b"test message").unwrap();
    assert!(!result.hash.is_empty());
    assert!(!result.salt.is_empty());
    assert_eq!(result.algorithm, "SHA-256");
    assert_eq!(result.mode, RandomizedHashMode::SaltPrefix);
}

#[test]
fn test_randomized_hash_config_default() {
    let config = RandomizedHashConfig::default();
    assert_eq!(config.algorithm, "SHA-256");
    assert_eq!(config.mode, RandomizedHashMode::SaltPrefix);
    assert_eq!(config.salt_length, 32);
    assert_eq!(config.salt_insertions, 3);
}

// ============================================================================
// Different hash modes
// ============================================================================

#[test]
fn test_hash_mode_none() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-256".to_string(),
        mode: RandomizedHashMode::None,
        salt_length: 0,
        salt_insertions: 0,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message").unwrap();
    assert!(!result.hash.is_empty());
    assert_eq!(result.mode, RandomizedHashMode::None);
}

#[test]
fn test_hash_mode_salt_prefix() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-256".to_string(),
        mode: RandomizedHashMode::SaltPrefix,
        salt_length: 16,
        salt_insertions: 0,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message").unwrap();
    assert!(!result.hash.is_empty());
    assert_eq!(result.salt.len(), 16);
}

#[test]
fn test_hash_mode_salt_suffix() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-256".to_string(),
        mode: RandomizedHashMode::SaltSuffix,
        salt_length: 16,
        salt_insertions: 0,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message").unwrap();
    assert!(!result.hash.is_empty());
}

#[test]
fn test_hash_mode_salt_distributed() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-256".to_string(),
        mode: RandomizedHashMode::SaltDistributed,
        salt_length: 16,
        salt_insertions: 3,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message for distributed salting").unwrap();
    assert!(!result.hash.is_empty());
}

// ============================================================================
// Different hash algorithms
// ============================================================================

#[test]
fn test_hash_sha384() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-384".to_string(),
        mode: RandomizedHashMode::SaltPrefix,
        salt_length: 32,
        salt_insertions: 0,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message").unwrap();
    assert_eq!(result.hash.len(), 48); // SHA-384 outputs 48 bytes
    assert_eq!(result.algorithm, "SHA-384");
}

#[test]
fn test_hash_sha512() {
    let config = RandomizedHashConfig {
        algorithm: "SHA-512".to_string(),
        mode: RandomizedHashMode::SaltPrefix,
        salt_length: 32,
        salt_insertions: 0,
    };
    let hasher = RandomizedHasher::new(config);
    let result = hasher.hash(b"test message").unwrap();
    assert_eq!(result.hash.len(), 64); // SHA-512 outputs 64 bytes
    assert_eq!(result.algorithm, "SHA-512");
}

// ============================================================================
// Verify
// ============================================================================

#[test]
fn test_verify_valid_hash() {
    let hasher = RandomizedHasher::default();
    let hash_result = hasher.hash(b"test message").unwrap();
    let is_valid = hasher.verify(b"test message", &hash_result).unwrap();
    assert!(is_valid);
}

#[test]
fn test_verify_wrong_message() {
    let hasher = RandomizedHasher::default();
    let hash_result = hasher.hash(b"test message").unwrap();
    let is_valid = hasher.verify(b"wrong message", &hash_result).unwrap();
    assert!(!is_valid);
}

#[test]
fn test_verify_with_different_modes() {
    for mode in [
        RandomizedHashMode::SaltPrefix,
        RandomizedHashMode::SaltSuffix,
        RandomizedHashMode::SaltDistributed,
    ] {
        let config = RandomizedHashConfig {
            algorithm: "SHA-256".to_string(),
            mode,
            salt_length: 16,
            salt_insertions: 3,
        };
        let hasher = RandomizedHasher::new(config);
        let hash_result = hasher.hash(b"test for mode").unwrap();
        let is_valid = hasher.verify(b"test for mode", &hash_result).unwrap();
        assert!(is_valid, "Verification should pass for matching message");
    }
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn test_hash_empty_message() {
    let hasher = RandomizedHasher::default();
    let result = hasher.hash(b"").unwrap();
    assert!(!result.hash.is_empty());
}

#[test]
fn test_hash_large_message() {
    let hasher = RandomizedHasher::default();
    let large_message = vec![0xABu8; 100_000];
    let result = hasher.hash(&large_message).unwrap();
    assert!(!result.hash.is_empty());
}

#[test]
fn test_hash_randomness() {
    let hasher = RandomizedHasher::default();
    let result1 = hasher.hash(b"same message").unwrap();
    let result2 = hasher.hash(b"same message").unwrap();
    // Different salts should produce different hashes
    assert_ne!(result1.salt, result2.salt);
    assert_ne!(result1.hash, result2.hash);
}

// ============================================================================
// RandomizedHash fields
// ============================================================================

#[test]
fn test_randomized_hash_fields() {
    let hasher = RandomizedHasher::default();
    let result = hasher.hash(b"test").unwrap();
    assert_eq!(result.algorithm, "SHA-256");
    assert_eq!(result.mode, RandomizedHashMode::SaltPrefix);
    assert_eq!(result.hash.len(), 32); // SHA-256 output
    assert_eq!(result.salt.len(), 32); // Default salt length
}

#[test]
fn test_randomized_hash_mode_equality() {
    assert_eq!(RandomizedHashMode::None, RandomizedHashMode::None);
    assert_eq!(RandomizedHashMode::SaltPrefix, RandomizedHashMode::SaltPrefix);
    assert_ne!(RandomizedHashMode::SaltPrefix, RandomizedHashMode::SaltSuffix);

    let mode = RandomizedHashMode::SaltDistributed;
    let debug = format!("{:?}", mode);
    assert!(debug.contains("SaltDistributed"));
}

#[test]
fn test_randomized_hash_config_clone() {
    let config = RandomizedHashConfig::default();
    let cloned = config.clone();
    assert_eq!(cloned.algorithm, config.algorithm);
    assert_eq!(cloned.salt_length, config.salt_length);

    let debug = format!("{:?}", config);
    assert!(debug.contains("SHA-256"));
}
