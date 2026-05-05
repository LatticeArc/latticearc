#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::redundant_clone,
    clippy::clone_on_copy,
    clippy::collapsible_if,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::explicit_iter_loop,
    clippy::explicit_auto_deref,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::print_stdout,
    clippy::unused_unit,
    clippy::expect_fun_call,
    clippy::useless_vec,
    clippy::cloned_instead_of_copied,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    clippy::manual_let_else
)]
//! Comprehensive ML-KEM Primitives Tests - Phase 2 Security Audit
//!
//! This test suite provides comprehensive coverage for ML-KEM (FIPS 203)
//! post-quantum key encapsulation mechanism implementation.
//!
//! ## Test Coverage (Tasks 2.1.1 - 2.1.13)
//! - Key generation for all security levels (MlKem512/768/1024)
//! - Encapsulation for all security levels
//! - Decapsulation for all security levels
//! - Shared secret equality verification
//! - Public key serialization roundtrip
//! - Ciphertext validation
//! - Corrupted ciphertext rejection
//! - Wrong key decapsulation detection
//! - Constant-time properties verification
//! - Zeroization of secret data
//! - NIST KAT vector testing (where applicable)
//!
//! ## FIPS 140-3 Compliance Note
//! The aws-lc-rs library (v1.16.0+) provides FIPS 140-3 validated ML-KEM with
//! full key serialization support including DecapsulationKey.

use latticearc::primitives::kem::ml_kem::{
    MlKem, MlKemCiphertext, MlKemConfig, MlKemError, MlKemPublicKey, MlKemSecretKey,
    MlKemSecurityLevel, MlKemSharedSecret,
};
use rand::RngCore;
use std::time::Instant;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// ============================================================================
// SECTION 1: Key Generation Tests (Task 2.1.1)
// ============================================================================

/// Test MlKem512 key generation produces valid keys
#[test]
fn test_mlkem_512_key_generation_succeeds() {
    let result = MlKem::generate_keypair(MlKemSecurityLevel::MlKem512);

    assert!(result.is_ok(), "MlKem512 key generation should succeed");

    let (pk, sk) = result.unwrap();

    // Verify public key size (800 bytes for MlKem512)
    assert_eq!(pk.as_bytes().len(), 800, "MlKem512 public key should be 800 bytes");

    // Verify secret key size (1632 bytes for MlKem512)
    assert_eq!(sk.expose_secret().len(), 1632, "MlKem512 secret key should be 1632 bytes");

    // Verify security level accessor
    assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem512);
    assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem512);
}

/// Test MlKem768 key generation produces valid keys
#[test]
fn test_mlkem_768_key_generation_succeeds() {
    let result = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768);

    assert!(result.is_ok(), "MlKem768 key generation should succeed");

    let (pk, sk) = result.unwrap();

    // Verify public key size (1184 bytes for MlKem768)
    assert_eq!(pk.as_bytes().len(), 1184, "MlKem768 public key should be 1184 bytes");

    // Verify secret key size (2400 bytes for MlKem768)
    assert_eq!(sk.expose_secret().len(), 2400, "MlKem768 secret key should be 2400 bytes");

    // Verify security level accessor
    assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem768);
    assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem768);
}

/// Test MlKem1024 key generation produces valid keys
#[test]
fn test_mlkem_1024_key_generation_succeeds() {
    let result = MlKem::generate_keypair(MlKemSecurityLevel::MlKem1024);

    assert!(result.is_ok(), "MlKem1024 key generation should succeed");

    let (pk, sk) = result.unwrap();

    // Verify public key size (1568 bytes for MlKem1024)
    assert_eq!(pk.as_bytes().len(), 1568, "MlKem1024 public key should be 1568 bytes");

    // Verify secret key size (3168 bytes for MlKem1024)
    assert_eq!(sk.expose_secret().len(), 3168, "MlKem1024 secret key should be 3168 bytes");

    // Verify security level accessor
    assert_eq!(pk.security_level(), MlKemSecurityLevel::MlKem1024);
    assert_eq!(sk.security_level(), MlKemSecurityLevel::MlKem1024);
}

/// Test key generation produces non-trivial keys (not all zeros)
#[test]
fn test_key_generation_produces_nontrivial_keys_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");

        // Public key should not be all zeros
        assert!(
            !pk.as_bytes().iter().all(|&b| b == 0),
            "Public key for {} should not be all zeros",
            level.name()
        );
    }
}

/// Test multiple key generations produce different keys (randomness check)
#[test]
fn test_key_generation_produces_unique_keys_are_unique() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk1, _sk1) = MlKem::generate_keypair(level).expect("key generation 1 should succeed");
        let (pk2, _sk2) = MlKem::generate_keypair(level).expect("key generation 2 should succeed");

        assert_ne!(
            pk1.as_bytes(),
            pk2.as_bytes(),
            "Consecutive key generations for {} should produce different keys",
            level.name()
        );
    }
}

/// Test key generation with config
#[test]
fn test_key_generation_with_config_succeeds() {
    let config = MlKemConfig { security_level: MlKemSecurityLevel::MlKem768 };

    let result = MlKem::generate_keypair_with_config(config);
    assert!(result.is_ok(), "Key generation with config should succeed");

    let (pk, sk) = result.unwrap();
    assert_eq!(pk.as_bytes().len(), 1184);
    assert_eq!(sk.expose_secret().len(), 2400);
}

// ============================================================================
// SECTION 2: Encapsulation Tests (Task 2.1.2)
// ============================================================================

/// Test MlKem512 encapsulation
#[test]
fn test_mlkem_512_encapsulation_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem512)
        .expect("key generation should succeed");

    let result = MlKem::encapsulate(&pk);
    assert!(result.is_ok(), "MlKem512 encapsulation should succeed");

    let (ss, ct) = result.unwrap();

    // Verify ciphertext size (768 bytes for MlKem512)
    assert_eq!(ct.as_bytes().len(), 768, "MlKem512 ciphertext should be 768 bytes");

    // Verify shared secret size (32 bytes)
    assert_eq!(ss.expose_secret().len(), 32, "Shared secret should be 32 bytes");
}

/// Test MlKem768 encapsulation
#[test]
fn test_mlkem_768_encapsulation_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");

    let result = MlKem::encapsulate(&pk);
    assert!(result.is_ok(), "MlKem768 encapsulation should succeed");

    let (ss, ct) = result.unwrap();

    // Verify ciphertext size (1088 bytes for MlKem768)
    assert_eq!(ct.as_bytes().len(), 1088, "MlKem768 ciphertext should be 1088 bytes");

    // Verify shared secret size (32 bytes)
    assert_eq!(ss.expose_secret().len(), 32, "Shared secret should be 32 bytes");
}

/// Test MlKem1024 encapsulation
#[test]
fn test_mlkem_1024_encapsulation_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem1024)
        .expect("key generation should succeed");

    let result = MlKem::encapsulate(&pk);
    assert!(result.is_ok(), "MlKem1024 encapsulation should succeed");

    let (ss, ct) = result.unwrap();

    // Verify ciphertext size (1568 bytes for MlKem1024)
    assert_eq!(ct.as_bytes().len(), 1568, "MlKem1024 ciphertext should be 1568 bytes");

    // Verify shared secret size (32 bytes)
    assert_eq!(ss.expose_secret().len(), 32, "Shared secret should be 32 bytes");
}

/// Test encapsulation produces non-trivial shared secrets
#[test]
fn test_encapsulation_produces_nontrivial_secrets_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        // Shared secret should not be all zeros
        assert!(
            !ss.expose_secret().iter().all(|&b| b == 0),
            "Shared secret for {} should not be all zeros",
            level.name()
        );

        // Ciphertext should not be all zeros
        assert!(
            !ct.as_bytes().iter().all(|&b| b == 0),
            "Ciphertext for {} should not be all zeros",
            level.name()
        );
    }
}

/// Test multiple encapsulations with same key produce different results (IND-CCA2)
#[test]
fn test_encapsulation_randomness_ind_cca2_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");

        let (ss1, ct1) = MlKem::encapsulate(&pk).expect("encapsulation 1 should succeed");
        let (ss2, ct2) = MlKem::encapsulate(&pk).expect("encapsulation 2 should succeed");

        // Ciphertexts must differ (randomized encapsulation)
        assert_ne!(
            ct1.as_bytes(),
            ct2.as_bytes(),
            "Ciphertexts for {} should differ across encapsulations",
            level.name()
        );

        // Shared secrets must also differ
        assert_ne!(
            ss1.expose_secret(),
            ss2.expose_secret(),
            "Shared secrets for {} should differ across encapsulations",
            level.name()
        );
    }
}

// ============================================================================
// SECTION 3: Decapsulation Tests (Task 2.1.3)
// ============================================================================

/// Test decapsulation roundtrip succeeds for all security levels
#[test]
fn test_decapsulation_roundtrip_all_levels_roundtrip() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss_enc, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        let ss_dec = MlKem::decapsulate(&sk, &ct)
            .unwrap_or_else(|e| panic!("Decapsulation for {} should succeed: {}", level.name(), e));

        assert_eq!(
            ss_enc.expose_secret(),
            ss_dec.expose_secret(),
            "Shared secrets for {} must match",
            level.name()
        );
    }
}

/// Test decapsulation with security level mismatch.
///
/// FIPS 203 §6.3 implicit-rejection contract: the failure path on
/// adversary-reachable input must surface the same opaque error string as
/// the constant-time decap rejection itself. Round-10 audit collapsed the
/// pre-check, so this test asserts only that the operation rejects — it
/// does NOT inspect the error string.
#[test]
fn test_decapsulation_security_level_mismatch_fails() {
    // Generate keypair for MlKem512
    let (pk_512, _sk_512) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem512)
        .expect("key generation should succeed");

    // Generate keypair for MlKem768
    let (_pk_768, sk_768) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");

    // Encapsulate with MlKem512 key
    let (_ss, ct_512) = MlKem::encapsulate(&pk_512).expect("encapsulation should succeed");

    // Attempt to decapsulate with MlKem768 secret key
    let result = MlKem::decapsulate(&sk_768, &ct_512);
    assert!(result.is_err(), "Decapsulation with mismatched security levels should fail");
}

// ============================================================================
// SECTION 4: Shared Secret Equality Tests (Task 2.1.4)
// ============================================================================

/// Test shared secret constant-time equality
#[test]
fn test_shared_secret_constant_time_equality_succeeds() {
    let ss1 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss3 = MlKemSharedSecret::new([0x43u8; 32]);

    // Equal secrets — compared via `ct_eq` (invariants I-5/I-6: secret types
    // intentionally do not implement `PartialEq`).
    assert!(
        bool::from(ss1.ct_eq(&ss2)),
        "Constant-time comparison should return true for equal secrets"
    );

    // Different secrets
    assert!(
        !bool::from(ss1.ct_eq(&ss3)),
        "Constant-time comparison should return false for different secrets"
    );
}

/// Test shared secret from_slice validation
#[test]
fn test_shared_secret_from_slice_succeeds() {
    // Valid 32-byte slice
    let valid_bytes = [0xAAu8; 32];
    let result = MlKemSharedSecret::from_slice(&valid_bytes);
    assert!(result.is_ok(), "from_slice with 32 bytes should succeed");
    assert_eq!(result.unwrap().expose_secret(), &valid_bytes);

    // Invalid lengths
    for invalid_len in [0, 16, 31, 33, 64, 128] {
        let invalid_bytes = vec![0u8; invalid_len];
        let result = MlKemSharedSecret::from_slice(&invalid_bytes);
        assert!(result.is_err(), "from_slice with {} bytes should fail", invalid_len);
    }
}

/// Test shared secret as_array conversion
#[test]
fn test_shared_secret_as_array_succeeds() {
    let bytes = [0x55u8; 32];
    let ss = MlKemSharedSecret::new(bytes);

    let array = ss.expose_secret_as_array();
    assert_eq!(*array, bytes, "as_array should return the original bytes");
    assert_eq!(ss.expose_secret(), &bytes, "as_bytes should return a slice of the bytes");
}

// ============================================================================
// SECTION 5: Public Key Serialization Tests (Task 2.1.5)
// ============================================================================

/// Test public key serialization roundtrip for all levels
#[test]
fn test_public_key_serialization_roundtrip_all_levels_roundtrip() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");

        // Serialize
        let pk_bytes = pk.to_bytes();
        assert_eq!(pk_bytes.len(), level.public_key_size());

        // Deserialize
        let restored_pk =
            MlKemPublicKey::from_bytes(&pk_bytes, level).expect("deserialization should succeed");

        // Verify equality
        assert_eq!(
            restored_pk.as_bytes(),
            pk.as_bytes(),
            "Restored public key for {} should match original",
            level.name()
        );
        assert_eq!(restored_pk.security_level(), level);
    }
}

/// Test restored public key can be used for encapsulation
#[test]
fn test_restored_public_key_encapsulation_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");

        // Serialize and restore
        let pk_bytes = pk.to_bytes();
        let restored_pk =
            MlKemPublicKey::from_bytes(&pk_bytes, level).expect("deserialization should succeed");

        // Encapsulate with restored key
        let result = MlKem::encapsulate(&restored_pk);
        assert!(
            result.is_ok(),
            "Encapsulation with restored key for {} should succeed",
            level.name()
        );

        let (ss, ct) = result.unwrap();
        assert_eq!(ss.expose_secret().len(), 32);
        assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
    }
}

/// Test public key from_bytes rejects wrong length
#[test]
fn test_public_key_from_bytes_wrong_length_fails() {
    let levels_and_sizes = [
        (MlKemSecurityLevel::MlKem512, 800),
        (MlKemSecurityLevel::MlKem768, 1184),
        (MlKemSecurityLevel::MlKem1024, 1568),
    ];

    for (level, correct_size) in levels_and_sizes {
        // Too small
        let small_bytes = vec![0u8; correct_size - 1];
        assert!(
            MlKemPublicKey::from_bytes(&small_bytes, level).is_err(),
            "from_bytes should reject key that is too small for {}",
            level.name()
        );

        // Too large
        let large_bytes = vec![0u8; correct_size + 1];
        assert!(
            MlKemPublicKey::from_bytes(&large_bytes, level).is_err(),
            "from_bytes should reject key that is too large for {}",
            level.name()
        );

        // Correct size should work
        let correct_bytes = vec![0u8; correct_size];
        assert!(
            MlKemPublicKey::from_bytes(&correct_bytes, level).is_ok(),
            "from_bytes should accept correctly sized key for {}",
            level.name()
        );
    }
}

/// Test public key into_bytes consumes the key
#[test]
fn test_public_key_into_bytes_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");

    let original_bytes = pk.as_bytes().to_vec();
    let consumed_bytes = pk.into_bytes();

    assert_eq!(consumed_bytes, original_bytes);
}

// ============================================================================
// SECTION 6: Ciphertext Validation Tests (Task 2.1.6)
// ============================================================================

/// Test ciphertext construction validates length
#[test]
fn test_ciphertext_construction_length_validation_has_correct_size() {
    let levels_and_sizes = [
        (MlKemSecurityLevel::MlKem512, 768),
        (MlKemSecurityLevel::MlKem768, 1088),
        (MlKemSecurityLevel::MlKem1024, 1568),
    ];

    for (level, correct_size) in levels_and_sizes {
        // Empty
        assert!(
            MlKemCiphertext::new(level, vec![]).is_err(),
            "Empty ciphertext should be rejected for {}",
            level.name()
        );

        // Too small
        let small = vec![0u8; correct_size - 1];
        assert!(
            MlKemCiphertext::new(level, small).is_err(),
            "Too small ciphertext should be rejected for {}",
            level.name()
        );

        // Too large
        let large = vec![0u8; correct_size + 1];
        assert!(
            MlKemCiphertext::new(level, large).is_err(),
            "Too large ciphertext should be rejected for {}",
            level.name()
        );

        // Correct size
        let correct = vec![0u8; correct_size];
        assert!(
            MlKemCiphertext::new(level, correct).is_ok(),
            "Correct size ciphertext should be accepted for {}",
            level.name()
        );
    }
}

/// Test ciphertext security level accessor
#[test]
fn test_ciphertext_security_level_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, _sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (_ss, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        assert_eq!(
            ct.security_level(),
            level,
            "Ciphertext security level should match for {}",
            level.name()
        );
    }
}

/// Test ciphertext into_bytes
#[test]
fn test_ciphertext_into_bytes_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");
    let (_ss, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

    let original_bytes = ct.as_bytes().to_vec();
    let consumed_bytes = ct.into_bytes();

    assert_eq!(consumed_bytes, original_bytes);
    assert_eq!(consumed_bytes.len(), 1088);
}

// ============================================================================
// SECTION 7: Corrupted Ciphertext Rejection Tests (Task 2.1.7)
// ============================================================================

/// Test decapsulation with all-zeros ciphertext
#[test]
fn test_decapsulate_all_zeros_ciphertext_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss_real, _ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        let zero_ct = MlKemCiphertext::new(level, vec![0u8; level.ciphertext_size()])
            .expect("ciphertext construction should succeed");

        // ML-KEM implicit rejection: invalid ciphertext produces a different shared secret
        let ss_zero = MlKem::decapsulate(&sk, &zero_ct)
            .expect("decapsulation should succeed (implicit rejection)");
        assert_ne!(
            ss_real.expose_secret(),
            ss_zero.expose_secret(),
            "All-zeros ciphertext must produce different shared secret for {}",
            level.name()
        );
    }
}

/// Test decapsulation with all-ones ciphertext (implicit rejection)
#[test]
fn test_decapsulate_all_ones_ciphertext_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss_real, _ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        let ones_ct = MlKemCiphertext::new(level, vec![0xFFu8; level.ciphertext_size()])
            .expect("ciphertext construction should succeed");

        let ss_ones = MlKem::decapsulate(&sk, &ones_ct)
            .expect("decapsulation should succeed (implicit rejection)");
        assert_ne!(
            ss_real.expose_secret(),
            ss_ones.expose_secret(),
            "All-ones ciphertext must produce different shared secret for {}",
            level.name()
        );
    }
}

/// Test decapsulation with random garbage ciphertext (implicit rejection)
#[test]
fn test_decapsulate_random_garbage_ciphertext_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let (pk, sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss_real, _ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        let mut garbage = vec![0u8; level.ciphertext_size()];
        latticearc::primitives::rand::secure_rng().fill_bytes(&mut garbage);

        let garbage_ct =
            MlKemCiphertext::new(level, garbage).expect("ciphertext construction should succeed");

        let ss_garbage = MlKem::decapsulate(&sk, &garbage_ct)
            .expect("decapsulation should succeed (implicit rejection)");
        assert_ne!(
            ss_real.expose_secret(),
            ss_garbage.expose_secret(),
            "Garbage ciphertext must produce different shared secret for {}",
            level.name()
        );
    }
}

/// Test encapsulation with corrupted public key (junk data)
#[test]
fn test_encapsulate_with_corrupted_public_key_fails() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        // Create junk public key with correct size
        let junk_bytes = vec![0xDEu8; level.public_key_size()];
        let junk_pk = MlKemPublicKey::new(level, junk_bytes)
            .expect("construction with correct size should succeed");

        // Encapsulation should fail
        let result = MlKem::encapsulate(&junk_pk);
        assert!(
            result.is_err(),
            "Encapsulation with junk public key should fail for {}",
            level.name()
        );
    }
}

// ============================================================================
// SECTION 8: Wrong Key Decapsulation Tests (Task 2.1.8)
// ============================================================================

/// Test decapsulation with wrong secret key produces different shared secret (implicit rejection)
#[test]
fn test_decapsulate_wrong_secret_key_fails() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        // Generate two different keypairs
        let (pk1, _sk1) = MlKem::generate_keypair(level).expect("key generation 1 should succeed");
        let (_pk2, sk2) = MlKem::generate_keypair(level).expect("key generation 2 should succeed");

        // Encapsulate with pk1
        let (ss_enc, ct) = MlKem::encapsulate(&pk1).expect("encapsulation should succeed");

        // Decapsulate with sk2 (wrong key) — implicit rejection produces different shared secret
        let ss_wrong = MlKem::decapsulate(&sk2, &ct)
            .expect("decapsulation should succeed (implicit rejection)");

        assert_ne!(
            ss_enc.expose_secret(),
            ss_wrong.expose_secret(),
            "Wrong secret key must produce different shared secret for {}",
            level.name()
        );
    }
}

/// Test cross-security-level decapsulation fails
#[test]
fn test_cross_security_level_decapsulation_succeeds() {
    let levels =
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024];

    for (i, enc_level) in levels.iter().enumerate() {
        for (j, dec_level) in levels.iter().enumerate() {
            if i == j {
                continue; // Skip same level
            }

            let (pk_enc, _sk_enc) =
                MlKem::generate_keypair(*enc_level).expect("key generation should succeed");
            let (_pk_dec, sk_dec) =
                MlKem::generate_keypair(*dec_level).expect("key generation should succeed");

            let (_ss, ct) = MlKem::encapsulate(&pk_enc).expect("encapsulation should succeed");

            let result = MlKem::decapsulate(&sk_dec, &ct);
            assert!(
                result.is_err(),
                "Cross-level decapsulation from {} to {} should fail",
                enc_level.name(),
                dec_level.name()
            );
        }
    }
}

// ============================================================================
// SECTION 9: Constant-Time Properties Tests (Task 2.1.9)
// ============================================================================

/// Test timing consistency for shared secret comparison
#[test]
fn test_shared_secret_comparison_timing_consistency_succeeds() {
    // This is a basic timing consistency check
    // More rigorous testing would require statistical analysis

    let ss1 = MlKemSharedSecret::new([0x00u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x00u8; 32]);
    let ss3 = MlKemSharedSecret::new([0xFFu8; 32]);

    const ITERATIONS: usize = 1000;

    // Time equal comparisons
    let start_equal = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ss1.ct_eq(&ss2);
    }
    let equal_time = start_equal.elapsed();

    // Time unequal comparisons
    let start_unequal = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = ss1.ct_eq(&ss3);
    }
    let unequal_time = start_unequal.elapsed();

    // Sub-microsecond ct_eq batches over 1000 iterations are dominated by OS
    // preemption noise on CI runners — a single scheduling stall on either
    // batch can produce ratios well outside [0.1, 10.0] even when the
    // underlying operation is constant-time. Use a loose sanity ceiling
    // matching the project's other timing-distribution tests (10000x in
    // primitives_side_channel.rs); real constant-time verification is done
    // by the dudect/ctgrind gates, not this microbench.
    let ratio = equal_time.as_nanos() as f64 / unequal_time.as_nanos().max(1) as f64;
    assert!(
        ratio > 0.0001 && ratio < 10_000.0,
        "Comparison times wildly inconsistent: equal={:?}, unequal={:?}, ratio={:.2}",
        equal_time,
        unequal_time,
        ratio
    );
}

/// Test security level constant-time comparison
#[test]
fn test_security_level_constant_time_eq_succeeds() {
    let level1 = MlKemSecurityLevel::MlKem512;
    let level2 = MlKemSecurityLevel::MlKem512;
    let level3 = MlKemSecurityLevel::MlKem768;

    // Same level
    assert!(bool::from(level1.ct_eq(&level2)));

    // Different levels
    assert!(!bool::from(level1.ct_eq(&level3)));
}

/// Test secret key constant-time comparison
#[test]
fn test_secret_key_constant_time_eq_succeeds() {
    let sk1 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x42u8; 1632])
        .expect("secret key construction should succeed");
    let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x42u8; 1632])
        .expect("secret key construction should succeed");
    let sk3 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![0x43u8; 1632])
        .expect("secret key construction should succeed");

    // Equal keys — compared via `ct_eq` (invariants I-5/I-6).
    assert!(bool::from(sk1.ct_eq(&sk2)));

    // Different keys
    assert!(!bool::from(sk1.ct_eq(&sk3)));
}

// ============================================================================
// SECTION 10: Zeroization Tests (Task 2.1.10)
// ============================================================================

/// Test shared secret zeroization
#[test]
fn test_shared_secret_zeroization_succeeds() {
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);

    // Verify initial state
    assert!(
        ss.expose_secret().iter().any(|&b| b != 0),
        "Shared secret should contain non-zero data initially"
    );

    // Zeroize
    ss.zeroize();

    // Verify all bytes are zero
    assert!(
        ss.expose_secret().iter().all(|&b| b == 0),
        "Shared secret should be all zeros after zeroization"
    );
}

/// Test secret key zeroization
#[test]
fn test_secret_key_zeroization_succeeds() {
    let mut sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xCDu8; 2400])
        .expect("secret key construction should succeed");

    // Verify initial state
    assert!(
        sk.expose_secret().iter().any(|&b| b != 0),
        "Secret key should contain non-zero data initially"
    );

    // Zeroize
    sk.zeroize();

    // Verify all bytes are zero
    assert!(
        sk.expose_secret().iter().all(|&b| b == 0),
        "Secret key should be all zeros after zeroization"
    );
}

/// Test zeroization works for all security levels
#[test]
fn test_zeroization_all_security_levels_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let mut sk = MlKemSecretKey::new(level, vec![0xEFu8; level.secret_key_size()])
            .expect("secret key construction should succeed");

        sk.zeroize();

        assert!(
            sk.expose_secret().iter().all(|&b| b == 0),
            "Secret key for {} should be zeroed",
            level.name()
        );
    }
}

// ============================================================================
// SECTION 11: NIST KAT Vector Tests (Task 2.1.11)
// ============================================================================

/// Test key sizes match FIPS 203 specification
#[test]
fn test_fips_203_key_sizes_has_correct_size() {
    // FIPS 203 Table 2: ML-KEM parameter sets
    let fips_specs = [
        (MlKemSecurityLevel::MlKem512, 800, 1632, 768, 32), // pk, sk, ct, ss
        (MlKemSecurityLevel::MlKem768, 1184, 2400, 1088, 32),
        (MlKemSecurityLevel::MlKem1024, 1568, 3168, 1568, 32),
    ];

    for (level, pk_size, sk_size, ct_size, ss_size) in fips_specs {
        let (pk, sk) = MlKem::generate_keypair(level).expect("key generation should succeed");
        let (ss, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

        assert_eq!(pk.as_bytes().len(), pk_size, "{} public key size mismatch", level.name());
        assert_eq!(sk.expose_secret().len(), sk_size, "{} secret key size mismatch", level.name());
        assert_eq!(ct.as_bytes().len(), ct_size, "{} ciphertext size mismatch", level.name());
        assert_eq!(
            ss.expose_secret().len(),
            ss_size,
            "{} shared secret size mismatch",
            level.name()
        );
    }
}

/// Test NIST security categories match levels
#[test]
fn test_nist_security_categories_succeeds() {
    assert_eq!(MlKemSecurityLevel::MlKem512.nist_security_category(), 1);
    assert_eq!(MlKemSecurityLevel::MlKem768.nist_security_category(), 3);
    assert_eq!(MlKemSecurityLevel::MlKem1024.nist_security_category(), 5);
}

/// Test security level names match FIPS 203 naming
#[test]
fn test_security_level_names_succeeds() {
    assert_eq!(MlKemSecurityLevel::MlKem512.name(), "ML-KEM-512");
    assert_eq!(MlKemSecurityLevel::MlKem768.name(), "ML-KEM-768");
    assert_eq!(MlKemSecurityLevel::MlKem1024.name(), "ML-KEM-1024");
}

// ============================================================================
// SECTION 12: Additional Edge Case Tests
// ============================================================================

/// Test SIMD status reporting
#[test]
fn test_simd_status_succeeds() {
    let status = MlKem::simd_status();

    // aws-lc-rs uses SIMD internally
    assert!(status.acceleration_available);
    assert!(status.performance_multiplier >= 1.0);
}

/// Test default config
#[test]
fn test_default_config_succeeds() {
    let config = MlKemConfig::default();

    assert_eq!(config.security_level, MlKemSecurityLevel::MlKem768);
}

/// Test empty public key construction fails
#[test]
fn test_empty_public_key_construction_succeeds() {
    let result = MlKemPublicKey::new(MlKemSecurityLevel::MlKem512, vec![]);
    assert!(result.is_err(), "Empty public key should be rejected");

    match result {
        Err(MlKemError::InvalidKeyLength { .. }) => {
            // Expected
        }
        _ => panic!("Expected InvalidKeyLength error"),
    }
}

/// Test empty secret key construction fails. Round-35 L7: SK::new
/// collapses both length-mismatch and structural-validation paths
/// to `InvalidKeyFormat` (Pattern-6 sibling — round-34 M7 had
/// introduced two distinct variants).
#[test]
fn test_empty_secret_key_construction_succeeds() {
    let result = MlKemSecretKey::new(MlKemSecurityLevel::MlKem512, vec![]);
    assert!(result.is_err(), "Empty secret key should be rejected");

    match result {
        Err(MlKemError::InvalidKeyFormat(_)) => {
            // Expected
        }
        _ => panic!("Expected InvalidKeyFormat error"),
    }
}

/// Test empty ciphertext construction fails
#[test]
fn test_empty_ciphertext_construction_succeeds() {
    let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem512, vec![]);
    assert!(result.is_err(), "Empty ciphertext should be rejected");

    match result {
        Err(MlKemError::InvalidCiphertextLength { .. }) => {
            // Expected
        }
        _ => panic!("Expected InvalidCiphertextLength error"),
    }
}

/// Test public key to_bytes is idempotent
#[test]
fn test_public_key_to_bytes_idempotent_is_deterministic() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");

    let bytes1 = pk.to_bytes();
    let bytes2 = pk.to_bytes();

    assert_eq!(bytes1, bytes2, "to_bytes should be idempotent");
}

/// Test security level method consistency
#[test]
fn test_security_level_methods_consistency_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        // Verify all size methods return consistent values
        assert!(level.public_key_size() > 0);
        assert!(level.secret_key_size() > 0);
        assert!(level.ciphertext_size() > 0);
        assert_eq!(level.shared_secret_size(), 32);

        // Secret key should be larger than public key
        assert!(level.secret_key_size() > level.public_key_size());
    }
}

// ============================================================================
// SECTION 13: Stress and Boundary Tests
// ============================================================================

/// Test multiple consecutive operations
#[test]
fn test_multiple_consecutive_operations_succeeds() {
    let level = MlKemSecurityLevel::MlKem768;

    for i in 0..10 {
        let (pk, _sk) =
            MlKem::generate_keypair(level).expect(&format!("key generation {} should succeed", i));
        let (ss, ct) =
            MlKem::encapsulate(&pk).expect(&format!("encapsulation {} should succeed", i));

        assert_eq!(ss.expose_secret().len(), 32);
        assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
    }
}

/// Test public key can be cloned and used
#[test]
fn test_public_key_clone_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");

    let pk_clone = pk.clone();

    assert_eq!(pk.as_bytes(), pk_clone.as_bytes());
    assert_eq!(pk.security_level(), pk_clone.security_level());

    // Both should work for encapsulation
    let result1 = MlKem::encapsulate(&pk);
    let result2 = MlKem::encapsulate(&pk_clone);

    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

/// Test ciphertext can be cloned
#[test]
fn test_ciphertext_clone_succeeds() {
    let (pk, _sk) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("key generation should succeed");
    let (_ss, ct) = MlKem::encapsulate(&pk).expect("encapsulation should succeed");

    let ct_clone = ct.clone();

    assert_eq!(ct.as_bytes(), ct_clone.as_bytes());
    assert_eq!(ct.security_level(), ct_clone.security_level());
}

/// Test secret key into_bytes consumes the key
#[test]
fn test_secret_key_into_bytes_succeeds() {
    let sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xABu8; 2400])
        .expect("construction should succeed");

    let original_bytes = sk.expose_secret().to_vec();
    let consumed_bytes = sk.into_bytes();

    // into_bytes() now returns Zeroizing<Vec<u8>> for automatic zeroization
    assert_eq!(&*consumed_bytes, &original_bytes);
    assert_eq!(consumed_bytes.len(), 2400);
}

/// Test MlKemDecapsulationKeyPair Debug impl
#[test]
fn test_decapsulation_keypair_debug_succeeds() {
    let keypair = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768)
        .expect("decapsulation keypair generation should succeed");

    let debug = format!("{:?}", keypair);
    assert!(debug.contains("MlKemDecapsulationKeyPair"), "Debug should contain struct name");
    assert!(debug.contains("[REDACTED]"), "Debug should redact the decaps key");
    assert!(debug.contains("MlKem768"), "Debug should show security level");
}

/// Test MlKemDecapsulationKeyPair getters
#[test]
fn test_decapsulation_keypair_getters_succeeds() {
    let keypair = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768)
        .expect("decapsulation keypair generation should succeed");

    assert_eq!(keypair.security_level(), MlKemSecurityLevel::MlKem768);
    assert_eq!(keypair.public_key().as_bytes().len(), 1184);
    assert_eq!(keypair.public_key_bytes().len(), 1184);
    assert_eq!(keypair.public_key().security_level(), MlKemSecurityLevel::MlKem768);
}

/// Test full encap/decap roundtrip with MlKemDecapsulationKeyPair
#[test]
fn test_decapsulation_keypair_roundtrip() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let keypair = MlKem::generate_decapsulation_keypair(level)
            .expect("decapsulation keypair generation should succeed");

        // Encapsulate using the public key
        let (ss_encap, ct) =
            MlKem::encapsulate(keypair.public_key()).expect("encapsulation should succeed");

        // Decapsulate using the decapsulation keypair
        let ss_decap = keypair.decapsulate(&ct).expect("decapsulation should succeed");

        // Shared secrets must match
        assert_eq!(
            ss_encap.expose_secret(),
            ss_decap.expose_secret(),
            "Encap and decap shared secrets should match for {}",
            level.name()
        );
    }
}

/// Test MlKemDecapsulationKeyPair rejects wrong security level ciphertext
#[test]
fn test_decapsulation_keypair_security_level_mismatch_fails() {
    let keypair_768 = MlKem::generate_decapsulation_keypair(MlKemSecurityLevel::MlKem768)
        .expect("generation should succeed");
    let (pk_512, _sk_512) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem512).expect("generation should succeed");

    let (_ss, ct_512) = MlKem::encapsulate(&pk_512).expect("encapsulation should succeed");

    // Try to decapsulate a 512 ciphertext with a 768 keypair
    let result = keypair_768.decapsulate(&ct_512);
    assert!(result.is_err(), "Mismatched security levels should fail");
}

/// Test shared_secret_size returns 32 for all levels
#[test]
fn test_shared_secret_size_all_levels_has_correct_size() {
    assert_eq!(MlKemSecurityLevel::MlKem512.shared_secret_size(), 32);
    assert_eq!(MlKemSecurityLevel::MlKem768.shared_secret_size(), 32);
    assert_eq!(MlKemSecurityLevel::MlKem1024.shared_secret_size(), 32);
}

/// Test error display implementations
#[test]
fn test_error_display_fails() {
    // Test InvalidKeyLength error
    let err = MlKemError::InvalidKeyLength {
        variant: "512".to_string(),
        size: 800,
        actual: 100,
        key_type: "public key".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("800"));
    assert!(msg.contains("100"));
    assert!(msg.contains("public key"));

    // Test InvalidCiphertextLength error
    let err = MlKemError::InvalidCiphertextLength {
        variant: "768".to_string(),
        expected: 1088,
        actual: 500,
    };
    let msg = err.to_string();
    assert!(msg.contains("1088"));
    assert!(msg.contains("500"));

    // Test generic errors
    let err = MlKemError::KeyGenerationError("test error".to_string());
    assert!(err.to_string().contains("test error"));

    let err = MlKemError::EncapsulationError("encaps failed".to_string());
    assert!(err.to_string().contains("encaps failed"));

    let err = MlKemError::DecapsulationError("decaps failed".to_string());
    assert!(err.to_string().contains("decaps failed"));
}
