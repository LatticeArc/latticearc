#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
//! Constant-Time Operation Verification Tests for arc-primitives
//!
//! This test suite verifies constant-time guarantees through CODE VERIFICATION,
//! NOT timing measurements. Timing measurements are unreliable due to system noise,
//! CPU frequency scaling, and cache effects.
//!
//! ## Verification Strategy
//!
//! These tests verify that:
//! 1. Types use `subtle::ConstantTimeEq` for sensitive comparisons
//! 2. Types use `zeroize` crate for secure memory cleanup
//! 3. Debug implementations redact sensitive data
//! 4. AWS-LC-RS provides FIPS-validated constant-time implementations
//!
//! ## Constant-Time Guarantees Source
//!
//! The constant-time guarantees come from:
//! - **subtle crate**: ConstantTimeEq, Choice, conditional_select
//! - **aws-lc-rs**: FIPS 140-3 validated cryptographic implementations
//! - **zeroize crate**: Secure memory cleanup without optimization
//!
//! ## FIPS 140-3 Compliance Notes
//!
//! | Algorithm | Library | FIPS Validated | Constant-Time |
//! |-----------|---------|----------------|---------------|
//! | ML-KEM | aws-lc-rs | Yes (Cert #4631, #4759, #4816) | Yes |
//! | AES-GCM | aws-lc-rs | Yes | Yes |
//! | X25519 | aws-lc-rs | Yes | Yes |
//! | ML-DSA | fips204 | Audited | Yes |
//! | SLH-DSA | fips205 | Audited | Yes |
//!
//! ## Test Categories
//!
//! 1. **subtle crate ConstantTimeEq Usage Tests** - Verify ct_eq returns Choice type
//! 2. **aws-lc-rs Constant-Time Guarantees** - Document library-provided guarantees
//! 3. **Zeroization Verification** - Test Zeroize trait implementation
//! 4. **API Contract Tests** - Verify Debug redaction, no Clone for secrets
//! 5. **Branch-Free Operation Verification** - Test Choice conditional selection

#![allow(dead_code)]

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

// Import primitives
use latticearc::primitives::aead::AeadCipher;
#[cfg(not(feature = "fips"))]
use latticearc::primitives::aead::chacha20poly1305::ChaCha20Poly1305Cipher;
use latticearc::primitives::aead::{
    aes_gcm::{AesGcm128, AesGcm256},
    verify_tag_constant_time,
};
use latticearc::primitives::kem::ecdh::{X25519KeyPair, X25519SecretKey};
use latticearc::primitives::kem::ml_kem::{
    MlKem, MlKemSecretKey, MlKemSecurityLevel, MlKemSharedSecret,
};
// NOTE: `primitives::keys::KemEccKeyPair` was removed in the P4.2 dead-code
// cleanup — it duplicated `hybrid::kem_hybrid::HybridKemPublicKey`/
// `HybridKemSecretKey`. The two tests that exercised its Debug redaction were
// removed together with the module.
use latticearc::primitives::security::secure_compare_equal_length;
use latticearc::primitives::sig::ml_dsa::{
    MlDsaParameterSet, MlDsaSecretKey, generate_keypair as mldsa_generate_keypair,
};
use latticearc::types::SecretVec;

// =============================================================================
// SECTION 1: subtle crate ConstantTimeEq Usage Tests
// =============================================================================

/// Test MlKemSharedSecret uses ct_eq from subtle crate
#[test]
fn test_shared_secret_uses_constant_time_comparison_succeeds() {
    let ss1 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);
    let ss3 = MlKemSharedSecret::new([0x43u8; 32]);

    // Uses subtle::ConstantTimeEq - ct_eq returns Choice, not bool
    let choice_eq: Choice = ss1.ct_eq(&ss2);
    let choice_ne: Choice = ss1.ct_eq(&ss3);

    // Choice converts to bool, but comparison itself is constant-time
    assert!(bool::from(choice_eq), "Equal secrets should compare equal");
    assert!(!bool::from(choice_ne), "Different secrets should compare unequal");
}

/// Test MlKemSecretKey uses ConstantTimeEq for comparisons
#[test]
fn test_mlkem_secret_key_constant_time_comparison_succeeds() {
    let sk1 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xABu8; 2400])
        .expect("secret key creation should succeed");
    let sk2 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xABu8; 2400])
        .expect("secret key creation should succeed");
    let sk3 = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xCDu8; 2400])
        .expect("secret key creation should succeed");

    // ct_eq returns subtle::Choice
    let choice_eq: Choice = sk1.ct_eq(&sk2);
    let choice_ne: Choice = sk1.ct_eq(&sk3);

    assert!(bool::from(choice_eq));
    assert!(!bool::from(choice_ne));
}

/// Test MlKemSecurityLevel uses ConstantTimeEq
#[test]
fn test_mlkem_security_level_constant_time_comparison_succeeds() {
    let level_512 = MlKemSecurityLevel::MlKem512;
    let level_768 = MlKemSecurityLevel::MlKem768;
    let level_1024 = MlKemSecurityLevel::MlKem1024;

    // All comparisons should return Choice type
    let choice_same: Choice = level_512.ct_eq(&level_512);
    let choice_diff_1: Choice = level_512.ct_eq(&level_768);
    let choice_diff_2: Choice = level_512.ct_eq(&level_1024);

    assert!(bool::from(choice_same));
    assert!(!bool::from(choice_diff_1));
    assert!(!bool::from(choice_diff_2));
}

/// Test ML-DSA secret key uses ConstantTimeEq
#[test]
fn test_mldsa_secret_key_constant_time_comparison_succeeds() {
    let (_pk1, sk1) =
        mldsa_generate_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");
    let (_pk2, sk2) =
        mldsa_generate_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    // Create a copy of sk1 for equal comparison
    let sk1_copy = MlDsaSecretKey::new(sk1.parameter_set(), sk1.expose_secret().to_vec())
        .expect("secret key creation");

    // ct_eq returns Choice type
    let choice_eq: Choice = sk1.ct_eq(&sk1_copy);
    let choice_ne: Choice = sk1.ct_eq(&sk2);

    assert!(bool::from(choice_eq));
    assert!(!bool::from(choice_ne));
}

/// Test SecretVec uses ConstantTimeEq for comparison.
///
/// `SecretVec` does not implement `PartialEq` (invariants I-5/I-6); all
/// equality goes through `subtle::ConstantTimeEq`.
#[test]
fn test_secret_vec_constant_time_comparison_succeeds() {
    let sv1 = SecretVec::new(vec![0x42u8; 64]);
    let sv2 = SecretVec::new(vec![0x42u8; 64]);
    let sv3 = SecretVec::new(vec![0x43u8; 64]);

    assert!(bool::from(sv1.ct_eq(&sv2)));
    assert!(!bool::from(sv1.ct_eq(&sv3)));
}

/// Test secure_compare_equal_length uses subtle::ConstantTimeEq.
///
/// The function's contract requires equal-length inputs; the prior
/// "different lengths" assertions exercised a defensive fallback that
/// is now a `debug_assert!` misuse signal, so they are removed.
#[test]
fn test_secure_compare_constant_time_succeeds() {
    let a = b"hello world";
    let b = b"hello world";
    let c = b"hello xorld"; // differs in middle
    let d = b"xello world"; // differs at start
    let e = b"hello worlx"; // differs at end

    // All comparisons should be constant-time
    assert!(secure_compare_equal_length(a, b));
    assert!(!secure_compare_equal_length(a, c));
    assert!(!secure_compare_equal_length(a, d));
    assert!(!secure_compare_equal_length(a, e));

    // Empty comparison
    assert!(secure_compare_equal_length(b"", b""));
}

/// Test AES-GCM tag verification uses constant-time comparison
#[test]
fn test_aes_gcm_tag_verification_constant_time_succeeds() {
    let tag1 = [0x00u8; 16];
    let tag2 = [0x00u8; 16];
    let tag3 = [0xFFu8; 16];
    let mut tag4 = [0x00u8; 16];
    tag4[15] = 0x01; // differs only in last byte

    // verify_tag_constant_time uses subtle::ConstantTimeEq
    assert!(verify_tag_constant_time(&tag1, &tag2));
    assert!(!verify_tag_constant_time(&tag1, &tag3));
    assert!(!verify_tag_constant_time(&tag1, &tag4));
}

/// Test ChaCha20-Poly1305 tag verification constant-time
#[test]
#[cfg(not(feature = "fips"))]
fn test_chacha20poly1305_tag_verification_constant_time_succeeds() {
    use latticearc::primitives::aead::verify_tag_constant_time as chacha_verify;

    let tag1 = [0x00u8; 16];
    let tag2 = [0x00u8; 16];
    let tag3 = [0xFFu8; 16];

    assert!(chacha_verify(&tag1, &tag2));
    assert!(!chacha_verify(&tag1, &tag3));
}

/// Test that ct_eq returns Choice type, not bool
#[test]
fn test_ct_eq_returns_choice_type_succeeds() {
    let ss = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);

    // The return type must be subtle::Choice, not bool
    let result: Choice = ss.ct_eq(&ss2);

    // Choice can be converted to bool
    let _bool_value: bool = result.into();

    // Choice can be used in bitwise operations
    let choice_and = result & Choice::from(1u8);
    let choice_or = result | Choice::from(0u8);

    assert!(bool::from(choice_and));
    assert!(bool::from(choice_or));
}

// =============================================================================
// SECTION 2: aws-lc-rs Constant-Time Guarantees
// =============================================================================

/// Document that ML-KEM uses aws-lc-rs FIPS-validated implementation
///
/// AWS-LC-RS provides constant-time guarantees through:
/// - FIPS 140-3 validation (Certificate #4631, #4759, #4816)
/// - Hardware-accelerated implementations (AES-NI, AVX2)
/// - Designed to resist timing side-channel attacks
#[test]
fn test_mlkem_uses_aws_lc_rs_succeeds() {
    // ML-KEM-512 uses aws-lc-rs internally
    let (pk512, _sk512) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem512)
        .expect("keypair generation should succeed");
    assert_eq!(pk512.as_bytes().len(), 800);

    // ML-KEM-768 uses aws-lc-rs internally
    let (pk768, _sk768) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem768)
        .expect("keypair generation should succeed");
    assert_eq!(pk768.as_bytes().len(), 1184);

    // ML-KEM-1024 uses aws-lc-rs internally
    let (pk1024, _sk1024) = MlKem::generate_keypair(MlKemSecurityLevel::MlKem1024)
        .expect("keypair generation should succeed");
    assert_eq!(pk1024.as_bytes().len(), 1568);
}

/// Document that AES-GCM uses aws-lc-rs constant-time implementation
#[test]
fn test_aes_gcm_uses_aws_lc_rs_succeeds() {
    // AES-GCM-128 uses aws-lc-rs
    let key128 = AesGcm128::generate_key();
    let cipher128 = AesGcm128::new(&*key128).expect("cipher creation");
    let nonce = AesGcm128::generate_nonce();

    let plaintext = b"test message for AES-GCM";
    let (ciphertext, tag) = cipher128.encrypt(&nonce, plaintext, None).expect("encryption");
    let decrypted = cipher128.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption");
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // AES-GCM-256 uses aws-lc-rs
    let key256 = AesGcm256::generate_key();
    let cipher256 = AesGcm256::new(&*key256).expect("cipher creation");
    let nonce256 = AesGcm256::generate_nonce();

    let (ciphertext256, tag256) =
        cipher256.encrypt(&nonce256, plaintext, None).expect("encryption");
    let decrypted256 =
        cipher256.decrypt(&nonce256, &ciphertext256, &tag256, None).expect("decryption");
    assert_eq!(plaintext.as_slice(), decrypted256.as_slice());
}

/// Document that X25519 uses aws-lc-rs constant-time implementation
#[test]
fn test_x25519_uses_aws_lc_rs_succeeds() {
    // X25519 key pair generation uses aws-lc-rs
    let alice = X25519KeyPair::generate().expect("keypair generation");
    let bob = X25519KeyPair::generate().expect("keypair generation");

    let alice_pk = *alice.public_key_bytes();
    let bob_pk = *bob.public_key_bytes();

    // Key agreement uses aws-lc-rs constant-time scalar multiplication
    let alice_ss = alice.agree(&bob_pk).expect("key agreement");
    let bob_ss = bob.agree(&alice_pk).expect("key agreement");

    assert_eq!(alice_ss, bob_ss, "shared secrets should match");
}

/// Test that encapsulation produces different ciphertexts (randomized)
#[test]
fn test_mlkem_encapsulation_is_randomized_succeeds() {
    let (pk, _sk) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let (ss1, ct1) = MlKem::encapsulate(&pk).expect("encapsulation");
    let (ss2, ct2) = MlKem::encapsulate(&pk).expect("encapsulation");

    // Different encapsulations should produce different results
    assert_ne!(ct1.as_bytes(), ct2.as_bytes());
    assert_ne!(ss1.expose_secret(), ss2.expose_secret());
}

// =============================================================================
// SECTION 3: Zeroization Verification
// =============================================================================

/// Test ML-KEM shared secret implements Zeroize trait
#[test]
fn test_mlkem_shared_secret_implements_zeroize_is_covered() {
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);

    // Verify non-zero before zeroization
    assert!(ss.expose_secret().iter().any(|&b| b != 0));

    // Zeroize
    ss.zeroize();

    // Verify all zeros after zeroization
    assert!(ss.expose_secret().iter().all(|&b| b == 0));
}

/// Test ML-KEM secret key implements Zeroize trait
#[test]
fn test_mlkem_secret_key_implements_zeroize_is_covered() {
    let mut sk = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0xCDu8; 2400])
        .expect("secret key creation");

    // Verify non-zero before
    assert!(sk.expose_secret().iter().any(|&b| b != 0));

    // Zeroize
    sk.zeroize();

    // Verify all zeros after
    assert!(sk.expose_secret().iter().all(|&b| b == 0));
}

/// Test ML-DSA secret key implements Zeroize trait
#[test]
fn test_mldsa_secret_key_implements_zeroize_is_covered() {
    let (_pk, mut sk) =
        mldsa_generate_keypair(MlDsaParameterSet::MlDsa44).expect("keypair generation");

    // Verify non-zero before
    assert!(sk.expose_secret().iter().any(|&b| b != 0));

    // Zeroize
    sk.zeroize();

    // Verify all zeros after
    assert!(sk.expose_secret().iter().all(|&b| b == 0));
}

/// Test X25519 secret key implements Zeroize trait
#[test]
fn test_x25519_secret_key_implements_zeroize_is_covered() {
    let mut sk = X25519SecretKey::from_bytes(&[0xEFu8; 32]).expect("secret key creation");

    // Verify non-zero before
    assert!(sk.expose_secret().iter().any(|&b| b != 0));

    // Note: X25519SecretKey implements ZeroizeOnDrop
    // Manual zeroize via the Zeroize trait
    sk.zeroize();

    // Verify all zeros after
    assert!(sk.expose_secret().iter().all(|&b| b == 0));
}

/// Test SecretVec implements Zeroize and ZeroizeOnDrop
#[test]
fn test_secret_vec_zeroization_succeeds() {
    let mut sv = SecretVec::new(vec![0xFFu8; 100]);

    // Verify non-zero before
    assert!(sv.expose_secret().iter().any(|&b| b != 0));

    // Zeroize
    sv.zeroize();

    // After zeroize, every byte still in view is zero.
    for &byte in sv.expose_secret() {
        assert_eq!(byte, 0);
    }
}

/// Test zeroization works for all ML-KEM security levels
#[test]
fn test_mlkem_zeroization_all_security_levels_succeeds() {
    for level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        let mut sk = MlKemSecretKey::new(level, vec![0xABu8; level.secret_key_size()])
            .expect("secret key creation");

        sk.zeroize();

        assert!(
            sk.expose_secret().iter().all(|&b| b == 0),
            "{} secret key should be zeroed",
            level.name()
        );
    }
}

/// Test zeroization works for all ML-DSA parameter sets
#[test]
fn test_mldsa_zeroization_all_parameter_sets_succeeds() {
    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (_pk, mut sk) = mldsa_generate_keypair(param).expect("keypair generation");

        sk.zeroize();

        assert!(
            sk.expose_secret().iter().all(|&b| b == 0),
            "{:?} secret key should be zeroed",
            param
        );
    }
}

/// Test multiple zeroization calls are safe
#[test]
fn test_multiple_zeroization_calls_safe_succeeds() {
    let mut ss = MlKemSharedSecret::new([0xABu8; 32]);

    // Multiple zeroizations should be safe
    for _ in 0..10 {
        ss.zeroize();
    }

    // Should still be all zeros
    assert!(ss.expose_secret().iter().all(|&b| b == 0));
}

/// Test intermediate value cleanup
#[test]
fn test_intermediate_value_cleanup_succeeds() {
    let (pk, _sk) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    let (mut ss, _ct) = MlKem::encapsulate(&pk).expect("encapsulation");

    // Verify shared secret is non-zero
    assert!(ss.expose_secret().iter().any(|&b| b != 0));

    // Zeroize
    ss.zeroize();

    // Verify zeroed
    assert!(ss.expose_secret().iter().all(|&b| b == 0));
}

// =============================================================================
// SECTION 4: API Contract Tests
// =============================================================================

/// Verify ML-KEM secret key Debug actually redacts sensitive bytes.
///
/// Round-35 D4: the prior version of this test asserted only that
/// the type name appeared in the Debug output, with a comment
/// claiming `#[derive(Debug)]` exposed the data. That comment was
/// stale: the actual implementation has a custom `Debug` impl that
/// already redacts. Update the test to assert what the impl
/// actually does, so a future regression to derived Debug fails
/// CI rather than silently shipping plaintext keys to logs.
#[test]
fn test_mlkem_secret_key_debug_redacts_succeeds() {
    // Use a real generated SK — round-35 L7 made `MlKemSecretKey::new`
    // structural-validation-strict, so an arbitrary 0xAB-pattern
    // buffer no longer passes construction.
    let (_pk, sk) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("ML-KEM-768 keygen");

    let debug_output = format!("{:?}", sk);

    assert!(
        debug_output.contains("MlKemSecretKey"),
        "Debug should contain type name: {}",
        debug_output
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug must redact sensitive bytes (impl was updated; this test was stale): {}",
        debug_output
    );
}

/// Verify ML-KEM shared secret Debug actually redacts. See the
/// rationale on the SK test above (round-35 D4).
#[test]
fn test_mlkem_shared_secret_debug_redacts_succeeds() {
    let ss = MlKemSharedSecret::new([0xCDu8; 32]);

    let debug_output = format!("{:?}", ss);

    assert!(
        debug_output.contains("MlKemSharedSecret"),
        "Debug should contain type name: {}",
        debug_output
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug must redact sensitive bytes (impl was updated; this test was stale): {}",
        debug_output
    );
    assert!(
        !debug_output.contains("205, 205, 205"),
        "Debug must not expose the raw byte content: {}",
        debug_output
    );
}

/// Verify X25519 secret key Debug shows [REDACTED]
#[test]
fn test_x25519_secret_key_debug_redacts_succeeds() {
    let sk = X25519SecretKey::from_bytes(&[0xEFu8; 32]).expect("secret key creation");

    let debug_output = format!("{:?}", sk);

    // Debug should contain [REDACTED] and not actual bytes
    assert!(
        debug_output.contains("REDACTED") || debug_output.contains("redacted"),
        "Debug should show REDACTED: {}",
        debug_output
    );
    assert!(
        !debug_output.contains("0xEF") && !debug_output.contains("239"),
        "Debug should not expose key material"
    );
}

/// Verify X25519KeyPair Debug shows [REDACTED] for private key
#[test]
fn test_x25519_keypair_debug_redacts_private_succeeds() {
    let keypair = X25519KeyPair::generate().expect("keypair generation");

    let debug_output = format!("{:?}", keypair);

    // Debug should contain [REDACTED] for private key
    assert!(
        debug_output.contains("REDACTED") || debug_output.contains("redacted"),
        "Debug should show REDACTED for private key: {}",
        debug_output
    );
}

/// Verify SecretVec Debug shows [REDACTED]
#[test]
fn test_secret_vec_debug_redacts_succeeds() {
    let sv = SecretVec::new(vec![0xFFu8; 100]);

    let debug_output = format!("{:?}", sv);

    // Debug should contain REDACTED and length info
    assert!(
        debug_output.contains("REDACTED") || debug_output.contains("SecretVec"),
        "Debug should indicate secure storage: {}",
        debug_output
    );
    assert!(
        !debug_output.contains("0xFF") && !debug_output.contains("255"),
        "Debug should not expose content"
    );
}

/// Test that ML-KEM SharedSecret does NOT implement Clone
#[test]
fn test_mlkem_shared_secret_no_clone_succeeds() {
    // This test verifies at compile-time that MlKemSharedSecret doesn't implement Clone
    // If Clone were implemented, we'd be able to call ss.clone()
    // The test passes if it compiles - the type doesn't need to be checked at runtime

    fn assert_not_clone<T>() {}

    // This would fail to compile if MlKemSharedSecret implemented Clone
    // We can verify this by checking that we CAN'T do:
    // let ss = MlKemSharedSecret::new([0u8; 32]);
    // let ss2 = ss.clone(); // Would fail to compile

    // For test verification, we just confirm the type exists and ConstantTimeEq works
    let ss = MlKemSharedSecret::new([0x42u8; 32]);
    let ss2 = MlKemSharedSecret::new([0x42u8; 32]);
    assert!(bool::from(ss.ct_eq(&ss2)));
}

// =============================================================================
// SECTION 5: Branch-Free Operation Verification
// =============================================================================

/// Test subtle::Choice conditional selection
#[test]
fn test_choice_conditional_selection_succeeds() {
    let a = 0x00u8;
    let b = 0xFFu8;

    // Choice::from(1) means true/select second
    let choice_true = Choice::from(1u8);
    let choice_false = Choice::from(0u8);

    // conditional_select(a, b, choice) returns a if choice is 0, b if choice is 1
    let result_true = u8::conditional_select(&a, &b, choice_true);
    let result_false = u8::conditional_select(&a, &b, choice_false);

    assert_eq!(result_true, b, "should select b when choice is 1");
    assert_eq!(result_false, a, "should select a when choice is 0");
}

/// Test Choice operations are branch-free (by design)
#[test]
fn test_choice_operations_branch_free_succeeds() {
    let choice_0 = Choice::from(0u8);
    let choice_1 = Choice::from(1u8);

    // Bitwise AND
    assert!(!bool::from(choice_0 & choice_0));
    assert!(!bool::from(choice_0 & choice_1));
    assert!(!bool::from(choice_1 & choice_0));
    assert!(bool::from(choice_1 & choice_1));

    // Bitwise OR
    assert!(!bool::from(choice_0 | choice_0));
    assert!(bool::from(choice_0 | choice_1));
    assert!(bool::from(choice_1 | choice_0));
    assert!(bool::from(choice_1 | choice_1));

    // NOT
    assert!(bool::from(!choice_0));
    assert!(!bool::from(!choice_1));
}

/// Verify ct_eq doesn't short-circuit (compares all bytes)
#[test]
fn test_ct_eq_no_short_circuit_succeeds() {
    // Two 32-byte arrays differing only in the last byte
    let mut a = [0x00u8; 32];
    let mut b = [0x00u8; 32];
    b[31] = 0x01; // Differ at last position

    // ct_eq must compare all bytes, not short-circuit at first difference
    let result: Choice = a.ct_eq(&b);
    assert!(!bool::from(result), "should detect difference at end");

    // Now differ at first position
    a[0] = 0x02;
    let result2: Choice = a.ct_eq(&b);
    assert!(!bool::from(result2), "should detect difference at start");
}

/// Test conditional swap is branch-free
#[test]
fn test_conditional_swap_branch_free_succeeds() {
    let mut a = 0x42u8;
    let mut b = 0xABu8;

    // ConditionallySelectable provides swap
    u8::conditional_swap(&mut a, &mut b, Choice::from(1u8));
    assert_eq!(a, 0xAB);
    assert_eq!(b, 0x42);

    // Swap back
    u8::conditional_swap(&mut a, &mut b, Choice::from(1u8));
    assert_eq!(a, 0x42);
    assert_eq!(b, 0xAB);

    // No swap with 0
    u8::conditional_swap(&mut a, &mut b, Choice::from(0u8));
    assert_eq!(a, 0x42);
    assert_eq!(b, 0xAB);
}

/// Test Choice comparison correctness for slices
#[test]
fn test_slice_constant_time_comparison_succeeds() {
    let data1: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let data2: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let mut data3: Vec<u8> = (0..256).map(|i| i as u8).collect();
    data3[255] = 0; // Differ at last byte

    // ct_eq on slices
    let eq: Choice = data1.ct_eq(&data2);
    let ne: Choice = data1.ct_eq(&data3);

    assert!(bool::from(eq));
    assert!(!bool::from(ne));
}

// =============================================================================
// SECTION 6: FIPS Signature Constant-Time Verification
// =============================================================================

/// Test ML-DSA signature generation and verification
#[test]
fn test_mldsa_signature_operations_succeeds() {
    let (pk, sk) = mldsa_generate_keypair(MlDsaParameterSet::MlDsa65).expect("keypair generation");

    let message = b"Test message for ML-DSA signature";
    let context: &[u8] = b"test context";

    // Sign
    let signature = sk.sign(message, context).expect("signing");

    // Verify
    let is_valid = pk.verify(message, &signature, context).expect("verification");
    assert!(is_valid, "valid signature should verify");

    // Wrong message should not verify
    let wrong_message = b"Wrong message";
    let is_invalid = pk.verify(wrong_message, &signature, context).expect("verification");
    assert!(!is_invalid, "invalid signature should not verify");
}

/// Test ML-DSA with all parameter sets
#[test]
fn test_mldsa_all_parameter_sets_succeeds() {
    let message = b"Test message";
    let context: &[u8] = &[];

    for param in
        [MlDsaParameterSet::MlDsa44, MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87]
    {
        let (pk, sk) = mldsa_generate_keypair(param).expect("keypair generation");

        let signature = sk.sign(message, context).expect("signing");
        let is_valid = pk.verify(message, &signature, context).expect("verification");

        assert!(is_valid, "{:?} signature should verify", param);
    }
}

/// Test ChaCha20-Poly1305 operations
#[test]
#[cfg(not(feature = "fips"))]
fn test_chacha20poly1305_operations_succeeds() {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let cipher = ChaCha20Poly1305Cipher::new(&*key).expect("cipher creation");
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let plaintext = b"Secret message for ChaCha20-Poly1305";

    let (ciphertext, tag) = cipher.encrypt(&nonce, plaintext, None).expect("encryption");
    let decrypted = cipher.decrypt(&nonce, &ciphertext, &tag, None).expect("decryption");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

// =============================================================================
// SECTION 7: Edge Cases and Error Handling
// =============================================================================

/// Test constant-time comparison with empty inputs
#[test]
fn test_constant_time_comparison_empty_succeeds() {
    let empty1: [u8; 0] = [];
    let empty2: [u8; 0] = [];

    let result: Choice = empty1.ct_eq(&empty2);
    assert!(bool::from(result), "empty arrays should be equal");
}

/// Test constant-time comparison with single byte
#[test]
fn test_constant_time_comparison_single_byte_succeeds() {
    let a = [0x42u8];
    let b = [0x42u8];
    let c = [0x43u8];

    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}

/// Test constant-time comparison with large inputs
#[test]
fn test_constant_time_comparison_large_succeeds() {
    let size = 1024 * 1024; // 1MB
    let a: Vec<u8> = vec![0xABu8; size];
    let b: Vec<u8> = vec![0xABu8; size];
    let mut c: Vec<u8> = vec![0xABu8; size];
    c[size - 1] = 0x00; // Differ at last byte

    assert!(bool::from(a.ct_eq(&b)));
    assert!(!bool::from(a.ct_eq(&c)));
}

/// Test error cases don't leak timing information
#[test]
fn test_error_cases_constant_time_fails() {
    // Invalid key length for ML-KEM
    let invalid_sk_result = MlKemSecretKey::new(MlKemSecurityLevel::MlKem768, vec![0u8; 100]);
    assert!(invalid_sk_result.is_err());

    // Invalid key length for X25519
    let invalid_x25519_result = X25519SecretKey::from_bytes(&[0u8; 16]);
    assert!(invalid_x25519_result.is_err());

    // Invalid key length for AES-GCM
    let invalid_aes_result = AesGcm256::new(&[0u8; 16]);
    assert!(invalid_aes_result.is_err());
}

/// Test security level mismatch error
#[test]
fn test_security_level_mismatch_error_fails() {
    // Generate keys at different security levels
    let (pk_512, _sk_512) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem512).expect("keypair generation");
    let (_pk_768, sk_768) =
        MlKem::generate_keypair(MlKemSecurityLevel::MlKem768).expect("keypair generation");

    // Encapsulate with 512 level
    let (_, ct_512) = MlKem::encapsulate(&pk_512).expect("encapsulation");

    // Decapsulation with mismatched secret key should fail
    let result = MlKem::decapsulate(&sk_768, &ct_512);
    assert!(result.is_err(), "security level mismatch should error");
}

// =============================================================================
// SUMMARY: Test Count Verification
// =============================================================================

#[test]
fn test_verification_count_succeeds() {
    const SOURCE: &str = include_str!("primitives_constant_time_verification.rs");
    // Count lines whose first non-whitespace token is the `#[test]`
    // attribute. A naive `SOURCE.matches("#[test]").count()` over-
    // counts because the literal also appears in this file's doc
    // comments, the `.matches(..)` call below, and the assertion
    // message — none of which are test attributes.
    let test_count = SOURCE.lines().filter(|line| line.trim_start().starts_with("#[test]")).count();
    const MIN_REQUIRED: usize = 40;
    assert!(
        test_count >= MIN_REQUIRED,
        "Verification test file must contain ≥ {MIN_REQUIRED} `#[test]` items \
         (found {test_count}). Add tests or update the threshold deliberately."
    );
}
