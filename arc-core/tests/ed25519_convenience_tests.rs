//! Comprehensive Ed25519 convenience API tests
//!
//! This test suite validates the Ed25519 signature convenience APIs in arc-core,
//! covering all API variants and edge cases per FIPS 186-5 and RFC 8032.
//!
//! Test coverage includes:
//! - RFC 8032 test vectors (well-known cryptographic test cases)
//! - SecurityMode::Verified with valid session scenarios
//! - SecurityMode::Verified validation edge cases
//! - Stress tests with large messages (1MB+)
//! - Unicode and international character handling
//! - Binary data edge cases (0x00, 0xFF, 0x7F, 0x80 boundaries)
//! - Cross-keypair verification failures
//! - Signature tampering detection
//! - Deterministic signature property verification
//! - Invalid input handling

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]

use arc_core::{
    SecurityMode, VerifiedSession, config::CoreConfig, error::Result, generate_keypair,
    sign_ed25519, sign_ed25519_unverified, sign_ed25519_with_config,
    sign_ed25519_with_config_unverified, verify_ed25519, verify_ed25519_unverified,
    verify_ed25519_with_config, verify_ed25519_with_config_unverified,
};

// ============================================================================
// RFC 8032 Test Vectors
// ============================================================================
// These test vectors are from RFC 8032 Section 7.1 (Ed25519)
// https://www.rfc-editor.org/rfc/rfc8032#section-7.1

/// RFC 8032 Test Vector 1: Empty message
/// Secret Key: 9d61b19deffd5a60ba844af492ec2cc4...
/// Public Key: d75a980182b10ab7d54bfed3c964073a...
/// Message: (empty)
/// Signature: e5564300c360ac729086e2cc806e828a...
#[test]
fn test_rfc8032_vector_1_empty_message() {
    // RFC 8032 test vector 1
    let secret_key: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let expected_public_key: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    let expected_signature: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    let message = b"";

    // Sign with the secret key
    let signature = sign_ed25519_unverified(message, &secret_key).expect("signing should succeed");

    // Verify signature matches expected
    assert_eq!(
        signature.as_slice(),
        expected_signature.as_slice(),
        "RFC 8032 Vector 1: Signature should match expected"
    );

    // Verify the signature
    let is_valid = verify_ed25519_unverified(message, &signature, &expected_public_key)
        .expect("verification should succeed");
    assert!(is_valid, "RFC 8032 Vector 1: Signature should verify");
}

/// RFC 8032 Test Vector 2: Single byte message (0x72)
#[test]
fn test_rfc8032_vector_2_single_byte() {
    let secret_key: [u8; 32] = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];

    let expected_public_key: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];

    let expected_signature: [u8; 64] = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];

    let message = [0x72u8]; // Single byte 'r'

    // Sign with the secret key
    let signature = sign_ed25519_unverified(&message, &secret_key).expect("signing should succeed");

    // Verify signature matches expected
    assert_eq!(
        signature.as_slice(),
        expected_signature.as_slice(),
        "RFC 8032 Vector 2: Signature should match expected"
    );

    // Verify the signature
    let is_valid = verify_ed25519_unverified(&message, &signature, &expected_public_key)
        .expect("verification should succeed");
    assert!(is_valid, "RFC 8032 Vector 2: Signature should verify");
}

/// RFC 8032 Test Vector 3: Two byte message
#[test]
fn test_rfc8032_vector_3_two_bytes() {
    let secret_key: [u8; 32] = [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ];

    let expected_public_key: [u8; 32] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ];

    let expected_signature: [u8; 64] = [
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01,
        0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a,
        0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98,
        0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce,
        0xea, 0x1e, 0xc4, 0x0a,
    ];

    let message = [0xafu8, 0x82u8]; // Two bytes

    // Sign with the secret key
    let signature = sign_ed25519_unverified(&message, &secret_key).expect("signing should succeed");

    // Verify signature matches expected
    assert_eq!(
        signature.as_slice(),
        expected_signature.as_slice(),
        "RFC 8032 Vector 3: Signature should match expected"
    );

    // Verify the signature
    let is_valid = verify_ed25519_unverified(&message, &signature, &expected_public_key)
        .expect("verification should succeed");
    assert!(is_valid, "RFC 8032 Vector 3: Signature should verify");
}

// ============================================================================
// SecurityMode::Verified Tests with Valid Session
// ============================================================================

#[test]
fn test_ed25519_sign_verify_with_verified_session() -> Result<()> {
    let message = b"Test message with verified session";
    let (pk, sk) = generate_keypair()?;

    // Create a verified session
    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    // Sign with verified mode
    let signature = sign_ed25519(message, sk.as_ref(), SecurityMode::Verified(&session))?;
    assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");

    // Verify with verified mode
    let is_valid = verify_ed25519(message, &signature, &pk, SecurityMode::Verified(&session))?;
    assert!(is_valid, "Signature should verify with verified session");

    Ok(())
}

#[test]
fn test_ed25519_with_config_and_verified_session() -> Result<()> {
    let message = b"Test with config and session";
    let config = CoreConfig::default();
    let (pk, sk) = generate_keypair()?;

    // Create a verified session
    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    // Sign with config and verified mode
    let signature =
        sign_ed25519_with_config(message, sk.as_ref(), &config, SecurityMode::Verified(&session))?;

    // Verify with config and verified mode
    let is_valid = verify_ed25519_with_config(
        message,
        &signature,
        &pk,
        &config,
        SecurityMode::Verified(&session),
    )?;
    assert!(is_valid, "Signature should verify with config and session");

    Ok(())
}

#[test]
fn test_ed25519_session_reuse_multiple_operations() -> Result<()> {
    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    // Perform multiple operations with the same session
    for i in 0..5 {
        let message = format!("Message number {}", i);
        let (pk, sk) = generate_keypair()?;

        let signature =
            sign_ed25519(message.as_bytes(), sk.as_ref(), SecurityMode::Verified(&session))?;

        let is_valid =
            verify_ed25519(message.as_bytes(), &signature, &pk, SecurityMode::Verified(&session))?;
        assert!(is_valid, "Signature {} should verify", i);
    }

    Ok(())
}

#[test]
fn test_ed25519_verified_session_is_valid() -> Result<()> {
    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    // Session should be valid immediately after creation
    assert!(session.is_valid(), "Freshly created session should be valid");

    // Use the session for crypto operations
    let message = b"Test validity";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519(message, sk.as_ref(), SecurityMode::Verified(&session))?;
    let is_valid = verify_ed25519(message, &signature, &pk, SecurityMode::Verified(&session))?;
    assert!(is_valid);

    Ok(())
}

// ============================================================================
// SecurityMode::Unverified Tests
// ============================================================================

#[test]
fn test_ed25519_sign_verify_unverified_mode() -> Result<()> {
    let message = b"Test with unverified mode";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519(message, sk.as_ref(), SecurityMode::Unverified)?;
    let is_valid = verify_ed25519(message, &signature, &pk, SecurityMode::Unverified)?;
    assert!(is_valid);

    Ok(())
}

#[test]
fn test_ed25519_unverified_convenience_functions() -> Result<()> {
    let message = b"Test unverified convenience";
    let (pk, sk) = generate_keypair()?;

    // Use the _unverified variants directly
    let signature = sign_ed25519_unverified(message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
    assert!(is_valid);

    Ok(())
}

#[test]
fn test_ed25519_with_config_unverified() -> Result<()> {
    let message = b"Test with config unverified";
    let config = CoreConfig::default();
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_with_config_unverified(message, sk.as_ref(), &config)?;
    let is_valid = verify_ed25519_with_config_unverified(message, &signature, &pk, &config)?;
    assert!(is_valid);

    Ok(())
}

// ============================================================================
// Stress Tests with Large Messages (1MB+)
// ============================================================================

#[test]
fn test_ed25519_1mb_message() -> Result<()> {
    let message = vec![0xABu8; 1_048_576]; // 1 MB
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    assert_eq!(signature.len(), 64, "Signature should be 64 bytes regardless of message size");

    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "1MB message signature should verify");

    Ok(())
}

#[test]
fn test_ed25519_2mb_message() -> Result<()> {
    let message = vec![0xCDu8; 2_097_152]; // 2 MB
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "2MB message signature should verify");

    Ok(())
}

#[test]
fn test_ed25519_5mb_message() -> Result<()> {
    let message = vec![0xEFu8; 5_242_880]; // 5 MB
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "5MB message signature should verify");

    Ok(())
}

#[test]
fn test_ed25519_large_message_with_verified_session() -> Result<()> {
    let message = vec![0x42u8; 1_048_576]; // 1 MB
    let (pk, sk) = generate_keypair()?;

    let (auth_pk, auth_sk) = generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let signature = sign_ed25519(&message, sk.as_ref(), SecurityMode::Verified(&session))?;
    let is_valid = verify_ed25519(&message, &signature, &pk, SecurityMode::Verified(&session))?;
    assert!(is_valid, "Large message with verified session should verify");

    Ok(())
}

// ============================================================================
// Unicode and International Character Tests
// ============================================================================

#[test]
fn test_ed25519_unicode_japanese() -> Result<()> {
    let message = "こんにちは世界"; // "Hello World" in Japanese
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Japanese Unicode message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_arabic() -> Result<()> {
    let message = "مرحبا بالعالم"; // "Hello World" in Arabic
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Arabic Unicode message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_chinese() -> Result<()> {
    let message = "你好世界"; // "Hello World" in Chinese
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Chinese Unicode message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_emoji() -> Result<()> {
    let message = "Hello 🌍🚀💻🔐 World!";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Emoji message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_mixed_scripts() -> Result<()> {
    let message = "Hello こんにちは مرحبا 你好 🌍";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Mixed script Unicode message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_cyrillic() -> Result<()> {
    let message = "Привет мир"; // "Hello World" in Russian
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Cyrillic Unicode message should verify");

    Ok(())
}

#[test]
fn test_ed25519_unicode_hebrew() -> Result<()> {
    let message = "שלום עולם"; // "Hello World" in Hebrew
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message.as_bytes(), sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message.as_bytes(), &signature, &pk)?;
    assert!(is_valid, "Hebrew Unicode message should verify");

    Ok(())
}

// ============================================================================
// Binary Data Edge Cases
// ============================================================================

#[test]
fn test_ed25519_binary_all_zeros() -> Result<()> {
    let message = vec![0x00u8; 256];
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "All zeros message should verify");

    Ok(())
}

#[test]
fn test_ed25519_binary_all_ones() -> Result<()> {
    let message = vec![0xFFu8; 256];
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "All 0xFF message should verify");

    Ok(())
}

#[test]
fn test_ed25519_binary_boundary_0x7f() -> Result<()> {
    // 0x7F is the boundary between ASCII printable and extended
    let message = vec![0x7Fu8; 256];
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "0x7F boundary message should verify");

    Ok(())
}

#[test]
fn test_ed25519_binary_boundary_0x80() -> Result<()> {
    // 0x80 is the start of extended ASCII / high bit set
    let message = vec![0x80u8; 256];
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "0x80 boundary message should verify");

    Ok(())
}

#[test]
fn test_ed25519_binary_full_byte_range() -> Result<()> {
    // Message containing all possible byte values
    let message: Vec<u8> = (0..=255).collect();
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "Full byte range message should verify");

    Ok(())
}

#[test]
fn test_ed25519_binary_alternating_pattern() -> Result<()> {
    // Alternating 0x00 and 0xFF
    let message: Vec<u8> = (0..256).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "Alternating pattern message should verify");

    Ok(())
}

#[test]
fn test_ed25519_single_null_byte() -> Result<()> {
    let message = [0x00u8];
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
    assert!(is_valid, "Single null byte should verify");

    Ok(())
}

// ============================================================================
// Cross-Keypair Verification Failures
// ============================================================================

#[test]
fn test_ed25519_cross_keypair_verification_fails() {
    let message = b"Test cross keypair";
    let (_pk1, sk1) = generate_keypair().expect("keypair 1");
    let (pk2, _sk2) = generate_keypair().expect("keypair 2");

    let signature = sign_ed25519_unverified(message, sk1.as_ref()).expect("signing should succeed");

    let result = verify_ed25519_unverified(message, &signature, &pk2);
    assert!(result.is_err(), "Signature from one key should not verify with different public key");
}

#[test]
fn test_ed25519_swapped_keys_fail() {
    let message = b"Test swapped keys";
    let (pk1, sk1) = generate_keypair().expect("keypair 1");
    let (pk2, sk2) = generate_keypair().expect("keypair 2");

    // Sign with sk1, try to verify with pk2
    let sig1 = sign_ed25519_unverified(message, sk1.as_ref()).expect("signing should succeed");
    let result1 = verify_ed25519_unverified(message, &sig1, &pk2);
    assert!(result1.is_err(), "sk1 signature should not verify with pk2");

    // Sign with sk2, try to verify with pk1
    let sig2 = sign_ed25519_unverified(message, sk2.as_ref()).expect("signing should succeed");
    let result2 = verify_ed25519_unverified(message, &sig2, &pk1);
    assert!(result2.is_err(), "sk2 signature should not verify with pk1");
}

#[test]
fn test_ed25519_many_cross_keypair_failures() {
    let message = b"Many cross keypairs";

    // Generate 5 keypairs
    let keypairs: Vec<_> = (0..5).map(|_| generate_keypair().expect("keypair")).collect();

    // For each keypair, sign and verify against all others
    for (i, (pk_i, sk_i)) in keypairs.iter().enumerate() {
        let signature =
            sign_ed25519_unverified(message, sk_i.as_ref()).expect("signing should succeed");

        // Should verify with matching public key
        let valid = verify_ed25519_unverified(message, &signature, pk_i)
            .expect("verification should succeed");
        assert!(valid, "Keypair {} should verify its own signature", i);

        // Should fail with all other public keys
        for (j, (pk_j, _)) in keypairs.iter().enumerate() {
            if i != j {
                let result = verify_ed25519_unverified(message, &signature, pk_j);
                assert!(
                    result.is_err(),
                    "Keypair {} signature should not verify with keypair {} public key",
                    i,
                    j
                );
            }
        }
    }
}

// ============================================================================
// Signature Tampering Detection
// ============================================================================

#[test]
fn test_ed25519_signature_first_byte_tampered() {
    let message = b"Test tampering first byte";
    let (pk, sk) = generate_keypair().expect("keypair");

    let mut signature =
        sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    // Tamper with first byte
    signature[0] ^= 0xFF;

    let result = verify_ed25519_unverified(message, &signature, &pk);
    assert!(result.is_err(), "Tampered first byte should fail verification");
}

#[test]
fn test_ed25519_signature_last_byte_tampered() {
    let message = b"Test tampering last byte";
    let (pk, sk) = generate_keypair().expect("keypair");

    let mut signature =
        sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    // Tamper with last byte
    let last_idx = signature.len() - 1;
    signature[last_idx] ^= 0xFF;

    let result = verify_ed25519_unverified(message, &signature, &pk);
    assert!(result.is_err(), "Tampered last byte should fail verification");
}

#[test]
fn test_ed25519_signature_middle_byte_tampered() {
    let message = b"Test tampering middle byte";
    let (pk, sk) = generate_keypair().expect("keypair");

    let mut signature =
        sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    // Tamper with middle byte
    signature[32] ^= 0x01;

    let result = verify_ed25519_unverified(message, &signature, &pk);
    assert!(result.is_err(), "Tampered middle byte should fail verification");
}

#[test]
fn test_ed25519_signature_single_bit_flip() {
    let message = b"Test single bit flip";
    let (pk, sk) = generate_keypair().expect("keypair");

    let mut signature =
        sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    // Flip just one bit
    signature[16] ^= 0x01;

    let result = verify_ed25519_unverified(message, &signature, &pk);
    assert!(result.is_err(), "Single bit flip should fail verification");
}

#[test]
fn test_ed25519_every_byte_tampered_fails() {
    let message = b"Every byte tampered";
    let (pk, sk) = generate_keypair().expect("keypair");

    let original_signature =
        sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    // Tamper each byte individually and verify it fails
    for i in 0..64 {
        let mut tampered = original_signature.clone();
        tampered[i] ^= 0xFF;

        let result = verify_ed25519_unverified(message, &tampered, &pk);
        assert!(result.is_err(), "Tampering byte {} should fail verification", i);
    }
}

// ============================================================================
// Deterministic Signature Property
// ============================================================================

#[test]
fn test_ed25519_deterministic_signatures() -> Result<()> {
    let message = b"Same message for deterministic test";
    let (_, sk) = generate_keypair()?;

    let sig1 = sign_ed25519_unverified(message, sk.as_ref())?;
    let sig2 = sign_ed25519_unverified(message, sk.as_ref())?;
    let sig3 = sign_ed25519_unverified(message, sk.as_ref())?;

    assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
    assert_eq!(sig2, sig3, "Ed25519 signatures should be deterministic");

    Ok(())
}

#[test]
fn test_ed25519_different_messages_different_signatures() -> Result<()> {
    let (_, sk) = generate_keypair()?;

    let sig1 = sign_ed25519_unverified(b"Message A", sk.as_ref())?;
    let sig2 = sign_ed25519_unverified(b"Message B", sk.as_ref())?;
    let sig3 = sign_ed25519_unverified(b"Message C", sk.as_ref())?;

    assert_ne!(sig1, sig2, "Different messages should produce different signatures");
    assert_ne!(sig2, sig3, "Different messages should produce different signatures");
    assert_ne!(sig1, sig3, "Different messages should produce different signatures");

    Ok(())
}

#[test]
fn test_ed25519_different_keys_different_signatures() -> Result<()> {
    let message = b"Same message, different keys";
    let (_, sk1) = generate_keypair()?;
    let (_, sk2) = generate_keypair()?;
    let (_, sk3) = generate_keypair()?;

    let sig1 = sign_ed25519_unverified(message, sk1.as_ref())?;
    let sig2 = sign_ed25519_unverified(message, sk2.as_ref())?;
    let sig3 = sign_ed25519_unverified(message, sk3.as_ref())?;

    assert_ne!(sig1, sig2, "Different keys should produce different signatures");
    assert_ne!(sig2, sig3, "Different keys should produce different signatures");
    assert_ne!(sig1, sig3, "Different keys should produce different signatures");

    Ok(())
}

// ============================================================================
// Invalid Input Handling
// ============================================================================

#[test]
fn test_ed25519_invalid_private_key_too_short() {
    let message = b"Test invalid key";
    let short_key = vec![0u8; 16]; // Only 16 bytes, need 32

    let result = sign_ed25519_unverified(message, &short_key);
    assert!(result.is_err(), "Short private key should fail");
}

#[test]
fn test_ed25519_invalid_public_key_too_short() {
    let message = b"Test invalid public key";
    let (_, sk) = generate_keypair().expect("keypair");
    let short_pk = vec![0u8; 16]; // Only 16 bytes, need 32

    let signature = sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    let result = verify_ed25519_unverified(message, &signature, &short_pk);
    assert!(result.is_err(), "Short public key should fail");
}

#[test]
fn test_ed25519_invalid_signature_too_short() {
    let message = b"Test invalid signature";
    let (pk, _) = generate_keypair().expect("keypair");
    let short_sig = vec![0u8; 32]; // Only 32 bytes, need 64

    let result = verify_ed25519_unverified(message, &short_sig, &pk);
    assert!(result.is_err(), "Short signature should fail");
}

#[test]
fn test_ed25519_empty_signature() {
    let message = b"Test empty signature";
    let (pk, _) = generate_keypair().expect("keypair");
    let empty_sig: Vec<u8> = vec![];

    let result = verify_ed25519_unverified(message, &empty_sig, &pk);
    assert!(result.is_err(), "Empty signature should fail");
}

#[test]
fn test_ed25519_empty_private_key() {
    let message = b"Test empty private key";
    let empty_sk: Vec<u8> = vec![];

    let result = sign_ed25519_unverified(message, &empty_sk);
    assert!(result.is_err(), "Empty private key should fail");
}

#[test]
fn test_ed25519_invalid_public_key_not_on_curve() {
    let message = b"Test invalid curve point";
    let (_, sk) = generate_keypair().expect("keypair");

    // Create an invalid public key (all zeros is not a valid curve point)
    let invalid_pk = vec![0u8; 32];

    let signature = sign_ed25519_unverified(message, sk.as_ref()).expect("signing should succeed");

    let result = verify_ed25519_unverified(message, &signature, &invalid_pk);
    assert!(result.is_err(), "Invalid curve point should fail");
}

// ============================================================================
// Edge Case Messages
// ============================================================================

#[test]
fn test_ed25519_empty_message() -> Result<()> {
    let message = b"";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message, sk.as_ref())?;
    assert_eq!(signature.len(), 64);

    let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
    assert!(is_valid, "Empty message signature should verify");

    Ok(())
}

#[test]
fn test_ed25519_single_byte_message() -> Result<()> {
    let message = b"X";
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_unverified(message, sk.as_ref())?;
    let is_valid = verify_ed25519_unverified(message, &signature, &pk)?;
    assert!(is_valid, "Single byte message should verify");

    Ok(())
}

#[test]
fn test_ed25519_power_of_two_sizes() -> Result<()> {
    let (pk, sk) = generate_keypair()?;

    for exp in 0..=16 {
        let size = 1 << exp; // 1, 2, 4, 8, ..., 65536
        let message = vec![0x42u8; size];

        let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
        let is_valid = verify_ed25519_unverified(&message, &signature, &pk)?;
        assert!(is_valid, "Message of size {} should verify", size);
    }

    Ok(())
}

#[test]
fn test_ed25519_message_with_wrong_message_fails() {
    let original = b"Original message";
    let tampered = b"Tampered message";
    let (pk, sk) = generate_keypair().expect("keypair");

    let signature = sign_ed25519_unverified(original, sk.as_ref()).expect("signing should succeed");

    let result = verify_ed25519_unverified(tampered, &signature, &pk);
    assert!(result.is_err(), "Wrong message should fail verification");
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

#[test]
fn test_ed25519_with_development_config() -> Result<()> {
    let message = b"Test development config";
    let config = CoreConfig::for_development();
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_with_config_unverified(message, sk.as_ref(), &config)?;
    let is_valid = verify_ed25519_with_config_unverified(message, &signature, &pk, &config)?;
    assert!(is_valid);

    Ok(())
}

#[test]
fn test_ed25519_with_production_config() -> Result<()> {
    let message = b"Test production config";
    let config = CoreConfig::for_production();
    let (pk, sk) = generate_keypair()?;

    let signature = sign_ed25519_with_config_unverified(message, sk.as_ref(), &config)?;
    let is_valid = verify_ed25519_with_config_unverified(message, &signature, &pk, &config)?;
    assert!(is_valid);

    Ok(())
}

// ============================================================================
// Signature Length Consistency Tests
// ============================================================================

#[test]
fn test_ed25519_signature_length_constant() -> Result<()> {
    let (_, sk) = generate_keypair()?;

    // Various message sizes
    let sizes = [0, 1, 10, 100, 1000, 10000];

    for size in sizes {
        let message = vec![0x42u8; size];
        let signature = sign_ed25519_unverified(&message, sk.as_ref())?;
        assert_eq!(
            signature.len(),
            64,
            "Signature length should always be 64 bytes, got {} for message size {}",
            signature.len(),
            size
        );
    }

    Ok(())
}

// ============================================================================
// Keypair Uniqueness Tests
// ============================================================================

#[test]
fn test_ed25519_keypair_uniqueness() -> Result<()> {
    let (pk1, sk1) = generate_keypair()?;
    let (pk2, sk2) = generate_keypair()?;
    let (pk3, sk3) = generate_keypair()?;

    // Public keys should be unique
    assert_ne!(pk1, pk2);
    assert_ne!(pk2, pk3);
    assert_ne!(pk1, pk3);

    // Private keys should be unique
    assert_ne!(sk1.as_ref(), sk2.as_ref());
    assert_ne!(sk2.as_ref(), sk3.as_ref());
    assert_ne!(sk1.as_ref(), sk3.as_ref());

    Ok(())
}

// ============================================================================
// Key Format Tests
// ============================================================================

#[test]
fn test_ed25519_key_sizes() -> Result<()> {
    let (pk, sk) = generate_keypair()?;

    assert_eq!(pk.len(), 32, "Ed25519 public key should be 32 bytes");
    assert_eq!(sk.as_ref().len(), 32, "Ed25519 private key should be 32 bytes");

    Ok(())
}

#[test]
fn test_ed25519_public_key_not_zero() -> Result<()> {
    let (pk, _) = generate_keypair()?;

    // Public key should not be all zeros
    assert!(!pk.iter().all(|&b| b == 0), "Public key should not be all zeros");

    Ok(())
}

#[test]
fn test_ed25519_private_key_not_zero() -> Result<()> {
    let (_, sk) = generate_keypair()?;

    // Private key should not be all zeros
    assert!(!sk.as_ref().iter().all(|&b| b == 0), "Private key should not be all zeros");

    Ok(())
}
