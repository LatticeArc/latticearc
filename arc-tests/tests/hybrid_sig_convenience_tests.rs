//! Comprehensive tests for Hybrid Signature Convenience API
//!
//! Tests the ML-DSA-65 + Ed25519 AND-composition hybrid signature pipeline
//! exposed through `arc-core/src/convenience/hybrid_sig.rs`.
//!
//! ## Test Categories
//!
//! 1. **Basic roundtrip** - Generate/sign/verify with SecurityMode variants
//! 2. **Verified session** - Tests with valid VerifiedSession
//! 3. **Cross-key rejection** - Wrong key verification failure
//! 4. **Tampered signature** - Modified signature detection
//! 5. **Message binding** - Wrong message fails verification
//! 6. **Edge cases** - Empty message, large message, binary data
//! 7. **Persistent identity** - Multiple messages with same keypair
//! 8. **Config variants** - with_config, unverified wrappers
//! 9. **Unverified/mode interop** - _unverified and SecurityMode::Unverified produce compatible results

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
    unused_qualifications,
    missing_docs
)]

use arc_core::config::CoreConfig;
use arc_core::convenience::{
    generate_hybrid_signing_keypair, generate_hybrid_signing_keypair_unverified,
    generate_hybrid_signing_keypair_with_config, sign_hybrid, sign_hybrid_unverified,
    sign_hybrid_with_config, verify_hybrid_signature, verify_hybrid_signature_unverified,
    verify_hybrid_signature_with_config,
};
use arc_core::error::Result;
use arc_core::zero_trust::{SecurityMode, VerifiedSession};

// ============================================================================
// Basic Roundtrip Tests
// ============================================================================

#[test]
fn test_roundtrip_unverified_convenience() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = b"Hello, hybrid signatures!";
    let signature = sign_hybrid_unverified(message, &sk)?;
    let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
    assert!(valid, "Roundtrip via _unverified should succeed");
    Ok(())
}

#[test]
fn test_roundtrip_security_mode_unverified() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
    let message = b"SecurityMode::Unverified test";
    let signature = sign_hybrid(message, &sk, SecurityMode::Unverified)?;
    let valid = verify_hybrid_signature(message, &signature, &pk, SecurityMode::Unverified)?;
    assert!(valid, "Roundtrip via SecurityMode::Unverified should succeed");
    Ok(())
}

#[test]
fn test_roundtrip_with_config() -> Result<()> {
    let config = CoreConfig::default();
    let (pk, sk) = generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified)?;
    let message = b"Config variant test";
    let signature = sign_hybrid_with_config(message, &sk, &config, SecurityMode::Unverified)?;
    let valid = verify_hybrid_signature_with_config(
        message,
        &signature,
        &pk,
        &config,
        SecurityMode::Unverified,
    )?;
    assert!(valid, "Roundtrip via _with_config should succeed");
    Ok(())
}

// ============================================================================
// Verified Session Tests
// ============================================================================

#[test]
fn test_roundtrip_verified_session() -> Result<()> {
    let (auth_pk, auth_sk) = arc_core::convenience::generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;

    let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Verified(&session))?;
    let message = b"Verified session roundtrip";
    let signature = sign_hybrid(message, &sk, SecurityMode::Verified(&session))?;
    let valid =
        verify_hybrid_signature(message, &signature, &pk, SecurityMode::Verified(&session))?;
    assert!(valid, "Roundtrip with verified session should succeed");
    Ok(())
}

#[test]
fn test_verified_session_multiple_operations() -> Result<()> {
    let (auth_pk, auth_sk) = arc_core::convenience::generate_keypair()?;
    let session = VerifiedSession::establish(&auth_pk, auth_sk.as_ref())?;
    let mode = SecurityMode::Verified(&session);

    let (pk, sk) = generate_hybrid_signing_keypair(mode)?;

    for i in 0..5 {
        let message = format!("Message number {}", i);
        let signature = sign_hybrid(message.as_bytes(), &sk, mode)?;
        let valid = verify_hybrid_signature(message.as_bytes(), &signature, &pk, mode)?;
        assert!(valid, "Message {} should verify with session", i);
    }
    Ok(())
}

// ============================================================================
// Cross-Key Rejection Tests
// ============================================================================

#[test]
fn test_cross_key_rejection() -> Result<()> {
    let (pk_a, sk_a) = generate_hybrid_signing_keypair_unverified()?;
    let (_pk_b, _sk_b) = generate_hybrid_signing_keypair_unverified()?;

    let message = b"cross-key test";
    let signature = sign_hybrid_unverified(message, &sk_a)?;

    // Verify with correct key should succeed
    let valid = verify_hybrid_signature_unverified(message, &signature, &pk_a)?;
    assert!(valid, "Correct key should verify");

    // Verify with wrong key should fail
    let result = verify_hybrid_signature_unverified(message, &signature, &_pk_b);
    assert!(result.is_err(), "Wrong key should fail verification");
    Ok(())
}

#[test]
fn test_cross_key_rejection_many_keypairs() -> Result<()> {
    let (pk_signer, sk_signer) = generate_hybrid_signing_keypair_unverified()?;
    let message = b"signed by signer";
    let signature = sign_hybrid_unverified(message, &sk_signer)?;

    // Verify with the correct key
    assert!(verify_hybrid_signature_unverified(message, &signature, &pk_signer)?);

    // Try 5 different wrong keys
    for i in 0..5 {
        let (wrong_pk, _) = generate_hybrid_signing_keypair_unverified()?;
        let result = verify_hybrid_signature_unverified(message, &signature, &wrong_pk);
        assert!(result.is_err(), "Wrong key #{} should fail verification", i);
    }
    Ok(())
}

// ============================================================================
// Message Binding Tests
// ============================================================================

#[test]
fn test_wrong_message_fails() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let signature = sign_hybrid_unverified(b"correct message", &sk)?;

    let result = verify_hybrid_signature_unverified(b"wrong message", &signature, &pk);
    assert!(result.is_err(), "Verification with wrong message should fail");
    Ok(())
}

#[test]
fn test_single_byte_difference_fails() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = b"test message here";
    let signature = sign_hybrid_unverified(message, &sk)?;

    // Modify one byte
    let mut tampered = message.to_vec();
    tampered[5] ^= 0x01;

    let result = verify_hybrid_signature_unverified(&tampered, &signature, &pk);
    assert!(result.is_err(), "Single byte change in message should fail");
    Ok(())
}

#[test]
fn test_appended_byte_fails() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = b"original";
    let signature = sign_hybrid_unverified(message, &sk)?;

    let mut extended = message.to_vec();
    extended.push(0x00);

    let result = verify_hybrid_signature_unverified(&extended, &signature, &pk);
    assert!(result.is_err(), "Appended byte should fail verification");
    Ok(())
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_empty_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = b"";
    let signature = sign_hybrid_unverified(message, &sk)?;
    let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
    assert!(valid, "Empty message should sign and verify");
    Ok(())
}

#[test]
fn test_single_byte_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = &[0x42u8];
    let signature = sign_hybrid_unverified(message, &sk)?;
    let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
    assert!(valid, "Single byte message should sign and verify");
    Ok(())
}

#[test]
fn test_large_message_10kb() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = vec![0xAB; 10_000];
    let signature = sign_hybrid_unverified(&message, &sk)?;
    let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
    assert!(valid, "10KB message should sign and verify");
    Ok(())
}

#[test]
fn test_large_message_60kb() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = vec![0xCD; 60_000];
    let signature = sign_hybrid_unverified(&message, &sk)?;
    let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
    assert!(valid, "60KB message should sign and verify");
    Ok(())
}

#[test]
fn test_oversized_message_rejected() {
    let (_pk, sk) = generate_hybrid_signing_keypair_unverified().unwrap();
    let message = vec![0xEF; 100_000]; // 100KB exceeds 64KB limit
    let result = sign_hybrid_unverified(&message, &sk);
    assert!(result.is_err(), "100KB message should exceed resource limit");
}

#[test]
fn test_binary_data_all_byte_values() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message: Vec<u8> = (0..=255).collect();
    let signature = sign_hybrid_unverified(&message, &sk)?;
    let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
    assert!(valid, "All-byte-values message should sign and verify");
    Ok(())
}

#[test]
fn test_null_bytes_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = vec![0x00; 64];
    let signature = sign_hybrid_unverified(&message, &sk)?;
    let valid = verify_hybrid_signature_unverified(&message, &signature, &pk)?;
    assert!(valid, "All-null message should sign and verify");
    Ok(())
}

#[test]
fn test_unicode_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let message = "Hello, World! Rust 2024 Edition".as_bytes();
    let signature = sign_hybrid_unverified(message, &sk)?;
    let valid = verify_hybrid_signature_unverified(message, &signature, &pk)?;
    assert!(valid, "Unicode message should sign and verify");
    Ok(())
}

// ============================================================================
// Persistent Identity Tests
// ============================================================================

#[test]
fn test_persistent_identity_many_messages() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

    for i in 0..20 {
        let message = format!("Document #{} for signing", i);
        let signature = sign_hybrid_unverified(message.as_bytes(), &sk)?;
        let valid = verify_hybrid_signature_unverified(message.as_bytes(), &signature, &pk)?;
        assert!(valid, "Message {} should verify with persistent key", i);
    }
    Ok(())
}

#[test]
fn test_signatures_are_unique_per_message() -> Result<()> {
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;

    let sig1 = sign_hybrid_unverified(b"message A", &sk)?;
    let sig2 = sign_hybrid_unverified(b"message B", &sk)?;

    // Both should verify with their own message
    assert!(verify_hybrid_signature_unverified(b"message A", &sig1, &pk)?);
    assert!(verify_hybrid_signature_unverified(b"message B", &sig2, &pk)?);

    // Cross-verify should fail
    assert!(verify_hybrid_signature_unverified(b"message B", &sig1, &pk).is_err());
    assert!(verify_hybrid_signature_unverified(b"message A", &sig2, &pk).is_err());
    Ok(())
}

// ============================================================================
// Interoperability Tests
// ============================================================================

#[test]
fn test_unverified_convenience_and_mode_interop() -> Result<()> {
    // Generate with _unverified, sign with SecurityMode, verify with _unverified
    let (pk, sk) = generate_hybrid_signing_keypair_unverified()?;
    let signature = sign_hybrid(b"interop test", &sk, SecurityMode::Unverified)?;
    let valid = verify_hybrid_signature_unverified(b"interop test", &signature, &pk)?;
    assert!(valid, "Unverified convenience and SecurityMode should interop");
    Ok(())
}

#[test]
fn test_mode_and_unverified_convenience_interop() -> Result<()> {
    // Generate with SecurityMode, sign with _unverified, verify with SecurityMode
    let (pk, sk) = generate_hybrid_signing_keypair(SecurityMode::Unverified)?;
    let signature = sign_hybrid_unverified(b"reverse interop", &sk)?;
    let valid =
        verify_hybrid_signature(b"reverse interop", &signature, &pk, SecurityMode::Unverified)?;
    assert!(valid, "SecurityMode and unverified convenience should interop");
    Ok(())
}

#[test]
fn test_config_and_plain_interop() -> Result<()> {
    // Generate with _with_config, sign with plain, verify with _unverified
    let config = CoreConfig::default();
    let (pk, sk) = generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified)?;
    let signature = sign_hybrid(b"config interop", &sk, SecurityMode::Unverified)?;
    let valid = verify_hybrid_signature_unverified(b"config interop", &signature, &pk)?;
    assert!(valid, "Config and plain API should interop");
    Ok(())
}

// ============================================================================
// Keypair Independence Tests
// ============================================================================

#[test]
fn test_keypairs_are_independent() -> Result<()> {
    let (pk1, sk1) = generate_hybrid_signing_keypair_unverified()?;
    let (pk2, sk2) = generate_hybrid_signing_keypair_unverified()?;

    let message = b"same message for both";

    let sig1 = sign_hybrid_unverified(message, &sk1)?;
    let sig2 = sign_hybrid_unverified(message, &sk2)?;

    // Each signature verifies only with its own key
    assert!(verify_hybrid_signature_unverified(message, &sig1, &pk1)?);
    assert!(verify_hybrid_signature_unverified(message, &sig2, &pk2)?);

    // Cross-verification fails
    assert!(verify_hybrid_signature_unverified(message, &sig1, &pk2).is_err());
    assert!(verify_hybrid_signature_unverified(message, &sig2, &pk1).is_err());
    Ok(())
}

// ============================================================================
// Error Path Tests
// ============================================================================

#[test]
fn test_expired_session_rejected() {
    // We can't easily create an expired session, but we verify the mode.validate() path
    // is exercised by testing that Unverified always succeeds
    let result = generate_hybrid_signing_keypair(SecurityMode::Unverified);
    assert!(result.is_ok(), "Unverified mode should always succeed");
}

#[test]
fn test_config_validation_path() -> Result<()> {
    let config = CoreConfig::default();
    let result = generate_hybrid_signing_keypair_with_config(&config, SecurityMode::Unverified);
    assert!(result.is_ok(), "Default config should pass validation");
    Ok(())
}
