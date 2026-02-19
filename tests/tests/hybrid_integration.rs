//! Integration tests for hybrid encryption APIs
//!
//! The main hybrid encryption tests are in `hybrid_convenience_tests.rs`.
//! This file contains additional integration-level tests for the ML-KEM keypair
//! generation and encapsulated key size validation.

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

use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use latticearc::unified_api::{
    convenience::generate_ml_kem_keypair, decrypt_hybrid_unverified, encrypt_hybrid_unverified,
    error::Result, generate_hybrid_keypair,
};

// ============================================================================
// ML-KEM Keypair Generation and Public Key Size Tests
// ============================================================================

#[test]
fn test_mlkem512_public_key_size() -> Result<()> {
    let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem512)?;
    assert_eq!(pk.len(), 800, "ML-KEM-512 public key should be 800 bytes");
    Ok(())
}

#[test]
fn test_mlkem768_public_key_size() -> Result<()> {
    let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem768)?;
    assert_eq!(pk.len(), 1184, "ML-KEM-768 public key should be 1184 bytes");
    Ok(())
}

#[test]
fn test_mlkem1024_public_key_size() -> Result<()> {
    let (pk, _sk) = generate_ml_kem_keypair(MlKemSecurityLevel::MlKem1024)?;
    assert_eq!(pk.len(), 1568, "ML-KEM-1024 public key should be 1568 bytes");
    Ok(())
}

#[test]
fn test_all_mlkem_key_sizes() -> Result<()> {
    let test_cases = vec![
        (MlKemSecurityLevel::MlKem512, 800, "ML-KEM-512"),
        (MlKemSecurityLevel::MlKem768, 1184, "ML-KEM-768"),
        (MlKemSecurityLevel::MlKem1024, 1568, "ML-KEM-1024"),
    ];

    for (level, expected_pk_size, name) in test_cases {
        let (pk, _sk) = generate_ml_kem_keypair(level)?;
        assert_eq!(pk.len(), expected_pk_size, "{} public key size mismatch", name);
    }

    Ok(())
}

// ============================================================================
// Hybrid Keypair Generation Tests
// ============================================================================

#[test]
fn test_hybrid_keypair_generation_succeeds() -> Result<()> {
    let (pk, sk) = generate_hybrid_keypair()?;

    // Verify keys can encrypt/decrypt
    let message = b"Keypair generation test";
    let encrypted = encrypt_hybrid_unverified(message, &pk)?;
    let decrypted = decrypt_hybrid_unverified(&encrypted, &sk)?;
    assert_eq!(decrypted.as_slice(), message, "decrypted plaintext should match original message");

    Ok(())
}

#[test]
fn test_hybrid_keypair_uniqueness() -> Result<()> {
    let (pk1, _sk1) = generate_hybrid_keypair()?;
    let (pk2, _sk2) = generate_hybrid_keypair()?;

    // Public keys should be different
    assert_ne!(pk1.ml_kem_pk, pk2.ml_kem_pk, "ML-KEM PKs should differ");
    assert_ne!(pk1.ecdh_pk, pk2.ecdh_pk, "X25519 PKs should differ");

    Ok(())
}
