//! Comprehensive tests for Zero Trust module
//!
//! This test suite validates all Zero Trust authentication, session management,
//! and security mode functionality in arc-core.
//!
//! # Test Coverage (Tasks 1.10.1-1.10.10)
//!
//! 1.10.1 - Session establishment
//! 1.10.2 - Session expiration
//! 1.10.3 - Session refresh
//! 1.10.4 - Invalid session handling
//! 1.10.5 - Concurrent sessions
//! 1.10.6 - Challenge-response protocol
//! 1.10.7 - Trust level transitions
//! 1.10.8 - SecurityMode::Verified/Unverified validation

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
    config::{CoreConfig, ProofComplexity, ZeroTrustConfig},
    convenience::generate_keypair,
    error::CoreError,
    traits::{ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable},
    types::{PrivateKey, PublicKey},
    zero_trust::{
        SecurityMode, TrustLevel, VerifiedSession, ZeroKnowledgeProof, ZeroTrustAuth,
        ZeroTrustSession,
    },
};
use chrono::{Duration, Utc};
use std::thread;
use std::time::Duration as StdDuration;

// ============================================================================
// Test 1.10.1: Session Establishment
// ============================================================================

#[test]
fn test_session_establishment_basic() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert!(session.is_valid(), "Newly established session should be valid");
}

#[test]
fn test_session_establishment_trust_level() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert_eq!(
        session.trust_level(),
        TrustLevel::Trusted,
        "Established session should have Trusted level"
    );
}

#[test]
fn test_session_establishment_session_id() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert_eq!(session.session_id().len(), 32, "Session ID should be 32 bytes");
}

#[test]
fn test_session_establishment_public_key() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert_eq!(session.public_key(), &public_key, "Session should store the correct public key");
}

#[test]
fn test_session_establishment_timestamps() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    let now = Utc::now();
    let auth_time = session.authenticated_at();
    let time_diff = now.signed_duration_since(auth_time);

    assert!(
        time_diff.num_seconds() < 5,
        "Authentication timestamp should be within last 5 seconds"
    );
}

#[test]
fn test_session_establishment_verify_valid() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert!(session.verify_valid().is_ok(), "Valid session should pass verification");
}

#[test]
fn test_session_establishment_unique_ids() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session1 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 1 establishment should succeed");
    let session2 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 2 establishment should succeed");

    assert_ne!(
        session1.session_id(),
        session2.session_id(),
        "Different sessions should have different IDs"
    );
}

// ============================================================================
// Test 1.10.2: Session Expiration
// ============================================================================

#[test]
fn test_session_expiration_time_set() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    let now = Utc::now();
    let expires = session.expires_at();
    let time_until_expiry = expires.signed_duration_since(now);

    // Should expire in approximately 30 minutes
    assert!(
        time_until_expiry.num_minutes() >= 29 && time_until_expiry.num_minutes() <= 30,
        "Session should expire in approximately 30 minutes"
    );
}

#[test]
fn test_session_expiration_is_valid_check() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Fresh session should be valid
    assert!(session.is_valid(), "Fresh session should be valid");
}

#[test]
fn test_session_expiration_expires_after_authenticated() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    assert!(
        session.expires_at() > session.authenticated_at(),
        "Session should expire after authentication"
    );
}

#[test]
fn test_challenge_expiration() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 1, // Very short timeout
        proof_complexity: ProofComplexity::Low,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    // Wait for timeout
    thread::sleep(StdDuration::from_millis(10));

    assert!(challenge.is_expired(), "Challenge should expire after timeout");
}

#[test]
fn test_challenge_verify_age_valid() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    let is_valid = auth.verify_challenge_age(&challenge).expect("age verification should succeed");
    assert!(is_valid, "Fresh challenge should be within timeout");
}

#[test]
fn test_challenge_verify_age_expired() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 1,
        proof_complexity: ProofComplexity::Low,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    thread::sleep(StdDuration::from_millis(10));

    let is_valid = auth.verify_challenge_age(&challenge).expect("age verification should succeed");
    assert!(!is_valid, "Expired challenge should fail age check");
}

// ============================================================================
// Test 1.10.3: Session Refresh
// ============================================================================

#[test]
fn test_session_refresh_by_reestablishment() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session1 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 1 should succeed");

    // Simulate refresh by creating new session
    let session2 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 2 should succeed");

    // New session should be valid
    assert!(session2.is_valid(), "Refreshed session should be valid");

    // New session should have later expiration
    assert!(
        session2.authenticated_at() >= session1.authenticated_at(),
        "New session should be authenticated at or after old one"
    );
}

#[test]
fn test_continuous_session_update_verification() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let mut continuous_session = auth.start_continuous_verification();

    // Update verification timestamp
    let result = continuous_session.update_verification();
    assert!(result.is_ok(), "Updating verification should succeed");

    // Session should still be valid
    let is_valid = continuous_session.is_valid().expect("validity check should succeed");
    assert!(is_valid, "Session should be valid after update");
}

#[test]
fn test_reauthentication() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    // Perform reauthentication
    let result = auth.reauthenticate();
    assert!(result.is_ok(), "Reauthentication should succeed");
}

#[test]
fn test_multiple_reauthentications() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    for i in 0..5 {
        let result = auth.reauthenticate();
        assert!(result.is_ok(), "Reauthentication {} should succeed", i);
    }
}

// ============================================================================
// Test 1.10.4: Invalid Session Handling
// ============================================================================

#[test]
fn test_unauthenticated_session_conversion_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    // Session should not be authenticated
    assert!(!session.is_authenticated(), "New session should not be authenticated");

    // Converting should fail
    let result = session.into_verified();
    assert!(result.is_err(), "Converting unauthenticated session should fail");

    match result {
        Err(CoreError::AuthenticationRequired(msg)) => {
            assert!(msg.contains("authenticated"));
        }
        _ => panic!("Expected AuthenticationRequired error"),
    }
}

#[test]
fn test_empty_challenge_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let result = auth.generate_proof(&[]);
    assert!(result.is_err(), "Empty challenge should fail");

    match result {
        Err(CoreError::AuthenticationFailed(msg)) => {
            assert!(msg.contains("Empty challenge"));
        }
        _ => panic!("Expected AuthenticationFailed error"),
    }
}

#[test]
fn test_tampered_proof_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    let mut proof = auth.generate_proof(&challenge.data).expect("proof generation should succeed");

    // Tamper with proof
    if !proof.proof.is_empty() {
        proof.proof[0] ^= 0xFF;
    }

    let result = auth.verify_proof(&proof, &challenge.data);
    assert!(
        result.is_err() || !result.expect("verify should return bool"),
        "Tampered proof should fail"
    );
}

#[test]
fn test_wrong_challenge_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    let wrong_challenge = vec![0x42u8; 32];
    let proof = auth.generate_proof(&wrong_challenge).expect("proof generation should succeed");

    let result = auth.verify_proof(&proof, &challenge.data);
    assert!(
        result.is_err() || !result.expect("verify should return bool"),
        "Proof for wrong challenge should fail"
    );
}

#[test]
fn test_tampered_pop_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let mut pop = auth.generate_pop().expect("PoP generation should succeed");

    // Tamper with signature
    if !pop.signature.is_empty() {
        pop.signature[0] ^= 0xFF;
    }

    let result = auth.verify_pop(&pop);
    assert!(
        result.is_err() || !result.expect("verify should return bool"),
        "Tampered PoP should fail"
    );
}

#[test]
fn test_zero_knowledge_proof_format_validation() {
    // Valid proof
    let valid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };
    assert!(valid_proof.is_valid_format());

    // Empty challenge
    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![],
        proof: vec![4, 5, 6],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };
    assert!(!invalid_proof.is_valid_format());

    // Empty proof
    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };
    assert!(!invalid_proof.is_valid_format());

    // Future timestamp
    let future_time = Utc::now().checked_add_signed(Duration::hours(1)).unwrap_or_else(Utc::now);
    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        timestamp: future_time,
        complexity: ProofComplexity::Low,
    };
    assert!(!invalid_proof.is_valid_format());
}

// ============================================================================
// Test 1.10.5: Concurrent Sessions
// ============================================================================

#[test]
fn test_multiple_sessions_same_keypair() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session1 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 1 should succeed");
    let session2 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 2 should succeed");
    let session3 = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session 3 should succeed");

    // All sessions should be valid
    assert!(session1.is_valid());
    assert!(session2.is_valid());
    assert!(session3.is_valid());

    // All sessions should have different IDs
    assert_ne!(session1.session_id(), session2.session_id());
    assert_ne!(session2.session_id(), session3.session_id());
    assert_ne!(session1.session_id(), session3.session_id());
}

#[test]
fn test_multiple_sessions_different_keypairs() {
    let (pk1, sk1) = generate_keypair().expect("keypair 1");
    let (pk2, sk2) = generate_keypair().expect("keypair 2");

    let session1 = VerifiedSession::establish(&pk1, sk1.as_slice()).expect("session 1");
    let session2 = VerifiedSession::establish(&pk2, sk2.as_slice()).expect("session 2");

    assert_ne!(session1.session_id(), session2.session_id());
    assert_ne!(session1.public_key(), session2.public_key());
}

#[test]
fn test_session_reuse_for_multiple_operations() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session should succeed");

    for i in 0..20 {
        let mode = SecurityMode::Verified(&session);
        let result = mode.validate();
        assert!(result.is_ok(), "Session should be valid for operation {} (reuse)", i);
    }
}

#[test]
fn test_rapid_session_creation() {
    for i in 0..20 {
        let (public_key, private_key) = generate_keypair().expect("keypair generation");
        let session = VerifiedSession::establish(&public_key, private_key.as_slice())
            .unwrap_or_else(|_| panic!("Session {} should succeed", i));
        assert!(session.is_valid(), "Session {} should be valid", i);
    }
}

// ============================================================================
// Test 1.10.6: Challenge-Response Protocol
// ============================================================================

#[test]
fn test_challenge_generation_low_complexity() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Low,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    assert_eq!(challenge.data.len(), 32, "Low complexity should use 32-byte challenge");
}

#[test]
fn test_challenge_generation_medium_complexity() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    assert_eq!(challenge.data.len(), 64, "Medium complexity should use 64-byte challenge");
}

#[test]
fn test_challenge_generation_high_complexity() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::High,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    assert_eq!(challenge.data.len(), 128, "High complexity should use 128-byte challenge");
}

#[test]
fn test_challenge_uniqueness() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    let challenge1 = auth.generate_challenge().expect("challenge 1");
    let challenge2 = auth.generate_challenge().expect("challenge 2");

    assert_ne!(challenge1.data, challenge2.data, "Challenges should be unique");
}

#[test]
fn test_proof_generation_and_verification() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation");
    let proof = auth.generate_proof(&challenge.data).expect("proof generation");
    let verified = auth.verify_proof(&proof, &challenge.data).expect("verification");

    assert!(verified, "Valid proof should verify");
}

#[test]
fn test_challenge_response_stress() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    for i in 0..50 {
        let challenge =
            auth.generate_challenge().unwrap_or_else(|_| panic!("Challenge {} should succeed", i));
        let proof = auth
            .generate_proof(&challenge.data)
            .unwrap_or_else(|_| panic!("Proof {} should succeed", i));
        let verified = auth
            .verify_proof(&proof, &challenge.data)
            .unwrap_or_else(|_| panic!("Verification {} should succeed", i));

        assert!(verified, "Proof {} should verify", i);
    }
}

#[test]
fn test_proof_of_possession_generation() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key.clone();
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let pop = auth.generate_pop().expect("PoP generation should succeed");

    assert_eq!(pop.public_key, public_key);
    assert!(!pop.signature.is_empty());
    assert!(pop.timestamp <= Utc::now());
}

#[test]
fn test_proof_of_possession_verification() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let pop = auth.generate_pop().expect("PoP generation");
    let is_valid = auth.verify_pop(&pop).expect("PoP verification");

    assert!(is_valid, "Valid PoP should verify");
}

// ============================================================================
// Test 1.10.7: Trust Level Transitions
// ============================================================================

#[test]
fn test_trust_level_ordering() {
    assert!(TrustLevel::Untrusted < TrustLevel::Partial);
    assert!(TrustLevel::Partial < TrustLevel::Trusted);
    assert!(TrustLevel::Trusted < TrustLevel::FullyTrusted);
}

#[test]
fn test_trust_level_is_trusted() {
    assert!(!TrustLevel::Untrusted.is_trusted());
    assert!(TrustLevel::Partial.is_trusted());
    assert!(TrustLevel::Trusted.is_trusted());
    assert!(TrustLevel::FullyTrusted.is_trusted());
}

#[test]
fn test_trust_level_is_fully_trusted() {
    assert!(!TrustLevel::Untrusted.is_fully_trusted());
    assert!(!TrustLevel::Partial.is_fully_trusted());
    assert!(!TrustLevel::Trusted.is_fully_trusted());
    assert!(TrustLevel::FullyTrusted.is_fully_trusted());
}

#[test]
fn test_trust_level_default() {
    let level = TrustLevel::default();
    assert_eq!(level, TrustLevel::Untrusted);
}

#[test]
fn test_trust_level_values() {
    assert_eq!(TrustLevel::Untrusted as i32, 0);
    assert_eq!(TrustLevel::Partial as i32, 1);
    assert_eq!(TrustLevel::Trusted as i32, 2);
    assert_eq!(TrustLevel::FullyTrusted as i32, 3);
}

#[test]
fn test_trust_level_clone_and_eq() {
    let level1 = TrustLevel::Trusted;
    let level2 = level1.clone();
    assert_eq!(level1, level2);
}

#[test]
fn test_trust_level_progression() {
    let levels = vec![
        TrustLevel::Untrusted,
        TrustLevel::Partial,
        TrustLevel::Trusted,
        TrustLevel::FullyTrusted,
    ];

    for (i, level) in levels.iter().enumerate() {
        assert_eq!(*level as usize, i);
    }
}

// ============================================================================
// Test 1.10.8: SecurityMode::Verified/Unverified Validation
// ============================================================================

#[test]
fn test_security_mode_verified_is_verified() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session should succeed");

    let mode = SecurityMode::Verified(&session);

    assert!(mode.is_verified());
    assert!(!mode.is_unverified());
}

#[test]
fn test_security_mode_unverified_is_unverified() {
    let mode = SecurityMode::Unverified;

    assert!(!mode.is_verified());
    assert!(mode.is_unverified());
}

#[test]
fn test_security_mode_verified_session() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session should succeed");

    let mode = SecurityMode::Verified(&session);

    assert!(mode.session().is_some());
}

#[test]
fn test_security_mode_unverified_session() {
    let mode = SecurityMode::Unverified;
    assert!(mode.session().is_none());
}

#[test]
fn test_security_mode_verified_validate() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session should succeed");

    let mode = SecurityMode::Verified(&session);
    let result = mode.validate();

    assert!(result.is_ok(), "Valid verified session should pass validation");
}

#[test]
fn test_security_mode_unverified_validate() {
    let mode = SecurityMode::Unverified;
    let result = mode.validate();

    assert!(result.is_ok(), "Unverified mode should always pass validation");
}

#[test]
fn test_security_mode_default() {
    let mode = SecurityMode::default();
    assert!(mode.is_unverified(), "Default SecurityMode should be Unverified");
}

#[test]
fn test_security_mode_from_session() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session should succeed");

    let mode: SecurityMode = (&session).into();

    assert!(mode.is_verified(), "SecurityMode from session should be Verified");
}

// ============================================================================
// Additional Integration Tests
// ============================================================================

#[test]
fn test_continuous_verification_status() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: true,
        verification_interval_ms: 100,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let status = auth.verify_continuously().expect("continuous verification check should succeed");

    assert!(matches!(status, VerificationStatus::Verified), "Fresh auth should be verified");
}

#[test]
fn test_continuous_session_validity() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key.clone();
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    let continuous_session = auth.start_continuous_verification();

    let is_valid = continuous_session.is_valid().expect("validity check should succeed");
    assert!(is_valid, "New continuous session should be valid");

    assert_eq!(continuous_session.auth_public_key(), &public_key);
}

#[test]
fn test_session_age_tracking() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    let age_ms = session.session_age_ms().expect("age calculation should succeed");
    assert!(age_ms < 1000, "New session age should be less than 1 second");

    thread::sleep(StdDuration::from_millis(50));

    let new_age_ms = session.session_age_ms().expect("age calculation should succeed");
    assert!(new_age_ms >= 50, "Session age should increase over time");
}

#[test]
fn test_zero_trust_auth_new() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let result = ZeroTrustAuth::new(public_key, private_key);
    assert!(result.is_ok(), "ZeroTrustAuth::new should succeed");
}

#[test]
fn test_zero_trust_auth_with_config() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig::new().with_timeout(10000).with_complexity(ProofComplexity::High);

    let result = ZeroTrustAuth::with_config(public_key, private_key, config);
    assert!(result.is_ok(), "ZeroTrustAuth::with_config should succeed");
}

#[test]
fn test_zero_trust_session_new() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    assert!(!session.is_authenticated(), "New session should not be authenticated");
}

#[test]
fn test_zero_trust_session_initiate_authentication() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");
    let mut session = ZeroTrustSession::new(auth);

    let challenge = session.initiate_authentication().expect("initiation should succeed");

    assert!(!challenge.is_expired());
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_proof_complexity_all_variants() {
    let complexities = vec![ProofComplexity::Low, ProofComplexity::Medium, ProofComplexity::High];

    for complexity in complexities {
        let (public_key, private_key) = generate_keypair().expect("keypair generation");

        let config = ZeroTrustConfig {
            base: CoreConfig::default(),
            challenge_timeout_ms: 5000,
            proof_complexity: complexity.clone(),
            continuous_verification: false,
            verification_interval_ms: 1000,
        };

        let pk: PublicKey = public_key;
        let sk: PrivateKey = private_key;

        let auth =
            ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");
        let challenge = auth.generate_challenge().expect("challenge should succeed");

        let expected_size = match complexity {
            ProofComplexity::Low => 32,
            ProofComplexity::Medium => 64,
            ProofComplexity::High => 128,
        };

        assert_eq!(challenge.data.len(), expected_size);
    }
}

#[test]
fn test_config_validation_zero_timeout() {
    let config = ZeroTrustConfig::new().with_timeout(0);

    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn test_config_validation_continuous_zero_interval() {
    let config =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(0);

    let result = config.validate();
    assert!(result.is_err());
}

#[test]
fn test_config_validation_disabled_continuous_zero_interval_ok() {
    let config =
        ZeroTrustConfig::new().with_continuous_verification(false).with_verification_interval(0);

    let result = config.validate();
    // When continuous verification is disabled, zero interval should be OK
    assert!(result.is_ok());
}

// ============================================================================
// Stress Tests
// ============================================================================

#[test]
fn test_stress_session_creation() {
    for i in 0..30 {
        let (public_key, private_key) = generate_keypair().expect("keypair generation");
        let session = VerifiedSession::establish(&public_key, private_key.as_slice())
            .unwrap_or_else(|_| panic!("Session {} should succeed", i));
        assert!(session.is_valid(), "Session {} should be valid", i);
    }
}

#[test]
fn test_stress_challenge_response() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    for i in 0..30 {
        let challenge =
            auth.generate_challenge().unwrap_or_else(|_| panic!("Challenge {} should succeed", i));
        let proof = auth
            .generate_proof(&challenge.data)
            .unwrap_or_else(|_| panic!("Proof {} should succeed", i));
        let verified = auth
            .verify_proof(&proof, &challenge.data)
            .unwrap_or_else(|_| panic!("Verification {} should succeed", i));

        assert!(verified, "Proof {} should verify", i);
    }
}

#[test]
fn test_stress_pop_generation() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    for i in 0..20 {
        let pop = auth.generate_pop().unwrap_or_else(|_| panic!("PoP {} should succeed", i));
        let verified = auth
            .verify_pop(&pop)
            .unwrap_or_else(|_| panic!("PoP verification {} should succeed", i));

        assert!(verified, "PoP {} should verify", i);
    }
}
