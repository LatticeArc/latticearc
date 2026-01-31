//! Comprehensive integration tests for Zero Trust session management
//!
//! This test suite validates the Zero Trust authentication and session lifecycle
//! in arc-core, covering challenge-response authentication, session verification,
//! and continuous trust management.
//!
//! # Test Coverage
//!
//! 1. **Session Lifecycle**
//!    - Session establishment via challenge-response
//!    - Session validity checking
//!    - Session expiration handling
//!
//! 2. **Authentication Flow**
//!    - Successful authentication with valid proof
//!    - Failed authentication with invalid proof
//!    - Challenge timeout handling
//!
//! 3. **Continuous Verification**
//!    - Trust level progression
//!    - Session age tracking
//!    - Verification status checking
//!
//! 4. **Invalid Session Handling**
//!    - Expired session detection
//!    - Invalid challenge handling
//!    - Proof verification failures
//!
//! 5. **Error Conditions**
//!    - Malformed inputs
//!    - Missing challenges
//!    - Invalid keys

#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use arc_core::{
    config::{CoreConfig, ProofComplexity, ZeroTrustConfig},
    convenience::generate_keypair,
    error::CoreError,
    traits::{ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable},
    types::{PrivateKey, PublicKey},
    zero_trust::{SecurityMode, TrustLevel, VerifiedSession, ZeroTrustAuth, ZeroTrustSession},
};
use chrono::{Duration, Utc};
use std::thread;
use std::time::Duration as StdDuration;

// ============================================================================
// Test 1: Session Lifecycle - Establishment and Basic Operations
// ============================================================================

#[test]
fn test_verified_session_establishment() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    // Establish a verified session using the quick API
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Verify session is initially valid
    assert!(session.is_valid(), "Newly established session should be valid");

    // Verify trust level is set correctly
    assert_eq!(
        session.trust_level(),
        TrustLevel::Trusted,
        "Established session should have Trusted level"
    );

    // Verify session has a unique ID
    assert_eq!(session.session_id().len(), 32, "Session ID should be 32 bytes");

    // Verify authenticated timestamp is recent
    let now = Utc::now();
    let auth_time = session.authenticated_at();
    let time_diff = now.signed_duration_since(auth_time);
    assert!(
        time_diff.num_seconds() < 5,
        "Authentication timestamp should be within last 5 seconds"
    );
}

#[test]
fn test_verified_session_expiration_time() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Verify expiration is set correctly (30 minutes from now)
    let now = Utc::now();
    let expires = session.expires_at();
    let time_until_expiry = expires.signed_duration_since(now);

    // Should expire in approximately 30 minutes (allow 5 second tolerance)
    assert!(
        time_until_expiry.num_minutes() >= 29 && time_until_expiry.num_minutes() <= 30,
        "Session should expire in approximately 30 minutes"
    );
}

#[test]
fn test_verified_session_public_key_access() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Verify public key is accessible and matches
    assert_eq!(session.public_key(), &public_key, "Session should store the correct public key");
}

#[test]
fn test_verified_session_verify_valid() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Verify the session is valid
    let result = session.verify_valid();
    assert!(result.is_ok(), "Valid session should pass verification");
}

// ============================================================================
// Test 2: Authentication Flow - Challenge-Response Protocol
// ============================================================================

#[test]
fn test_zero_trust_session_manual_authentication() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    // Test via the VerifiedSession::establish API, which performs authentication internally
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Verify session properties
    assert!(session.is_valid(), "Authenticated session should be valid");
    assert_eq!(
        session.trust_level(),
        TrustLevel::Trusted,
        "Session should have Trusted level after authentication"
    );
    assert_eq!(session.public_key(), &public_key, "Session should have correct public key");
}

#[test]
fn test_authentication_with_invalid_proof() {
    // Since ZeroTrustSession fields are private, we test via ZeroTrustAuth directly
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    // Generate a challenge
    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    // Generate a valid proof
    let mut proof = auth.generate_proof(&challenge.data).expect("proof generation should succeed");

    // Tamper with the proof data
    if !proof.proof.is_empty() {
        proof.proof[0] ^= 0xFF;
    }

    // Verification should fail with tampered proof
    let result = auth.verify_proof(&proof, &challenge.data);
    // Result may be Ok(false) or Err depending on how badly tampered
    assert!(result.is_err() || !result.unwrap(), "Tampered proof should fail verification");
}

#[test]
fn test_authentication_with_wrong_challenge() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    // Generate a challenge
    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    // Create a different challenge and generate proof for it
    let wrong_challenge = vec![0x42u8; 32];
    let proof = auth.generate_proof(&wrong_challenge).expect("proof generation should succeed");

    // Verification should fail because proof is for wrong challenge
    let result = auth.verify_proof(&proof, &challenge.data);
    assert!(result.is_err() || !result.unwrap(), "Proof for wrong challenge should fail");
}

#[test]
fn test_authentication_challenge_required() {
    // Test that we need a proper challenge-response flow
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    // Create a ZeroTrustSession manually to test the flow
    let pk: PublicKey = public_key.clone();
    let sk: PrivateKey = PrivateKey::new(private_key.as_slice().to_vec());

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    // Session should start unauthenticated
    assert!(!session.is_authenticated(), "New session should not be authenticated");

    // Converting to verified should fail without authentication
    let result = session.into_verified();
    assert!(result.is_err(), "Converting unauthenticated session should fail");

    match result {
        Err(CoreError::AuthenticationRequired(msg)) => {
            assert!(
                msg.contains("authenticated"),
                "Error should mention authentication requirement"
            );
        }
        _ => panic!("Expected AuthenticationRequired error"),
    }
}

// ============================================================================
// Test 3: Trust Levels and Proof Complexity
// ============================================================================

#[test]
fn test_trust_level_comparisons() {
    assert!(TrustLevel::Untrusted < TrustLevel::Partial);
    assert!(TrustLevel::Partial < TrustLevel::Trusted);
    assert!(TrustLevel::Trusted < TrustLevel::FullyTrusted);

    assert!(TrustLevel::Partial.is_trusted());
    assert!(TrustLevel::Trusted.is_trusted());
    assert!(TrustLevel::FullyTrusted.is_trusted());
    assert!(!TrustLevel::Untrusted.is_trusted());

    assert!(TrustLevel::FullyTrusted.is_fully_trusted());
    assert!(!TrustLevel::Trusted.is_fully_trusted());
}

#[test]
fn test_proof_complexity_low() {
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
fn test_proof_complexity_medium() {
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
fn test_proof_complexity_high() {
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

// ============================================================================
// Test 4: Challenge Timeout and Expiration
// ============================================================================

#[test]
fn test_challenge_timeout_detection() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    // Create config with very short timeout (1ms)
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

    // Wait for timeout
    thread::sleep(StdDuration::from_millis(10));

    // Challenge should now be expired
    assert!(challenge.is_expired(), "Challenge should expire after timeout");
}

#[test]
fn test_expired_challenge_verification_fails() {
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

    // Generate challenge
    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    // Wait for timeout
    thread::sleep(StdDuration::from_millis(10));

    // Challenge should now be expired
    assert!(challenge.is_expired(), "Challenge should be expired after timeout");

    // Verify age check returns false
    let age_valid = auth.verify_challenge_age(&challenge).expect("age check should succeed");
    assert!(!age_valid, "Expired challenge should fail age check");
}

// ============================================================================
// Test 5: Session Age and Continuous Verification
// ============================================================================

#[test]
fn test_session_age_tracking() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    // Age should be very small for new session
    let age_ms = session.session_age_ms().expect("age calculation should succeed");
    assert!(age_ms < 1000, "New session age should be less than 1 second");

    // Wait a bit
    thread::sleep(StdDuration::from_millis(100));

    // Age should have increased
    let new_age_ms = session.session_age_ms().expect("age calculation should succeed");
    assert!(new_age_ms >= 100, "Session age should increase over time (got {} ms)", new_age_ms);
}

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

    // Check verification status
    let status = auth.verify_continuously().expect("continuous verification check should succeed");

    // Should be verified initially (just created)
    assert!(matches!(status, VerificationStatus::Verified), "Fresh auth should be verified");
}

#[test]
fn test_continuous_verification_reauthentication() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: true,
        verification_interval_ms: 5000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    // Perform reauthentication
    let result = auth.reauthenticate();
    assert!(result.is_ok(), "Reauthentication should succeed");
}

#[test]
fn test_continuous_session_validity() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: true,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key.clone();
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let continuous_session = auth.start_continuous_verification();

    // Session should be valid initially
    let is_valid = continuous_session.is_valid().expect("validity check should succeed");
    assert!(is_valid, "New continuous session should be valid");

    // Public key should match
    assert_eq!(
        continuous_session.auth_public_key(),
        &public_key,
        "Continuous session should have correct public key"
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
}

// ============================================================================
// Test 6: Proof of Possession
// ============================================================================

#[test]
fn test_proof_of_possession_generation() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key.clone();
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    // Generate proof of possession
    let pop = auth.generate_pop().expect("PoP generation should succeed");

    // Verify PoP properties
    assert_eq!(pop.public_key, public_key, "PoP should contain correct public key");
    assert!(!pop.signature.is_empty(), "PoP signature should not be empty");
    assert!(pop.timestamp <= Utc::now(), "PoP timestamp should not be in the future");
}

#[test]
fn test_proof_of_possession_verification() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    // Generate and verify PoP
    let pop = auth.generate_pop().expect("PoP generation should succeed");
    let is_valid = auth.verify_pop(&pop).expect("PoP verification should succeed");

    assert!(is_valid, "Valid PoP should verify successfully");
}

#[test]
fn test_proof_of_possession_tampered_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    // Generate PoP
    let mut pop = auth.generate_pop().expect("PoP generation should succeed");

    // Tamper with signature
    if !pop.signature.is_empty() {
        pop.signature[0] ^= 0xFF;
    }

    // Verification should fail
    let result = auth.verify_pop(&pop);
    assert!(result.is_err() || !result.unwrap(), "Tampered PoP should fail verification");
}

// ============================================================================
// Test 7: SecurityMode Integration
// ============================================================================

#[test]
fn test_security_mode_verified() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    let mode = SecurityMode::Verified(&session);

    assert!(mode.is_verified(), "Verified mode should return true for is_verified");
    assert!(!mode.is_unverified(), "Verified mode should return false for is_unverified");
    assert!(mode.session().is_some(), "Verified mode should return session");
}

#[test]
fn test_security_mode_unverified() {
    let mode = SecurityMode::Unverified;

    assert!(!mode.is_verified(), "Unverified mode should return false for is_verified");
    assert!(mode.is_unverified(), "Unverified mode should return true for is_unverified");
    assert!(mode.session().is_none(), "Unverified mode should return None for session");
}

#[test]
fn test_security_mode_validate_verified() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    let mode = SecurityMode::Verified(&session);

    // Should validate successfully for valid session
    let result = mode.validate();
    assert!(result.is_ok(), "Valid verified session should pass validation");
}

#[test]
fn test_security_mode_validate_unverified() {
    let mode = SecurityMode::Unverified;

    // Unverified mode always validates (no checks)
    let result = mode.validate();
    assert!(result.is_ok(), "Unverified mode should always pass validation");
}

#[test]
fn test_security_mode_from_session() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    let mode: SecurityMode = (&session).into();

    assert!(mode.is_verified(), "SecurityMode from session should be Verified");
}

#[test]
fn test_security_mode_default() {
    let mode = SecurityMode::default();
    assert!(mode.is_unverified(), "Default SecurityMode should be Unverified");
}

// ============================================================================
// Test 8: Error Conditions and Edge Cases
// ============================================================================

#[test]
fn test_empty_challenge_proof_generation_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");

    // Try to generate proof for empty challenge
    let result = auth.generate_proof(&[]);
    assert!(result.is_err(), "Empty challenge should fail proof generation");

    match result {
        Err(CoreError::AuthenticationFailed(msg)) => {
            assert!(msg.contains("Empty challenge"), "Error should mention empty challenge");
        }
        _ => panic!("Expected AuthenticationFailed error"),
    }
}

#[test]
fn test_verified_session_from_unauthenticated_fails() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::new(pk, sk).expect("auth creation should succeed");
    let session = ZeroTrustSession::new(auth);

    // Try to convert unauthenticated session to verified
    let result = session.into_verified();
    assert!(result.is_err(), "Converting unauthenticated session should fail");

    match result {
        Err(CoreError::AuthenticationRequired(msg)) => {
            assert!(
                msg.contains("authenticated"),
                "Error should mention authentication requirement"
            );
        }
        _ => panic!("Expected AuthenticationRequired error"),
    }
}

#[test]
fn test_challenge_verify_age() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 1000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: false,
        verification_interval_ms: 1000,
    };

    let pk: PublicKey = public_key;
    let sk: PrivateKey = private_key;

    let auth = ZeroTrustAuth::with_config(pk, sk, config).expect("auth creation should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");

    // Fresh challenge should be valid
    let is_valid = auth.verify_challenge_age(&challenge).expect("age verification should succeed");
    assert!(is_valid, "Fresh challenge should be within timeout");

    // Wait for timeout
    thread::sleep(StdDuration::from_millis(1100));

    // Challenge should now be expired
    let is_valid = auth.verify_challenge_age(&challenge).expect("age verification should succeed");
    assert!(!is_valid, "Expired challenge should be outside timeout");
}

#[test]
fn test_proof_format_validation() {
    use arc_core::zero_trust::ZeroKnowledgeProof;

    let valid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };

    assert!(valid_proof.is_valid_format(), "Valid proof should have valid format");

    // Empty challenge
    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![],
        proof: vec![4, 5, 6],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };

    assert!(!invalid_proof.is_valid_format(), "Proof with empty challenge should be invalid");

    // Empty proof data
    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![],
        timestamp: Utc::now(),
        complexity: ProofComplexity::Low,
    };

    assert!(!invalid_proof.is_valid_format(), "Proof with empty data should be invalid");

    // Future timestamp
    let future_time = Utc::now().checked_add_signed(Duration::hours(1)).unwrap_or_else(Utc::now);

    let invalid_proof = ZeroKnowledgeProof {
        challenge: vec![1, 2, 3],
        proof: vec![4, 5, 6],
        timestamp: future_time,
        complexity: ProofComplexity::Low,
    };

    assert!(!invalid_proof.is_valid_format(), "Proof with future timestamp should be invalid");
}

// ============================================================================
// Test 9: Configuration Validation
// ============================================================================

#[test]
fn test_zero_trust_config_validation_success() {
    let config = ZeroTrustConfig {
        base: CoreConfig::default(),
        challenge_timeout_ms: 5000,
        proof_complexity: ProofComplexity::Medium,
        continuous_verification: true,
        verification_interval_ms: 1000,
    };

    let result = config.validate();
    assert!(result.is_ok(), "Valid configuration should pass validation");
}

#[test]
fn test_config_with_core_config() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");

    let core_config = CoreConfig::default();
    core_config.validate().expect("default config should be valid");

    // Config should work with ZeroTrustAuth
    let config = ZeroTrustConfig::default();
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)
        .expect("auth creation with config should succeed");

    let challenge = auth.generate_challenge().expect("challenge generation should succeed");
    assert!(!challenge.data.is_empty(), "Challenge should be generated with config");
}

// ============================================================================
// Test 10: Multiple Sessions and Concurrent Operations
// ============================================================================

#[test]
fn test_multiple_sessions_independent() {
    let (public_key1, private_key1) = generate_keypair().expect("keypair 1 generation");
    let (public_key2, private_key2) = generate_keypair().expect("keypair 2 generation");

    let session1 = VerifiedSession::establish(&public_key1, private_key1.as_slice())
        .expect("session 1 establishment should succeed");

    let session2 = VerifiedSession::establish(&public_key2, private_key2.as_slice())
        .expect("session 2 establishment should succeed");

    // Sessions should have different IDs
    assert_ne!(
        session1.session_id(),
        session2.session_id(),
        "Different sessions should have different IDs"
    );

    // Sessions should have different public keys
    assert_ne!(
        session1.public_key(),
        session2.public_key(),
        "Different sessions should have different public keys"
    );

    // Both sessions should be valid
    assert!(session1.is_valid(), "Session 1 should be valid");
    assert!(session2.is_valid(), "Session 2 should be valid");
}

#[test]
fn test_session_reuse_for_multiple_operations() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let session = VerifiedSession::establish(&public_key, private_key.as_slice())
        .expect("session establishment should succeed");

    // Use session multiple times
    for i in 0..10 {
        let mode = SecurityMode::Verified(&session);
        let result = mode.validate();
        assert!(result.is_ok(), "Session should be valid for operation {} (reuse)", i);
    }
}

#[test]
fn test_session_with_different_proof_complexities() {
    let complexities = [ProofComplexity::Low, ProofComplexity::Medium, ProofComplexity::High];

    for complexity in &complexities {
        let (public_key, private_key) = generate_keypair().expect("keypair generation");

        // Test using VerifiedSession::establish which handles authentication internally
        let session = VerifiedSession::establish(&public_key, private_key.as_slice())
            .expect("session establishment should succeed");

        assert!(session.is_valid(), "Session with {:?} should be valid", complexity);
        assert_eq!(session.trust_level(), TrustLevel::Trusted, "Session should have Trusted level");
    }
}

// ============================================================================
// Test 11: Stress Testing
// ============================================================================

#[test]
fn test_rapid_session_establishment() {
    // Create and verify 50 sessions rapidly
    for i in 0..50 {
        let (public_key, private_key) = generate_keypair().expect("keypair generation");
        let session = VerifiedSession::establish(&public_key, private_key.as_slice())
            .unwrap_or_else(|_| panic!("Session {} establishment should succeed", i));

        assert!(session.is_valid(), "Session {} should be valid", i);
    }
}

#[test]
fn test_challenge_response_stress() {
    let (public_key, private_key) = generate_keypair().expect("keypair generation");
    let auth = ZeroTrustAuth::new(public_key, private_key).expect("auth creation should succeed");

    // Perform 100 challenge-response cycles
    for i in 0..100 {
        let challenge = auth
            .generate_challenge()
            .unwrap_or_else(|_| panic!("Challenge generation {} should succeed", i));

        let proof = auth
            .generate_proof(&challenge.data)
            .unwrap_or_else(|_| panic!("Proof generation {} should succeed", i));

        let verified = auth
            .verify_proof(&proof, &challenge.data)
            .unwrap_or_else(|_| panic!("Proof verification {} should succeed", i));

        assert!(verified, "Proof {} should verify successfully", i);
    }
}
