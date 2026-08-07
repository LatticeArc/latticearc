//! Unit and integration tests for the `zero_trust` module, covering
//! `TrustLevel`, `SecurityMode`, `VerifiedSession`, `ZeroTrustAuth`,
//! `Challenge`, `ZeroTrustSession`, and `ProofComplexity` interactions.
#![expect(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::useless_vec,
    unused_qualifications,
    reason = "test/bench scaffolding: lints suppressed for this module"
)]

use super::*;
use crate::types::PublicKey;
use crate::types::traits::{
    ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable,
};
use crate::unified_api::error::{CoreError, Result};
use crate::unified_api::{ProofComplexity, ZeroTrustConfig, generate_keypair};
use chrono::{Duration, Utc};

/// Test helper: drive `auth` through a successful challenge-response
/// so subsequent calls to `start_continuous_verification` clear the
/// "must verify at least once" precondition.
fn warm_up_auth(auth: &ZeroTrustAuth) -> Result<()> {
    let challenge = auth.generate_challenge()?;
    let proof = auth.generate_proof(challenge.data())?;
    let verified = auth.verify_proof(&proof, challenge.data())?;
    assert!(verified, "warm-up proof must verify");
    Ok(())
}

// TrustLevel tests
#[test]
fn test_trust_level_default_has_correct_value_succeeds() {
    let level = TrustLevel::default();
    assert_eq!(level, TrustLevel::Untrusted);
}

#[test]
fn test_trust_level_variants_are_correct() {
    assert_eq!(TrustLevel::Untrusted as i32, 0);
    assert_eq!(TrustLevel::Partial as i32, 1);
    assert_eq!(TrustLevel::Trusted as i32, 2);
    assert_eq!(TrustLevel::FullyTrusted as i32, 3);
}

#[test]
fn test_trust_level_is_trusted_succeeds() {
    assert!(!TrustLevel::Untrusted.is_trusted());
    assert!(TrustLevel::Partial.is_trusted());
    assert!(TrustLevel::Trusted.is_trusted());
    assert!(TrustLevel::FullyTrusted.is_trusted());
}

#[test]
fn test_trust_level_is_fully_trusted_succeeds() {
    assert!(!TrustLevel::Untrusted.is_fully_trusted());
    assert!(!TrustLevel::Partial.is_fully_trusted());
    assert!(!TrustLevel::Trusted.is_fully_trusted());
    assert!(TrustLevel::FullyTrusted.is_fully_trusted());
}

#[test]
fn test_trust_level_ordering_is_correct() {
    assert!(TrustLevel::Untrusted < TrustLevel::Partial);
    assert!(TrustLevel::Partial < TrustLevel::Trusted);
    assert!(TrustLevel::Trusted < TrustLevel::FullyTrusted);
}

// SecurityMode tests
#[test]
fn test_security_mode_unverified_is_unverified_succeeds() {
    let mode = SecurityMode::Unverified;
    assert!(mode.is_unverified());
    assert!(!mode.is_verified());
}

#[test]
fn test_security_mode_validate_unverified_succeeds() -> Result<()> {
    let mode = SecurityMode::Unverified;
    mode.validate()?;
    Ok(())
}

// VerifiedSession tests
#[test]
fn test_verified_session_establish_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    assert!(session.is_valid());
    // After self-authentication during establish, trust level is upgraded
    assert!(session.trust_level() >= TrustLevel::Partial);
    Ok(())
}

#[test]
fn test_verified_session_session_id_is_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let session_id = session.session_id();
    assert_eq!(session_id.len(), 32);
    Ok(())
}

#[test]
fn test_verified_session_public_key_is_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let pk = session.public_key();
    assert!(!pk.is_empty());
    Ok(())
}

#[test]
fn test_verified_session_timestamps_are_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let authenticated_at = session.authenticated_at();
    let expires_at = session.expires_at();

    assert!(expires_at > authenticated_at, "Session should expire after authentication");
    Ok(())
}

#[test]
fn test_verified_session_verify_valid_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    session.verify_valid()?;
    Ok(())
}

#[test]
fn test_security_mode_verified_with_session_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let mode = SecurityMode::Verified(&session);
    assert!(mode.is_verified());
    assert!(!mode.is_unverified());
    Ok(())
}

#[test]
fn test_security_mode_verified_validate_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let mode = SecurityMode::Verified(&session);
    mode.validate()?;
    Ok(())
}

#[test]
fn test_security_mode_verified_session_is_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let mode = SecurityMode::Verified(&session);
    assert!(mode.session().is_some());
    Ok(())
}

#[test]
fn test_security_mode_unverified_session_returns_none_succeeds() {
    let mode = SecurityMode::Unverified;
    assert!(mode.session().is_none());
}

// ZeroTrustAuth tests
#[test]
fn test_zero_trust_auth_new_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    // Just verify it was created successfully
    assert!(std::mem::size_of_val(&auth) > 0);
    Ok(())
}

#[test]
fn test_zero_trust_auth_with_config_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_timeout(10000).with_complexity(ProofComplexity::High);

    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
    assert!(std::mem::size_of_val(&auth) > 0);
    Ok(())
}

#[test]
fn test_zero_trust_auth_generate_challenge_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge = auth.generate_challenge()?;
    assert!(!challenge.is_expired());
    Ok(())
}

#[test]
fn test_zero_trust_auth_multiple_challenges_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge1 = auth.generate_challenge()?;
    let challenge2 = auth.generate_challenge()?;

    // Challenges should be different
    assert!(!challenge1.is_expired());
    assert!(!challenge2.is_expired());
    Ok(())
}

#[test]
fn test_zero_trust_auth_verify_challenge_age_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge = auth.generate_challenge()?;
    let is_valid = auth.verify_challenge_age(&challenge)?;

    assert!(is_valid, "Freshly generated challenge should be valid");
    Ok(())
}

#[test]
fn test_zero_trust_auth_start_continuous_verification_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    warm_up_auth(&auth)?;

    let continuous = auth.start_continuous_verification()?;
    let result = continuous.is_valid();

    assert!(result.is_ok());
    Ok(())
}

#[test]
fn test_start_continuous_verification_rejects_unverified_session() -> Result<()> {
    // A freshly-constructed `ZeroTrustAuth` (no successful proof
    // handshake) must NOT hand out a continuous session — that
    // path would bypass the ZKP gate entirely.
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let result = auth.start_continuous_verification();
    match result {
        Err(CoreError::AuthenticationFailed(_)) => Ok(()),
        other => panic!("expected AuthenticationFailed, got {:?}", other),
    }
}

// Challenge tests
#[test]
fn test_challenge_is_not_expired_when_fresh_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge = auth.generate_challenge()?;
    assert!(!challenge.is_expired());
    Ok(())
}

// ZeroTrustSession tests
#[test]
fn test_zero_trust_session_new_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let session = ZeroTrustSession::new(auth);
    assert!(!session.is_authenticated());
    Ok(())
}

#[test]
fn test_zero_trust_session_initiate_authentication_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let mut session = ZeroTrustSession::new(auth);
    let challenge = session.initiate_authentication()?;

    assert!(!challenge.is_expired());
    Ok(())
}

#[test]
fn test_zero_trust_session_is_not_authenticated_initially_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let session = ZeroTrustSession::new(auth);
    assert!(!session.is_authenticated());
    Ok(())
}

// ProofComplexity tests
#[test]
fn test_proof_complexity_variants_are_correct() {
    let _low = ProofComplexity::Low;
    let _medium = ProofComplexity::Medium;
    let _high = ProofComplexity::High;

    assert_eq!(ProofComplexity::Medium, ProofComplexity::Medium);
}

// Integration tests
#[test]
fn test_verified_session_with_multiple_instances_succeeds() -> Result<()> {
    // Test creating multiple sessions
    for _ in 0..3 {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
        assert!(session.is_valid());
    }
    Ok(())
}

#[test]
fn test_zero_trust_config_variations_all_succeed_succeeds() -> Result<()> {
    // Test with different configurations
    let configs = vec![
        ZeroTrustConfig::new().with_timeout(5000),
        ZeroTrustConfig::new().with_complexity(ProofComplexity::Low),
        ZeroTrustConfig::new().with_complexity(ProofComplexity::High),
        ZeroTrustConfig::new().with_continuous_verification(true),
        ZeroTrustConfig::new().with_verification_interval(60000),
    ];

    for config in configs {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
        let _challenge = auth.generate_challenge()?;
    }
    Ok(())
}

#[test]
fn test_trust_level_progression_is_correct() {
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

#[test]
fn test_verified_session_multiple_sessions_all_succeed_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;

    // Create multiple sessions with same keys
    let session1 = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
    let session2 = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    // Sessions should have different IDs
    assert!(session1.is_valid());
    assert!(session2.is_valid());
    assert_ne!(session1.session_id(), session2.session_id());
    Ok(())
}

#[test]
fn test_challenge_generation_produces_unique_challenges_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let mut challenges = Vec::new();
    for _ in 0..5 {
        challenges.push(auth.generate_challenge()?);
    }

    // All challenges should be valid
    for challenge in &challenges {
        assert!(!challenge.is_expired());
    }
    Ok(())
}

#[test]
fn test_continuous_session_validation_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_continuous_verification(true);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    warm_up_auth(&auth)?;

    let continuous = auth.start_continuous_verification()?;
    assert!(continuous.is_valid().is_ok());
    Ok(())
}

#[test]
fn test_zero_trust_auth_with_all_complexity_levels_succeeds() -> Result<()> {
    let complexities = vec![ProofComplexity::Low, ProofComplexity::Medium, ProofComplexity::High];

    for complexity in complexities {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(complexity);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
        let challenge = auth.generate_challenge()?;
        assert!(!challenge.is_expired());
    }
    Ok(())
}

// ========================================================================
// Coverage: SecurityMode default/from, VerifiedSession edge cases
// ========================================================================

#[test]
fn test_security_mode_explicit_unverified_succeeds() {
    // Pinning the explicit-construction shape after `impl Default for
    // SecurityMode` was removed. Callers must
    // now opt into `Unverified` by name; this test guards the variant's
    // behaviour, not the (deliberately-absent) `Default` impl.
    let mode = SecurityMode::Unverified;
    assert!(mode.is_unverified());
    assert!(!mode.is_verified());
    assert!(mode.session().is_none());
}

#[test]
fn test_security_mode_from_verified_session_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    let mode: SecurityMode = SecurityMode::from(&session);
    assert!(mode.is_verified());
    assert!(mode.session().is_some());
    Ok(())
}

#[test]
fn test_verified_session_from_unauthenticated_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;
    let session = ZeroTrustSession::new(auth);

    // Session is not authenticated yet
    assert!(!session.is_authenticated());
    let result = session.into_verified();
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_zero_trust_session_verify_response_returns_error_without_challenge_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;
    let mut session = ZeroTrustSession::new(auth);

    // Try verify without initiating authentication
    let fake_proof =
        ZeroKnowledgeProof::new(vec![1, 2, 3], vec![0u8; 64], Utc::now(), ProofComplexity::Low);
    let result = session.verify_response(&fake_proof);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_zero_trust_session_verify_response_consumes_challenge_replay_blocked() -> Result<()> {
    // Regression test: verify_response must consume the challenge so a
    // captured (challenge, proof) pair on the wire cannot be replayed
    // against the same session within the challenge_timeout_ms window.
    // Ed25519 is deterministic per RFC 8032, so the proof bytes are
    // bit-for-bit reusable; the defense is server-side challenge
    // single-use.
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;
    let mut session = ZeroTrustSession::new(auth);

    let challenge = session.initiate_authentication()?;
    let proof = session.generate_proof(&challenge)?;

    // First verify succeeds.
    assert!(session.verify_response(&proof)?, "first verify_response must accept");

    // Second verify with the SAME proof must reject — the challenge
    // is now consumed (set to None inside verify_response). The
    // exact error variant is opaque (Pattern-6), but we assert the
    // err shape is `AuthenticationFailed` to lock the contract.
    let replay = session.verify_response(&proof);
    match replay {
        Err(CoreError::AuthenticationFailed(_)) => Ok(()),
        other => panic!("replay must reject with AuthenticationFailed, got {other:?}"),
    }
}

#[test]
fn test_zero_trust_session_session_age_ms_is_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;
    let session = ZeroTrustSession::new(auth);

    let age = session.session_age_ms()?;
    // Just created, should be very small
    assert!(age < 5000, "Session age should be < 5 seconds, got {}ms", age);
    Ok(())
}

#[test]
fn test_continuous_session_auth_public_key_is_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key.clone(), private_key)?;

    warm_up_auth(&auth)?;

    let continuous = auth.start_continuous_verification()?;
    assert_eq!(continuous.auth_public_key(), &public_key);
    Ok(())
}

/// M-update_verification: `ContinuousSession::update_verification`
/// was removed because it was a public, proof-less clock bump and
/// had no in-crate non-test callers. Refresh must route through
/// `ZeroTrustAuth::reauthenticate`, which is proof-gated.
#[test]
fn test_continuous_session_refresh_via_reauthenticate() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    warm_up_auth(&auth)?;

    let continuous = auth.start_continuous_verification()?;
    assert!(continuous.is_valid()?);

    auth.reauthenticate()?;
    Ok(())
}

#[test]
fn test_zero_knowledge_proof_has_valid_format_has_correct_size() {
    // Valid format
    let valid =
        ZeroKnowledgeProof::new(vec![1, 2, 3], vec![0u8; 64], Utc::now(), ProofComplexity::Low);
    assert!(valid.is_valid_format());

    // Empty challenge
    let empty_challenge =
        ZeroKnowledgeProof::new(vec![], vec![0u8; 64], Utc::now(), ProofComplexity::Low);
    assert!(!empty_challenge.is_valid_format());

    // Empty proof
    let empty_proof = ZeroKnowledgeProof::new(vec![1], vec![], Utc::now(), ProofComplexity::Low);
    assert!(!empty_proof.is_valid_format());
}

#[test]
fn test_zero_trust_auth_reauthenticate_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    // Reauthenticate should succeed
    auth.reauthenticate()?;
    Ok(())
}

#[test]
fn test_zero_trust_auth_verify_continuously_verified_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    // Default config has `continuous_verification = true`, so the
    // status now depends on `last_verification`. Drive a successful
    // proof to bump it; without this warm-up the M9/M10 gate
    // correctly reports `Pending` for a never-verified instance.
    warm_up_auth(&auth)?;

    let status = auth.verify_continuously()?;
    assert_eq!(status, VerificationStatus::Verified);
    Ok(())
}

#[test]
fn test_zero_trust_auth_verify_continuously_with_cv_enabled_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(60000);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    warm_up_auth(&auth)?;

    let status = auth.verify_continuously()?;
    // Within the 60 s interval, just-warmed-up auth reports Verified.
    assert_eq!(status, VerificationStatus::Verified);
    Ok(())
}

#[test]
fn test_verify_continuously_pending_before_first_proof() -> Result<()> {
    // M9/M10 regression guard: with `continuous_verification`
    // enabled, a freshly-constructed auth that has never
    // completed a proof must report `Pending`, not `Verified`.
    let (public_key, private_key) = generate_keypair()?;
    let config =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(60000);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let status = auth.verify_continuously()?;
    assert_eq!(status, VerificationStatus::Pending);
    Ok(())
}

#[test]
fn test_generate_proof_returns_error_for_empty_challenge_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let result = auth.generate_proof(&[]);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_verify_proof_returns_error_for_wrong_challenge_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge = auth.generate_challenge()?;
    let proof = auth.generate_proof(challenge.data())?;

    // Verify with a different challenge should fail
    let different_challenge = vec![0xFF; 32];
    let result = auth.verify_proof(&proof, &different_challenge)?;
    assert!(!result);
    Ok(())
}

#[test]
fn test_verify_proof_returns_error_for_short_proof_data_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let challenge_data = vec![1u8; 32];
    let short_proof = ZeroKnowledgeProof::new(
        challenge_data.clone(),
        vec![0u8; 10], // Too short (< 64 bytes)
        Utc::now(),
        ProofComplexity::Low,
    );
    let result = auth.verify_proof(&short_proof, &challenge_data)?;
    assert!(!result);
    Ok(())
}

#[test]
fn test_full_challenge_response_low_complexity_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    let proof = auth.generate_proof(challenge.data())?;
    let verified = auth.verify_proof(&proof, challenge.data())?;
    assert!(verified);
    Ok(())
}

#[test]
fn test_full_challenge_response_medium_complexity_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    let proof = auth.generate_proof(challenge.data())?;
    let verified = auth.verify_proof(&proof, challenge.data())?;
    assert!(verified);
    Ok(())
}

#[test]
fn test_full_challenge_response_high_complexity_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    let proof = auth.generate_proof(challenge.data())?;
    let verified = auth.verify_proof(&proof, challenge.data())?;
    assert!(verified);
    Ok(())
}

#[test]
fn test_proof_of_possession_roundtrip() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;

    let pop = auth.generate_pop(b"unit-test-challenge")?;
    let verified = auth.verify_pop(&pop, b"unit-test-challenge")?;
    assert!(verified);
    Ok(())
}

#[test]
fn test_full_session_flow_with_into_verified_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let auth = ZeroTrustAuth::new(public_key, private_key)?;
    let mut session = ZeroTrustSession::new(auth);

    // Initiate -> prove -> verify -> convert
    let challenge = session.initiate_authentication()?;
    let proof = session.auth.generate_proof(challenge.data())?;
    let verified = session.verify_response(&proof)?;
    assert!(verified);
    assert!(session.is_authenticated());

    let verified_session = session.into_verified()?;
    assert!(verified_session.is_valid());
    assert_eq!(verified_session.trust_level(), TrustLevel::Trusted);
    Ok(())
}

#[test]
fn test_verified_session_debug_has_correct_format() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    // VerifiedSession does not implement Clone (sessions are non-cloneable by design).
    // Verify Debug output instead.
    let debug = format!("{:?}", session);
    assert!(debug.contains("VerifiedSession"));
    Ok(())
}

#[test]
fn test_security_mode_debug_has_correct_format() -> Result<()> {
    let mode = SecurityMode::Unverified;
    let debug = format!("{:?}", mode);
    assert!(debug.contains("Unverified"));

    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
    let verified_mode = SecurityMode::Verified(&session);
    let debug2 = format!("{:?}", verified_mode);
    assert!(debug2.contains("Verified"));
    Ok(())
}

#[test]
fn test_challenge_fields_are_accessible() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_timeout(5000).with_complexity(ProofComplexity::High);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    assert_eq!(challenge.data().len(), 128); // High complexity = 128 bytes
    assert_eq!(challenge.timeout_ms(), 5000);
    assert!(!challenge.is_expired());

    let debug = format!("{:?}", challenge);
    assert!(debug.contains("Challenge"));
    Ok(())
}

// ========================================================================
// Expired session coverage
// ========================================================================

#[test]
fn test_verified_session_expired_verify_valid_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    // Manually create an expired session by setting expires_at in the past
    // force expiry via the monotonic path. Wall-clock
    // `expires_at` is now audit-only; `is_valid` consults
    // `issued_at_monotonic` + `lifetime`, so we set
    // `lifetime = 0ns` to make `Instant::elapsed()` exceed it
    // immediately.
    let expired_session = VerifiedSession {
        session_id: *session.session_id(),
        authenticated_at: session.authenticated_at(),
        trust_level: session.trust_level(),
        public_key: session.public_key().clone(),
        expires_at: Utc::now() - Duration::seconds(1),
        issued_at_monotonic: std::time::Instant::now(),
        lifetime: std::time::Duration::from_nanos(0),
    };
    assert!(!expired_session.is_valid());

    let result = expired_session.verify_valid();
    assert!(result.is_err(), "Expired session should fail verify_valid");
    match result {
        Err(CoreError::SessionExpired) => {} // expected
        other => panic!("Expected SessionExpired, got: {:?}", other),
    }
    Ok(())
}

#[test]
fn test_security_mode_validate_expired_session_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

    // force expiry via the monotonic path. Wall-clock
    // `expires_at` is now audit-only; `is_valid` consults
    // `issued_at_monotonic` + `lifetime`, so we set
    // `lifetime = 0ns` to make `Instant::elapsed()` exceed it
    // immediately.
    let expired_session = VerifiedSession {
        session_id: *session.session_id(),
        authenticated_at: session.authenticated_at(),
        trust_level: session.trust_level(),
        public_key: session.public_key().clone(),
        expires_at: Utc::now() - Duration::seconds(1),
        issued_at_monotonic: std::time::Instant::now(),
        lifetime: std::time::Duration::from_nanos(0),
    };

    let mode = SecurityMode::Verified(&expired_session);
    let result = mode.validate();
    assert!(result.is_err(), "Expired session in SecurityMode should fail validation");
    Ok(())
}

// ========================================================================
// Continuous verification edge cases
// ========================================================================

#[test]
fn test_continuous_verification_pending_after_interval_succeeds() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    // Set verification_interval to 1ms so it immediately triggers Pending
    let config =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(1);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    // Sleep to ensure we're past 1ms interval
    std::thread::sleep(std::time::Duration::from_millis(5));

    let status = auth.verify_continuously()?;
    assert_eq!(status, VerificationStatus::Pending, "Should be Pending after interval elapsed");
    Ok(())
}

#[test]
fn test_challenge_generation_low_complexity_has_correct_size() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    assert_eq!(challenge.data().len(), 32, "Low complexity = 32 bytes");
    Ok(())
}

#[test]
fn test_challenge_generation_medium_complexity_has_correct_size() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge = auth.generate_challenge()?;
    assert_eq!(challenge.data().len(), 64, "Medium complexity = 64 bytes");
    Ok(())
}

#[test]
fn test_verify_proof_medium_short_proof_rejects_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge_data = vec![1u8; 64];
    // Proof is 64 bytes (just signature, no timestamp) — too short for Medium (needs 72)
    let short_proof = ZeroKnowledgeProof::new(
        challenge_data.clone(),
        vec![0u8; 64],
        Utc::now(),
        ProofComplexity::Medium,
    );
    let result = auth.verify_proof(&short_proof, &challenge_data)?;
    assert!(!result, "Medium-complexity proof without timestamp should fail");
    Ok(())
}

#[test]
fn test_verify_proof_high_short_proof_rejects_fails() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

    let challenge_data = vec![1u8; 128];
    // Proof is 70 bytes — too short for High (needs 72)
    let short_proof = ZeroKnowledgeProof::new(
        challenge_data.clone(),
        vec![0u8; 70],
        Utc::now(),
        ProofComplexity::High,
    );
    let result = auth.verify_proof(&short_proof, &challenge_data)?;
    assert!(!result, "High-complexity proof too short should fail");
    Ok(())
}

// regression coverage for the
// L-3 fix that capped forward clock-skew tolerance at
// 30 s on `verify_proof`. Previously `now_ms.abs_diff(proof_ts_ms)
// > 300_000` allowed proofs up to 5 min in the future; an
// attacker with a forward-skewed clock got a 10-min replay
// window. The fix added `if proof_ts_ms > now_ms + 30_000 {
// return Ok(false); }` to all three ProofComplexity paths.
// These tests assert that a 31 s-ahead timestamp is rejected on
// each path, locking in the contract against future refactors
// that might reorder the gates.
//
// Helper: forge a proof whose embedded timestamp is `skew_ms`
// ahead of "now". The forged signature is invalid against the
// forged message; the future-skew check should reject BEFORE
// signature verification, so the test asserts `Ok(false)`
// regardless of signature validity.
fn forge_future_skewed_proof(skew_ms: i64, complexity: ProofComplexity) -> ZeroKnowledgeProof {
    let now_ms = Utc::now().timestamp_millis();
    let future_ts = now_ms.saturating_add(skew_ms);
    let timestamp_bytes = future_ts.to_le_bytes();
    let mut proof_data = vec![0u8; 64]; // dummy 64-byte signature
    proof_data.extend_from_slice(&timestamp_bytes);
    ZeroKnowledgeProof::new(vec![1u8; 32], proof_data, Utc::now(), complexity)
}

#[test]
fn test_verify_proof_low_rejects_31s_future_timestamp() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
    let challenge = vec![1u8; 32];
    let proof = forge_future_skewed_proof(31_000, ProofComplexity::Low);
    let result = auth.verify_proof(&proof, &challenge)?;
    assert!(!result, "Low: 31 s future-skew must reject before signature check");
    Ok(())
}

#[test]
fn test_verify_proof_medium_rejects_31s_future_timestamp() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
    let challenge = vec![1u8; 32];
    let proof = forge_future_skewed_proof(31_000, ProofComplexity::Medium);
    let result = auth.verify_proof(&proof, &challenge)?;
    assert!(!result, "Medium: 31 s future-skew must reject before signature check");
    Ok(())
}

#[test]
fn test_verify_proof_high_rejects_31s_future_timestamp() -> Result<()> {
    let (public_key, private_key) = generate_keypair()?;
    let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
    let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
    let challenge = vec![1u8; 32];
    let proof = forge_future_skewed_proof(31_000, ProofComplexity::High);
    let result = auth.verify_proof(&proof, &challenge)?;
    assert!(!result, "High: 31 s future-skew must reject before signature check");
    Ok(())
}

#[test]
fn test_zero_knowledge_proof_debug_and_clone_succeeds() {
    let proof =
        ZeroKnowledgeProof::new(vec![1, 2, 3], vec![0u8; 64], Utc::now(), ProofComplexity::Low);
    let cloned = proof.clone();
    assert_eq!(cloned.challenge(), proof.challenge());
    assert_eq!(cloned.proof_data(), proof.proof_data());
    let debug = format!("{:?}", proof);
    assert!(debug.contains("ZeroKnowledgeProof"));
}

#[test]
fn test_proof_of_possession_data_debug_and_clone_succeeds() {
    let pop = ProofOfPossessionData::new(PublicKey::new(vec![1, 2, 3]), vec![0u8; 64], Utc::now());
    let cloned = pop.clone();
    assert_eq!(cloned.public_key(), pop.public_key());
    let debug = format!("{:?}", pop);
    assert!(debug.contains("ProofOfPossessionData"));
}

// =========================================================================
// Pattern P4: ZeroTrustConfig Parameter Influence Tests
// Each test proves changing ONLY one field changes the observable output.
// =========================================================================

#[test]
fn test_challenge_timeout_ms_influences_challenge_timeout_succeeds() -> Result<()> {
    let (public_key_a, private_key_a) = generate_keypair()?;
    let config_a = ZeroTrustConfig::new().with_timeout(1000);
    let auth_a = ZeroTrustAuth::with_config(public_key_a, private_key_a, config_a)?;
    let challenge_a = auth_a.generate_challenge()?;

    let (public_key_b, private_key_b) = generate_keypair()?;
    let config_b = ZeroTrustConfig::new().with_timeout(9999);
    let auth_b = ZeroTrustAuth::with_config(public_key_b, private_key_b, config_b)?;
    let challenge_b = auth_b.generate_challenge()?;

    assert_ne!(
        challenge_a.timeout_ms(),
        challenge_b.timeout_ms(),
        "challenge_timeout_ms must influence the timeout embedded in generated challenges"
    );
    Ok(())
}

#[test]
fn test_proof_complexity_influences_challenge_data_size_has_correct_size() -> Result<()> {
    let (public_key_a, private_key_a) = generate_keypair()?;
    let config_a = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
    let auth_a = ZeroTrustAuth::with_config(public_key_a, private_key_a, config_a)?;
    let challenge_a = auth_a.generate_challenge()?;

    let (public_key_b, private_key_b) = generate_keypair()?;
    let config_b = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
    let auth_b = ZeroTrustAuth::with_config(public_key_b, private_key_b, config_b)?;
    let challenge_b = auth_b.generate_challenge()?;

    // Low => 32-byte challenge, High => 128-byte challenge
    assert_ne!(
        challenge_a.data().len(),
        challenge_b.data().len(),
        "proof_complexity must influence the size of generated challenge data"
    );
    assert_eq!(challenge_a.data().len(), 32, "Low complexity must produce 32-byte challenge");
    assert_eq!(challenge_b.data().len(), 128, "High complexity must produce 128-byte challenge");
    Ok(())
}

#[test]
fn test_proof_complexity_influences_proof_data_size_has_correct_size() -> Result<()> {
    // Low now also carries the
    // 8-byte timestamp suffix (mandatory replay protection), so Low
    // and Medium are byte-identical (72 bytes = signature + ts).
    // The remaining functional difference is that High additionally
    // binds the public key into the signed message — but that does
    // NOT change the proof-data length (the timestamp suffix is the
    // same shape). This test now asserts the floor invariant: every
    // complexity level produces at least 72 bytes (sig + ts).
    let (public_key_a, private_key_a) = generate_keypair()?;
    let config_a = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
    let auth_a = ZeroTrustAuth::with_config(public_key_a, private_key_a, config_a)?;
    let challenge_a = auth_a.generate_challenge()?;
    let proof_a = auth_a.generate_proof(challenge_a.data())?;

    let (public_key_b, private_key_b) = generate_keypair()?;
    let config_b = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
    let auth_b = ZeroTrustAuth::with_config(public_key_b, private_key_b, config_b)?;
    let challenge_b = auth_b.generate_challenge()?;
    let proof_b = auth_b.generate_proof(challenge_b.data())?;

    assert!(
        proof_a.proof_data().len() >= 72,
        "Low proof must be at least 72 bytes (signature + 8-byte timestamp), got {}",
        proof_a.proof_data().len()
    );
    assert!(
        proof_b.proof_data().len() >= 72,
        "High proof must be at least 72 bytes, got {}",
        proof_b.proof_data().len()
    );
    Ok(())
}

#[test]
fn test_continuous_verification_influences_verify_continuously_succeeds() -> Result<()> {
    let (public_key_a, private_key_a) = generate_keypair()?;
    // continuous_verification=false: verify_continuously returns Verified immediately
    let config_a =
        ZeroTrustConfig::new().with_continuous_verification(false).with_verification_interval(1); // 1ms interval — irrelevant when cv=false
    let auth_a = ZeroTrustAuth::with_config(public_key_a, private_key_a, config_a)?;

    let (public_key_b, private_key_b) = generate_keypair()?;
    // continuous_verification=true with 1ms interval triggers Pending immediately
    let config_b =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(1);
    let auth_b = ZeroTrustAuth::with_config(public_key_b, private_key_b, config_b)?;

    // Sleep to ensure the 1ms verification interval elapses for auth_b
    std::thread::sleep(std::time::Duration::from_millis(5));

    // auth_a (cv=false) must stay Verified since cv is disabled
    let status_a = auth_a.verify_continuously()?;
    // auth_b (cv=true, 1ms) must go Pending after the interval elapses
    let status_b = auth_b.verify_continuously()?;

    // cv=false → Verified; cv=true + 1ms → Pending (interval already elapsed)
    assert_eq!(
        status_a,
        VerificationStatus::Verified,
        "continuous_verification=false must return Verified without interval check"
    );
    assert_eq!(
        status_b,
        VerificationStatus::Pending,
        "continuous_verification=true with 1ms interval must return Pending after elapsed"
    );
    Ok(())
}

#[test]
fn test_verification_interval_ms_influences_continuous_session_validity_succeeds() -> Result<()> {
    let (public_key_a, private_key_a) = generate_keypair()?;
    // Very short interval (1ms): is_valid() will return false almost immediately
    let config_a =
        ZeroTrustConfig::new().with_continuous_verification(true).with_verification_interval(1);
    let auth_a = ZeroTrustAuth::with_config(public_key_a, private_key_a, config_a)?;

    let (public_key_b, private_key_b) = generate_keypair()?;
    // Long interval (1 hour): is_valid() stays true
    let config_b = ZeroTrustConfig::new()
        .with_continuous_verification(true)
        .with_verification_interval(3_600_000);
    let auth_b = ZeroTrustAuth::with_config(public_key_b, private_key_b, config_b)?;

    warm_up_auth(&auth_a)?;
    warm_up_auth(&auth_b)?;

    let session_a = auth_a.start_continuous_verification()?;
    let session_b = auth_b.start_continuous_verification()?;

    // Let 1ms pass so the short-interval session expires
    std::thread::sleep(std::time::Duration::from_millis(5));

    let valid_a = session_a.is_valid()?;
    let valid_b = session_b.is_valid()?;

    assert_ne!(
        valid_a, valid_b,
        "verification_interval_ms must influence continuous session validity"
    );
    assert!(!valid_a, "1ms interval session must be invalid after 5ms sleep");
    assert!(valid_b, "1-hour interval session must remain valid");
    Ok(())
}
