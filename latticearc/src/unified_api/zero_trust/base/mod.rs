#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust authentication base implementation
//!
//! This module provides zero-knowledge proof based authentication using
//! Schnorr signatures on the secp256k1 curve.

mod auth;
mod constants;
mod proofs;
mod requests;
mod schnorr;
mod session;
mod types;

// Re-export public API
pub use auth::ZeroTrustAuth;
pub use constants::{CHALLENGE_LENGTH, PROOF_LENGTH, SESSION_ID_LENGTH, TOKEN_ID_LENGTH};
pub use proofs::{ProofOfPossessionToken, ZeroKnowledgeProof};
pub use requests::{AuthenticationRequest, AuthenticationResponse};
pub use schnorr::SchnorrProof;
pub use session::VerificationSession;
pub use types::{AuthenticationFactor, ProofMetadata, ProofType};

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};
    use std::time::Duration;

    #[test]
    fn test_generate_challenge() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let challenge = auth.generate_challenge("client1").expect("Failed to generate challenge");
        assert_eq!(challenge.len(), CHALLENGE_LENGTH);
    }

    #[test]
    fn test_generate_zkp() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let secret = vec![1u8; 32];
        let challenge = auth.generate_challenge("client1").expect("Failed to generate challenge");
        let proof = auth.generate_zkp(&secret, &challenge).expect("Failed to generate ZKP");
        assert!(proof.is_valid());
        assert_eq!(proof.proof_type, ProofType::Schnorr);
        // Schnorr proof should be 65 bytes (33 commitment + 32 response)
        assert_eq!(proof.proof_data.len(), 65);
    }

    #[test]
    fn test_verify_zkp_valid_proof() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");

        // Generate a key pair for proper Schnorr testing
        let secret_scalar = k256::elliptic_curve::Scalar::from_repr([1u8; 32]).unwrap();
        let public_key_point: ProjectivePoint = k256::ProjectivePoint::GENERATOR * secret_scalar;
        let secret_bytes = k256::elliptic_curve::scalar::Scalar::to_bytes(&secret_scalar).to_vec();
        let public_key_bytes = public_key_point.to_encoded_point(true).as_bytes().to_vec();

        let challenge = auth.generate_challenge("client1").expect("Failed to generate challenge");
        let proof = auth.generate_zkp(&secret_bytes, &challenge).expect("Failed to generate ZKP");

        // Verification with correct public key should succeed
        let verified = auth.verify_zkp(&proof, &challenge, &public_key_bytes).expect("Failed to verify");
        assert!(verified, "Proof should verify with correct public key");
    }

    #[test]
    fn test_verify_zkp_wrong_public_key() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");

        let secret_scalar = k256::elliptic_curve::Scalar::from_repr([1u8; 32]).unwrap();
        let secret_bytes = k256::elliptic_curve::scalar::Scalar::to_bytes(&secret_scalar).to_vec();

        // Create a different public key
        let wrong_secret_scalar = k256::elliptic_curve::Scalar::from_repr([2u8; 32]).unwrap();
        let wrong_public_key_point: ProjectivePoint = k256::ProjectivePoint::GENERATOR * wrong_secret_scalar;
        let wrong_public_key_bytes = wrong_public_key_point.to_encoded_point(true).as_bytes().to_vec();

        let challenge = auth.generate_challenge("client1").expect("Failed to generate challenge");
        let proof = auth.generate_zkp(&secret_bytes, &challenge).expect("Failed to generate ZKP");

        // Verification with wrong public key should fail
        let verified = auth.verify_zkp(&proof, &challenge, &wrong_public_key_bytes).expect("Failed to verify");
        assert!(!verified, "Proof should not verify with wrong public key");
    }

    #[test]
    fn test_verify_zkp_corrupted_proof() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");

        let secret_scalar = k256::elliptic_curve::Scalar::from_repr([1u8; 32]).unwrap();
        let public_key_point: ProjectivePoint = k256::ProjectivePoint::GENERATOR * secret_scalar;
        let secret_bytes = k256::elliptic_curve::scalar::Scalar::to_bytes(&secret_scalar).to_vec();
        let public_key_bytes = public_key_point.to_encoded_point(true).as_bytes().to_vec();

        let challenge = auth.generate_challenge("client1").expect("Failed to generate challenge");
        let mut proof = auth.generate_zkp(&secret_bytes, &challenge).expect("Failed to generate ZKP");

        // Corrupt the proof
        proof.proof_data[0] ^= 0xFF;

        // Verification with corrupted proof should fail
        let verified = auth.verify_zkp(&proof, &challenge, &public_key_bytes).expect("Failed to verify");
        assert!(!verified, "Proof should not verify when corrupted");
    }

    #[test]
    fn test_session_creation() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let session = auth.start_session("client1").expect("Failed to create session");
        assert!(!session.is_expired());
        assert!(!session.session_id.is_empty());
    }

    #[test]
    fn test_session_expiration() {
        let auth = ZeroTrustAuth::with_timeout(
            ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
                .expect("Failed to create auth"),
            Duration::from_millis(10),
        );
        let session = auth.start_session("client1").expect("Failed to create session");
        std::thread::sleep(Duration::from_millis(50));
        assert!(session.is_expired());
    }

    #[test]
    fn test_possession_token() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let key_pair = (vec![1u8; 32], crate::unified_api::types::PrivateKey::new(vec![2u8; 32]));
        let token =
            auth.generate_possession_token(&key_pair, "key1").expect("Failed to generate token");
        assert!(token.is_valid());
        assert_eq!(token.key_id, "key1");
    }

    #[test]
    fn test_possession_token_verification() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let public_key = vec![1u8; 32];
        let private_key_bytes = vec![2u8; 32];
        let key_pair = (public_key.clone(), crate::unified_api::types::PrivateKey::new(private_key_bytes.clone()));
        let token =
            auth.generate_possession_token(&key_pair, "key1").expect("Failed to generate token");

        // Verification with correct key should succeed
        let verified = auth.verify_possession_token(&token, &public_key)
            .expect("Verification should not error");
        assert!(verified, "Token verification should succeed with correct key");

        // Verification with wrong key should fail
        let wrong_key = vec![9u8; 32];
        let verified = auth.verify_possession_token(&token, &wrong_key)
            .expect("Verification should not error");
        assert!(!verified, "Token verification should fail with wrong key");
    }

    #[test]
    fn test_authentication_flow() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let client_id = "client1";

        // Generate a key pair for proper Schnorr testing
        let secret_scalar = k256::elliptic_curve::Scalar::from_repr([1u8; 32]).unwrap();
        let public_key_point: ProjectivePoint = k256::ProjectivePoint::GENERATOR * secret_scalar;
        let secret_bytes = k256::elliptic_curve::scalar::Scalar::to_bytes(&secret_scalar).to_vec();
        let public_key_bytes = public_key_point.to_encoded_point(true).as_bytes().to_vec();

        let challenge = auth.generate_challenge(client_id).expect("Failed to generate challenge");
        let proof = auth.generate_zkp(&secret_bytes, &challenge).expect("Failed to generate ZKP");
        let request = AuthenticationRequest::new(client_id.to_string(), challenge, proof);
        let response = auth.verify_authentication(&request, &public_key_bytes).expect("Failed to verify");
        assert!(response.success);
        assert!(response.session_id.is_some());
    }

    #[test]
    fn test_session_revocation() {
        let auth = ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
            .expect("Failed to create auth");
        let session = auth.start_session("client1").expect("Failed to create session");
        auth.revoke_session(&session.session_id).expect("Failed to revoke session");
        let count = auth.active_session_count().expect("Failed to get count");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_cleanup_expired_sessions() {
        let auth = ZeroTrustAuth::with_timeout(
            ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)
                .expect("Failed to create auth"),
            Duration::from_millis(10),
        );
        auth.start_session("client1").expect("Failed to create session");
        std::thread::sleep(Duration::from_millis(50));
        let cleaned = auth.cleanup_expired_sessions().expect("Failed to cleanup");
        assert_eq!(cleaned, 1);
    }
}
