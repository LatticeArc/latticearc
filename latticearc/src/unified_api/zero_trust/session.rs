//! `ZeroTrustSession`: manual challenge/proof/verify authentication flow,
//! convertible into a [`super::VerifiedSession`].

use super::{Challenge, VerifiedSession, ZeroKnowledgeProof, ZeroTrustAuth};
use crate::log_zero_trust_session_verification_failed;
use crate::types::traits::ZeroTrustAuthenticable;
use crate::unified_api::error::{CoreError, Result};
use chrono::{DateTime, Utc};

/// A zero-trust session managing the authentication flow.
pub struct ZeroTrustSession {
    /// The underlying authentication handler.
    pub(crate) auth: ZeroTrustAuth,
    /// Current active challenge, if any.
    challenge: Option<Challenge>,
    /// Whether the session has been verified.
    verified: bool,
    /// When the session started.
    session_start: DateTime<Utc>,
}

impl ZeroTrustSession {
    /// Creates a new zero-trust session.
    #[must_use]
    pub fn new(auth: ZeroTrustAuth) -> Self {
        Self { auth, challenge: None, verified: false, session_start: Utc::now() }
    }

    /// Initiates the authentication flow by generating a new challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::EntropyDepleted` if the system cannot generate random bytes
    /// for the challenge.
    pub fn initiate_authentication(&mut self) -> Result<Challenge> {
        let challenge = self.auth.generate_challenge()?;
        self.challenge = Some(challenge.clone());
        Ok(challenge)
    }

    /// Verifies a proof response against the active challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if:
    /// - No challenge has been initiated (no active challenge).
    /// - The challenge has expired.
    /// - The proof format is invalid for Medium/High complexity proofs.
    ///
    /// Returns `CoreError::InvalidInput` if the public key or signature format is invalid
    /// during Ed25519 verification.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the public key has incorrect length.
    pub fn verify_response(&mut self, proof: &ZeroKnowledgeProof) -> Result<bool> {
        // Pattern-6: collapse the "no active challenge" and "challenge
        // expired" cases to a single fixed string in the typed error
        // AND in the SIEM audit log. Both are caller-protocol mistakes
        // (not adversary-controllable crypto material), but distinct
        // strings let an attacker mapping the protocol state machine
        // fingerprint which check tripped. The discriminator goes to
        // `tracing::debug!` for operator visibility, mirroring
        // `verify_pop`'s posture.
        const VERIFY_RESPONSE_FAILED: &str = "challenge verification failed";

        let challenge = self.challenge.as_ref().ok_or_else(|| {
            log_zero_trust_session_verification_failed!("pending", VERIFY_RESPONSE_FAILED);
            tracing::debug!("verify_response rejected: no active challenge");
            CoreError::AuthenticationFailed(VERIFY_RESPONSE_FAILED.to_string())
        })?;

        if challenge.is_expired() {
            log_zero_trust_session_verification_failed!("pending", VERIFY_RESPONSE_FAILED);
            tracing::debug!("verify_response rejected: challenge expired");
            return Err(CoreError::AuthenticationFailed(VERIFY_RESPONSE_FAILED.to_string()));
        }

        // Snapshot challenge data, then immediately consume the
        // challenge regardless of verification outcome. Without this,
        // a captured (challenge, proof) pair on the wire is bit-for-bit
        // replayable against the SAME ZeroTrustSession instance within
        // the `challenge_timeout_ms` window (Ed25519 is deterministic
        // per RFC 8032; the proof bytes don't change). Mirrors the
        // posture of `verify_pop` (which uses `pop_replay_cache` for
        // the same attack class). Off-machine replay defense still
        // requires transport-binding (TLS); see SECURITY.md.
        let challenge_data = challenge.data().to_vec();
        self.challenge = None;

        let verified = self.auth.verify_proof(proof, &challenge_data)?;
        self.verified = verified;

        if !verified {
            log_zero_trust_session_verification_failed!("pending", "Proof verification failed");
        }

        Ok(self.verified)
    }

    /// Generates a zero-knowledge proof for the given challenge.
    ///
    /// This is used in the manual authentication flow: after calling
    /// [`initiate_authentication`](Self::initiate_authentication) to get a challenge,
    /// generate a proof and then pass it to [`verify_response`](Self::verify_response).
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if the challenge data is empty.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the private key has incorrect length.
    ///
    /// Returns `CoreError::InvalidInput` if the private key format is invalid.
    pub fn generate_proof(&self, challenge: &Challenge) -> Result<ZeroKnowledgeProof> {
        self.auth.generate_proof(challenge.data())
    }

    /// Returns `true` if the session has been successfully authenticated.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.verified
    }

    /// Returns the age of the session in milliseconds since creation.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    pub fn session_age_ms(&self) -> Result<u64> {
        let elapsed = Utc::now().signed_duration_since(self.session_start);
        // Convert safely: negative elapsed times treated as 0 (just started)
        let elapsed_u64 = u64::try_from(elapsed.num_milliseconds()).unwrap_or(0);
        Ok(elapsed_u64)
    }

    /// Convert this session into a `VerifiedSession` after successful authentication.
    ///
    /// This consumes the `ZeroTrustSession` and returns a `VerifiedSession` that
    /// can be used to authorize cryptographic operations.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationRequired` if the session has not been
    /// successfully authenticated via `verify_response()`.
    ///
    /// Returns `CoreError::EntropyDepleted` if session ID generation fails.
    pub fn into_verified(self) -> Result<VerifiedSession> {
        VerifiedSession::from_authenticated(&self)
    }
}
