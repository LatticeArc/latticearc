//! Wire types for the challenge-response / proof-of-possession protocol:
//! `Challenge`, `ZeroKnowledgeProof`, `ProofOfPossessionData`, `ContinuousSession`.

use crate::types::PublicKey;
use crate::unified_api::{ProofComplexity, error::Result};
use chrono::{DateTime, Utc};

/// A cryptographic challenge for zero-trust authentication.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Random challenge data.
    ///
    /// `pub(super)`: constructed via struct literal by
    /// `zero_trust::auth::ZeroTrustAuth::generate_challenge`.
    pub(super) data: Vec<u8>,
    /// When the challenge was created.
    pub(super) timestamp: DateTime<Utc>,
    /// Required proof complexity.
    pub(super) complexity: ProofComplexity,
    /// Timeout in milliseconds.
    pub(super) timeout_ms: u64,
}

impl Challenge {
    /// Returns the random challenge bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the timestamp when the challenge was created.
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Returns the required proof complexity for this challenge.
    #[must_use]
    pub fn complexity(&self) -> &ProofComplexity {
        &self.complexity
    }

    /// Returns the timeout in milliseconds for this challenge.
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Returns `true` if the challenge has expired.
    ///
    /// A future-dated timestamp (negative elapsed — typically clock skew or
    /// a forged challenge) is treated as **expired**, matching
    /// `ZeroTrustAuth::verify_challenge_age`: we'd rather reject a confusing
    /// timestamp than accept one. Previously this returned `false` via
    /// `unwrap_or(0)`, inconsistent with the sibling helper and an accidental
    /// "future-stamped challenges live forever" footgun.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.timestamp);
        let elapsed_u64 = u64::try_from(elapsed.num_milliseconds()).unwrap_or(u64::MAX);
        elapsed_u64 > self.timeout_ms
    }
}

/// A zero-knowledge proof response to a challenge.
#[derive(Debug, Clone)]
pub struct ZeroKnowledgeProof {
    /// The original challenge that was responded to.
    ///
    /// `pub(super)`: constructed via struct literal by
    /// `zero_trust::auth::ZeroTrustAuth::generate_proof`.
    pub(super) challenge: Vec<u8>,
    /// The cryptographic proof data.
    pub(super) proof: Vec<u8>,
    /// When the proof was generated.
    pub(super) timestamp: DateTime<Utc>,
    /// Complexity level of the proof.
    pub(super) complexity: ProofComplexity,
}

impl ZeroKnowledgeProof {
    /// Creates a new `ZeroKnowledgeProof` with the given fields.
    #[must_use]
    pub fn new(
        challenge: Vec<u8>,
        proof: Vec<u8>,
        timestamp: DateTime<Utc>,
        complexity: ProofComplexity,
    ) -> Self {
        Self { challenge, proof, timestamp, complexity }
    }

    /// Returns the challenge bytes this proof was generated for.
    #[must_use]
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// Returns the cryptographic proof data.
    #[must_use]
    pub fn proof_data(&self) -> &[u8] {
        &self.proof
    }

    /// Returns a mutable reference to the proof data (e.g., for tampering in tests).
    #[must_use]
    pub fn proof_data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.proof
    }

    /// Returns the timestamp when the proof was generated.
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Returns the complexity level of the proof.
    #[must_use]
    pub fn complexity(&self) -> &ProofComplexity {
        &self.complexity
    }

    /// Returns `true` if the proof has a valid format.
    #[must_use]
    pub fn is_valid_format(&self) -> bool {
        !self.challenge.is_empty() && !self.proof.is_empty() && self.timestamp <= Utc::now()
    }
}

/// Data proving possession of a private key.
#[derive(Debug, Clone)]
pub struct ProofOfPossessionData {
    /// Public key associated with the proof.
    ///
    /// `pub(super)`: constructed via struct literal by
    /// `zero_trust::auth::ZeroTrustAuth::generate_pop`.
    pub(super) public_key: PublicKey,
    /// Signature proving possession.
    pub(super) signature: Vec<u8>,
    /// When the proof was generated.
    pub(super) timestamp: DateTime<Utc>,
}

impl ProofOfPossessionData {
    /// Creates a new `ProofOfPossessionData` with the given fields.
    #[must_use]
    pub fn new(public_key: PublicKey, signature: Vec<u8>, timestamp: DateTime<Utc>) -> Self {
        Self { public_key, signature, timestamp }
    }

    /// Returns the public key associated with this proof.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns a mutable reference to the signature bytes (e.g., for tampering in tests).
    #[must_use]
    pub fn signature_mut(&mut self) -> &mut Vec<u8> {
        &mut self.signature
    }

    /// Returns the signature bytes proving possession.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns the timestamp when the proof was generated.
    #[must_use]
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }
}

/// A continuous verification session.
#[derive(Debug)]
pub struct ContinuousSession {
    /// Public key that authenticated the session.
    ///
    /// `pub(super)`: constructed via struct literal by
    /// `zero_trust::auth::ZeroTrustAuth::start_continuous_verification`.
    pub(super) auth_public_key: PublicKey,
    /// When the session started.
    pub(super) start_time: DateTime<Utc>,
    /// Verification interval in milliseconds.
    pub(super) verification_interval_ms: u64,
    /// Last successful verification timestamp.
    pub(super) last_verification: DateTime<Utc>,
}

impl ContinuousSession {
    /// Get the public key that authenticated this session
    #[must_use]
    pub fn auth_public_key(&self) -> &PublicKey {
        &self.auth_public_key
    }

    /// Timestamp of the last successful verification on this session.
    /// Exposed so callers (and tests) can observe the cached timestamp
    /// the validity window is computed from. (The former unauthenticated
    /// `update_verification` mutator was removed — see the module note —
    /// so this value only advances through real re-verification.)
    #[must_use]
    pub fn last_verification(&self) -> DateTime<Utc> {
        self.last_verification
    }

    /// Checks whether the continuous session is still valid.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    #[must_use = "session validity check should not be discarded — act on the boolean"]
    pub fn is_valid(&self) -> Result<bool> {
        let elapsed = Utc::now().signed_duration_since(self.start_time);

        let max_duration: u64 = 60 * 60 * 1000;

        // Convert safely: negative elapsed times treated as 0 (just started)
        let elapsed_u64 = u64::try_from(elapsed.num_milliseconds()).unwrap_or(0);
        if elapsed_u64 > max_duration {
            return Ok(false);
        }

        let verification_elapsed = Utc::now().signed_duration_since(self.last_verification);

        // Convert safely: negative elapsed times treated as 0 (just verified)
        let verification_elapsed_u64 =
            u64::try_from(verification_elapsed.num_milliseconds()).unwrap_or(0);
        Ok(verification_elapsed_u64 <= self.verification_interval_ms)
    }

    // M-update_verification: the pre-fix `pub fn update_verification`
    // bumped `self.last_verification` to `Utc::now()` with no proof —
    // equivalent to "extend my session forever" from anyone holding
    // `&mut ContinuousSession`. There were zero in-crate non-test
    // callers (verify_continuously / reauthenticate operate on
    // `ZeroTrustAuth.last_verification`, not the session-side copy),
    // so the method has been removed rather than merely cfg-gated.
    // Callers that legitimately need to refresh a continuous session
    // must route through `ZeroTrustAuth::reauthenticate`, which IS
    // proof-gated (generates challenge → generates proof → verifies →
    // bumps the auth-side clock).
}
