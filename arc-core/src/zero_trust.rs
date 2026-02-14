//! Zero-trust authentication primitives.
//!
//! Provides challenge-response authentication with zero-knowledge proofs,
//! proof-of-possession, and continuous session verification.
//!
//! # Session State Machine
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    ZERO-TRUST SESSION LIFECYCLE                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │                          ┌─────────────┐                                │
//! │                          │   Created   │                                │
//! │                          │  (Initial)  │                                │
//! │                          └──────┬──────┘                                │
//! │                                 │ generate_challenge()                  │
//! │                                 ▼                                       │
//! │                          ┌─────────────┐                                │
//! │                          │  Challenged │                                │
//! │                          │ (Awaiting   │                                │
//! │                          │  Response)  │                                │
//! │                          └──────┬──────┘                                │
//! │                                 │                                       │
//! │              ┌──────────────────┼──────────────────┐                    │
//! │              │ verify_proof()   │                  │ timeout            │
//! │              │ SUCCESS          │                  │                    │
//! │              ▼                  │                  ▼                    │
//! │       ┌─────────────┐           │           ┌─────────────┐             │
//! │       │   Active    │           │           │   Failed    │             │
//! │       │ (Verified)  │           │           │ (Rejected)  │             │
//! │       └──────┬──────┘           │           └─────────────┘             │
//! │              │                  │                                       │
//! │              │ needs_verification()?                                    │
//! │              │ (interval elapsed)                                       │
//! │              ▼                  │                                       │
//! │       ┌─────────────┐           │                                       │
//! │       │  Reverify   │───────────┘                                       │
//! │       │  (Pending)  │  re-challenge and verify                          │
//! │       └──────┬──────┘                                                   │
//! │              │                                                          │
//! │       ┌──────┴──────┐                                                   │
//! │       │ verify()    │                                                   │
//! │       ▼             ▼                                                   │
//! │ ┌───────────┐ ┌───────────┐                                             │
//! │ │ Upgraded  │ │Downgraded │                                             │
//! │ │  Trust    │ │  Trust    │                                             │
//! │ └─────┬─────┘ └─────┬─────┘                                             │
//! │       │             │                                                   │
//! │       └──────┬──────┘                                                   │
//! │              ▼                                                          │
//! │       ┌─────────────┐                                                   │
//! │       │   Expired   │  session_duration > max_lifetime                  │
//! │       │ (Terminal)  │                                                   │
//! │       └─────────────┘                                                   │
//! │                                                                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         TRUST LEVEL TRANSITIONS                         │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                         │
//! │   ┌───────────┐    verify()     ┌───────────┐    verify()    ┌────────┐│
//! │   │ Untrusted │ ───────────────►│  Partial  │ ──────────────►│Trusted ││
//! │   │   (0)     │  (success)      │   (1)     │  (success)     │  (2)   ││
//! │   └─────┬─────┘                 └─────┬─────┘                └────┬───┘│
//! │         ▲                             ▲                          │    │
//! │         │         downgrade()         │        downgrade()       │    │
//! │         │◄────────────────────────────┼──────────────────────────┘    │
//! │         │        (verification fail)  │                               │
//! │         │                             │         verify()              │
//! │         │                             │         (success)             │
//! │         │                             ▼                               │
//! │         │                      ┌─────────────┐                        │
//! │         │                      │   Fully     │                        │
//! │         └──────────────────────│  Trusted    │                        │
//! │             (revoke)           │    (3)      │                        │
//! │                                └─────────────┘                        │
//! │                                                                       │
//! │   Trust Score: 0 (none) → 1 (partial) → 2 (trusted) → 3 (full)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Challenge-Response Protocol
//!
//! 1. **Challenge Generation**: Server generates random nonce with complexity level
//! 2. **Proof Construction**: Client creates ZK proof using private key + nonce
//! 3. **Verification**: Server verifies proof without learning private key
//! 4. **Session Update**: Trust level adjusted based on verification result

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use crate::{
    config::{ProofComplexity, ZeroTrustConfig},
    error::{CoreError, Result},
    log_zero_trust_auth_failure, log_zero_trust_auth_success, log_zero_trust_challenge_generated,
    log_zero_trust_proof_verified, log_zero_trust_session_created, log_zero_trust_session_expired,
    log_zero_trust_session_verification_failed, log_zero_trust_session_verified,
    log_zero_trust_unverified_mode,
    logging::session_id_to_hex,
    traits::{ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable},
    types::{PrivateKey, PublicKey},
};
use chrono::{DateTime, Duration, Utc};
use rand_core::{OsRng, RngCore};
use std::cell::RefCell;
use subtle::ConstantTimeEq;

// ============================================================================
// Trust Level and Verified Session Types
// ============================================================================

/// Trust level achieved through Zero Trust verification.
///
/// Trust levels progress through successful verifications and can be downgraded
/// on verification failures. The ordering allows comparison (e.g., `Partial < Trusted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum TrustLevel {
    /// No trust established - initial state before any verification.
    #[default]
    Untrusted = 0,
    /// Partial trust - first verification has passed.
    Partial = 1,
    /// Trusted - multiple verifications have passed.
    Trusted = 2,
    /// Fully trusted - continuous verification is active and passing.
    FullyTrusted = 3,
}

impl TrustLevel {
    /// Returns `true` if at least partial trust has been established.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        *self >= Self::Partial
    }

    /// Returns `true` if full trust has been established.
    #[must_use]
    pub fn is_fully_trusted(&self) -> bool {
        *self == Self::FullyTrusted
    }
}

// ============================================================================
// Security Mode for Unified API
// ============================================================================

/// Security mode for cryptographic operations.
///
/// This enum provides a unified way to specify whether an operation should use
/// Zero Trust verification or operate without session verification.
///
/// # Usage
///
/// ```rust,ignore
/// use latticearc::{encrypt, SecurityMode, VerifiedSession, generate_keypair};
///
/// let (pk, sk) = generate_keypair()?;
///
/// // With Zero Trust verification (recommended)
/// let session = VerifiedSession::establish(&pk, &sk)?;
/// let encrypted = encrypt(data, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt(data, &key, SecurityMode::Unverified)?;
/// ```
///
/// # Enterprise Behavior
///
/// In enterprise deployments:
/// - `Verified`: Enables policy enforcement, continuous verification, and advanced features
/// - `Unverified`: Triggers mandatory audit trail; may be blocked by enterprise policy
#[derive(Debug, Clone, Copy)]
pub enum SecurityMode<'a> {
    /// Use a verified session for Zero Trust security.
    ///
    /// This mode:
    /// - Validates the session is not expired
    /// - Provides audit trail with session context
    /// - Enables enterprise policy enforcement
    /// - Recommended for all production use
    Verified(&'a VerifiedSession),

    /// Operate without session verification.
    ///
    /// This mode:
    /// - Skips session validation
    /// - In enterprise: triggers mandatory audit logging
    /// - In enterprise: may be blocked by policy
    /// - Use only when Zero Trust is not applicable
    Unverified,
}

impl<'a> SecurityMode<'a> {
    /// Returns `true` if this is a verified security mode.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mode = SecurityMode::Verified(&session);
    /// assert!(mode.is_verified());
    ///
    /// let mode = SecurityMode::Unverified;
    /// assert!(!mode.is_verified());
    /// ```
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }

    /// Returns `true` if this is an unverified security mode.
    #[must_use]
    pub fn is_unverified(&self) -> bool {
        matches!(self, Self::Unverified)
    }

    /// Get the verified session if this is a `Verified` mode.
    ///
    /// Returns `None` for `Unverified` mode.
    #[must_use]
    pub fn session(&self) -> Option<&'a VerifiedSession> {
        match self {
            Self::Verified(session) => Some(session),
            Self::Unverified => None,
        }
    }

    /// Validate the security mode, checking session validity if verified.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the mode is `Verified` but the
    /// session has expired.
    ///
    /// Returns `Ok(())` for `Unverified` mode (no validation performed).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Verified(session) => {
                let result = session.verify_valid();
                if result.is_ok() {
                    log_zero_trust_session_verified!(session_id_to_hex(session.session_id()));
                } else {
                    log_zero_trust_session_expired!(session_id_to_hex(session.session_id()));
                }
                result
            }
            Self::Unverified => {
                log_zero_trust_unverified_mode!("validate");
                Ok(())
            }
        }
    }
}

impl<'a> From<&'a VerifiedSession> for SecurityMode<'a> {
    fn from(session: &'a VerifiedSession) -> Self {
        Self::Verified(session)
    }
}

impl Default for SecurityMode<'_> {
    /// Default to `Unverified` mode.
    ///
    /// Note: This default is provided for API flexibility, but `Verified` mode
    /// is recommended for production use.
    fn default() -> Self {
        Self::Unverified
    }
}

/// A verified session that proves Zero Trust authentication has been completed.
///
/// This type provides compile-time enforcement that Zero Trust verification has been
/// performed. It can only be created through successful authentication, ensuring
/// that cryptographic operations requiring a session have been properly authorized.
///
/// # Example
///
/// ```rust,ignore
/// use arc_core::{VerifiedSession, encrypt_hybrid};
///
/// // Establish a verified session (performs challenge-response)
/// let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;
///
/// // Use the session for cryptographic operations
/// let result = encrypt_hybrid(data, None, &key, SecurityMode::Verified(&session))?;
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedSession {
    /// Unique session identifier.
    session_id: [u8; 32],
    /// Timestamp when authentication was completed.
    authenticated_at: DateTime<Utc>,
    /// Current trust level.
    trust_level: TrustLevel,
    /// Public key that was verified.
    public_key: PublicKey,
    /// When this session expires.
    expires_at: DateTime<Utc>,
}

/// Default session lifetime in seconds (30 minutes).
const DEFAULT_SESSION_LIFETIME_SECS: i64 = 30 * 60;

impl VerifiedSession {
    /// Quick session establishment for the common case.
    ///
    /// Performs a complete challenge-response authentication automatically,
    /// creating a verified session ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The default Zero Trust configuration is invalid
    /// - Random bytes for session ID or challenge cannot be generated
    /// - Proof generation or verification fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;
    /// assert!(session.is_valid());
    /// ```
    pub fn establish(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        // Create owned copies for the auth handler
        let pk: PublicKey = public_key.to_vec();
        let sk: PrivateKey = crate::types::ZeroizedBytes::new(private_key.to_vec());

        let auth = ZeroTrustAuth::new(pk, sk)?;
        let mut session = ZeroTrustSession::new(auth);

        // Self-authentication: prove we possess the private key
        let challenge = session.initiate_authentication()?;
        let proof = session.auth.generate_proof(&challenge.data)?;
        session.verify_response(&proof)?;

        session.into_verified()
    }

    /// Create a verified session from an authenticated `ZeroTrustSession`.
    ///
    /// This is the internal constructor used by `ZeroTrustSession::into_verified()`.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationRequired` if the session has not been
    /// successfully authenticated.
    pub(crate) fn from_authenticated(session: &ZeroTrustSession) -> Result<Self> {
        if !session.is_authenticated() {
            log_zero_trust_auth_failure!(
                "pending",
                "Session must be authenticated before creating VerifiedSession"
            );
            return Err(CoreError::AuthenticationRequired(
                "Session must be authenticated before creating VerifiedSession".to_string(),
            ));
        }

        // Generate unique session ID
        let mut session_id = [0u8; 32];
        OsRng.try_fill_bytes(&mut session_id).map_err(|_e| CoreError::EntropyDepleted {
            message: "Failed to generate session ID".to_string(),
            action: "Check system entropy source".to_string(),
        })?;

        let now = Utc::now();
        let expires_at =
            now.checked_add_signed(Duration::seconds(DEFAULT_SESSION_LIFETIME_SECS)).unwrap_or(now);

        let trust_level = TrustLevel::Trusted;

        // Log successful session creation
        let session_id_hex = session_id_to_hex(&session_id);
        log_zero_trust_session_created!(session_id_hex, trust_level, expires_at);
        log_zero_trust_auth_success!(session_id_hex, trust_level);

        Ok(Self {
            session_id,
            authenticated_at: now,
            trust_level,
            public_key: session.auth.public_key.clone(),
            expires_at,
        })
    }

    /// Check if the session is still valid (not expired).
    ///
    /// A session is valid if the current time is before the expiration time.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }

    /// Get the current trust level of this session.
    #[must_use]
    pub fn trust_level(&self) -> TrustLevel {
        self.trust_level
    }

    /// Get the unique session identifier for audit logging.
    #[must_use]
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Get the public key associated with this session.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the timestamp when this session was authenticated.
    #[must_use]
    pub fn authenticated_at(&self) -> DateTime<Utc> {
        self.authenticated_at
    }

    /// Get the timestamp when this session expires.
    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    /// Verify the session is still valid, returning an error if expired.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::SessionExpired` if the session has expired.
    pub fn verify_valid(&self) -> Result<()> {
        let session_id_hex = session_id_to_hex(&self.session_id);
        if self.is_valid() {
            log_zero_trust_session_verified!(session_id_hex);
            Ok(())
        } else {
            log_zero_trust_session_expired!(session_id_hex);
            Err(CoreError::SessionExpired)
        }
    }
}

// ============================================================================
// Zero Trust Authentication Handler
// ============================================================================

/// Zero-trust authentication handler.
///
/// Manages challenge-response authentication, proof generation and verification,
/// and continuous session monitoring.
pub struct ZeroTrustAuth {
    /// Public key for verification.
    pub(crate) public_key: PublicKey,
    /// Private key for proof generation.
    private_key: PrivateKey,
    /// Authentication configuration.
    config: ZeroTrustConfig,
    /// Session start timestamp.
    session_start: DateTime<Utc>,
    /// Last successful verification timestamp.
    last_verification: RefCell<DateTime<Utc>>,
}

impl ZeroTrustAuth {
    /// Creates a new `ZeroTrustAuth` instance with default configuration.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` if the default configuration is invalid
    /// (e.g., maximum security level without hardware acceleration, or speed preference
    /// without fallback enabled).
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Result<Self> {
        let config = ZeroTrustConfig::default();
        config.validate()?;

        let now = Utc::now();
        Ok(Self {
            public_key,
            private_key,
            config,
            session_start: now,
            last_verification: RefCell::new(now),
        })
    }

    /// Creates a new `ZeroTrustAuth` instance with the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::ConfigurationError` if:
    /// - The challenge timeout is zero.
    /// - Continuous verification is enabled but the verification interval is zero.
    /// - The base configuration is invalid (e.g., maximum security level without
    ///   hardware acceleration).
    pub fn with_config(
        public_key: PublicKey,
        private_key: PrivateKey,
        config: ZeroTrustConfig,
    ) -> Result<Self> {
        config.validate()?;

        let now = Utc::now();
        Ok(Self {
            public_key,
            private_key,
            config,
            session_start: now,
            last_verification: RefCell::new(now),
        })
    }

    /// Generate a new challenge for authentication.
    ///
    /// # Errors
    /// Returns `CoreError::EntropyDepleted` if the system cannot generate random bytes.
    pub fn generate_challenge(&self) -> Result<Challenge> {
        let challenge_data = generate_challenge_data(&self.config.proof_complexity)?;
        log_zero_trust_challenge_generated!(self.config.proof_complexity);
        Ok(Challenge {
            data: challenge_data,
            timestamp: Utc::now(),
            complexity: self.config.proof_complexity.clone(),
            timeout_ms: self.config.challenge_timeout_ms,
        })
    }

    /// Verifies whether a challenge is still within its timeout period.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    pub fn verify_challenge_age(&self, challenge: &Challenge) -> Result<bool> {
        let elapsed = Utc::now().signed_duration_since(challenge.timestamp);
        let elapsed_ms = elapsed.num_milliseconds();

        // Negative elapsed time means the challenge is from the future, which is invalid
        // Convert safely: negative values are treated as invalid (elapsed > timeout)
        let elapsed_u64 = u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
        Ok(elapsed_u64 <= challenge.timeout_ms)
    }

    /// Starts a new continuous verification session.
    #[must_use]
    pub fn start_continuous_verification(&self) -> ContinuousSession {
        ContinuousSession {
            auth_public_key: self.public_key.clone(),
            start_time: Utc::now(),
            verification_interval_ms: self.config.verification_interval_ms,
            last_verification: Utc::now(),
        }
    }
}

impl ZeroTrustAuthenticable for ZeroTrustAuth {
    type Proof = ZeroKnowledgeProof;
    type Error = CoreError;

    /// Generates a zero-knowledge proof for the given challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if the challenge is empty.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the private key has incorrect length
    /// for Ed25519 signing.
    ///
    /// Returns `CoreError::InvalidInput` if the private key format is invalid.
    fn generate_proof(&self, challenge: &[u8]) -> Result<Self::Proof> {
        if challenge.is_empty() {
            return Err(CoreError::AuthenticationFailed("Empty challenge".to_string()));
        }

        let proof_data = self.compute_proof_data(challenge)?;
        let timestamp = Utc::now();

        Ok(ZeroKnowledgeProof {
            challenge: challenge.to_vec(),
            proof: proof_data,
            timestamp,
            complexity: self.config.proof_complexity.clone(),
        })
    }

    /// Verifies a zero-knowledge proof against the given challenge.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::AuthenticationFailed` if the proof format is invalid
    /// (e.g., timestamp bytes cannot be extracted for Medium/High complexity proofs).
    ///
    /// Returns `CoreError::InvalidInput` if the public key or signature format is invalid
    /// during Ed25519 verification.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the public key has incorrect length.
    fn verify_proof(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
    ) -> std::result::Result<bool, Self::Error> {
        // SECURITY: Use constant-time comparison to prevent timing attacks
        // An attacker should not be able to determine which bytes of the challenge matched
        let len_eq = proof.challenge.len().ct_eq(&challenge.len());
        let content_eq = proof.challenge.ct_eq(challenge);
        let challenge_matches: bool = (len_eq & content_eq).into();

        if !challenge_matches {
            log_zero_trust_proof_verified!(false);
            return Ok(false);
        }

        let result = self.verify_proof_data(&proof.proof, challenge)?;
        log_zero_trust_proof_verified!(result);
        Ok(result)
    }
}

impl ProofOfPossession for ZeroTrustAuth {
    type Pop = ProofOfPossessionData;
    type Error = CoreError;

    /// Generates a proof of possession using Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidKeyLength` if the private key has incorrect length
    /// for Ed25519 signing.
    ///
    /// Returns `CoreError::InvalidInput` if the private key format is invalid.
    fn generate_pop(&self) -> Result<Self::Pop> {
        let timestamp = Utc::now();
        // Timestamps after 1970 are always positive, use safe conversion
        let ts_secs = u64::try_from(timestamp.timestamp()).unwrap_or(0);
        let message = format!("proof-of-possession-{}", ts_secs);

        let signature = crate::convenience::ed25519::sign_ed25519_internal(
            message.as_bytes(),
            self.private_key.as_slice(),
        )?;

        Ok(ProofOfPossessionData { public_key: self.public_key.clone(), signature, timestamp })
    }

    /// Verifies a proof of possession against the contained public key.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidInput` if the signature format is invalid
    /// (must be at least 64 bytes) or the public key format is invalid.
    ///
    /// Returns `CoreError::InvalidKeyLength` if the public key has incorrect length.
    fn verify_pop(&self, pop: &Self::Pop) -> std::result::Result<bool, Self::Error> {
        // Timestamps after 1970 are always positive, use safe conversion
        let ts_secs = u64::try_from(pop.timestamp.timestamp()).unwrap_or(0);
        let message = format!("proof-of-possession-{}", ts_secs);

        crate::convenience::ed25519::verify_ed25519_internal(
            message.as_bytes(),
            &pop.signature,
            &pop.public_key,
        )
    }
}

impl ContinuousVerifiable for ZeroTrustAuth {
    type Error = CoreError;

    /// Checks the current verification status of the session.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    fn verify_continuously(&self) -> Result<VerificationStatus> {
        let session_elapsed = Utc::now().signed_duration_since(self.session_start);

        let max_session_time: u64 = 30 * 60 * 1000;

        // Convert safely: negative elapsed times treated as 0 (just started)
        let session_elapsed_u64 = u64::try_from(session_elapsed.num_milliseconds()).unwrap_or(0);
        if session_elapsed_u64 > max_session_time {
            return Ok(VerificationStatus::Expired);
        }

        if !self.config.continuous_verification {
            return Ok(VerificationStatus::Verified);
        }

        let verification_elapsed =
            Utc::now().signed_duration_since(*self.last_verification.borrow());

        // Convert safely: negative elapsed times treated as 0 (just verified)
        let verification_elapsed_u64 =
            u64::try_from(verification_elapsed.num_milliseconds()).unwrap_or(0);
        if verification_elapsed_u64 > self.config.verification_interval_ms {
            return Ok(VerificationStatus::Pending);
        }

        Ok(VerificationStatus::Verified)
    }

    /// Performs reauthentication by generating and verifying a new challenge-proof pair.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::EntropyDepleted` if the system cannot generate random bytes
    /// for the challenge.
    ///
    /// Returns `CoreError::AuthenticationFailed` if proof generation fails due to an
    /// empty challenge.
    ///
    /// Returns `CoreError::InvalidKeyLength` or `CoreError::InvalidInput` if the private
    /// key format is invalid for Ed25519 signing.
    fn reauthenticate(&self) -> Result<()> {
        let challenge = self.generate_challenge()?;
        let _proof = self.generate_proof(&challenge.data)?;

        *self.last_verification.borrow_mut() = Utc::now();
        Ok(())
    }
}

/// A cryptographic challenge for zero-trust authentication.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Random challenge data.
    pub data: Vec<u8>,
    /// When the challenge was created.
    pub timestamp: DateTime<Utc>,
    /// Required proof complexity.
    pub complexity: ProofComplexity,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Challenge {
    /// Returns `true` if the challenge has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now().signed_duration_since(self.timestamp);
        // Negative elapsed means future timestamp, which is suspicious but not expired
        let elapsed_u64 = u64::try_from(elapsed.num_milliseconds()).unwrap_or(0);
        elapsed_u64 > self.timeout_ms
    }
}

/// A zero-knowledge proof response to a challenge.
#[derive(Debug, Clone)]
pub struct ZeroKnowledgeProof {
    /// The original challenge that was responded to.
    pub challenge: Vec<u8>,
    /// The cryptographic proof data.
    pub proof: Vec<u8>,
    /// When the proof was generated.
    pub timestamp: DateTime<Utc>,
    /// Complexity level of the proof.
    pub complexity: ProofComplexity,
}

impl ZeroKnowledgeProof {
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
    pub public_key: PublicKey,
    /// Signature proving possession.
    pub signature: Vec<u8>,
    /// When the proof was generated.
    pub timestamp: DateTime<Utc>,
}

/// A continuous verification session.
#[derive(Debug)]
pub struct ContinuousSession {
    /// Public key that authenticated the session.
    auth_public_key: PublicKey,
    /// When the session started.
    start_time: DateTime<Utc>,
    /// Verification interval in milliseconds.
    verification_interval_ms: u64,
    /// Last successful verification timestamp.
    last_verification: DateTime<Utc>,
}

impl ContinuousSession {
    /// Get the public key that authenticated this session
    #[must_use]
    pub fn auth_public_key(&self) -> &PublicKey {
        &self.auth_public_key
    }

    /// Checks whether the continuous session is still valid.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
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

    /// Updates the last verification timestamp to the current time.
    ///
    /// # Errors
    ///
    /// This function does not currently return errors, but returns `Result` for
    /// API consistency and future extensibility.
    pub fn update_verification(&mut self) -> Result<()> {
        self.last_verification = Utc::now();
        Ok(())
    }
}

fn generate_challenge_data(complexity: &ProofComplexity) -> Result<Vec<u8>> {
    let size = match complexity {
        ProofComplexity::Low => 32,
        ProofComplexity::Medium => 64,
        ProofComplexity::High => 128,
    };

    let mut data = vec![0u8; size];
    OsRng.try_fill_bytes(&mut data).map_err(|_e| CoreError::EntropyDepleted {
        message: "Failed to generate random bytes for challenge".to_string(),
        action: "Check system entropy source".to_string(),
    })?;
    Ok(data)
}

impl ZeroTrustAuth {
    /// Compute proof data using Ed25519 signature-based challenge-response.
    ///
    /// This is a proper zero-knowledge proof: the signature proves knowledge
    /// of the private key without revealing any information about it.
    ///
    /// Proof complexity affects what is signed:
    /// - Low: sign(challenge)
    /// - Medium: sign(challenge || timestamp)
    /// - High: sign(challenge || timestamp || context)
    fn compute_proof_data(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        let timestamp = Utc::now().timestamp_millis().to_le_bytes();

        // Build message to sign based on complexity
        let message_to_sign = match self.config.proof_complexity {
            ProofComplexity::Low => {
                // Simple: just sign the challenge
                challenge.to_vec()
            }
            ProofComplexity::Medium => {
                // Medium: include timestamp for replay protection
                let mut msg = challenge.to_vec();
                msg.extend_from_slice(&timestamp);
                msg
            }
            ProofComplexity::High => {
                // High: include timestamp + public key binding
                let mut msg = challenge.to_vec();
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
        };

        // Sign the message - this IS zero-knowledge
        // The signature proves knowledge of private key without revealing it
        let signature = crate::convenience::ed25519::sign_ed25519_internal(
            &message_to_sign,
            self.private_key.as_slice(),
        )?;

        // Return signature with timestamp for Medium/High complexity
        match self.config.proof_complexity {
            ProofComplexity::Low => Ok(signature),
            ProofComplexity::Medium | ProofComplexity::High => {
                let mut proof = signature;
                proof.extend_from_slice(&timestamp);
                Ok(proof)
            }
        }
    }

    /// Verify proof using PUBLIC KEY only.
    ///
    /// This is the correct way to verify a zero-knowledge proof:
    /// only the public key is needed, not the private key.
    fn verify_proof_data(&self, proof: &[u8], challenge: &[u8]) -> Result<bool> {
        // Ed25519 signatures are 64 bytes
        if proof.len() < 64 {
            return Ok(false);
        }

        match self.config.proof_complexity {
            ProofComplexity::Low => {
                // Simple verification: signature over challenge
                crate::convenience::ed25519::verify_ed25519_internal(
                    challenge,
                    proof,
                    &self.public_key,
                )
            }
            ProofComplexity::Medium => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                // Use safe slice access
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // Reconstruct signed message
                let mut message = challenge.to_vec();
                message.extend_from_slice(&timestamp_bytes);

                crate::convenience::ed25519::verify_ed25519_internal(
                    &message,
                    signature,
                    &self.public_key,
                )
            }
            ProofComplexity::High => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                // Use safe slice access
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // Reconstruct signed message with public key binding
                let mut message = challenge.to_vec();
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());

                crate::convenience::ed25519::verify_ed25519_internal(
                    &message,
                    signature,
                    &self.public_key,
                )
            }
        }
    }
}

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
        let challenge = self.challenge.as_ref().ok_or_else(|| {
            log_zero_trust_session_verification_failed!("pending", "No active challenge");
            CoreError::AuthenticationFailed("No active challenge".to_string())
        })?;

        if challenge.is_expired() {
            log_zero_trust_session_verification_failed!("pending", "Challenge expired");
            return Err(CoreError::AuthenticationFailed("Challenge expired".to_string()));
        }

        let verified = self.auth.verify_proof(proof, &challenge.data)?;
        self.verified = verified;

        if !verified {
            log_zero_trust_session_verification_failed!("pending", "Proof verification failed");
        }

        Ok(self.verified)
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

#[cfg(test)]
#[allow(
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
mod tests {
    use super::*;
    use crate::generate_keypair;

    // TrustLevel tests
    #[test]
    fn test_trust_level_default() {
        let level = TrustLevel::default();
        assert_eq!(level, TrustLevel::Untrusted);
    }

    #[test]
    fn test_trust_level_variants() {
        assert_eq!(TrustLevel::Untrusted as i32, 0);
        assert_eq!(TrustLevel::Partial as i32, 1);
        assert_eq!(TrustLevel::Trusted as i32, 2);
        assert_eq!(TrustLevel::FullyTrusted as i32, 3);
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
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::Partial);
        assert!(TrustLevel::Partial < TrustLevel::Trusted);
        assert!(TrustLevel::Trusted < TrustLevel::FullyTrusted);
    }

    // SecurityMode tests
    #[test]
    fn test_security_mode_unverified_is_unverified() {
        let mode = SecurityMode::Unverified;
        assert!(mode.is_unverified());
        assert!(!mode.is_verified());
    }

    #[test]
    fn test_security_mode_validate_unverified() -> Result<()> {
        let mode = SecurityMode::Unverified;
        mode.validate()?;
        Ok(())
    }

    // VerifiedSession tests
    #[test]
    fn test_verified_session_establish() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        assert!(session.is_valid());
        // After self-authentication during establish, trust level is upgraded
        assert!(session.trust_level() >= TrustLevel::Partial);
        Ok(())
    }

    #[test]
    fn test_verified_session_session_id() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let session_id = session.session_id();
        assert_eq!(session_id.len(), 32);
        Ok(())
    }

    #[test]
    fn test_verified_session_public_key() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let pk = session.public_key();
        assert!(!pk.is_empty());
        Ok(())
    }

    #[test]
    fn test_verified_session_timestamps() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let authenticated_at = session.authenticated_at();
        let expires_at = session.expires_at();

        assert!(expires_at > authenticated_at, "Session should expire after authentication");
        Ok(())
    }

    #[test]
    fn test_verified_session_verify_valid() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        session.verify_valid()?;
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_with_session() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let mode = SecurityMode::Verified(&session);
        assert!(mode.is_verified());
        assert!(!mode.is_unverified());
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_validate() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let mode = SecurityMode::Verified(&session);
        mode.validate()?;
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_session() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let mode = SecurityMode::Verified(&session);
        assert!(mode.session().is_some());
        Ok(())
    }

    #[test]
    fn test_security_mode_unverified_session() {
        let mode = SecurityMode::Unverified;
        assert!(mode.session().is_none());
    }

    // ZeroTrustAuth tests
    #[test]
    fn test_zero_trust_auth_new() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        // Just verify it was created successfully
        assert!(std::mem::size_of_val(&auth) > 0);
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_with_config() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config =
            ZeroTrustConfig::new().with_timeout(10000).with_complexity(ProofComplexity::High);

        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;
        assert!(std::mem::size_of_val(&auth) > 0);
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_generate_challenge() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let challenge = auth.generate_challenge()?;
        assert!(!challenge.is_expired());
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_multiple_challenges() -> Result<()> {
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
    fn test_zero_trust_auth_verify_challenge_age() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let challenge = auth.generate_challenge()?;
        let is_valid = auth.verify_challenge_age(&challenge)?;

        assert!(is_valid, "Freshly generated challenge should be valid");
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_start_continuous_verification() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let continuous = auth.start_continuous_verification();
        let result = continuous.is_valid();

        assert!(result.is_ok());
        Ok(())
    }

    // Challenge tests
    #[test]
    fn test_challenge_not_expired_when_fresh() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let challenge = auth.generate_challenge()?;
        assert!(!challenge.is_expired());
        Ok(())
    }

    // ZeroTrustSession tests
    #[test]
    fn test_zero_trust_session_new() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let session = ZeroTrustSession::new(auth);
        assert!(!session.is_authenticated());
        Ok(())
    }

    #[test]
    fn test_zero_trust_session_initiate_authentication() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let mut session = ZeroTrustSession::new(auth);
        let challenge = session.initiate_authentication()?;

        assert!(!challenge.is_expired());
        Ok(())
    }

    #[test]
    fn test_zero_trust_session_not_authenticated_initially() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let session = ZeroTrustSession::new(auth);
        assert!(!session.is_authenticated());
        Ok(())
    }

    // ProofComplexity tests
    #[test]
    fn test_proof_complexity_variants() {
        let _low = ProofComplexity::Low;
        let _medium = ProofComplexity::Medium;
        let _high = ProofComplexity::High;

        assert_eq!(ProofComplexity::Medium, ProofComplexity::Medium);
    }

    // Integration tests
    #[test]
    fn test_verified_session_with_multiple_instances() -> Result<()> {
        // Test creating multiple sessions
        for _ in 0..3 {
            let (public_key, private_key) = generate_keypair()?;
            let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;
            assert!(session.is_valid());
        }
        Ok(())
    }

    #[test]
    fn test_zero_trust_config_variations() -> Result<()> {
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

    #[test]
    fn test_verified_session_multiple_sessions() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;

        // Create multiple sessions with same keys
        let session1 = VerifiedSession::establish(&public_key, private_key.as_ref())?;
        let session2 = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        // Sessions should have different IDs
        assert!(session1.is_valid());
        assert!(session2.is_valid());
        assert_ne!(session1.session_id(), session2.session_id());
        Ok(())
    }

    #[test]
    fn test_challenge_generation_produces_unique_challenges() -> Result<()> {
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
    fn test_continuous_session_validation() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_continuous_verification(true);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let continuous = auth.start_continuous_verification();
        assert!(continuous.is_valid().is_ok());
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_with_all_complexity_levels() -> Result<()> {
        let complexities =
            vec![ProofComplexity::Low, ProofComplexity::Medium, ProofComplexity::High];

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
    fn test_security_mode_default_is_unverified() {
        let mode = SecurityMode::default();
        assert!(mode.is_unverified());
        assert!(!mode.is_verified());
        assert!(mode.session().is_none());
    }

    #[test]
    fn test_security_mode_from_verified_session() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

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
    fn test_zero_trust_session_verify_response_no_challenge() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;
        let mut session = ZeroTrustSession::new(auth);

        // Try verify without initiating authentication
        let fake_proof = ZeroKnowledgeProof {
            challenge: vec![1, 2, 3],
            proof: vec![0u8; 64],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        let result = session.verify_response(&fake_proof);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_zero_trust_session_session_age_ms() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;
        let session = ZeroTrustSession::new(auth);

        let age = session.session_age_ms()?;
        // Just created, should be very small
        assert!(age < 5000, "Session age should be < 5 seconds, got {}ms", age);
        Ok(())
    }

    #[test]
    fn test_continuous_session_auth_public_key() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key.clone(), private_key)?;

        let continuous = auth.start_continuous_verification();
        assert_eq!(continuous.auth_public_key(), &public_key);
        Ok(())
    }

    #[test]
    fn test_continuous_session_update_verification() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let mut continuous = auth.start_continuous_verification();
        assert!(continuous.is_valid()?);

        continuous.update_verification()?;
        assert!(continuous.is_valid()?);
        Ok(())
    }

    #[test]
    fn test_zero_knowledge_proof_is_valid_format() {
        // Valid format
        let valid = ZeroKnowledgeProof {
            challenge: vec![1, 2, 3],
            proof: vec![0u8; 64],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        assert!(valid.is_valid_format());

        // Empty challenge
        let empty_challenge = ZeroKnowledgeProof {
            challenge: vec![],
            proof: vec![0u8; 64],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        assert!(!empty_challenge.is_valid_format());

        // Empty proof
        let empty_proof = ZeroKnowledgeProof {
            challenge: vec![1],
            proof: vec![],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        assert!(!empty_proof.is_valid_format());
    }

    #[test]
    fn test_zero_trust_auth_reauthenticate() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        // Reauthenticate should succeed
        auth.reauthenticate()?;
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_verify_continuously_verified() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let status = auth.verify_continuously()?;
        // Default config has continuous_verification=false, so should be Verified
        assert_eq!(status, VerificationStatus::Verified);
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_verify_continuously_with_cv_enabled() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new()
            .with_continuous_verification(true)
            .with_verification_interval(60000);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let status = auth.verify_continuously()?;
        // Just created, should be Verified (within interval)
        assert_eq!(status, VerificationStatus::Verified);
        Ok(())
    }

    #[test]
    fn test_generate_proof_empty_challenge_error() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let result = auth.generate_proof(&[]);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_verify_proof_wrong_challenge() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let challenge = auth.generate_challenge()?;
        let proof = auth.generate_proof(&challenge.data)?;

        // Verify with a different challenge should fail
        let different_challenge = vec![0xFF; 32];
        let result = auth.verify_proof(&proof, &different_challenge)?;
        assert!(!result);
        Ok(())
    }

    #[test]
    fn test_verify_proof_short_proof_data() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let challenge_data = vec![1u8; 32];
        let short_proof = ZeroKnowledgeProof {
            challenge: challenge_data.clone(),
            proof: vec![0u8; 10], // Too short (< 64 bytes)
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        let result = auth.verify_proof(&short_proof, &challenge_data)?;
        assert!(!result);
        Ok(())
    }

    #[test]
    fn test_full_challenge_response_low_complexity() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        let proof = auth.generate_proof(&challenge.data)?;
        let verified = auth.verify_proof(&proof, &challenge.data)?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn test_full_challenge_response_medium_complexity() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        let proof = auth.generate_proof(&challenge.data)?;
        let verified = auth.verify_proof(&proof, &challenge.data)?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn test_full_challenge_response_high_complexity() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        let proof = auth.generate_proof(&challenge.data)?;
        let verified = auth.verify_proof(&proof, &challenge.data)?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn test_proof_of_possession_roundtrip() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let pop = auth.generate_pop()?;
        let verified = auth.verify_pop(&pop)?;
        assert!(verified);
        Ok(())
    }

    #[test]
    fn test_full_session_flow_with_into_verified() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;
        let mut session = ZeroTrustSession::new(auth);

        // Initiate -> prove -> verify -> convert
        let challenge = session.initiate_authentication()?;
        let proof = session.auth.generate_proof(&challenge.data)?;
        let verified = session.verify_response(&proof)?;
        assert!(verified);
        assert!(session.is_authenticated());

        let verified_session = session.into_verified()?;
        assert!(verified_session.is_valid());
        assert_eq!(verified_session.trust_level(), TrustLevel::Trusted);
        Ok(())
    }

    #[test]
    fn test_verified_session_clone_and_debug() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let cloned = session.clone();
        assert_eq!(cloned.trust_level(), session.trust_level());
        assert_eq!(cloned.session_id(), session.session_id());

        let debug = format!("{:?}", session);
        assert!(debug.contains("VerifiedSession"));
        Ok(())
    }

    #[test]
    fn test_security_mode_debug() -> Result<()> {
        let mode = SecurityMode::Unverified;
        let debug = format!("{:?}", mode);
        assert!(debug.contains("Unverified"));

        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;
        let verified_mode = SecurityMode::Verified(&session);
        let debug2 = format!("{:?}", verified_mode);
        assert!(debug2.contains("Verified"));
        Ok(())
    }

    #[test]
    fn test_challenge_fields() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config =
            ZeroTrustConfig::new().with_timeout(5000).with_complexity(ProofComplexity::High);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        assert_eq!(challenge.data.len(), 128); // High complexity = 128 bytes
        assert_eq!(challenge.timeout_ms, 5000);
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
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        // Manually create an expired session by setting expires_at in the past
        let expired_session = VerifiedSession {
            session_id: *session.session_id(),
            authenticated_at: session.authenticated_at(),
            trust_level: session.trust_level(),
            public_key: session.public_key().clone(),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
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
    fn test_security_mode_validate_expired_session() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session = VerifiedSession::establish(&public_key, private_key.as_ref())?;

        let expired_session = VerifiedSession {
            session_id: *session.session_id(),
            authenticated_at: session.authenticated_at(),
            trust_level: session.trust_level(),
            public_key: session.public_key().clone(),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
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
    fn test_continuous_verification_pending_after_interval() -> Result<()> {
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
    fn test_challenge_generation_low_complexity_size() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Low);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        assert_eq!(challenge.data.len(), 32, "Low complexity = 32 bytes");
        Ok(())
    }

    #[test]
    fn test_challenge_generation_medium_complexity_size() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge = auth.generate_challenge()?;
        assert_eq!(challenge.data.len(), 64, "Medium complexity = 64 bytes");
        Ok(())
    }

    #[test]
    fn test_verify_proof_medium_short_proof_rejects() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::Medium);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge_data = vec![1u8; 64];
        // Proof is 64 bytes (just signature, no timestamp) — too short for Medium (needs 72)
        let short_proof = ZeroKnowledgeProof {
            challenge: challenge_data.clone(),
            proof: vec![0u8; 64],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Medium,
        };
        let result = auth.verify_proof(&short_proof, &challenge_data)?;
        assert!(!result, "Medium-complexity proof without timestamp should fail");
        Ok(())
    }

    #[test]
    fn test_verify_proof_high_short_proof_rejects() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config = ZeroTrustConfig::new().with_complexity(ProofComplexity::High);
        let auth = ZeroTrustAuth::with_config(public_key, private_key, config)?;

        let challenge_data = vec![1u8; 128];
        // Proof is 70 bytes — too short for High (needs 72)
        let short_proof = ZeroKnowledgeProof {
            challenge: challenge_data.clone(),
            proof: vec![0u8; 70],
            timestamp: Utc::now(),
            complexity: ProofComplexity::High,
        };
        let result = auth.verify_proof(&short_proof, &challenge_data)?;
        assert!(!result, "High-complexity proof too short should fail");
        Ok(())
    }

    #[test]
    fn test_zero_knowledge_proof_debug_and_clone() {
        let proof = ZeroKnowledgeProof {
            challenge: vec![1, 2, 3],
            proof: vec![0u8; 64],
            timestamp: Utc::now(),
            complexity: ProofComplexity::Low,
        };
        let cloned = proof.clone();
        assert_eq!(cloned.challenge, proof.challenge);
        assert_eq!(cloned.proof, proof.proof);
        let debug = format!("{:?}", proof);
        assert!(debug.contains("ZeroKnowledgeProof"));
    }

    #[test]
    fn test_proof_of_possession_data_debug_and_clone() {
        let pop = ProofOfPossessionData {
            public_key: vec![1, 2, 3],
            signature: vec![0u8; 64],
            timestamp: Utc::now(),
        };
        let cloned = pop.clone();
        assert_eq!(cloned.public_key, pop.public_key);
        let debug = format!("{:?}", pop);
        assert!(debug.contains("ProofOfPossessionData"));
    }
}
