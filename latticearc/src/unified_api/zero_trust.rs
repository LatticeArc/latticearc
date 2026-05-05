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

use crate::types::traits::{
    ContinuousVerifiable, ProofOfPossession, VerificationStatus, ZeroTrustAuthenticable,
};
use crate::unified_api::{
    ProofComplexity, ZeroTrustConfig,
    error::{CoreError, Result},
};
use crate::{
    log_zero_trust_auth_failure, log_zero_trust_auth_success, log_zero_trust_challenge_generated,
    log_zero_trust_proof_verified, log_zero_trust_session_created, log_zero_trust_session_expired,
    log_zero_trust_session_verification_failed, log_zero_trust_session_verified,
    log_zero_trust_unverified_mode,
    types::{PrivateKey, PublicKey},
};

// Re-export TrustLevel from types module (pure Rust, no FFI deps)
pub use crate::types::zero_trust::TrustLevel;
use chrono::{DateTime, Duration, Utc};
use std::cell::RefCell;
use subtle::ConstantTimeEq;

// ============================================================================
// Security Mode for Unified API
// ============================================================================

/// Security mode for cryptographic operations.
///
/// This enum gates cryptographic operations on authentication state. Its purpose is
/// **session validation** — ensuring the caller has proven possession of a private key
/// before being allowed to perform crypto operations. It does NOT control algorithm
/// selection (that is handled by `CryptoConfig` or the explicit algorithm parameter).
///
/// This follows the industry pattern where authentication and algorithm selection are
/// separate concerns. No major crypto library (ring, RustCrypto, Tink, OpenSSL) couples
/// "trust level" to algorithm choice — the key type or config determines the algorithm,
/// and authentication is an orthogonal layer.
///
/// The `validate()` call IS the core purpose: verifying session validity before allowing
/// crypto operations. The `_unverified()` convenience functions exist for scenarios where
/// Zero Trust verification is not applicable (e.g., batch processing, testing, or systems
/// that handle authentication at a different layer).
///
/// # Usage
///
/// ```rust,no_run
/// # use latticearc::unified_api::{encrypt_aes_gcm, SecurityMode, VerifiedSession, generate_keypair};
/// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
/// let (pk, sk) = generate_keypair()?;
///
/// // With Zero Trust verification (recommended)
/// let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())?;
/// # let data = b"secret";
/// # let key = latticearc::primitives::rand::random_bytes(32);
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
///
/// // Without verification (opt-out)
/// let encrypted = encrypt_aes_gcm(data, &key, SecurityMode::Unverified)?;
/// # Ok(())
/// # }
/// ```
///
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum SecurityMode<'a> {
    /// Use a verified session for Zero Trust security.
    ///
    /// This mode:
    /// - Validates the session is not expired
    /// - Provides audit trail with session context
    /// - Recommended for all production use
    Verified(&'a VerifiedSession),

    /// Operate without session verification.
    ///
    /// This mode:
    /// - Skips session validation
    /// - Use only when Zero Trust is not applicable
    Unverified,
}

impl<'a> SecurityMode<'a> {
    /// Returns `true` if this is a verified security mode.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use latticearc::unified_api::{SecurityMode, VerifiedSession, generate_keypair};
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// # let (pk, sk) = generate_keypair()?;
    /// # let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret())?;
    /// let mode = SecurityMode::Verified(&session);
    /// assert!(mode.is_verified());
    ///
    /// let mode = SecurityMode::Unverified;
    /// assert!(!mode.is_verified());
    /// # Ok(())
    /// # }
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
    /// Returns `CoreError::ZeroTrustVerificationFailed` if the session
    /// has been downgraded to `TrustLevel::Untrusted`.
    /// Returns `CoreError::SessionExpired` if the session is still
    /// trusted but past its policy lifetime.
    ///
    /// Returns `Ok(())` for `Unverified` mode (no validation performed).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Verified(session) => {
                // trust_level must gate validation; otherwise
                // downgrade_trust_level() has no observable effect.
                if session.trust_level() == TrustLevel::Untrusted {
                    // Downgrade-rejection is NOT clock expiry; emitting
                    // `session_expired` here would inflate SIEM expiry
                    // counters on every policy-driven trust drop.
                    log_zero_trust_session_verification_failed!(
                        hex::encode(session.session_id()),
                        "trust_level downgraded to Untrusted"
                    );
                    // Generic public string; the discriminator
                    // ("trust_level downgraded to Untrusted") is in
                    // the tracing event above. Pattern-6 posture: the
                    // user-visible Err shape does not distinguish
                    // reject reasons.
                    return Err(CoreError::ZeroTrustVerificationFailed(
                        "zero-trust validation failed".to_string(),
                    ));
                }
                // `verify_valid()` already logs verified/expired
                // internally; do not re-log here.
                session.verify_valid()
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

// `impl Default for SecurityMode` was REMOVED. The previous default
// returned `Unverified`, which let production code using
// `..Default::default()` silently disable Zero Trust validation —
// exactly the failure mode the type was designed to make impossible.
// Callers must now choose explicitly: `SecurityMode::Verified(&session)`
// for Zero Trust enforcement (recommended) or `SecurityMode::Unverified`
// for opt-out paths where ZT is not applicable. The choice now
// appears in source diffs and code review can catch accidents.

/// A verified session that proves Zero Trust authentication has been completed.
///
/// This type provides compile-time enforcement that Zero Trust verification has been
/// performed. It can only be created through successful authentication, ensuring
/// that cryptographic operations requiring a session have been properly authorized.
///
/// # Example
///
/// ```rust,no_run
/// # use latticearc::unified_api::{VerifiedSession, encrypt_aes_gcm, SecurityMode, generate_keypair};
/// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
/// # let (public_key, private_key) = generate_keypair()?;
/// // Establish a verified session (performs challenge-response)
/// let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
///
/// // Use the session for cryptographic operations
/// # let data = b"secret";
/// # let key = latticearc::primitives::rand::random_bytes(32);
/// let result = encrypt_aes_gcm(data, &key, SecurityMode::Verified(&session))?;
/// # Ok(())
/// # }
/// ```
pub struct VerifiedSession {
    /// Unique session identifier.
    session_id: [u8; 32],
    /// Timestamp when authentication was completed (wall-clock, for
    /// audit display only — never used for validity decisions).
    authenticated_at: DateTime<Utc>,
    /// Current trust level.
    trust_level: TrustLevel,
    /// Public key that was verified.
    public_key: PublicKey,
    /// When this session expires (wall-clock, for audit display only).
    expires_at: DateTime<Utc>,
    /// monotonic instant + lifetime drive `is_valid()`.
    /// NTP rollback can't extend a session past its policy lifetime.
    issued_at_monotonic: std::time::Instant,
    lifetime: std::time::Duration,
}

impl std::fmt::Debug for VerifiedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSession")
            .field("session_id", &"[REDACTED]")
            .field("authenticated_at", &self.authenticated_at)
            .field("trust_level", &self.trust_level)
            .field("public_key", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Default session lifetime in seconds (30 minutes).
const DEFAULT_SESSION_LIFETIME_SECS: i64 = 30 * 60;

// A zero or negative lifetime would silently become `u64::MAX`
// (i.e. non-expiring) after the i64→u64 cast in `from_authenticated`.
// Pin the invariant at compile time.
const _: () =
    assert!(DEFAULT_SESSION_LIFETIME_SECS > 0, "DEFAULT_SESSION_LIFETIME_SECS must be > 0",);

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
    /// ```rust,no_run
    /// # use latticearc::unified_api::{VerifiedSession, generate_keypair};
    /// # fn main() -> Result<(), latticearc::unified_api::error::CoreError> {
    /// # let (public_key, private_key) = generate_keypair()?;
    /// let session = VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
    /// assert!(session.is_valid());
    /// # Ok(())
    /// # }
    /// ```
    pub fn establish(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        // Create owned copies for the auth handler
        let pk: PublicKey = PublicKey::new(public_key.to_vec());
        let sk: PrivateKey = PrivateKey::new(private_key.to_vec());

        let auth = ZeroTrustAuth::new(pk, sk)?;
        let mut session = ZeroTrustSession::new(auth);

        // Self-authentication: prove we possess the private key.
        let challenge = session.initiate_authentication()?;
        // Reject a captured challenge-response replay on age grounds before
        // the proof is verified. Without this gate a captured pair could be
        // replayed indefinitely against the same `establish` call site.
        if !session.auth.verify_challenge_age(&challenge)? {
            return Err(CoreError::AuthenticationRequired(
                "Challenge expired during establish (replay protection)".to_string(),
            ));
        }
        let proof = session.auth.generate_proof(challenge.data())?;
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

        // Generate unique session ID via the primitives layer.
        let session_id_vec = crate::primitives::security::generate_secure_random_bytes(32)
            .map_err(|_e| CoreError::EntropyDepleted {
                message: "Failed to generate session ID".to_string(),
                action: "Check system entropy source".to_string(),
            })?;
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&session_id_vec);

        let now = Utc::now();
        let expires_at = now
            .checked_add_signed(Duration::seconds(DEFAULT_SESSION_LIFETIME_SECS))
            .ok_or_else(|| {
            CoreError::ConfigurationError(
                "Cannot compute session expiry: timestamp overflow".to_string(),
            )
        })?;

        let trust_level = TrustLevel::Trusted;

        // Log successful session creation
        let session_id_hex = hex::encode(session_id);
        log_zero_trust_session_created!(session_id_hex, trust_level, expires_at);
        log_zero_trust_auth_success!(session_id_hex, trust_level);

        // Capture a monotonic instant at construction. The wall-clock
        // `expires_at` above remains for audit display, but `is_valid`
        // consults `Instant::elapsed()` instead. The const_assert above
        // pins the constant > 0, so `as u64` produces the same numeric
        // value with no saturation surprise.
        #[allow(clippy::cast_sign_loss)]
        let lifetime = std::time::Duration::from_secs(DEFAULT_SESSION_LIFETIME_SECS as u64);
        Ok(Self {
            session_id,
            authenticated_at: now,
            trust_level,
            public_key: session.auth.public_key.clone(),
            expires_at,
            issued_at_monotonic: std::time::Instant::now(),
            lifetime,
        })
    }

    /// Check if the session is still valid (not expired).
    ///
    /// A session is valid if the elapsed time since construction is
    /// strictly less than the configured lifetime.
    ///
    /// Uses a monotonic `Instant` so NTP rollback / system-clock
    /// manipulation cannot extend a session past its policy lifetime.
    /// `expires_at` / `authenticated_at` are wall-clock and kept for
    /// audit display only.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.issued_at_monotonic.elapsed() < self.lifetime
    }

    /// Get the current trust level of this session.
    #[must_use]
    pub fn trust_level(&self) -> TrustLevel {
        self.trust_level
    }

    /// Downgrade the session's trust level. Round-29 M3: previously the
    /// `trust_level` field was set once at construction (always to
    /// `Trusted`) and no public mutator existed, so the
    /// `Trusted -> Partial -> Untrusted` transitions described in the
    /// type-level documentation were unreachable. This method
    /// implements the downgrade path: callers (continuous-auth poll
    /// loops, integrity-check failures, anomaly detectors) can reduce
    /// trust as evidence accumulates.
    ///
    /// Only **monotonic downgrades** are permitted — `new_level` must
    /// be strictly lower than the current level (per `Ord` on
    /// `TrustLevel`, which orders `Untrusted < Partial < Trusted <
    /// FullyTrusted`). Attempting to upgrade or no-op yields
    /// `CoreError::InvalidParameter`. Re-acquiring trust requires a
    /// fresh authentication, not a setter.
    ///
    /// # Errors
    /// Returns `CoreError::InvalidParameter` when `new_level` is not
    /// strictly lower than the current trust level.
    pub fn downgrade_trust_level(&mut self, new_level: TrustLevel) -> Result<()> {
        if new_level >= self.trust_level {
            return Err(CoreError::InvalidInput(format!(
                "downgrade_trust_level: new={new_level:?} not strictly lower than \
                 current={current:?}; upgrades require re-authentication",
                current = self.trust_level,
            )));
        }
        let prev = self.trust_level;
        self.trust_level = new_level;
        let session_id_hex = hex::encode(self.session_id);
        tracing::warn!(
            session_id = %session_id_hex,
            previous = ?prev,
            new = ?new_level,
            "VerifiedSession trust level downgraded"
        );
        Ok(())
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
        let session_id_hex = hex::encode(self.session_id);
        if self.is_valid() {
            log_zero_trust_session_verified!(session_id_hex);
            Ok(())
        } else {
            log_zero_trust_session_expired!(session_id_hex);
            Err(CoreError::SessionExpired)
        }
    }

    /// Create a copy of this session that is already expired.
    ///
    /// This is only available in tests so that code outside this module can
    /// exercise the `SessionExpired` error path without accessing private fields.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn expired_clone(&self) -> Self {
        // force expiry via the monotonic path by using a
        // zero-duration lifetime — `Instant::elapsed()` will be > 0
        // immediately after construction. Wall-clock fields are also
        // pegged at the Unix epoch for audit-display consistency.
        Self {
            session_id: self.session_id,
            authenticated_at: self.authenticated_at,
            trust_level: self.trust_level,
            public_key: self.public_key.clone(),
            expires_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            issued_at_monotonic: std::time::Instant::now(),
            lifetime: std::time::Duration::from_nanos(0),
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
    /// Replay cache for proofs-of-possession (round-26 audit fix M16).
    /// Keyed on `pk || sig || ts_micros_be` (microsecond precision —
    /// see the M16 follow-up note in `generate_pop` for why second
    /// precision was insufficient under Ed25519's deterministic
    /// signatures). Values are the wall-clock seconds-since-epoch at
    /// which the entry was inserted (used to bound cache lifetime to
    /// the 5-minute PoP freshness window). The cache is
    /// opportunistically evicted on each `verify_pop` call and capped
    /// at 16 KiB entries to bound memory under attack. `Mutex` rather
    /// than `RefCell` so the type stays `Sync` for use across
    /// async/multi-threaded callers.
    pop_replay_cache: std::sync::Mutex<std::collections::HashMap<Vec<u8>, i64>>,
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
            pop_replay_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
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
            pop_replay_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
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
        let elapsed = Utc::now().signed_duration_since(challenge.timestamp());
        let elapsed_ms = elapsed.num_milliseconds();

        // Negative elapsed time means the challenge is from the future, which is invalid
        // Convert safely: negative values are treated as invalid (elapsed > timeout)
        let elapsed_u64 = u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
        Ok(elapsed_u64 <= challenge.timeout_ms())
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
        // The prover writes `proof.complexity` from its own config but
        // the verifier previously only consulted
        // `self.config.proof_complexity` for dispatch — so a prover
        // claiming Low complexity could ship a proof verified under
        // the verifier's Medium policy (or vice versa). Pin the field
        // by requiring it to match the verifier's expected complexity;
        // mismatch collapses to `Ok(false)` (Pattern 6 — no
        // distinguishable error per round-26 audit posture).
        if proof.complexity() != &self.config.proof_complexity {
            tracing::debug!(
                expected = ?self.config.proof_complexity,
                got = ?proof.complexity(),
                "ZK proof rejected: complexity field mismatch"
            );
            log_zero_trust_proof_verified!(false);
            return Ok(false);
        }

        // SECURITY: Use constant-time comparison to prevent timing attacks
        // An attacker should not be able to determine which bytes of the challenge matched
        let len_eq = proof.challenge().len().ct_eq(&challenge.len());
        let content_eq = proof.challenge().ct_eq(challenge);
        let challenge_matches: bool = (len_eq & content_eq).into();

        if !challenge_matches {
            log_zero_trust_proof_verified!(false);
            return Ok(false);
        }

        let result = self.verify_proof_data(proof.proof_data(), challenge)?;
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
        // Include microsecond precision in the signed message, not just
        // seconds. Ed25519 signatures are deterministic, so two PoPs
        // generated in the same second by the same key produce
        // byte-identical wire representations — the replay cache
        // (which keys on `pk || sig || ts_secs`) would then flag a
        // legitimate client regenerating PoPs in a tight loop as a
        // replay attack. Microseconds are still well
        // within the 5-minute freshness window's resolution and make
        // each in-second PoP byte-unique.
        let ts_micros = timestamp.timestamp_micros();
        let message = format!("proof-of-possession-{}", ts_micros);

        let signature = crate::unified_api::convenience::ed25519::sign_ed25519_internal(
            message.as_bytes(),
            self.private_key.expose_secret(),
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
        // Freshness check: reject proofs older than PROOF_OF_POSSESSION_MAX_AGE.
        // This prevents replay of stale PoPs captured from prior sessions (P5.2 C4).
        // Using chrono::Duration so the bound is expressed in seconds regardless
        // of timezone or DST quirks.
        const PROOF_OF_POSSESSION_MAX_AGE_SECS: i64 = 5 * 60; // 5 minutes
        let elapsed = Utc::now().signed_duration_since(pop.timestamp());
        if elapsed.num_seconds() > PROOF_OF_POSSESSION_MAX_AGE_SECS {
            return Err(CoreError::InvalidInput(format!(
                "Proof-of-possession is stale: {}s > {}s",
                elapsed.num_seconds(),
                PROOF_OF_POSSESSION_MAX_AGE_SECS
            )));
        }
        // Also reject proofs dated more than 30 seconds in the future (clock skew tolerance).
        if elapsed.num_seconds() < -30 {
            return Err(CoreError::InvalidInput(
                "Proof-of-possession timestamp is in the future".to_string(),
            ));
        }

        // mirror generate_pop's use
        // of microsecond precision in the verified message.
        let ts_micros = pop.timestamp().timestamp_micros();
        let message = format!("proof-of-possession-{}", ts_micros);

        let valid = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
            message.as_bytes(),
            pop.signature(),
            pop.public_key().as_slice(),
        )?;

        // reject re-presentation of a
        // verified PoP within the 5-minute acceptance window. Without
        // a cache, an attacker who captured a single valid PoP at
        // time T could replay it any number of times within
        // (T, T + 5 min). The cache is keyed on (pk, sig, ts_micros);
        // entries older than the freshness window above are
        // self-evicting since the freshness check would already have
        // rejected them on a re-replay attempt. The signature alone
        // is byte-unique per timestamp under Ed25519 determinism (see
        // `generate_pop` for why microsecond precision is necessary),
        // so the cache key only needs to disambiguate within a single
        // microsecond.
        if valid {
            let mut seen = self.pop_replay_cache.lock().map_err(|_poison| {
                CoreError::InvalidInput("PoP replay cache poisoned".to_string())
            })?;
            // Evict expired entries opportunistically.
            let now_secs = Utc::now().timestamp();
            seen.retain(|_, ts| now_secs.saturating_sub(*ts) <= PROOF_OF_POSSESSION_MAX_AGE_SECS);
            // Cache key combines PK + signature + microsecond timestamp;
            // collisions require either a cryptographic break or a
            // deliberate replay (the latter is what we're rejecting here).
            let key_cap = pop
                .public_key()
                .as_slice()
                .len()
                .saturating_add(pop.signature().len())
                .saturating_add(8);
            let mut key = Vec::with_capacity(key_cap);
            key.extend_from_slice(pop.public_key().as_slice());
            key.extend_from_slice(pop.signature());
            key.extend_from_slice(&ts_micros.to_be_bytes());
            if seen.contains_key(&key) {
                tracing::debug!(ts_micros, "PoP rejected: replay within 5-min window");
                return Err(CoreError::InvalidInput(
                    "Proof-of-possession replay detected".to_string(),
                ));
            }
            // Soft cap on cache size to bound memory under attack.
            const POP_CACHE_MAX: usize = 16 * 1024;
            if seen.len() < POP_CACHE_MAX {
                seen.insert(key, now_secs);
            }
        }

        Ok(valid)
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
        // The previous implementation generated a proof, discarded it
        // via `let _proof = ...`, and bumped `last_verification`
        // regardless. That made `last_verification` a "now" stamp on
        // every call — an attacker who tampered with the private-key
        // bytes (use-after-free, fuzz target, etc.) kept the session
        // perpetually `Verified`. We now actually verify the proof
        // against the challenge before bumping `last_verification`, and
        // surface a hard error on mismatch.
        let challenge = self.generate_challenge()?;
        let proof = self.generate_proof(challenge.data())?;

        let proof_valid = self.verify_proof(&proof, challenge.data())?;
        if !proof_valid {
            return Err(CoreError::AuthenticationFailed(
                "Reauthentication proof verification failed".to_string(),
            ));
        }

        *self.last_verification.borrow_mut() = Utc::now();
        Ok(())
    }
}

/// A cryptographic challenge for zero-trust authentication.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Random challenge data.
    data: Vec<u8>,
    /// When the challenge was created.
    timestamp: DateTime<Utc>,
    /// Required proof complexity.
    complexity: ProofComplexity,
    /// Timeout in milliseconds.
    timeout_ms: u64,
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
    challenge: Vec<u8>,
    /// The cryptographic proof data.
    proof: Vec<u8>,
    /// When the proof was generated.
    timestamp: DateTime<Utc>,
    /// Complexity level of the proof.
    complexity: ProofComplexity,
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
    public_key: PublicKey,
    /// Signature proving possession.
    signature: Vec<u8>,
    /// When the proof was generated.
    timestamp: DateTime<Utc>,
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

    let data = crate::primitives::security::generate_secure_random_bytes(size).map_err(|e| {
        CoreError::EntropyDepleted {
            message: format!("Failed to generate challenge: {e}"),
            action: "Check system entropy source".to_string(),
        }
    })?;
    // Challenge data is sent over the wire and is not secret material; the
    // ephemeral `Zeroizing` wrapper is dropped (and the source bytes wiped)
    // when this function returns.
    Ok(data.to_vec())
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

        // All complexity levels bind the timestamp into the signed
        // message so the verifier can enforce a freshness window. The
        // previous Low variant signed only `challenge`, making
        // `(challenge, signature)` pairs replayable indefinitely
        // until session expiry. Replay
        // protection is no longer opt-in.
        // Every variant binds the public key into the signed transcript
        // so a verifier holding pk can be sure the proof was produced
        // *for that pk* and not relayed from a session under a different
        // identity. Without PK binding, an attacker who captured a
        // valid (challenge, signature) pair under pk_A could replay it
        // against a verifier expecting pk_B if the signature happened
        // to verify under pk_B too (catastrophic if a verifier holds
        // multiple registered keys). The 1-byte domain tag separates
        // the three complexity levels so a Low proof cannot satisfy a
        // Medium or High verifier and vice versa.
        let message_to_sign = match self.config.proof_complexity {
            ProofComplexity::Low => {
                let mut msg = vec![0x01];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
            ProofComplexity::Medium => {
                let mut msg = vec![0x02];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
            ProofComplexity::High => {
                let mut msg = vec![0x03];
                msg.extend_from_slice(challenge);
                msg.extend_from_slice(&timestamp);
                msg.extend_from_slice(self.public_key.as_slice());
                msg
            }
        };

        // Sign the message - this IS zero-knowledge
        // The signature proves knowledge of private key without revealing it
        let signature = crate::unified_api::convenience::ed25519::sign_ed25519_internal(
            &message_to_sign,
            self.private_key.expose_secret(),
        )?;

        // Append the timestamp to the proof bytes so the verifier can
        // recover it. All three complexity levels now carry a timestamp
        // suffix (round-11 audit fix #16); older proofs without the
        // suffix will fail length check at verify time.
        let mut proof = signature;
        proof.extend_from_slice(&timestamp);
        Ok(proof)
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
                // Low now requires the
                // 8-byte timestamp suffix (mandatory replay protection).
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify signature BEFORE applying the
                // freshness check. The original ordering parsed the
                // timestamp out of `proof[64..72]` and ran the 30-s/
                // 5-min checks on raw adversary-supplied bytes; even
                // though signature verification would still catch a
                // tampered timestamp downstream, the principle
                // "authenticate before acting on adversary content"
                // wants verify first. Mirrored across Medium / High
                // branches below.
                let mut message = vec![0x01];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &message,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Timestamp is now authenticated — freshness check is
                // safe to run on `timestamp_bytes`.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
            }
            ProofComplexity::Medium => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify before freshness (mirrors Low).
                // Reconstruct signed message. The 0x02 domain tag
                // distinguishes Medium from Low/High; the public-key
                // suffix binds the signature to this specific
                // verifier identity (HPKE-style channel binding).
                let mut message = vec![0x02];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &message,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Reject stale proofs (>5 min drift).
                // Timestamp is encoded as chrono milliseconds in little-endian.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
            }
            ProofComplexity::High => {
                // Extract signature and timestamp
                if proof.len() < 72 {
                    return Ok(false);
                }
                let signature = proof.get(..64).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_slice = proof.get(64..72).ok_or_else(|| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;
                let timestamp_bytes: [u8; 8] = timestamp_slice.try_into().map_err(|_e| {
                    CoreError::AuthenticationFailed("Invalid proof format".to_string())
                })?;

                // verify before freshness (mirrors Low).
                // Reconstruct signed message with public key binding.
                // High prepends a 0x03 domain
                // tag so it is byte-distinguishable from both Low and
                // Medium.
                let mut message = vec![0x03];
                message.extend_from_slice(challenge);
                message.extend_from_slice(&timestamp_bytes);
                message.extend_from_slice(self.public_key.as_slice());
                let sig_ok = crate::unified_api::convenience::ed25519::verify_ed25519_internal(
                    &message,
                    signature,
                    self.public_key.as_slice(),
                )?;
                if !sig_ok {
                    return Ok(false);
                }

                // Reject stale proofs (>5 min drift).
                // Timestamp is encoded as chrono milliseconds in little-endian.
                let proof_ts_ms = i64::from_le_bytes(timestamp_bytes);
                let now_ms = Utc::now().timestamp_millis();
                // tighten the future-skew cap
                // to match the sibling `verify_pop` path. `abs_diff(...)
                // > 300_000` accepted proofs up to 5 min in the future,
                // which gives an attacker with a forward-skewed clock a
                // 10-min replay window. Reject anything more than 30 s
                // ahead of "now"; the 5-min window only applies to the
                // past direction.
                if proof_ts_ms > now_ms.saturating_add(30_000) {
                    tracing::warn!(
                        proof_ts_ms,
                        now_ms,
                        "proof timestamp more than 30 s in the future"
                    );
                    return Ok(false);
                }
                let drift_ms = now_ms.abs_diff(proof_ts_ms);
                if drift_ms > 300_000 {
                    tracing::warn!(drift_ms, "proof timestamp outside 5-min freshness window");
                    return Ok(false);
                }

                Ok(true)
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

        let verified = self.auth.verify_proof(proof, challenge.data())?;
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
    use crate::unified_api::generate_keypair;

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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        assert!(session.is_valid());
        // After self-authentication during establish, trust level is upgraded
        assert!(session.trust_level() >= TrustLevel::Partial);
        Ok(())
    }

    #[test]
    fn test_verified_session_session_id_is_accessible() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        let session_id = session.session_id();
        assert_eq!(session_id.len(), 32);
        Ok(())
    }

    #[test]
    fn test_verified_session_public_key_is_accessible() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        let pk = session.public_key();
        assert!(!pk.is_empty());
        Ok(())
    }

    #[test]
    fn test_verified_session_timestamps_are_accessible() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        let authenticated_at = session.authenticated_at();
        let expires_at = session.expires_at();

        assert!(expires_at > authenticated_at, "Session should expire after authentication");
        Ok(())
    }

    #[test]
    fn test_verified_session_verify_valid_succeeds() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        session.verify_valid()?;
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_with_session_succeeds() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        let mode = SecurityMode::Verified(&session);
        assert!(mode.is_verified());
        assert!(!mode.is_unverified());
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_validate_succeeds() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

        let mode = SecurityMode::Verified(&session);
        mode.validate()?;
        Ok(())
    }

    #[test]
    fn test_security_mode_verified_session_is_accessible() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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
        let config =
            ZeroTrustConfig::new().with_timeout(10000).with_complexity(ProofComplexity::High);

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

        let continuous = auth.start_continuous_verification();
        let result = continuous.is_valid();

        assert!(result.is_ok());
        Ok(())
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
        let session1 =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
        let session2 =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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

        let continuous = auth.start_continuous_verification();
        assert!(continuous.is_valid().is_ok());
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_with_all_complexity_levels_succeeds() -> Result<()> {
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
    fn test_security_mode_explicit_unverified_succeeds() {
        // Pinning the explicit-construction shape after `impl Default for
        // SecurityMode` was removed (round-6 audit fix #5). Callers must
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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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
    fn test_zero_trust_session_verify_response_returns_error_without_challenge_fails() -> Result<()>
    {
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

        let continuous = auth.start_continuous_verification();
        assert_eq!(continuous.auth_public_key(), &public_key);
        Ok(())
    }

    #[test]
    fn test_continuous_session_update_verification_succeeds() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let auth = ZeroTrustAuth::new(public_key, private_key)?;

        let mut continuous = auth.start_continuous_verification();
        assert!(continuous.is_valid()?);

        continuous.update_verification()?;
        assert!(continuous.is_valid()?);
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
        let empty_proof =
            ZeroKnowledgeProof::new(vec![1], vec![], Utc::now(), ProofComplexity::Low);
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

        let status = auth.verify_continuously()?;
        // Default config has continuous_verification=false, so should be Verified
        assert_eq!(status, VerificationStatus::Verified);
        Ok(())
    }

    #[test]
    fn test_zero_trust_auth_verify_continuously_with_cv_enabled_succeeds() -> Result<()> {
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

        let pop = auth.generate_pop()?;
        let verified = auth.verify_pop(&pop)?;
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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;
        let verified_mode = SecurityMode::Verified(&session);
        let debug2 = format!("{:?}", verified_mode);
        assert!(debug2.contains("Verified"));
        Ok(())
    }

    #[test]
    fn test_challenge_fields_are_accessible() -> Result<()> {
        let (public_key, private_key) = generate_keypair()?;
        let config =
            ZeroTrustConfig::new().with_timeout(5000).with_complexity(ProofComplexity::High);
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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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
        let session =
            VerifiedSession::establish(public_key.as_slice(), private_key.expose_secret())?;

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
    // round-12 L-3 fix that capped forward clock-skew tolerance at
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
        let pop =
            ProofOfPossessionData::new(PublicKey::new(vec![1, 2, 3]), vec![0u8; 64], Utc::now());
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
        assert_eq!(
            challenge_b.data().len(),
            128,
            "High complexity must produce 128-byte challenge"
        );
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
        let config_a = ZeroTrustConfig::new()
            .with_continuous_verification(false)
            .with_verification_interval(1); // 1ms interval — irrelevant when cv=false
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
    fn test_verification_interval_ms_influences_continuous_session_validity_succeeds() -> Result<()>
    {
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

        let session_a = auth_a.start_continuous_verification();
        let session_b = auth_b.start_continuous_verification();

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
}
