//! `VerifiedSession`: proof that Zero Trust authentication has completed.

use super::{TrustLevel, ZeroTrustAuth, ZeroTrustSession};
use crate::types::traits::ZeroTrustAuthenticable;
use crate::unified_api::error::{CoreError, Result};
use crate::{
    log_zero_trust_auth_failure, log_zero_trust_auth_success, log_zero_trust_session_created,
    log_zero_trust_session_expired, log_zero_trust_session_verified,
    types::{PrivateKey, PublicKey},
};
use chrono::{DateTime, Duration, Utc};

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
    ///
    /// `pub(super)`: constructed via struct literal by the `tests`
    /// submodule (expired-session fixtures) — see `zero_trust::tests`.
    pub(super) session_id: [u8; 32],
    /// Timestamp when authentication was completed (wall-clock, for
    /// audit display only — never used for validity decisions).
    pub(super) authenticated_at: DateTime<Utc>,
    /// Current trust level.
    pub(super) trust_level: TrustLevel,
    /// Public key that was verified.
    pub(super) public_key: PublicKey,
    /// When this session expires (wall-clock, for audit display only).
    pub(super) expires_at: DateTime<Utc>,
    /// monotonic instant + lifetime drive `is_valid()`.
    /// NTP rollback can't extend a session past its policy lifetime.
    pub(super) issued_at_monotonic: std::time::Instant,
    pub(super) lifetime: std::time::Duration,
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

    /// Downgrade the session's trust level. M3: previously the
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
