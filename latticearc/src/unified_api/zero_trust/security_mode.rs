//! Security mode gate: `SecurityMode` and its validation logic.

use super::TrustLevel;
use super::VerifiedSession;
use crate::log_zero_trust_session_verification_failed;
use crate::log_zero_trust_unverified_mode;
use crate::unified_api::error::{CoreError, Result};

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
