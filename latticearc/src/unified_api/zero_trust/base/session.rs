#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Verification session management

use chrono::{DateTime, Duration, Utc};

use crate::unified_api::error::CryptoError;

/// Verification session
#[derive(Debug, Clone)]
pub struct VerificationSession {
    /// Unique session identifier
    pub session_id: String,
    /// Client identifier
    pub client_id: String,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Last verification time
    pub last_verified: DateTime<Utc>,
    /// Next verification time
    pub next_verification: DateTime<Utc>,
}

impl VerificationSession {
    /// Create a new verification session
    pub fn new(
        session_id: String,
        client_id: String,
        timeout: Duration,
        verifier_interval: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            session_id,
            client_id,
            created_at: now,
            expires_at: now
                .checked_add(timeout)
                .unwrap_or_else(|| now.checked_add(Duration::from_secs(3600)).unwrap()),
            last_verified: now,
            next_verification: now.checked_add(verifier_interval).unwrap_or(now),
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_millis() > 0,
            Err(_) => false,
        }
    }

    /// Check if session needs verification
    pub fn needs_verification(&self) -> bool {
        match self.next_verification.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_millis() > 0,
            Err(_) => true,
        }
    }

    /// Extend the session
    pub fn extend(&mut self, additional_time: Duration) -> Result<(), CryptoError> {
        self.expires_at = self.expires_at.checked_add(additional_time).ok_or_else(|| {
            CryptoError::InvalidInput("Cannot extend session: overflow".to_string())
        })?;
        self.next_verification =
            Utc::now().checked_add_signed(chrono::Duration::from_std(additional_time).unwrap()).ok_or_else(|| {
                CryptoError::InvalidInput("Cannot extend verification time: overflow".to_string())
            })?;
        Ok(())
    }
}
