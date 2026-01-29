#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Authentication request and response structures

use chrono::{DateTime, Duration, Utc};
use zeroize::Zeroize;

use super::constants::CHALLENGE_LENGTH;
use super::proofs::ZeroKnowledgeProof;
use crate::unified_api::error::CryptoError;

/// Authentication request
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    /// Client identifier
    pub client_id: String,
    /// Challenge bytes
    pub challenge: Vec<u8>,
    /// Zero-knowledge proof
    pub proof: ZeroKnowledgeProof,
    /// Request timestamp
    pub timestamp: DateTime<Utc>,
}

impl AuthenticationRequest {
    /// Create a new authentication request
    pub fn new(client_id: String, challenge: Vec<u8>, proof: ZeroKnowledgeProof) -> Self {
        Self { client_id, challenge, proof, timestamp: DateTime::<Utc>::now() }
    }

    /// Check if request is valid
    pub fn is_valid(&self) -> bool {
        !self.client_id.is_empty()
            && self.challenge.len() == CHALLENGE_LENGTH
            && self.proof.is_valid()
    }

    /// Get age of the request
    pub fn age(&self) -> Result<Duration, CryptoError> {
        let now = Utc::now();
        let duration = now.signed_duration_since(self.timestamp);
        duration.to_std().map_err(|e| CryptoError::InvalidInput(format!("Invalid duration: {}", e)))
    }
}

impl Drop for AuthenticationRequest {
    fn drop(&mut self) {
        self.challenge.zeroize();
        self.proof.proof_data.zeroize();
    }
}

/// Authentication response
#[derive(Debug, Clone)]
pub struct AuthenticationResponse {
    /// Whether authentication succeeded
    pub success: bool,
    /// Session ID if successful
    pub session_id: Option<String>,
    /// Session expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Next verification time
    pub next_verification: Option<DateTime<Utc>>,
}

impl AuthenticationResponse {
    /// Create a successful response
    pub fn success(
        session_id: String,
        expires_at: DateTime<Utc>,
        next_verification: DateTime<Utc>,
    ) -> Self {
        Self {
            success: true,
            session_id: Some(session_id),
            expires_at: Some(expires_at),
            next_verification: Some(next_verification),
        }
    }

    /// Create a failure response
    pub fn failure() -> Self {
        Self { success: false, session_id: None, expires_at: None, next_verification: None }
    }
}
