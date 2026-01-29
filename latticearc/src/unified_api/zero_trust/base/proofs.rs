#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-knowledge proof and proof-of-possession token structures

use chrono::{DateTime, Duration, Utc};
use zeroize::Zeroize;

use super::types::{ProofMetadata, ProofType};
use crate::unified_api::error::CryptoError;

/// Zero-knowledge proof structure
#[derive(Debug, Clone)]
pub struct ZeroKnowledgeProof {
    /// Type of proof
    pub proof_type: ProofType,
    /// Proof data bytes
    pub proof_data: Vec<u8>,
    /// Proof metadata
    pub metadata: ProofMetadata,
}

impl Drop for ZeroKnowledgeProof {
    fn drop(&mut self) {
        self.proof_data.zeroize();
    }
}

impl ZeroKnowledgeProof {
    /// Create a new zero-knowledge proof
    pub fn new(proof_type: ProofType, proof_data: Vec<u8>, metadata: ProofMetadata) -> Self {
        Self { proof_type, proof_data, metadata }
    }

    /// Create a Schnorr proof with default metadata
    pub fn schnorr(proof_data: Vec<u8>) -> Self {
        Self { proof_type: ProofType::Schnorr, proof_data, metadata: ProofMetadata::default() }
    }

    /// Check if proof is valid
    pub fn is_valid(&self) -> bool {
        !self.proof_data.is_empty()
    }

    /// Get age of the proof
    pub fn age(&self) -> Result<Duration, CryptoError> {
        let now = Utc::now();
        let duration = now.signed_duration_since(self.metadata.created_at);
        duration.to_std().map_err(|e| CryptoError::InvalidInput(format!("Invalid duration: {}", e)))
    }
}

/// Proof of possession token
#[derive(Debug, Clone)]
pub struct ProofOfPossessionToken {
    /// Key identifier
    pub key_id: String,
    /// Token data
    pub token_data: Vec<u8>,
    /// Signature over token data
    pub signature: Vec<u8>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
}

impl ProofOfPossessionToken {
    /// Create a new proof of possession token
    pub fn new(
        key_id: String,
        token_data: Vec<u8>,
        signature: Vec<u8>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self { key_id, token_data, signature, expires_at }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_secs() > 0,
            Err(_) => false,
        }
    }

    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        !self.token_data.is_empty()
            && !self.signature.is_empty()
            && !self.key_id.is_empty()
            && !self.is_expired()
    }
}

impl Drop for ProofOfPossessionToken {
    fn drop(&mut self) {
        self.token_data.zeroize();
        self.signature.zeroize();
    }
}
