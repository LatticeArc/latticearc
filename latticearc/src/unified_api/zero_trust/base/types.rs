#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Type definitions for zero-trust authentication

use chrono::{DateTime, Utc};

/// Type of zero-knowledge proof
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofType {
    /// Schnorr signature-based proof
    Schnorr,
    /// Knowledge of key proof
    KnowledgeOfKey,
    /// Discrete logarithm proof
    DiscreteLog,
}

/// Authentication factor type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthenticationFactor {
    /// Knowledge factor (password, PIN)
    SomethingYouKnow,
    /// Possession factor (token, device)
    SomethingYouHave,
    /// Inherence factor (biometric)
    SomethingYouAre,
}

/// Metadata for zero-knowledge proofs
#[derive(Debug, Clone)]
pub struct ProofMetadata {
    /// Type of proof
    pub proof_type: ProofType,
    /// Authentication factors used
    pub factors: Vec<AuthenticationFactor>,
    /// Security level in bits
    pub security_level: u32,
    /// Timestamp when proof was created
    pub created_at: DateTime<Utc>,
}

impl Default for ProofMetadata {
    fn default() -> Self {
        Self {
            proof_type: ProofType::Schnorr,
            factors: vec![AuthenticationFactor::SomethingYouHave],
            security_level: 128,
            created_at: DateTime::<Utc>::now(),
        }
    }
}
