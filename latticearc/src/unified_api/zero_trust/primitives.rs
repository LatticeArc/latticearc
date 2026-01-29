#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust security primitives.
//!
//! This module provides foundational security types including trust levels,
//! security contexts, MFA challenges/responses, and verification results.

use chrono::{DateTime, Utc};

use crate::unified_api::{error::CryptoError, types::CryptoContext};

use super::super::zero_trust::ZeroKnowledgeProof;

pub const TRUST_LEVEL_ZERO_DURATION_SECS: u64 = 300;
pub const TRUST_LEVEL_LOW_DURATION_SECS: u64 = 1800;
pub const TRUST_LEVEL_MEDIUM_DURATION_SECS: u64 = 3600;
pub const TRUST_LEVEL_HIGH_DURATION_SECS: u64 = 7200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TrustLevel {
    Zero = 0,
    Low = 1,
    #[default]
    Medium = 2,
    High = 3,
}

impl TrustLevel {
    pub fn verification_interval_secs(&self) -> u64 {
        match self {
            TrustLevel::Zero => 300,
            TrustLevel::Low => 600,
            TrustLevel::Medium => 1800,
            TrustLevel::High => 3600,
        }
    }

    pub fn session_duration_secs(&self) -> u64 {
        match self {
            TrustLevel::Zero => TRUST_LEVEL_ZERO_DURATION_SECS,
            TrustLevel::Low => TRUST_LEVEL_LOW_DURATION_SECS,
            TrustLevel::Medium => TRUST_LEVEL_MEDIUM_DURATION_SECS,
            TrustLevel::High => TRUST_LEVEL_HIGH_DURATION_SECS,
        }
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(TrustLevel::Zero),
            1 => Some(TrustLevel::Low),
            2 => Some(TrustLevel::Medium),
            3 => Some(TrustLevel::High),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecurityContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<Location>,
    pub device_fingerprint: Option<String>,
    pub additional_context: std::collections::HashMap<String, String>,
}

impl SecurityContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn with_location(mut self, loc: Location) -> Self {
        self.location = Some(loc);
        self
    }

    pub fn with_device_fingerprint(mut self, fp: String) -> Self {
        self.device_fingerprint = Some(fp);
        self
    }

    pub fn add_context(mut self, key: String, value: String) -> Self {
        self.additional_context.insert(key, value);
        self
    }
}

#[derive(Debug, Clone)]
pub struct Location {
    pub country: String,
    pub region: String,
    pub city: String,
}

impl Location {
    pub fn new(country: String, region: String, city: String) -> Self {
        Self { country, region, city }
    }

    pub fn matches(&self, allowed_locations: &[String]) -> bool {
        allowed_locations
            .iter()
            .any(|loc| loc == &self.country || loc == &self.region || loc == &self.city)
    }
}

#[derive(Debug, Clone)]
pub struct MFAChallenge {
    pub challenge_id: String,
    pub challenge_type: MFAChallengeType,
    pub challenge_data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MFAChallengeType {
    TOTP,
    SMS,
    Email,
    HardwareToken,
    Biometric,
}

impl MFAChallenge {
    pub fn new(
        challenge_id: String,
        challenge_type: MFAChallengeType,
        challenge_data: Vec<u8>,
        expires_in_secs: u64,
    ) -> Result<Self, CryptoError> {
        if challenge_data.is_empty() {
            return Err(CryptoError::InvalidInput("Challenge data cannot be empty".to_string()));
        }

        let now = Utc::now();
        let expires_at = now
            .checked_add(std::time::Duration::from_secs(expires_in_secs))
            .ok_or_else(|| CryptoError::InvalidInput("Invalid expiration time".to_string()))?;

        Ok(Self { challenge_id, challenge_type, challenge_data, expires_at, created_at: now })
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at.signed_duration_since(Utc::now()).to_std() {
            Ok(duration) => duration.as_millis() > 0,
            Err(_) => false,
        }
    }

    pub fn age_secs(&self) -> u64 {
        self.created_at.timestamp() as u64
    }
}

#[derive(Debug, Clone)]
pub struct MFAResponse {
    pub challenge_id: String,
    pub response_data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

impl MFAResponse {
    pub fn new(challenge_id: String, response_data: Vec<u8>) -> Self {
        Self { challenge_id, response_data, timestamp: DateTime::<Utc>::now() }
    }

    pub fn is_valid(&self) -> bool {
        !self.challenge_id.is_empty() && !self.response_data.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationContext {
    pub trust_level: TrustLevel,
    pub security_context: SecurityContext,
    pub mfa_required: bool,
    pub continuous_verification: bool,
    pub verification_interval_secs: u64,
    pub crypto_context: CryptoContext,
}

impl Default for AuthenticationContext {
    fn default() -> Self {
        Self {
            trust_level: TrustLevel::default(),
            security_context: SecurityContext::default(),
            mfa_required: false,
            continuous_verification: true,
            verification_interval_secs: TrustLevel::Medium.verification_interval_secs(),
            crypto_context: CryptoContext::default(),
        }
    }
}

impl AuthenticationContext {
    pub fn new(trust_level: TrustLevel) -> Self {
        Self {
            trust_level,
            verification_interval_secs: trust_level.verification_interval_secs(),
            ..Default::default()
        }
    }

    pub fn with_security_context(mut self, ctx: SecurityContext) -> Self {
        self.security_context = ctx;
        self
    }

    pub fn with_mfa_required(mut self, required: bool) -> Self {
        self.mfa_required = required;
        self
    }

    pub fn with_continuous_verification(mut self, enabled: bool) -> Self {
        self.continuous_verification = enabled;
        self
    }

    pub fn with_verification_interval(mut self, interval_secs: u64) -> Self {
        self.verification_interval_secs = interval_secs;
        self
    }

    pub fn with_crypto_context(mut self, ctx: CryptoContext) -> Self {
        self.crypto_context = ctx;
        self
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub verified: bool,
    pub trust_level: TrustLevel,
    pub confidence: f64,
    pub timestamp: DateTime<Utc>,
    pub metadata: std::collections::HashMap<String, String>,
}

impl VerificationResult {
    pub fn success(trust_level: TrustLevel) -> Self {
        Self {
            verified: true,
            trust_level,
            confidence: 1.0,
            timestamp: DateTime::<Utc>::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn failure(reason: String) -> Self {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("reason".to_string(), reason);

        Self {
            verified: false,
            trust_level: TrustLevel::Zero,
            confidence: 0.0,
            timestamp: DateTime::<Utc>::now(),
            metadata,
        }
    }

    pub fn partial(trust_level: TrustLevel, confidence: f64) -> Self {
        Self {
            verified: confidence > 0.5,
            trust_level,
            confidence,
            timestamp: DateTime::<Utc>::now(),
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn is_verified(&self) -> bool {
        self.verified
    }
}

pub trait TrustEvaluatable {
    fn evaluate_trust(
        &self,
        ctx: &AuthenticationContext,
    ) -> Result<VerificationResult, CryptoError>;
    fn trust_level(&self) -> TrustLevel;
    fn requires_mfa(&self) -> bool;
    fn requires_reverification(&self, last_verified: DateTime<Utc>) -> bool;
}

pub trait ZeroTrustPrimitives {
    type Error;

    fn generate_challenge(&self) -> Result<Vec<u8>, Self::Error>;
    fn verify_challenge(
        &self,
        challenge: &[u8],
        proof: &ZeroKnowledgeProof,
    ) -> Result<bool, Self::Error>;
    fn compute_trust_score(&self, factors: &TrustFactors) -> Result<f64, Self::Error>;
}

#[derive(Debug, Clone, Default)]
pub struct TrustFactors {
    pub authentication_success: bool,
    pub mfa_verified: bool,
    pub device_known: bool,
    pub location_allowed: bool,
    pub time_window_valid: bool,
    pub behavior_normal: bool,
}

impl TrustFactors {
    pub fn score(&self) -> f64 {
        let mut score = 0.0;
        let weight = 1.0 / 6.0;

        if self.authentication_success {
            score += weight;
        }
        if self.mfa_verified {
            score += weight;
        }
        if self.device_known {
            score += weight;
        }
        if self.location_allowed {
            score += weight;
        }
        if self.time_window_valid {
            score += weight;
        }
        if self.behavior_normal {
            score += weight;
        }

        score
    }

    pub fn trust_level(&self) -> TrustLevel {
        let score = self.score();

        if score >= 0.8 {
            TrustLevel::High
        } else if score >= 0.6 {
            TrustLevel::Medium
        } else if score >= 0.4 {
            TrustLevel::Low
        } else {
            TrustLevel::Zero
        }
    }

    pub fn requires_mfa(&self) -> bool {
        !self.mfa_verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_durations() {
        assert_eq!(TrustLevel::Zero.session_duration_secs(), 300);
        assert_eq!(TrustLevel::Low.session_duration_secs(), 1800);
        assert_eq!(TrustLevel::Medium.session_duration_secs(), 3600);
    }

    #[test]
    fn test_trust_level_verification_intervals() {
        assert_eq!(TrustLevel::Zero.verification_interval_secs(), 300);
        assert_eq!(TrustLevel::Low.verification_interval_secs(), 600);
        assert_eq!(TrustLevel::Medium.verification_interval_secs(), 1800);
    }

    #[test]
    fn test_trust_level_ord() {
        assert!(TrustLevel::High > TrustLevel::Medium);
        assert!(TrustLevel::Medium > TrustLevel::Low);
        assert!(TrustLevel::Low > TrustLevel::Zero);
    }

    #[test]
    fn test_security_context_builder() {
        let ctx = SecurityContext::new()
            .with_ip("127.0.0.1".to_string())
            .with_user_agent("Mozilla/5.0".to_string())
            .with_device_fingerprint("fp123".to_string())
            .add_context("key1".to_string(), "value1".to_string());

        assert_eq!(ctx.ip_address, Some("127.0.0.1".to_string()));
        assert_eq!(ctx.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(ctx.device_fingerprint, Some("fp123".to_string()));
        assert_eq!(ctx.additional_context.get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_mfa_challenge_expiration() {
        let challenge =
            MFAChallenge::new("id1".to_string(), MFAChallengeType::TOTP, vec![1, 2, 3], 10)
                .expect("Failed to create challenge");

        assert!(!challenge.is_expired());

        let expired_challenge =
            MFAChallenge::new("id2".to_string(), MFAChallengeType::TOTP, vec![1, 2, 3], 0)
                .expect("Failed to create challenge");

        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(expired_challenge.is_expired());
    }

    #[test]
    fn test_trust_factors_scoring() {
        let mut factors = TrustFactors::default();
        assert_eq!(factors.score(), 0.0);

        factors.authentication_success = true;
        assert!(factors.score() > 0.0);

        factors.mfa_verified = true;
        factors.device_known = true;
        factors.location_allowed = true;
        factors.time_window_valid = true;
        factors.behavior_normal = true;

        assert!((factors.score() - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_trust_factors_level() {
        let mut factors = TrustFactors::default();
        assert_eq!(factors.trust_level(), TrustLevel::Zero);

        factors.authentication_success = true;
        factors.mfa_verified = true;
        factors.device_known = true;
        factors.location_allowed = true;

        factors.time_window_valid = true;

        assert_eq!(factors.trust_level(), TrustLevel::High);

        factors.behavior_normal = true;
    }

    #[test]
    fn test_location_matching() {
        let loc = Location::new("US".to_string(), "CA".to_string(), "SF".to_string());

        assert!(loc.matches(&["US".to_string()]));
        assert!(loc.matches(&["CA".to_string()]));
        assert!(loc.matches(&["SF".to_string()]));
        assert!(!loc.matches(&["UK".to_string()]));
    }

    #[test]
    fn test_authentication_context() {
        let ctx = AuthenticationContext::new(TrustLevel::High)
            .with_mfa_required(true)
            .with_continuous_verification(true)
            .with_verification_interval(1800);

        assert!(ctx.mfa_required);
        assert!(ctx.continuous_verification);
        assert_eq!(ctx.verification_interval_secs, 1800);
    }

    #[test]
    fn test_verification_result() {
        let success = VerificationResult::success(TrustLevel::High);
        assert!(success.is_verified());
        assert_eq!(success.confidence, 1.0);

        let failure = VerificationResult::failure("Invalid proof".to_string());
        assert!(!failure.is_verified());
        assert_eq!(failure.trust_level, TrustLevel::Zero);

        let partial = VerificationResult::partial(TrustLevel::Medium, 0.6);
        assert!(partial.is_verified());
        assert_eq!(partial.confidence, 0.6);
    }
}
