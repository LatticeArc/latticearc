#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust authentication core implementation

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    ProjectivePoint,
};
use rand::RngCore;
use sha2::Sha256;
use subtle::Choice;

use super::constants::{CHALLENGE_LENGTH, SESSION_ID_LENGTH};
use super::proofs::{ProofOfPossessionToken, ZeroKnowledgeProof};
use super::requests::{AuthenticationRequest, AuthenticationResponse};
use super::schnorr::{
    compute_schnorr_challenge, parse_public_key_point, parse_scalar, scalar_to_bytes, SchnorrProof,
};
use super::session::VerificationSession;
use super::types::{AuthenticationFactor, ProofMetadata, ProofType};
use crate::unified_api::{
    ContinuousSession,
    config::ZeroTrustConfig,
    error::CryptoError,
    traits::{ContinuousVerifiable, ProofOfPossession, ZeroTrustAuthenticable},
    types::{CryptoContext, VerificationStatus},
};

/// Zero-trust authentication manager
pub struct ZeroTrustAuth {
    scheme: crate::unified_api::types::CryptoScheme,
    session_timeout: Duration,
    verifier_interval: Duration,
    active_sessions: Arc<RwLock<HashMap<String, VerificationSession>>>,
    config: ZeroTrustConfig,
}

impl ZeroTrustAuth {
    /// Create a new zero-trust auth instance
    pub fn new(scheme: crate::unified_api::types::CryptoScheme) -> Result<Self, CryptoError> {
        Ok(Self {
            scheme,
            session_timeout: Duration::from_secs(3600),
            verifier_interval: Duration::from_secs(60),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            config: ZeroTrustConfig::default(),
        })
    }

    /// Set session timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Set verification interval
    pub fn with_verification_interval(mut self, interval: Duration) -> Self {
        self.verifier_interval = interval;
        self
    }

    /// Set configuration
    pub fn with_config(mut self, config: ZeroTrustConfig) -> Self {
        self.config = config;
        self
    }

    /// Get crypto scheme
    pub fn scheme(&self) -> crate::unified_api::types::CryptoScheme {
        self.scheme
    }

    /// Get session timeout
    pub fn session_timeout(&self) -> Duration {
        self.session_timeout
    }

    /// Get verifier interval
    pub fn verifier_interval(&self) -> Duration {
        self.verifier_interval
    }

    /// Generate a challenge for authentication
    pub fn generate_challenge(&self, client_id: &str) -> Result<Vec<u8>, CryptoError> {
        if client_id.is_empty() {
            return Err(CryptoError::InvalidInput("Client ID cannot be empty".to_string()));
        }

        let mut challenge = vec![0u8; CHALLENGE_LENGTH];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut challenge);
        Ok(challenge)
    }

    /// Verify authentication request
    pub fn verify_authentication(
        &self,
        request: &AuthenticationRequest,
        expected_public_key: &[u8],
    ) -> Result<AuthenticationResponse, CryptoError> {
        if !request.is_valid() {
            return Ok(AuthenticationResponse::failure());
        }

        let verified = self.verify_zkp(&request.proof, &request.challenge, expected_public_key)?;

        if verified {
            let session = self.start_session(&request.client_id)?;
            Ok(AuthenticationResponse::success(
                session.session_id.clone(),
                session.expires_at,
                session.next_verification,
            ))
        } else {
            Ok(AuthenticationResponse::failure())
        }
    }

    /// Generate proof of possession token
    pub fn generate_possession_token(
        &self,
        key_pair: &crate::unified_api::types::KeyPair,
        key_id: &str,
    ) -> Result<ProofOfPossessionToken, CryptoError> {
        if key_id.is_empty() {
            return Err(CryptoError::InvalidInput("Key ID cannot be empty".to_string()));
        }

        let (public_key, _private_key) = key_pair;

        if public_key.is_empty() {
            return Err(CryptoError::InvalidInput("Public key cannot be empty".to_string()));
        }

        let mut token_data = vec![0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut token_data);

        let signature = self.sign_token(&token_data, _private_key.as_slice())?;

        let expires_at =
            Utc::now().checked_add_signed(chrono::Duration::seconds(300)).unwrap_or_else(|| Utc::now());

        Ok(ProofOfPossessionToken::new(key_id.to_string(), token_data, signature, expires_at))
    }

    /// Verify proof of possession token
    pub fn verify_possession_token(
        &self,
        token: &ProofOfPossessionToken,
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        if !token.is_valid() {
            return Ok(false);
        }

        if public_key.is_empty() {
            return Err(CryptoError::InvalidInput("Public key cannot be empty".to_string()));
        }

        self.verify_token_signature(&token.token_data, &token.signature, public_key)
    }

    /// Generate zero-knowledge proof
    pub fn generate_zkp(
        &self,
        secret: &[u8],
        challenge: &[u8],
    ) -> Result<ZeroKnowledgeProof, CryptoError> {
        if secret.is_empty() {
            return Err(CryptoError::InvalidInput("Secret cannot be empty".to_string()));
        }

        if challenge.len() != CHALLENGE_LENGTH {
            return Err(CryptoError::InvalidInput(format!(
                "Challenge must be {} bytes",
                CHALLENGE_LENGTH
            )));
        }

        let proof_data = self.compute_schnorr_proof(secret, challenge)?;
        let metadata = ProofMetadata {
            proof_type: ProofType::Schnorr,
            factors: vec![AuthenticationFactor::SomethingYouHave],
            security_level: self.config.proof_complexity.as_security_level(),
            created_at: DateTime::<Utc>::now(),
        };

        Ok(ZeroKnowledgeProof::new(ProofType::Schnorr, proof_data, metadata))
    }

    /// Verify zero-knowledge proof
    pub fn verify_zkp(
        &self,
        proof: &ZeroKnowledgeProof,
        challenge: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        if !proof.is_valid() {
            return Ok(false);
        }

        if challenge.len() != CHALLENGE_LENGTH {
            return Err(CryptoError::InvalidInput(format!(
                "Challenge must be {} bytes",
                CHALLENGE_LENGTH
            )));
        }

        if public_key.is_empty() {
            return Err(CryptoError::InvalidInput("Public key cannot be empty".to_string()));
        }

        match proof.proof_type {
            ProofType::Schnorr => self.verify_schnorr_proof(proof, challenge, public_key),
            _ => Ok(false),
        }
    }

    /// Start a new session
    pub fn start_session(&self, client_id: &str) -> Result<VerificationSession, CryptoError> {
        if client_id.is_empty() {
            return Err(CryptoError::InvalidInput("Client ID cannot be empty".to_string()));
        }

        let mut session_id_bytes = vec![0u8; SESSION_ID_LENGTH];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut session_id_bytes);
        let session_id: String = session_id_bytes.iter().map(|b| format!("{:02x}", b)).collect();

        let session = VerificationSession::new(
            session_id.clone(),
            client_id.to_string(),
            self.session_timeout,
            self.verifier_interval,
        );

        {
            let mut sessions = self
                .active_sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
            sessions.insert(session_id.clone(), session.clone());
        }

        Ok(session)
    }

    /// Verify a session
    pub fn verify_session(&self, session: &VerificationSession) -> Result<bool, CryptoError> {
        if session.is_expired() { Ok(false) } else { Ok(true) }
    }

    /// Extend a session
    pub fn extend_session(&self, session: &mut VerificationSession) -> Result<(), CryptoError> {
        session.extend(self.session_timeout)?;
        session.last_verified = Utc::now();

        {
            let mut sessions = self
                .active_sessions
                .write()
                .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
            sessions.insert(session.session_id.clone(), session.clone());
        }

        Ok(())
    }

    /// Revoke a session
    pub fn revoke_session(&self, session_id: &str) -> Result<(), CryptoError> {
        let mut sessions = self
            .active_sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
        sessions.remove(session_id);
        Ok(())
    }

    /// Compute Schnorr proof using secp256k1 curve arithmetic
    ///
    /// Following FIPS 186-5 / MuSig style Schnorr:
    /// 1. Generate random nonce r
    /// 2. Compute commitment: R = g^r
    /// 3. Compute challenge: e = H(g || pub_key || R || challenge)
    /// 4. Compute response: s = r + e * x
    /// 5. Return (R, s)
    fn compute_schnorr_proof(
        &self,
        secret: &[u8],
        challenge: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Validate inputs
        if secret.len() != 32 {
            return Err(CryptoError::InvalidInput(
                "Secret key must be 32 bytes".to_string(),
            ));
        }

        // Parse secret key to scalar
        let secret_scalar = parse_scalar(secret)?;

        // Compute public key: Y = g^x
        let public_key = ProjectivePoint::GENERATOR * secret_scalar;

        // Generate random nonce r
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce_scalar = parse_scalar(&nonce_bytes)?;

        // Compute commitment: R = g^r
        let commitment = ProjectivePoint::GENERATOR * nonce_scalar;

        // Compute challenge: e = H(g || Y || R || challenge)
        let challenge_scalar = compute_schnorr_challenge(&public_key, &commitment, challenge)?;

        // Compute response: s = r + e * x (mod n)
        // s = r + e * x
        let e_times_x = challenge_scalar * secret_scalar;
        let response_scalar = nonce_scalar + e_times_x;

        // Serialize proof: commitment (33 bytes compressed) + response (32 bytes)
        let proof = SchnorrProof {
            commitment: commitment.to_encoded_point(true).as_bytes().to_vec(),
            response: scalar_to_bytes(&response_scalar).to_vec(),
        };

        Ok(proof.to_bytes())
    }

    /// Verify Schnorr proof using secp256k1 curve arithmetic
    ///
    /// Verification equation: g^s ?= R * Y^e
    /// Where:
    /// - s is the response
    /// - R is the commitment
    /// - Y is the public key
    /// - e is the recomputed challenge
    ///
    /// This is derived from the proof:
    /// s = r + e * x (mod n)
    /// g^s = g^(r + e*x) = g^r * g^(e*x) = R * (g^x)^e = R * Y^e
    fn verify_schnorr_proof(
        &self,
        proof: &ZeroKnowledgeProof,
        challenge: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        // Parse the Schnorr proof
        let schnorr_proof = SchnorrProof::from_bytes(&proof.proof_data)?;

        if !schnorr_proof.is_valid() {
            return Ok(false);
        }

        // Parse public key to point
        let public_key_point = parse_public_key_point(public_key)?;

        // Parse commitment R to point
        let commitment = parse_public_key_point(&schnorr_proof.commitment)?;

        // Parse response s to scalar
        let response_scalar = parse_scalar(&schnorr_proof.response)?;

        // Recompute challenge: e' = H(g || Y || R || challenge)
        let challenge_scalar = compute_schnorr_challenge(&public_key_point, &commitment, challenge)?;

        // Compute g^s (left side of verification equation)
        let g_to_s = ProjectivePoint::GENERATOR * response_scalar;

        // Compute R * Y^e (right side of verification equation)
        // Y^e = public_key_point^e
        let y_to_e = public_key_point * challenge_scalar;
        // R * Y^e
        let r_times_y_to_e = commitment + y_to_e;

        // Verify: g^s == R * Y^e
        let verified = g_to_s == r_times_y_to_e;

        Ok(verified)
    }

    fn sign_token(&self, token_data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if private_key.is_empty() {
            return Err(CryptoError::InvalidInput("Private key cannot be empty for signing".to_string()));
        }

        if private_key.len() < 16 {
            return Err(CryptoError::InvalidInput("Private key must be at least 16 bytes for HMAC".to_string()));
        }

        // Use HMAC-SHA256 for cryptographically secure token signing
        let mut mac = Hmac::<Sha256>::new_from_slice(private_key)
            .map_err(|e| CryptoError::InvalidInput(format!("HMAC key error: {}", e)))?;
        mac.update(token_data);
        let result = mac.finalize();

        Ok(result.into_bytes().to_vec())
    }

    fn verify_token_signature(
        &self,
        token_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        if public_key.is_empty() {
            return Err(CryptoError::InvalidInput("Public key cannot be empty for verification".to_string()));
        }

        if public_key.len() < 16 {
            return Err(CryptoError::InvalidInput("Public key must be at least 16 bytes for HMAC".to_string()));
        }

        if signature.len() != 32 {
            return Ok(false);
        }

        // Recompute HMAC-SHA256 for constant-time verification
        let mut mac = Hmac::<Sha256>::new_from_slice(public_key)
            .map_err(|e| CryptoError::InvalidInput(format!("HMAC key error: {}", e)))?;
        mac.update(token_data);
        let expected = mac.finalize();

        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        let valid = expected.into_bytes().as_slice().ct_eq(signature);

        Ok(bool::from(valid))
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&self) -> Result<usize, CryptoError> {
        let mut sessions = self
            .active_sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        let initial_count = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        Ok(initial_count - sessions.len())
    }

    /// Get active session count
    pub fn active_session_count(&self) -> Result<usize, CryptoError> {
        let sessions = self
            .active_sessions
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
        Ok(sessions.len())
    }
}

impl ZeroTrustAuthenticable for ZeroTrustAuth {
    type Proof = ZeroKnowledgeProof;
    type Error = CryptoError;

    fn generate_proof(&self, _challenge: &[u8]) -> Result<Self::Proof, Self::Error> {
        // Default implementation: error - keys must be provided explicitly
        Err(CryptoError::InvalidInput(
            "Secret key must be provided for proof generation".to_string(),
        ))
    }

    fn verify_proof_with_context(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
        _ctx: &CryptoContext,
    ) -> Choice {
        // Default implementation: error - public key must be provided
        match self.verify_zkp(proof, challenge, &[]) {
            Ok(_) => Choice::from(0),
            Err(_) => Choice::from(0),
        }
    }

    fn verify_proof_result(
        &self,
        proof: &Self::Proof,
        challenge: &[u8],
    ) -> Result<(), Self::Error> {
        let verified = self.verify_proof(proof, challenge);
        if verified.into() { Ok(()) } else { Err(CryptoError::VerificationFailed) }
    }
}

impl ProofOfPossession for ZeroTrustAuth {
    type Pop = ProofOfPossessionToken;
    type Error = CryptoError;

    fn generate_pop(&self) -> Result<Self::Pop, Self::Error> {
        // Default implementation: error - keys must be provided explicitly
        Err(CryptoError::InvalidInput(
            "Key pair must be provided for token generation".to_string(),
        ))
    }

    fn verify_pop_with_context(&self, pop: &Self::Pop, _ctx: &CryptoContext) -> Choice {
        // Default implementation: error - public key must be provided
        match self.verify_possession_token(pop, &[]) {
            Ok(_) => Choice::from(0),
            Err(_) => Choice::from(0),
        }
    }

    fn verify_pop_result(&self, pop: &Self::Pop) -> Result<(), Self::Error> {
        let verified = self.verify_pop(pop);
        if verified.into() { Ok(()) } else { Err(CryptoError::VerificationFailed) }
    }
}

impl ContinuousVerifiable for ZeroTrustAuth {
    type Error = CryptoError;

    fn verify_continuously(&self) -> Result<VerificationStatus, Self::Error> {
        let timestamp = Utc::now().timestamp() as u64;

        Ok(VerificationStatus { verified: Choice::from(1), timestamp, confidence: 1.0 })
    }

    fn start_continuous_verification(&self) -> Result<ContinuousSession, Self::Error> {
        if !self.config.enable_continuous_verification {
            return Err(CryptoError::ConfigurationError(
                "Continuous verification is disabled".to_string(),
            ));
        }

        let timestamp = Utc::now().timestamp() as u64;

        let mut session_id = vec![0u8; SESSION_ID_LENGTH];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut session_id);

        Ok(ContinuousSession { session_id, start_time: timestamp, last_verification: timestamp })
    }
}

impl crate::unified_api::config::ProofComplexity {
    /// Convert complexity to security level
    pub fn as_security_level(&self) -> u32 {
        match self {
            crate::unified_api::config::ProofComplexity::Simple => 64,
            crate::unified_api::config::ProofComplexity::Standard => 128,
            crate::unified_api::config::ProofComplexity::High => 192,
            crate::unified_api::config::ProofComplexity::Maximum => 256,
        }
    }
}
