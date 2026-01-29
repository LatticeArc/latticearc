#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Zero-trust authenticator implementation.
//!
//! This module provides the main zero-trust authenticator with support for
//! credentials, DID authentication, MFA flows, and continuous verification.

use rand::RngCore;
use std::sync::Arc;
use chrono::{DateTime, Utc};

use crate::unified_api::{
    error::CryptoError,
    types::{PrivateKey, PublicKey},
};

use super::{
    ZeroKnowledgeProof, ZeroTrustAuth,
    did::{DidDocument, DidRegistry, did_authenticate, generate_did, resolve_did, verify_did},
    primitives::{
        AuthenticationContext, MFAChallenge, MFAChallengeType, MFAResponse, SecurityContext,
        TrustLevel, VerificationResult,
    },
    session::{SessionStore, ZeroTrustSession},
};

pub const _CHALLENGE_LENGTH: usize = 32;
pub const MFA_CODE_LENGTH: usize = 6;
pub const MFA_EXPIRATION_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub user_id: String,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub did: Option<String>,
    pub mfa_secret: Option<String>,
}

impl Credentials {
    pub fn new(user_id: String, public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self { user_id, public_key, private_key, did: None, mfa_secret: None }
    }

    pub fn with_did(mut self, did: String) -> Self {
        self.did = Some(did);
        self
    }

    pub fn with_mfa_secret(mut self, secret: String) -> Self {
        self.mfa_secret = Some(secret);
        self
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub success: bool,
    pub session: Option<ZeroTrustSession>,
    pub trust_level: TrustLevel,
    pub requires_mfa: bool,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

impl AuthenticationResult {
    pub fn success(session: ZeroTrustSession, trust_level: TrustLevel) -> Self {
        Self {
            success: true,
            session: Some(session),
            trust_level,
            requires_mfa: false,
            reason: "Authentication successful".to_string(),
            timestamp: DateTime::<Utc>::now(),
        }
    }

    pub fn failure(reason: String) -> Self {
        Self {
            success: false,
            session: None,
            trust_level: TrustLevel::Zero,
            requires_mfa: false,
            reason,
            timestamp: DateTime::<Utc>::now(),
        }
    }

    pub fn requires_mfa(session: ZeroTrustSession) -> Self {
        Self {
            success: true,
            session: Some(session),
            trust_level: TrustLevel::Low,
            requires_mfa: true,
            reason: "MFA required".to_string(),
            timestamp: DateTime::<Utc>::now(),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.success && !self.requires_mfa
    }

    pub fn is_partial(&self) -> bool {
        self.success && self.requires_mfa
    }
}

pub struct ZeroTrustAuthenticator {
    zero_trust_auth: ZeroTrustAuth,
    session_store: SessionStore,
    did_registry: DidRegistry,
    mfa_store: Arc<std::sync::Mutex<std::collections::HashMap<String, MFAChallenge>>>,
}

impl ZeroTrustAuthenticator {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Self {
            zero_trust_auth: ZeroTrustAuth::new(crate::unified_api::types::CryptoScheme::HybridPq)?,
            session_store: SessionStore::new(),
            did_registry: DidRegistry::new(),
            mfa_store: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    pub fn authenticate(
        &self,
        credentials: &Credentials,
        trust_level: TrustLevel,
    ) -> Result<AuthenticationResult, CryptoError> {
        if credentials.user_id.is_empty() {
            return Ok(AuthenticationResult::failure("User ID cannot be empty".to_string()));
        }

        let auth_context = AuthenticationContext::new(trust_level);

        let challenge = self.zero_trust_auth.generate_challenge(&credentials.user_id)?;

        let proof =
            self.zero_trust_auth.generate_zkp(credentials.private_key.as_slice(), &challenge)?;

        let auth_request =
            super::AuthenticationRequest::new(credentials.user_id.clone(), challenge, proof);

        let verification_result =
            self.zero_trust_auth.verify_authentication(&auth_request, &credentials.public_key)?;

        if !verification_result.success {
            return Ok(AuthenticationResult::failure("Authentication failed".to_string()));
        }

        let session = self.session_store.create_session(
            &credentials.user_id,
            credentials.did.as_deref(),
            trust_level,
            trust_level.session_duration_secs(),
            SecurityContext::default(),
        )?;

        if auth_context.mfa_required {
            Ok(AuthenticationResult::requires_mfa(session))
        } else {
            Ok(AuthenticationResult::success(session, trust_level))
        }
    }

    pub fn authenticate_with_did(
        &self,
        did_document: &DidDocument,
        trust_level: TrustLevel,
        private_key: Option<&[u8]>,
    ) -> Result<AuthenticationResult, CryptoError> {
        let user_id = did_document.did.clone();

        let challenge = self.zero_trust_auth.generate_challenge(&user_id)?;

        let proof = self.generate_did_proof(did_document, &challenge, private_key)?;

        let verification_result = did_authenticate(did_document, &challenge, &proof)?;

        if !verification_result.is_verified() {
            return Ok(AuthenticationResult::failure("DID authentication failed".to_string()));
        }

        self.did_registry.register(did_document.clone())?;

        let session = self.session_store.create_session(
            &user_id,
            Some(&did_document.did),
            trust_level,
            trust_level.session_duration_secs(),
            SecurityContext::default(),
        )?;

        Ok(AuthenticationResult::success(session, trust_level))
    }

    pub fn initiate_mfa(&self, user_id: &str) -> Result<MFAChallenge, CryptoError> {
        if user_id.is_empty() {
            return Err(CryptoError::InvalidInput("User ID cannot be empty".to_string()));
        }

        let challenge_id = generate_challenge_id()?;

        let mut challenge_data = vec![0u8; MFA_CODE_LENGTH];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut challenge_data);

        let mfa_challenge = MFAChallenge::new(
            challenge_id.clone(),
            MFAChallengeType::TOTP,
            challenge_data,
            MFA_EXPIRATION_SECS,
        )?;

        self.mfa_store
            .lock()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?
            .insert(challenge_id, mfa_challenge.clone());

        Ok(mfa_challenge)
    }

    pub fn verify_mfa(
        &self,
        challenge: &MFAChallenge,
        response: &MFAResponse,
        session_id: &str,
    ) -> Result<AuthenticationResult, CryptoError> {
        if challenge.challenge_id != response.challenge_id {
            return Ok(AuthenticationResult::failure("Challenge ID mismatch".to_string()));
        }

        if challenge.is_expired() {
            return Ok(AuthenticationResult::failure("MFA challenge expired".to_string()));
        }

        let mut session = self.session_store.get_session(session_id)?;

        session.upgrade_trust(TrustLevel::Medium);

        let mut sessions = self
            .session_store
            .sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        sessions.insert(session_id.to_string(), session.clone());

        self.mfa_store
            .lock()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?
            .remove(&challenge.challenge_id);

        Ok(AuthenticationResult::success(session, TrustLevel::Medium))
    }

    pub fn continuous_verify(&self, session_id: &str) -> Result<VerificationResult, CryptoError> {
        let session = self.session_store.get_session(session_id)?;

        if !self.session_store.verify_session(session_id)? {
            return Ok(VerificationResult::failure("Session verification failed".to_string()));
        }

        Ok(VerificationResult::success(session.trust_level))
    }

    pub fn logout(&self, session_id: &str) -> Result<(), CryptoError> {
        self.session_store.revoke_session(session_id)
    }

    pub fn get_session(&self, session_id: &str) -> Result<ZeroTrustSession, CryptoError> {
        self.session_store.get_session(session_id)
    }

    fn generate_did_proof(
        &self,
        did_document: &DidDocument,
        challenge: &[u8],
        private_key: Option<&[u8]>,
    ) -> Result<ZeroKnowledgeProof, CryptoError> {
        let verification_method = did_document
            .verification_methods
            .first()
            .ok_or_else(|| CryptoError::InvalidInput("No verification method found".to_string()))?;

        let _public_key = verification_method
            .public_key
            .as_ref()
            .ok_or_else(|| CryptoError::InvalidInput("No public key found".to_string()))?;

        // Use provided private key or extract from DID document
        let signing_key = private_key
            .ok_or_else(|| {
                CryptoError::InvalidInput(
                    "Private key must be provided for DID proof generation".to_string(),
                )
            })?;

        // Validate private key length
        if signing_key.len() < 32 {
            return Err(CryptoError::InvalidInput(format!(
                "Private key must be at least 32 bytes, got {}",
                signing_key.len()
            )));
        }

        let proof_data =
            self.zero_trust_auth.generate_zkp(signing_key, challenge)?.proof_data.clone();

        Ok(ZeroKnowledgeProof::schnorr(proof_data))
    }

    pub fn update_trust_level(
        &self,
        session_id: &str,
        new_level: TrustLevel,
    ) -> Result<(), CryptoError> {
        let mut sessions = self
            .session_store
            .sessions
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| CryptoError::InvalidInput("Session not found".to_string()))?;

        session.upgrade_trust(new_level);

        Ok(())
    }
}

impl Default for ZeroTrustAuthenticator {
    fn default() -> Self {
        Self::new().expect("Failed to create ZeroTrustAuthenticator")
    }
}

pub fn authenticate_zt(
    credentials: &Credentials,
    trust_level: TrustLevel,
) -> Result<ZeroTrustSession, CryptoError> {
    let authenticator = ZeroTrustAuthenticator::new()?;
    let result = authenticator.authenticate(credentials, trust_level)?;

    if result.is_authenticated() {
        result.session.ok_or_else(|| {
            CryptoError::InvalidInput("Authentication successful but no session".to_string())
        })
    } else {
        Err(CryptoError::VerificationFailed)
    }
}

pub fn create_identity() -> Result<DidDocument, CryptoError> {
    generate_did()
}

pub fn verify_identity(did: &str) -> Result<bool, CryptoError> {
    let did_document = resolve_did(did)?;
    verify_did(&did_document)
}

fn generate_challenge_id() -> Result<String, CryptoError> {
    let mut id_bytes = vec![0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut id_bytes);
    Ok(hex::encode(&id_bytes))
}

#[cfg(test)]
mod tests {
    use super::super::SecurityContext;
    use super::super::generate_did;
    use super::*;
    use std::time::Duration;

    fn create_test_credentials() -> Credentials {
        Credentials::new(
            "user-1".to_string(),
            vec![1u8; 32],
            crate::unified_api::types::PrivateKey::new(vec![2u8; 32]),
        )
    }

    #[test]
    fn test_credentials_builder() {
        let credentials = Credentials::new(
            "user-1".to_string(),
            vec![1u8; 32],
            crate::unified_api::types::PrivateKey::new(vec![2u8; 32]),
        )
        .with_did("did:example:123".to_string())
        .with_mfa_secret("secret123".to_string());

        assert_eq!(credentials.user_id, "user-1");
        assert_eq!(credentials.did, Some("did:example:123".to_string()));
        assert_eq!(credentials.mfa_secret, Some("secret123".to_string()));
    }

    #[test]
    fn test_authentication_result() {
        let session = ZeroTrustSession::new(
            "session-1".to_string(),
            "user-1".to_string(),
            None,
            TrustLevel::Medium,
            Duration::from_secs(3600),
            Duration::from_secs(600),
            SecurityContext::default(),
        )
        .expect("Failed to create session");

        let success = AuthenticationResult::success(session.clone(), TrustLevel::Medium);
        assert!(success.is_authenticated());
        assert!(!success.is_partial());

        let mfa_required = AuthenticationResult::requires_mfa(session);
        assert!(mfa_required.is_partial());
        assert!(!mfa_required.is_authenticated());

        let failure = AuthenticationResult::failure("Invalid credentials".to_string());
        assert!(!failure.is_authenticated());
        assert!(!failure.is_partial());
    }

    #[test]
    fn test_mfa_challenge() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");

        let challenge = authenticator.initiate_mfa("user-1").expect("Failed to initiate MFA");

        assert!(!challenge.is_expired());
        assert_eq!(challenge.challenge_data.len(), MFA_CODE_LENGTH);
    }

    #[test]
    fn test_mfa_response() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");

        let challenge = authenticator.initiate_mfa("user-1").expect("Failed to initiate MFA");

        let response = MFAResponse::new(challenge.challenge_id.clone(), vec![1, 2, 3, 4, 5, 6]);

        assert!(response.is_valid());
    }

    #[test]
    fn test_authenticate() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");
        let credentials = create_test_credentials();

        let result = authenticator
            .authenticate(&credentials, TrustLevel::Medium)
            .expect("Failed to authenticate");

        assert!(result.is_authenticated());
        assert!(result.session.is_some());
    }

    #[test]
    fn test_authenticate_with_did() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");

        let mut did_document = generate_did().expect("Failed to generate DID");

        let verification_method = crate::unified_api::zero_trust::did::VerificationMethod::new(
            "key-1".to_string(),
            crate::unified_api::zero_trust::did::VerificationMethodType::Ed25519VerificationKey2018,
            did_document.did.clone(),
            Some(vec![1u8; 32]),
        );
        did_document.add_verification_method(verification_method);

        let private_key = vec![2u8; 32]; // Test private key

        let result = authenticator
            .authenticate_with_did(&did_document, TrustLevel::High, Some(&private_key))
            .expect("Failed to authenticate with DID");

        assert!(result.is_authenticated());
        assert!(result.session.is_some());
    }

    #[test]
    fn test_continuous_verify() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");
        let credentials = create_test_credentials();

        let auth_result = authenticator
            .authenticate(&credentials, TrustLevel::Medium)
            .expect("Failed to authenticate");

        let session = auth_result.session.unwrap();

        let verification_result = authenticator
            .continuous_verify(&session.session_id)
            .expect("Failed to verify continuously");

        assert!(verification_result.is_verified());
    }

    #[test]
    fn test_update_trust_level() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");
        let credentials = create_test_credentials();

        let auth_result = authenticator
            .authenticate(&credentials, TrustLevel::Medium)
            .expect("Failed to authenticate");

        let session = auth_result.session.unwrap();

        authenticator
            .update_trust_level(&session.session_id, TrustLevel::High)
            .expect("Failed to update trust level");

        let updated_session =
            authenticator.get_session(&session.session_id).expect("Failed to get session");

        assert_eq!(updated_session.trust_level, TrustLevel::High);
    }

    #[test]
    fn test_logout() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");
        let credentials = create_test_credentials();

        let auth_result = authenticator
            .authenticate(&credentials, TrustLevel::Medium)
            .expect("Failed to authenticate");

        let session = auth_result.session.unwrap();

        authenticator.logout(&session.session_id).expect("Failed to logout");

        let result = authenticator.get_session(&session.session_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_mfa_flow() {
        let authenticator = ZeroTrustAuthenticator::new().expect("Failed to create authenticator");
        let credentials = create_test_credentials();

        let auth_result = authenticator
            .authenticate(&credentials, TrustLevel::Low)
            .expect("Failed to authenticate");

        if !auth_result.is_authenticated() && auth_result.is_partial() {
            let session = auth_result.session.unwrap();

            let challenge =
                authenticator.initiate_mfa(&credentials.user_id).expect("Failed to initiate MFA");

            let response =
                MFAResponse::new(challenge.challenge_id.clone(), challenge.challenge_data.clone());

            let mfa_result = authenticator
                .verify_mfa(&challenge, &response, &session.session_id)
                .expect("Failed to verify MFA");

            assert!(mfa_result.is_authenticated());
        }
    }
}
