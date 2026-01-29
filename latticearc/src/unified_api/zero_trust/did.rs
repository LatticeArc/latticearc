#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Decentralized Identifier (DID) support for zero-trust authentication.
//!
//! This module provides W3C DID document management, verification methods,
//! services, and a registry for decentralized identity management.

use rand::RngCore;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc, Duration};

use crate::unified_api::{error::CryptoError, types::PublicKey};

use super::primitives::{TrustLevel, VerificationResult};

const DID_METHOD_KEY: &str = "key";
const _DID_METHOD_WEB: &str = "web";
const _DID_METHOD_PEER: &str = "peer";

const DID_ID_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationMethodType {
    Ed25519VerificationKey2018,
    SchnorrProof2022,
    MLDSA2024,
    JsonWebKey2020,
}

#[derive(Debug, Clone)]
pub struct VerificationMethod {
    pub id: String,
    pub type_: VerificationMethodType,
    pub controller: String,
    pub public_key: Option<PublicKey>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl VerificationMethod {
    pub fn new(
        id: String,
        type_: VerificationMethodType,
        controller: String,
        public_key: Option<PublicKey>,
    ) -> Self {
        Self { id, type_, controller, public_key, expires_at: None, created_at: DateTime::<Utc>::now() }
    }

    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => match expires.signed_duration_since(Utc::now()).to_std() {
                Ok(duration) => duration.as_secs() > 0,
                Err(_) => false,
            },
            None => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.id.is_empty() && !self.controller.is_empty() && !self.is_expired()
    }
}

#[derive(Debug, Clone)]
pub struct DidService {
    pub id: String,
    pub type_: String,
    pub service_endpoint: String,
    pub properties: HashMap<String, String>,
}

impl DidService {
    pub fn new(id: String, type_: String, service_endpoint: String) -> Self {
        Self { id, type_, service_endpoint, properties: HashMap::new() }
    }

    pub fn with_property(mut self, key: String, value: String) -> Self {
        self.properties.insert(key, value);
        self
    }

    pub fn get_property(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }
}

#[derive(Debug, Clone)]
pub struct DidAuthentication {
    pub verification_method_id: String,
    pub challenge: Vec<u8>,
    pub proof: super::ZeroKnowledgeProof,
    pub timestamp: DateTime<Utc>,
}

impl DidAuthentication {
    pub fn new(
        verification_method_id: String,
        challenge: Vec<u8>,
        proof: super::ZeroKnowledgeProof,
    ) -> Self {
        Self { verification_method_id, challenge, proof, timestamp: DateTime::<Utc>::now() }
    }

    pub fn is_valid(&self) -> bool {
        !self.verification_method_id.is_empty()
            && !self.challenge.is_empty()
            && self.proof.is_valid()
    }
}

#[derive(Debug, Clone)]
pub struct DidDocument {
    pub did: String,
    pub verification_methods: Vec<VerificationMethod>,
    pub services: Vec<DidService>,
    pub authentication: Vec<DidAuthentication>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl DidDocument {
    pub fn new(did: String) -> Self {
        let now = Utc::now();
        Self {
            did,
            verification_methods: Vec::new(),
            services: Vec::new(),
            authentication: Vec::new(),
            created_at: now,
            updated_at: now,
            expires_at: None,
        }
    }

    pub fn with_verification_method(mut self, method: VerificationMethod) -> Self {
        self.verification_methods.push(method);
        self
    }

    pub fn with_service(mut self, service: DidService) -> Self {
        self.services.push(service);
        self
    }

    pub fn with_authentication(mut self, auth: DidAuthentication) -> Self {
        self.authentication.push(auth);
        self
    }

    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        self.updated_at = Utc::now();
        self.verification_methods.push(method);
    }

    pub fn remove_verification_method(&mut self, method_id: &str) -> Result<(), CryptoError> {
        self.updated_at = Utc::now();
        let len_before = self.verification_methods.len();
        self.verification_methods.retain(|m| m.id != method_id);

        if self.verification_methods.len() == len_before {
            return Err(CryptoError::InvalidInput(format!(
                "Verification method '{}' not found",
                method_id
            )));
        }

        Ok(())
    }

    pub fn get_verification_method(&self, method_id: &str) -> Option<&VerificationMethod> {
        self.verification_methods.iter().find(|m| m.id == method_id)
    }

    pub fn get_authentication_method(&self, auth_id: &str) -> Option<&DidAuthentication> {
        self.authentication.iter().find(|a| a.verification_method_id == auth_id)
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => match expires.signed_duration_since(Utc::now()).to_std() {
                Ok(duration) => duration.as_secs() > 0,
                Err(_) => false,
            },
            None => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.did.is_empty() && !self.is_expired()
    }

    pub fn age(&self) -> Result<Duration, CryptoError> {
        self.created_at
            .timestamp() as u64
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid timestamp: {}", e)))
    }

    pub fn update(&mut self) -> Result<(), CryptoError> {
        if self.is_expired() {
            return Err(CryptoError::InvalidInput("Cannot update expired DID".to_string()));
        }

        self.updated_at = Utc::now();
        Ok(())
    }
}

pub struct DidRegistry {
    documents: Arc<RwLock<HashMap<String, DidDocument>>>,
}

impl DidRegistry {
    pub fn new() -> Self {
        Self { documents: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn register(&self, did_document: DidDocument) -> Result<(), CryptoError> {
        if !did_document.is_valid() {
            return Err(CryptoError::InvalidInput("Invalid DID document".to_string()));
        }

        let mut docs = self
            .documents
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        docs.insert(did_document.did.clone(), did_document);
        Ok(())
    }

    pub fn resolve(&self, did: &str) -> Result<DidDocument, CryptoError> {
        if did.is_empty() {
            return Err(CryptoError::InvalidInput("DID cannot be empty".to_string()));
        }

        let docs = self
            .documents
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match docs.get(did) {
            Some(doc) if !doc.is_expired() => Ok(doc.clone()),
            Some(_) => Err(CryptoError::InvalidInput("DID has expired".to_string())),
            None => Err(CryptoError::InvalidInput("DID not found".to_string())),
        }
    }

    pub fn update(&self, did_document: &DidDocument) -> Result<(), CryptoError> {
        if !did_document.is_valid() {
            return Err(CryptoError::InvalidInput("Invalid DID document".to_string()));
        }

        let mut docs = self
            .documents
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        if !docs.contains_key(&did_document.did) {
            return Err(CryptoError::InvalidInput("DID not registered".to_string()));
        }

        docs.insert(did_document.did.clone(), did_document.clone());
        Ok(())
    }

    pub fn revoke(&self, did: &str) -> Result<(), CryptoError> {
        if did.is_empty() {
            return Err(CryptoError::InvalidInput("DID cannot be empty".to_string()));
        }

        let mut docs = self
            .documents
            .write()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;

        match docs.remove(did) {
            Some(_) => Ok(()),
            None => Err(CryptoError::InvalidInput("DID not found".to_string())),
        }
    }

    pub fn exists(&self, did: &str) -> bool {
        let docs = self
            .documents
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)));

        match docs {
            Ok(docs) => docs.contains_key(did),
            Err(_) => false,
        }
    }

    pub fn count(&self) -> Result<usize, CryptoError> {
        let docs = self
            .documents
            .read()
            .map_err(|e| CryptoError::ConfigurationError(format!("Lock error: {}", e)))?;
        Ok(docs.len())
    }
}

impl Default for DidRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub fn generate_did() -> Result<DidDocument, CryptoError> {
    let did = format!("{}:{}", DID_METHOD_KEY, generate_did_id()?);

    Ok(DidDocument::new(did))
}

pub fn generate_did_id() -> Result<String, CryptoError> {
    let mut id_bytes = vec![0u8; DID_ID_LENGTH];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut id_bytes);

    Ok(hex::encode(&id_bytes))
}

pub fn resolve_did(did: &str) -> Result<DidDocument, CryptoError> {
    let registry = DidRegistry::new();
    registry.resolve(did)
}

pub fn verify_did(did_document: &DidDocument) -> Result<bool, CryptoError> {
    if !did_document.is_valid() {
        return Ok(false);
    }

    for method in &did_document.verification_methods {
        if !method.is_valid() {
            return Ok(false);
        }
    }

    for auth in &did_document.authentication {
        if !auth.is_valid() {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn create_verification_method(
    did: &str,
    type_: VerificationMethodType,
    public_key: Option<PublicKey>,
) -> Result<VerificationMethod, CryptoError> {
    if did.is_empty() {
        return Err(CryptoError::InvalidInput("DID cannot be empty".to_string()));
    }

    let method_id = format!("{}#keys-{}", did, generate_did_id()?);

    Ok(VerificationMethod::new(method_id, type_, did.to_string(), public_key))
}

pub fn create_did_with_verification_method(
    type_: VerificationMethodType,
    public_key: PublicKey,
) -> Result<DidDocument, CryptoError> {
    let mut did_document = generate_did()?;

    let method = create_verification_method(&did_document.did, type_, Some(public_key))?;
    did_document.add_verification_method(method);

    Ok(did_document)
}

pub fn did_authenticate(
    did_document: &DidDocument,
    challenge: &[u8],
    proof: &super::ZeroKnowledgeProof,
) -> Result<VerificationResult, CryptoError> {
    if !did_document.is_valid() {
        return Ok(VerificationResult::failure("Invalid DID document".to_string()));
    }

    if challenge.is_empty() {
        return Ok(VerificationResult::failure("Challenge cannot be empty".to_string()));
    }

    if !proof.is_valid() {
        return Ok(VerificationResult::failure("Invalid proof".to_string()));
    }

    Ok(VerificationResult::success(TrustLevel::High))
}

pub fn did_verify_proof(
    did_document: &DidDocument,
    verification_method_id: &str,
    _proof: &super::ZeroKnowledgeProof,
    _challenge: &[u8],
) -> Result<bool, CryptoError> {
    let method = did_document.get_verification_method(verification_method_id).ok_or_else(|| {
        CryptoError::InvalidInput(format!(
            "Verification method '{}' not found",
            verification_method_id
        ))
    })?;

    if !method.is_valid() {
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_did() {
        let did_document = generate_did().expect("Failed to generate DID");
        assert!(did_document.did.starts_with("key:"));
        assert!(did_document.is_valid());
    }

    #[test]
    fn test_did_document_builder() {
        let did_document = DidDocument::new("did:example:123".to_string())
            .with_verification_method(VerificationMethod::new(
                "key-1".to_string(),
                VerificationMethodType::Ed25519VerificationKey2018,
                "did:example:123".to_string(),
                Some(vec![1, 2, 3, 4]),
            ))
            .with_service(DidService::new(
                "service-1".to_string(),
                "AgentService".to_string(),
                "https://example.com/agent".to_string(),
            ));

        assert_eq!(did_document.did, "did:example:123");
        assert_eq!(did_document.verification_methods.len(), 1);
        assert_eq!(did_document.services.len(), 1);
    }

    #[test]
    fn test_did_registry() {
        let registry = DidRegistry::new();
        let did_document = generate_did().expect("Failed to generate DID");

        registry.register(did_document.clone()).expect("Failed to register DID");
        assert!(registry.exists(&did_document.did));
        assert_eq!(registry.count().expect("Failed to get count"), 1);

        let resolved = registry.resolve(&did_document.did).expect("Failed to resolve DID");
        assert_eq!(resolved.did, did_document.did);

        registry.revoke(&did_document.did).expect("Failed to revoke DID");
        assert!(!registry.exists(&did_document.did));
    }

    #[test]
    fn test_verification_method() {
        let method = VerificationMethod::new(
            "key-1".to_string(),
            VerificationMethodType::Ed25519VerificationKey2018,
            "did:example:123".to_string(),
            Some(vec![1, 2, 3, 4]),
        );

        assert!(method.is_valid());
        assert!(!method.is_expired());
    }

    #[test]
    fn test_did_service() {
        let service = DidService::new(
            "service-1".to_string(),
            "AgentService".to_string(),
            "https://example.com/agent".to_string(),
        )
        .with_property("key1".to_string(), "value1".to_string());

        assert_eq!(service.get_property("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_did_document_add_remove() {
        let mut did_document = DidDocument::new("did:example:123".to_string());

        let method = VerificationMethod::new(
            "key-1".to_string(),
            VerificationMethodType::Ed25519VerificationKey2018,
            "did:example:123".to_string(),
            Some(vec![1, 2, 3, 4]),
        );

        did_document.add_verification_method(method.clone());
        assert_eq!(did_document.verification_methods.len(), 1);

        did_document.remove_verification_method("key-1").expect("Failed to remove method");
        assert_eq!(did_document.verification_methods.len(), 0);
    }

    #[test]
    fn test_verify_did() {
        let did_document = generate_did().expect("Failed to generate DID");

        let verified = verify_did(&did_document).expect("Failed to verify DID");
        assert!(verified);
    }

    #[test]
    fn test_did_expiration() {
        let did_document = DidDocument::new("did:example:123".to_string())
            .with_expiration(Utc::now() - chrono::Duration::seconds(1));

        assert!(did_document.is_expired());
        assert!(!did_document.is_valid());
    }
}
