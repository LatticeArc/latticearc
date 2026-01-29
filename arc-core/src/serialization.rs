#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Serialization utilities for cryptographic types.
//!
//! Provides JSON serialization for encrypted data, signed data, and key pairs
//! using Base64 encoding for binary fields.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use serde::{Deserialize, Serialize};

use crate::{
    error::{CoreError, Result},
    types::{EncryptedData, KeyPair, SignedData},
};

/// Serializable form of encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableEncryptedData {
    /// Base64-encoded encrypted data
    pub data: String,
    /// Metadata for decryption
    pub metadata: SerializableEncryptedMetadata,
    /// Encryption scheme identifier
    pub scheme: String,
    /// Timestamp of encryption
    pub timestamp: u64,
}

/// Serializable encrypted data metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableEncryptedMetadata {
    /// Base64-encoded nonce
    pub nonce: String,
    /// Base64-encoded authentication tag (optional)
    pub tag: Option<String>,
    /// Key identifier (optional)
    pub key_id: Option<String>,
}

/// Serializable form of signed data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSignedData {
    /// Base64-encoded original data
    pub data: String,
    /// Signature metadata
    pub metadata: SerializableSignedMetadata,
    /// Signature scheme identifier
    pub scheme: String,
    /// Timestamp of signing
    pub timestamp: u64,
}

/// Serializable signed data metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSignedMetadata {
    /// Base64-encoded signature
    pub signature: String,
    /// Signature algorithm
    pub signature_algorithm: String,
    /// Base64-encoded public key
    pub public_key: String,
    /// Key identifier (optional)
    pub key_id: Option<String>,
}

/// Serializable form of a key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableKeyPair {
    /// Base64-encoded public key
    pub public_key: String,
    /// Base64-encoded private key
    pub private_key: String,
}

impl From<&EncryptedData> for SerializableEncryptedData {
    fn from(encrypted: &EncryptedData) -> Self {
        Self {
            data: BASE64_ENGINE.encode(&encrypted.data),
            metadata: SerializableEncryptedMetadata {
                nonce: BASE64_ENGINE.encode(&encrypted.metadata.nonce),
                tag: encrypted.metadata.tag.as_ref().map(|t| BASE64_ENGINE.encode(t)),
                key_id: encrypted.metadata.key_id.clone(),
            },
            scheme: encrypted.scheme.clone(),
            timestamp: encrypted.timestamp,
        }
    }
}

impl TryFrom<SerializableEncryptedData> for EncryptedData {
    type Error = CoreError;

    fn try_from(serializable: SerializableEncryptedData) -> Result<Self> {
        let data = BASE64_ENGINE
            .decode(&serializable.data)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let nonce = BASE64_ENGINE
            .decode(&serializable.metadata.nonce)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let tag = serializable
            .metadata
            .tag
            .map(|t| BASE64_ENGINE.decode(&t))
            .transpose()
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        Ok(EncryptedData {
            data,
            metadata: crate::types::EncryptedMetadata {
                nonce,
                tag,
                key_id: serializable.metadata.key_id,
            },
            scheme: serializable.scheme,
            timestamp: serializable.timestamp,
        })
    }
}

impl From<&SignedData> for SerializableSignedData {
    fn from(signed: &SignedData) -> Self {
        Self {
            data: BASE64_ENGINE.encode(&signed.data),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(&signed.metadata.signature),
                signature_algorithm: signed.metadata.signature_algorithm.clone(),
                public_key: BASE64_ENGINE.encode(&signed.metadata.public_key),
                key_id: signed.metadata.key_id.clone(),
            },
            scheme: signed.scheme.clone(),
            timestamp: signed.timestamp,
        }
    }
}

impl TryFrom<SerializableSignedData> for SignedData {
    type Error = CoreError;

    fn try_from(serializable: SerializableSignedData) -> Result<Self> {
        let data = BASE64_ENGINE
            .decode(&serializable.data)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let signature = BASE64_ENGINE
            .decode(&serializable.metadata.signature)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let public_key = BASE64_ENGINE
            .decode(&serializable.metadata.public_key)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        Ok(SignedData {
            data,
            metadata: crate::types::SignedMetadata {
                signature,
                signature_algorithm: serializable.metadata.signature_algorithm,
                public_key,
                key_id: serializable.metadata.key_id,
            },
            scheme: serializable.scheme,
            timestamp: serializable.timestamp,
        })
    }
}

impl From<&KeyPair> for SerializableKeyPair {
    fn from(keypair: &KeyPair) -> Self {
        Self {
            public_key: BASE64_ENGINE.encode(&keypair.public_key),
            private_key: BASE64_ENGINE.encode(keypair.private_key.as_slice()),
        }
    }
}

impl TryFrom<SerializableKeyPair> for KeyPair {
    type Error = CoreError;

    fn try_from(serializable: SerializableKeyPair) -> Result<Self> {
        let public_key = BASE64_ENGINE
            .decode(&serializable.public_key)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let private_key_bytes = BASE64_ENGINE
            .decode(&serializable.private_key)
            .map_err(|e| CoreError::SerializationError(e.to_string()))?;

        let private_key = crate::types::PrivateKey::new(private_key_bytes);

        Ok(KeyPair { public_key, private_key })
    }
}

/// Serializes encrypted data to a JSON string.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_encrypted_data(encrypted: &EncryptedData) -> Result<String> {
    let serializable = SerializableEncryptedData::from(encrypted);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes encrypted data from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of the encrypted data, nonce, or tag fails
pub fn deserialize_encrypted_data(data: &str) -> Result<EncryptedData> {
    let serializable: SerializableEncryptedData =
        serde_json::from_str(data).map_err(|e| CoreError::SerializationError(e.to_string()))?;
    serializable.try_into()
}

/// Serializes signed data to a JSON string.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_signed_data(signed: &SignedData) -> Result<String> {
    let serializable = SerializableSignedData::from(signed);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes signed data from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of the data, signature, or public key fails
pub fn deserialize_signed_data(data: &str) -> Result<SignedData> {
    let serializable: SerializableSignedData =
        serde_json::from_str(data).map_err(|e| CoreError::SerializationError(e.to_string()))?;
    serializable.try_into()
}

/// Serializes a keypair to a JSON string.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn serialize_keypair(keypair: &KeyPair) -> Result<String> {
    let serializable = SerializableKeyPair::from(keypair);
    serde_json::to_string(&serializable).map_err(|e| CoreError::SerializationError(e.to_string()))
}

/// Deserializes a keypair from a JSON string.
///
/// # Errors
///
/// Returns an error if:
/// - JSON parsing fails
/// - Base64 decoding of the public key or private key fails
pub fn deserialize_keypair(data: &str) -> Result<KeyPair> {
    let serializable: SerializableKeyPair =
        serde_json::from_str(data).map_err(|e| CoreError::SerializationError(e.to_string()))?;
    serializable.try_into()
}
