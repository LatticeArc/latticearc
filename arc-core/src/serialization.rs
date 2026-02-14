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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{CryptoPayload, EncryptedMetadata, PrivateKey, SignedMetadata};

    fn make_encrypted_data() -> EncryptedData {
        CryptoPayload {
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            metadata: EncryptedMetadata {
                nonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                tag: Some(vec![0xAA; 16]),
                key_id: Some("key-001".to_string()),
            },
            scheme: "AES-256-GCM".to_string(),
            timestamp: 1700000000,
        }
    }

    fn make_encrypted_data_no_tag() -> EncryptedData {
        CryptoPayload {
            data: vec![0xFF; 32],
            metadata: EncryptedMetadata { nonce: vec![0u8; 12], tag: None, key_id: None },
            scheme: "ChaCha20Poly1305".to_string(),
            timestamp: 1700000001,
        }
    }

    fn make_signed_data() -> SignedData {
        CryptoPayload {
            data: vec![1, 2, 3, 4],
            metadata: SignedMetadata {
                signature: vec![0xBB; 64],
                signature_algorithm: "ML-DSA-65".to_string(),
                public_key: vec![0xCC; 32],
                key_id: Some("sig-key-001".to_string()),
            },
            scheme: "ML-DSA-65+Ed25519".to_string(),
            timestamp: 1700000002,
        }
    }

    fn make_keypair() -> KeyPair {
        KeyPair { public_key: vec![1u8; 32], private_key: PrivateKey::new(vec![2u8; 64]) }
    }

    // --- EncryptedData serialization ---

    #[test]
    fn test_encrypted_data_roundtrip() {
        let original = make_encrypted_data();
        let json = serialize_encrypted_data(&original).unwrap();
        let deserialized = deserialize_encrypted_data(&json).unwrap();

        assert_eq!(original.data, deserialized.data);
        assert_eq!(original.metadata.nonce, deserialized.metadata.nonce);
        assert_eq!(original.metadata.tag, deserialized.metadata.tag);
        assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
        assert_eq!(original.scheme, deserialized.scheme);
        assert_eq!(original.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_encrypted_data_roundtrip_no_tag() {
        let original = make_encrypted_data_no_tag();
        let json = serialize_encrypted_data(&original).unwrap();
        let deserialized = deserialize_encrypted_data(&json).unwrap();

        assert_eq!(original.data, deserialized.data);
        assert!(deserialized.metadata.tag.is_none());
        assert!(deserialized.metadata.key_id.is_none());
    }

    #[test]
    fn test_encrypted_data_from_trait() {
        let original = make_encrypted_data();
        let serializable = SerializableEncryptedData::from(&original);
        assert!(!serializable.data.is_empty());
        assert_eq!(serializable.scheme, "AES-256-GCM");
        assert_eq!(serializable.timestamp, 1700000000);
    }

    #[test]
    fn test_encrypted_data_try_from_invalid_base64() {
        let bad = SerializableEncryptedData {
            data: "not-valid-base64!!!".to_string(),
            metadata: SerializableEncryptedMetadata {
                nonce: "AQID".to_string(),
                tag: None,
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<EncryptedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_try_from_invalid_nonce() {
        let bad = SerializableEncryptedData {
            data: BASE64_ENGINE.encode(b"hello"),
            metadata: SerializableEncryptedMetadata {
                nonce: "not-valid!!!".to_string(),
                tag: None,
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<EncryptedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_try_from_invalid_tag() {
        let bad = SerializableEncryptedData {
            data: BASE64_ENGINE.encode(b"hello"),
            metadata: SerializableEncryptedMetadata {
                nonce: BASE64_ENGINE.encode(b"nonce12bytes"),
                tag: Some("not-valid!!!".to_string()),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<EncryptedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_encrypted_data_invalid_json() {
        let result = deserialize_encrypted_data("not json");
        assert!(result.is_err());
    }

    // --- SignedData serialization ---

    #[test]
    fn test_signed_data_roundtrip() {
        let original = make_signed_data();
        let json = serialize_signed_data(&original).unwrap();
        let deserialized = deserialize_signed_data(&json).unwrap();

        assert_eq!(original.data, deserialized.data);
        assert_eq!(original.metadata.signature, deserialized.metadata.signature);
        assert_eq!(
            original.metadata.signature_algorithm,
            deserialized.metadata.signature_algorithm
        );
        assert_eq!(original.metadata.public_key, deserialized.metadata.public_key);
        assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
        assert_eq!(original.scheme, deserialized.scheme);
        assert_eq!(original.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_signed_data_from_trait() {
        let original = make_signed_data();
        let serializable = SerializableSignedData::from(&original);
        assert!(!serializable.data.is_empty());
        assert_eq!(serializable.metadata.signature_algorithm, "ML-DSA-65");
    }

    #[test]
    fn test_signed_data_try_from_invalid_base64() {
        let bad = SerializableSignedData {
            data: "not-valid!!!".to_string(),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(b"sig"),
                signature_algorithm: "test".to_string(),
                public_key: BASE64_ENGINE.encode(b"pk"),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_data_try_from_invalid_signature() {
        let bad = SerializableSignedData {
            data: BASE64_ENGINE.encode(b"data"),
            metadata: SerializableSignedMetadata {
                signature: "not-valid!!!".to_string(),
                signature_algorithm: "test".to_string(),
                public_key: BASE64_ENGINE.encode(b"pk"),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_signed_data_try_from_invalid_public_key() {
        let bad = SerializableSignedData {
            data: BASE64_ENGINE.encode(b"data"),
            metadata: SerializableSignedMetadata {
                signature: BASE64_ENGINE.encode(b"sig"),
                signature_algorithm: "test".to_string(),
                public_key: "not-valid!!!".to_string(),
                key_id: None,
            },
            scheme: "test".to_string(),
            timestamp: 0,
        };
        let result: std::result::Result<SignedData, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_signed_data_invalid_json() {
        let result = deserialize_signed_data("not json");
        assert!(result.is_err());
    }

    // --- KeyPair serialization ---

    #[test]
    fn test_keypair_roundtrip() {
        let original = make_keypair();
        let json = serialize_keypair(&original).unwrap();
        let deserialized = deserialize_keypair(&json).unwrap();

        assert_eq!(original.public_key, deserialized.public_key);
        assert_eq!(original.private_key.as_slice(), deserialized.private_key.as_slice());
    }

    #[test]
    fn test_keypair_from_trait() {
        let original = make_keypair();
        let serializable = SerializableKeyPair::from(&original);
        assert!(!serializable.public_key.is_empty());
        assert!(!serializable.private_key.is_empty());
    }

    #[test]
    fn test_keypair_try_from_invalid_public_key() {
        let bad = SerializableKeyPair {
            public_key: "not-valid!!!".to_string(),
            private_key: BASE64_ENGINE.encode(b"secret"),
        };
        let result: std::result::Result<KeyPair, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_try_from_invalid_private_key() {
        let bad = SerializableKeyPair {
            public_key: BASE64_ENGINE.encode(b"public"),
            private_key: "not-valid!!!".to_string(),
        };
        let result: std::result::Result<KeyPair, _> = bad.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_keypair_invalid_json() {
        let result = deserialize_keypair("not json");
        assert!(result.is_err());
    }

    // --- Serializable struct debug/clone ---

    #[test]
    fn test_serializable_encrypted_data_clone_debug() {
        let original = make_encrypted_data();
        let ser = SerializableEncryptedData::from(&original);
        let cloned = ser.clone();
        assert_eq!(cloned.scheme, ser.scheme);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableEncryptedData"));
    }

    #[test]
    fn test_serializable_signed_data_clone_debug() {
        let original = make_signed_data();
        let ser = SerializableSignedData::from(&original);
        let cloned = ser.clone();
        assert_eq!(cloned.scheme, ser.scheme);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableSignedData"));
    }

    #[test]
    fn test_serializable_keypair_clone_debug() {
        let original = make_keypair();
        let ser = SerializableKeyPair::from(&original);
        let cloned = ser.clone();
        assert_eq!(cloned.public_key, ser.public_key);
        let debug = format!("{:?}", ser);
        assert!(debug.contains("SerializableKeyPair"));
    }
}
