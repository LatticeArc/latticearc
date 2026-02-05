//! Comprehensive serialization integration tests for arc-core
//!
//! Tests all serialization paths: EncryptedData, SignedData, KeyPair
//! Target: 0% -> 95% coverage

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::useless_vec,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::clone_on_copy,
    clippy::len_zero,
    clippy::single_match,
    clippy::unnested_or_patterns,
    clippy::default_constructed_unit_structs,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::unnecessary_unwrap,
    clippy::redundant_pattern_matching,
    clippy::missing_const_for_thread_local,
    clippy::get_first,
    clippy::float_cmp,
    clippy::needless_borrows_for_generic_args,
    unused_qualifications
)]

use arc_core::error::{CoreError, Result};
use arc_core::serialization::{
    SerializableEncryptedData, SerializableEncryptedMetadata, SerializableKeyPair,
    SerializableSignedData, SerializableSignedMetadata, deserialize_encrypted_data,
    deserialize_keypair, deserialize_signed_data, serialize_encrypted_data, serialize_keypair,
    serialize_signed_data,
};
use arc_core::types::{
    EncryptedData, EncryptedMetadata, KeyPair, PrivateKey, SignedData, SignedMetadata,
};

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_encrypted_data() -> EncryptedData {
    EncryptedData {
        data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        metadata: EncryptedMetadata {
            nonce: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            tag: Some(vec![
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
                0xF0, 0x00,
            ]),
            key_id: Some("test-key-id".to_string()),
        },
        scheme: "AES-256-GCM".to_string(),
        timestamp: 1706745600,
    }
}

fn create_test_encrypted_data_no_tag() -> EncryptedData {
    EncryptedData {
        data: vec![0x01, 0x02, 0x03],
        metadata: EncryptedMetadata { nonce: vec![0xAA; 12], tag: None, key_id: None },
        scheme: "ChaCha20-Poly1305".to_string(),
        timestamp: 1706745601,
    }
}

fn create_test_signed_data() -> SignedData {
    SignedData {
        data: b"Hello, World!".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0xDE; 64],
            signature_algorithm: "ML-DSA-65".to_string(),
            public_key: vec![0xCA; 32],
            key_id: Some("signer-key-id".to_string()),
        },
        scheme: "ML-DSA".to_string(),
        timestamp: 1706745602,
    }
}

fn create_test_signed_data_no_key_id() -> SignedData {
    SignedData {
        data: b"Test message".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0x11; 48],
            signature_algorithm: "Ed25519".to_string(),
            public_key: vec![0x55; 32],
            key_id: None,
        },
        scheme: "Ed25519".to_string(),
        timestamp: 1706745603,
    }
}

fn create_test_keypair() -> KeyPair {
    KeyPair { public_key: vec![0x01; 32], private_key: PrivateKey::new(vec![0x10; 32]) }
}

// ============================================================================
// EncryptedData Serialization Tests
// ============================================================================

#[test]
fn test_serialize_encrypted_data_roundtrip() -> Result<()> {
    let original = create_test_encrypted_data();
    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.data, deserialized.data);
    assert_eq!(original.metadata.nonce, deserialized.metadata.nonce);
    assert_eq!(original.metadata.tag, deserialized.metadata.tag);
    assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
    assert_eq!(original.scheme, deserialized.scheme);
    assert_eq!(original.timestamp, deserialized.timestamp);
    Ok(())
}

#[test]
fn test_serialize_encrypted_data_no_tag_roundtrip() -> Result<()> {
    let original = create_test_encrypted_data_no_tag();
    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.data, deserialized.data);
    assert_eq!(original.metadata.nonce, deserialized.metadata.nonce);
    assert!(deserialized.metadata.tag.is_none());
    assert!(deserialized.metadata.key_id.is_none());
    Ok(())
}

#[test]
fn test_serialize_encrypted_data_empty_data() -> Result<()> {
    let original = EncryptedData {
        data: vec![],
        metadata: EncryptedMetadata { nonce: vec![0; 12], tag: None, key_id: None },
        scheme: "TEST".to_string(),
        timestamp: 0,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert!(deserialized.data.is_empty());
    Ok(())
}

#[test]
fn test_serialize_encrypted_data_large_data() -> Result<()> {
    let original = EncryptedData {
        data: vec![0xAB; 10_000], // 10KB
        metadata: EncryptedMetadata {
            nonce: vec![0xFF; 12],
            tag: Some(vec![0x00; 16]),
            key_id: Some("large-key".to_string()),
        },
        scheme: "AES-256-GCM".to_string(),
        timestamp: u64::MAX,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.data.len(), deserialized.data.len());
    assert_eq!(original.data, deserialized.data);
    Ok(())
}

#[test]
fn test_serialize_encrypted_data_binary_values() -> Result<()> {
    let original = EncryptedData {
        data: vec![0x00, 0x7F, 0x80, 0xFF],
        metadata: EncryptedMetadata {
            nonce: vec![0x00, 0x7F, 0x80, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            tag: Some(vec![0xFF; 16]),
            key_id: Some("binary-test".to_string()),
        },
        scheme: "BINARY".to_string(),
        timestamp: 12345,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.data, deserialized.data);
    assert_eq!(original.metadata.nonce, deserialized.metadata.nonce);
    Ok(())
}

#[test]
fn test_deserialize_encrypted_data_invalid_json() {
    let result = deserialize_encrypted_data("not valid json");
    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::SerializationError(_) => {}
        other => panic!("Expected SerializationError, got: {:?}", other),
    }
}

#[test]
fn test_deserialize_encrypted_data_invalid_base64_data() {
    let invalid_json = r#"{"data":"!!!invalid base64!!!","metadata":{"nonce":"AA==","tag":null,"key_id":null},"scheme":"TEST","timestamp":0}"#;
    let result = deserialize_encrypted_data(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_encrypted_data_invalid_base64_nonce() {
    let invalid_json = r#"{"data":"AQID","metadata":{"nonce":"!!!invalid!!!","tag":null,"key_id":null},"scheme":"TEST","timestamp":0}"#;
    let result = deserialize_encrypted_data(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_encrypted_data_invalid_base64_tag() {
    let invalid_json = r#"{"data":"AQID","metadata":{"nonce":"AAAAAAAAAAAAAAAAAAA=","tag":"!!!invalid!!!","key_id":null},"scheme":"TEST","timestamp":0}"#;
    let result = deserialize_encrypted_data(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_encrypted_data_missing_field() {
    let incomplete_json = r#"{"data":"AQID"}"#;
    let result = deserialize_encrypted_data(incomplete_json);
    assert!(result.is_err());
}

// ============================================================================
// SignedData Serialization Tests
// ============================================================================

#[test]
fn test_serialize_signed_data_roundtrip() -> Result<()> {
    let original = create_test_signed_data();
    let json = serialize_signed_data(&original)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(original.data, deserialized.data);
    assert_eq!(original.metadata.signature, deserialized.metadata.signature);
    assert_eq!(original.metadata.signature_algorithm, deserialized.metadata.signature_algorithm);
    assert_eq!(original.metadata.public_key, deserialized.metadata.public_key);
    assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
    assert_eq!(original.scheme, deserialized.scheme);
    assert_eq!(original.timestamp, deserialized.timestamp);
    Ok(())
}

#[test]
fn test_serialize_signed_data_no_key_id_roundtrip() -> Result<()> {
    let original = create_test_signed_data_no_key_id();
    let json = serialize_signed_data(&original)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(original.data, deserialized.data);
    assert!(deserialized.metadata.key_id.is_none());
    Ok(())
}

#[test]
fn test_serialize_signed_data_empty_data() -> Result<()> {
    let original = SignedData {
        data: vec![],
        metadata: SignedMetadata {
            signature: vec![0; 64],
            signature_algorithm: "EMPTY".to_string(),
            public_key: vec![0; 32],
            key_id: None,
        },
        scheme: "EMPTY".to_string(),
        timestamp: 0,
    };

    let json = serialize_signed_data(&original)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert!(deserialized.data.is_empty());
    Ok(())
}

#[test]
fn test_serialize_signed_data_large_signature() -> Result<()> {
    let original = SignedData {
        data: b"Large signature test".to_vec(),
        metadata: SignedMetadata {
            signature: vec![0xAB; 4096], // Large signature (SLH-DSA)
            signature_algorithm: "SLH-DSA-256s".to_string(),
            public_key: vec![0xCD; 64],
            key_id: Some("slh-dsa-key".to_string()),
        },
        scheme: "SLH-DSA".to_string(),
        timestamp: 9999999999,
    };

    let json = serialize_signed_data(&original)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(original.metadata.signature.len(), deserialized.metadata.signature.len());
    Ok(())
}

#[test]
fn test_deserialize_signed_data_invalid_json() {
    let result = deserialize_signed_data("{invalid");
    assert!(result.is_err());
}

#[test]
fn test_deserialize_signed_data_invalid_base64_signature() {
    let invalid_json = r#"{"data":"SGVsbG8=","metadata":{"signature":"!!!invalid!!!","signature_algorithm":"ED25519","public_key":"AAAA","key_id":null},"scheme":"ED25519","timestamp":0}"#;
    let result = deserialize_signed_data(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_signed_data_invalid_base64_public_key() {
    let invalid_json = r#"{"data":"SGVsbG8=","metadata":{"signature":"AAAA","signature_algorithm":"ED25519","public_key":"!!!invalid!!!","key_id":null},"scheme":"ED25519","timestamp":0}"#;
    let result = deserialize_signed_data(invalid_json);
    assert!(result.is_err());
}

// ============================================================================
// KeyPair Serialization Tests
// ============================================================================

#[test]
fn test_serialize_keypair_roundtrip() -> Result<()> {
    let original = create_test_keypair();
    let json = serialize_keypair(&original)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(original.public_key, deserialized.public_key);
    assert_eq!(original.private_key.as_slice(), deserialized.private_key.as_slice());
    Ok(())
}

#[test]
fn test_serialize_keypair_small_keys() -> Result<()> {
    let original = KeyPair { public_key: vec![0x01], private_key: PrivateKey::new(vec![0x02]) };

    let json = serialize_keypair(&original)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(original.public_key, deserialized.public_key);
    Ok(())
}

#[test]
fn test_serialize_keypair_large_keys() -> Result<()> {
    let original = KeyPair {
        public_key: vec![0xAA; 2048], // Large key (ML-KEM-1024)
        private_key: PrivateKey::new(vec![0xBB; 3168]),
    };

    let json = serialize_keypair(&original)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(original.public_key.len(), deserialized.public_key.len());
    assert_eq!(original.private_key.as_slice().len(), deserialized.private_key.as_slice().len());
    Ok(())
}

#[test]
fn test_serialize_keypair_binary_keys() -> Result<()> {
    let original = KeyPair {
        public_key: vec![0x00, 0x7F, 0x80, 0xFF],
        private_key: PrivateKey::new(vec![0xFF, 0x80, 0x7F, 0x00]),
    };

    let json = serialize_keypair(&original)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(original.public_key, deserialized.public_key);
    assert_eq!(original.private_key.as_slice(), deserialized.private_key.as_slice());
    Ok(())
}

#[test]
fn test_deserialize_keypair_invalid_json() {
    let result = deserialize_keypair("not json");
    assert!(result.is_err());
}

#[test]
fn test_deserialize_keypair_invalid_base64_public_key() {
    let invalid_json = r#"{"public_key":"!!!invalid!!!","private_key":"AAAA"}"#;
    let result = deserialize_keypair(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_keypair_invalid_base64_private_key() {
    let invalid_json = r#"{"public_key":"AAAA","private_key":"!!!invalid!!!"}"#;
    let result = deserialize_keypair(invalid_json);
    assert!(result.is_err());
}

// ============================================================================
// Serializable Type Conversion Tests
// ============================================================================

#[test]
fn test_encrypted_data_to_serializable_conversion() {
    let original = create_test_encrypted_data();
    let serializable = SerializableEncryptedData::from(&original);

    // Verify Base64 encoding occurred
    assert!(!serializable.data.is_empty());
    assert!(!serializable.metadata.nonce.is_empty());
    assert!(serializable.metadata.tag.is_some());
    assert_eq!(serializable.scheme, original.scheme);
    assert_eq!(serializable.timestamp, original.timestamp);
}

#[test]
fn test_serializable_to_encrypted_data_conversion() -> Result<()> {
    let serializable = SerializableEncryptedData {
        data: "AQIDBA==".to_string(), // [1, 2, 3, 4]
        metadata: SerializableEncryptedMetadata {
            nonce: "AQIDBAUG".to_string(),
            tag: Some("AQIDBA==".to_string()),
            key_id: Some("test".to_string()),
        },
        scheme: "TEST".to_string(),
        timestamp: 123,
    };

    let encrypted: EncryptedData = serializable.try_into()?;
    assert_eq!(encrypted.data, vec![1, 2, 3, 4]);
    Ok(())
}

#[test]
fn test_signed_data_to_serializable_conversion() {
    let original = create_test_signed_data();
    let serializable = SerializableSignedData::from(&original);

    assert!(!serializable.data.is_empty());
    assert!(!serializable.metadata.signature.is_empty());
    assert!(!serializable.metadata.public_key.is_empty());
    assert_eq!(serializable.scheme, original.scheme);
}

#[test]
fn test_serializable_to_signed_data_conversion() -> Result<()> {
    let serializable = SerializableSignedData {
        data: "SGVsbG8=".to_string(), // "Hello"
        metadata: SerializableSignedMetadata {
            signature: "AQIDBA==".to_string(),
            signature_algorithm: "TEST".to_string(),
            public_key: "AQIDBA==".to_string(),
            key_id: None,
        },
        scheme: "TEST".to_string(),
        timestamp: 456,
    };

    let signed: SignedData = serializable.try_into()?;
    assert_eq!(signed.data, b"Hello");
    Ok(())
}

#[test]
fn test_keypair_to_serializable_conversion() {
    let original = create_test_keypair();
    let serializable = SerializableKeyPair::from(&original);

    assert!(!serializable.public_key.is_empty());
    assert!(!serializable.private_key.is_empty());
}

#[test]
fn test_serializable_to_keypair_conversion() -> Result<()> {
    let serializable = SerializableKeyPair {
        public_key: "AQIDBA==".to_string(),
        private_key: "BQYHCA==".to_string(),
    };

    let keypair: KeyPair = serializable.try_into()?;
    assert_eq!(keypair.public_key, vec![1, 2, 3, 4]);
    assert_eq!(keypair.private_key.as_slice(), &[5, 6, 7, 8]);
    Ok(())
}

// ============================================================================
// JSON Structure Validation Tests
// ============================================================================

#[test]
fn test_encrypted_data_json_structure() -> Result<()> {
    let original = create_test_encrypted_data();
    let json = serialize_encrypted_data(&original)?;

    // Parse as generic JSON to validate structure
    let parsed: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| CoreError::SerializationError(e.to_string()))?;

    assert!(parsed.get("data").is_some());
    assert!(parsed.get("metadata").is_some());
    assert!(parsed.get("scheme").is_some());
    assert!(parsed.get("timestamp").is_some());

    let metadata = parsed.get("metadata").expect("metadata");
    assert!(metadata.get("nonce").is_some());
    assert!(metadata.get("tag").is_some());
    assert!(metadata.get("key_id").is_some());

    Ok(())
}

#[test]
fn test_signed_data_json_structure() -> Result<()> {
    let original = create_test_signed_data();
    let json = serialize_signed_data(&original)?;

    let parsed: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| CoreError::SerializationError(e.to_string()))?;

    assert!(parsed.get("data").is_some());
    assert!(parsed.get("metadata").is_some());
    assert!(parsed.get("scheme").is_some());
    assert!(parsed.get("timestamp").is_some());

    let metadata = parsed.get("metadata").expect("metadata");
    assert!(metadata.get("signature").is_some());
    assert!(metadata.get("signature_algorithm").is_some());
    assert!(metadata.get("public_key").is_some());

    Ok(())
}

#[test]
fn test_keypair_json_structure() -> Result<()> {
    let original = create_test_keypair();
    let json = serialize_keypair(&original)?;

    let parsed: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| CoreError::SerializationError(e.to_string()))?;

    assert!(parsed.get("public_key").is_some());
    assert!(parsed.get("private_key").is_some());

    Ok(())
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_serialize_special_characters_in_key_id() -> Result<()> {
    let original = EncryptedData {
        data: vec![1, 2, 3],
        metadata: EncryptedMetadata {
            nonce: vec![0; 12],
            tag: None,
            key_id: Some("key-with-special-chars-!@#$%^&*()".to_string()),
        },
        scheme: "TEST".to_string(),
        timestamp: 0,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.metadata.key_id, deserialized.metadata.key_id);
    Ok(())
}

#[test]
fn test_serialize_unicode_in_scheme() -> Result<()> {
    let original = EncryptedData {
        data: vec![1, 2, 3],
        metadata: EncryptedMetadata { nonce: vec![0; 12], tag: None, key_id: None },
        scheme: "AES-256-GCM-日本語".to_string(),
        timestamp: 0,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.scheme, deserialized.scheme);
    Ok(())
}

#[test]
fn test_serialize_max_timestamp() -> Result<()> {
    let original = EncryptedData {
        data: vec![1],
        metadata: EncryptedMetadata { nonce: vec![0; 12], tag: None, key_id: None },
        scheme: "TEST".to_string(),
        timestamp: u64::MAX,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.timestamp, deserialized.timestamp);
    Ok(())
}

#[test]
fn test_serialize_zero_timestamp() -> Result<()> {
    let original = EncryptedData {
        data: vec![1],
        metadata: EncryptedMetadata { nonce: vec![0; 12], tag: None, key_id: None },
        scheme: "TEST".to_string(),
        timestamp: 0,
    };

    let json = serialize_encrypted_data(&original)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(original.timestamp, deserialized.timestamp);
    Ok(())
}

// ============================================================================
// Multiple Roundtrip Tests
// ============================================================================

#[test]
fn test_multiple_encrypt_roundtrips() -> Result<()> {
    let original = create_test_encrypted_data();

    // First roundtrip
    let json1 = serialize_encrypted_data(&original)?;
    let data1 = deserialize_encrypted_data(&json1)?;

    // Second roundtrip
    let json2 = serialize_encrypted_data(&data1)?;
    let data2 = deserialize_encrypted_data(&json2)?;

    // Third roundtrip
    let json3 = serialize_encrypted_data(&data2)?;
    let data3 = deserialize_encrypted_data(&json3)?;

    assert_eq!(original.data, data3.data);
    Ok(())
}

#[test]
fn test_multiple_signed_roundtrips() -> Result<()> {
    let original = create_test_signed_data();

    let json1 = serialize_signed_data(&original)?;
    let data1 = deserialize_signed_data(&json1)?;

    let json2 = serialize_signed_data(&data1)?;
    let data2 = deserialize_signed_data(&json2)?;

    assert_eq!(original.data, data2.data);
    assert_eq!(original.metadata.signature, data2.metadata.signature);
    Ok(())
}

#[test]
fn test_multiple_keypair_roundtrips() -> Result<()> {
    let original = create_test_keypair();

    let json1 = serialize_keypair(&original)?;
    let keypair1 = deserialize_keypair(&json1)?;

    let json2 = serialize_keypair(&keypair1)?;
    let keypair2 = deserialize_keypair(&json2)?;

    assert_eq!(original.public_key, keypair2.public_key);
    Ok(())
}
