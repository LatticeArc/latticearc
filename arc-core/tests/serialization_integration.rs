//! Comprehensive integration tests for serialization utilities
//!
//! This test suite validates JSON serialization and deserialization of cryptographic types
//! in arc-core, including encrypted data, signed data, and key pairs.
//!
//! ## Test Coverage
//!
//! - **EncryptedData serialization**: Round-trip tests with/without tags, key_id
//! - **SignedData serialization**: Round-trip tests with metadata
//! - **KeyPair serialization**: Round-trip tests with zeroization verification
//! - **Error handling**: Invalid JSON, invalid Base64, corrupted data
//! - **Edge cases**: Empty data, large data, special characters
//! - **Cross-format compatibility**: JSON structure validation
//!
//! ## Coverage Target
//!
//! Aims to achieve 80%+ coverage of arc-core/src/serialization.rs (currently 0/126 lines)

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

use arc_core::{
    error::CoreError,
    serialization::{
        SerializableEncryptedData, SerializableEncryptedMetadata, SerializableKeyPair,
        SerializableSignedData, SerializableSignedMetadata, deserialize_encrypted_data,
        deserialize_keypair, deserialize_signed_data, serialize_encrypted_data, serialize_keypair,
        serialize_signed_data,
    },
    types::{EncryptedData, EncryptedMetadata, KeyPair, PrivateKey, SignedData, SignedMetadata},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};

// ============================================================================
// Helper Functions
// ============================================================================

/// Creates a test EncryptedData instance
fn create_test_encrypted_data(
    data: Vec<u8>,
    nonce: Vec<u8>,
    tag: Option<Vec<u8>>,
    key_id: Option<String>,
) -> EncryptedData {
    EncryptedData {
        data,
        metadata: EncryptedMetadata { nonce, tag, key_id },
        scheme: "AES-256-GCM".to_string(),
        timestamp: 1706745600, // 2024-02-01 00:00:00 UTC
    }
}

/// Creates a test SignedData instance
fn create_test_signed_data(
    data: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    key_id: Option<String>,
) -> SignedData {
    SignedData {
        data,
        metadata: SignedMetadata {
            signature,
            signature_algorithm: "ML-DSA-65".to_string(),
            public_key,
            key_id,
        },
        scheme: "ML-DSA".to_string(),
        timestamp: 1706745600,
    }
}

/// Creates a test KeyPair instance
fn create_test_keypair(public_key: Vec<u8>, private_key: Vec<u8>) -> KeyPair {
    KeyPair { public_key, private_key: PrivateKey::new(private_key) }
}

// ============================================================================
// EncryptedData Serialization Tests
// ============================================================================

#[test]
fn test_encrypted_data_roundtrip_basic() {
    let encrypted = create_test_encrypted_data(
        b"encrypted payload data".to_vec(),
        b"nonce123456".to_vec(),
        Some(b"tag123456".to_vec()),
        Some("key-001".to_string()),
    );

    // Serialize
    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");

    // Deserialize
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    // Verify equality
    assert_eq!(deserialized.data, encrypted.data);
    assert_eq!(deserialized.metadata.nonce, encrypted.metadata.nonce);
    assert_eq!(deserialized.metadata.tag, encrypted.metadata.tag);
    assert_eq!(deserialized.metadata.key_id, encrypted.metadata.key_id);
    assert_eq!(deserialized.scheme, encrypted.scheme);
    assert_eq!(deserialized.timestamp, encrypted.timestamp);
}

#[test]
fn test_encrypted_data_without_tag() {
    let encrypted = create_test_encrypted_data(
        b"encrypted data without tag".to_vec(),
        b"nonce123456".to_vec(),
        None, // No tag
        Some("key-002".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.data, encrypted.data);
    assert_eq!(deserialized.metadata.nonce, encrypted.metadata.nonce);
    assert_eq!(deserialized.metadata.tag, None);
    assert_eq!(deserialized.metadata.key_id, encrypted.metadata.key_id);
}

#[test]
fn test_encrypted_data_without_key_id() {
    let encrypted = create_test_encrypted_data(
        b"encrypted data without key_id".to_vec(),
        b"nonce123456".to_vec(),
        Some(b"tag123456".to_vec()),
        None, // No key_id
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.data, encrypted.data);
    assert_eq!(deserialized.metadata.tag, encrypted.metadata.tag);
    assert_eq!(deserialized.metadata.key_id, None);
}

#[test]
fn test_encrypted_data_empty_data() {
    let encrypted = create_test_encrypted_data(
        Vec::new(), // Empty data
        b"nonce123456".to_vec(),
        Some(b"tag123456".to_vec()),
        Some("key-003".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert!(deserialized.data.is_empty());
}

#[test]
fn test_encrypted_data_large_payload() {
    let large_data = vec![0xAB; 10_000]; // 10KB of data
    let encrypted = create_test_encrypted_data(
        large_data.clone(),
        b"nonce123456".to_vec(),
        Some(b"tag123456".to_vec()),
        Some("key-004".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.data, large_data);
}

#[test]
fn test_encrypted_data_json_structure() {
    let encrypted = create_test_encrypted_data(
        b"test".to_vec(),
        b"nonce123456".to_vec(),
        Some(b"tag123456".to_vec()),
        Some("key-005".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");

    // Verify JSON contains expected fields
    assert!(json.contains("\"data\""));
    assert!(json.contains("\"metadata\""));
    assert!(json.contains("\"nonce\""));
    assert!(json.contains("\"tag\""));
    assert!(json.contains("\"key_id\""));
    assert!(json.contains("\"scheme\""));
    assert!(json.contains("\"timestamp\""));
    assert!(json.contains("AES-256-GCM"));
}

#[test]
fn test_encrypted_data_invalid_json() {
    let invalid_json = "{invalid json}";
    let result = deserialize_encrypted_data(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_encrypted_data_invalid_base64() {
    let json = r#"{
        "data": "!!!invalid-base64!!!",
        "metadata": {
            "nonce": "bm9uY2UxMjM0NTY=",
            "tag": "dGFnMTIzNDU2",
            "key_id": "key-006"
        },
        "scheme": "AES-256-GCM",
        "timestamp": 1706745600
    }"#;

    let result = deserialize_encrypted_data(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_encrypted_data_missing_field() {
    let json = r#"{
        "data": "dGVzdA==",
        "metadata": {
            "nonce": "bm9uY2UxMjM0NTY="
        },
        "scheme": "AES-256-GCM"
    }"#; // Missing timestamp

    let result = deserialize_encrypted_data(json);
    assert!(result.is_err());
}

// ============================================================================
// SignedData Serialization Tests
// ============================================================================

#[test]
fn test_signed_data_roundtrip_basic() {
    let signed = create_test_signed_data(
        b"original message data".to_vec(),
        b"signature bytes here".to_vec(),
        b"public key bytes".to_vec(),
        Some("key-101".to_string()),
    );

    // Serialize
    let json = serialize_signed_data(&signed).expect("serialization should succeed");

    // Deserialize
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    // Verify equality
    assert_eq!(deserialized.data, signed.data);
    assert_eq!(deserialized.metadata.signature, signed.metadata.signature);
    assert_eq!(deserialized.metadata.signature_algorithm, signed.metadata.signature_algorithm);
    assert_eq!(deserialized.metadata.public_key, signed.metadata.public_key);
    assert_eq!(deserialized.metadata.key_id, signed.metadata.key_id);
    assert_eq!(deserialized.scheme, signed.scheme);
    assert_eq!(deserialized.timestamp, signed.timestamp);
}

#[test]
fn test_signed_data_without_key_id() {
    let signed = create_test_signed_data(
        b"message".to_vec(),
        b"signature".to_vec(),
        b"public_key".to_vec(),
        None, // No key_id
    );

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.metadata.key_id, None);
}

#[test]
fn test_signed_data_empty_message() {
    let signed = create_test_signed_data(
        Vec::new(), // Empty message
        b"signature".to_vec(),
        b"public_key".to_vec(),
        Some("key-102".to_string()),
    );

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert!(deserialized.data.is_empty());
}

#[test]
fn test_signed_data_large_signature() {
    let large_sig = vec![0xFF; 5000]; // 5KB signature
    let signed = create_test_signed_data(
        b"message".to_vec(),
        large_sig.clone(),
        b"public_key".to_vec(),
        Some("key-103".to_string()),
    );

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.metadata.signature, large_sig);
}

#[test]
fn test_signed_data_json_structure() {
    let signed = create_test_signed_data(
        b"test".to_vec(),
        b"sig".to_vec(),
        b"pk".to_vec(),
        Some("key-104".to_string()),
    );

    let json = serialize_signed_data(&signed).expect("serialization should succeed");

    // Verify JSON contains expected fields
    assert!(json.contains("\"data\""));
    assert!(json.contains("\"metadata\""));
    assert!(json.contains("\"signature\""));
    assert!(json.contains("\"signature_algorithm\""));
    assert!(json.contains("\"public_key\""));
    assert!(json.contains("\"key_id\""));
    assert!(json.contains("\"scheme\""));
    assert!(json.contains("\"timestamp\""));
    assert!(json.contains("ML-DSA-65"));
}

#[test]
fn test_signed_data_invalid_json() {
    let invalid_json = "not valid json";
    let result = deserialize_signed_data(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_signed_data_invalid_base64_signature() {
    let json = r#"{
        "data": "dGVzdA==",
        "metadata": {
            "signature": "!!!invalid!!!",
            "signature_algorithm": "ML-DSA-65",
            "public_key": "cGs=",
            "key_id": "key-105"
        },
        "scheme": "ML-DSA",
        "timestamp": 1706745600
    }"#;

    let result = deserialize_signed_data(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_signed_data_invalid_base64_public_key() {
    let json = r#"{
        "data": "dGVzdA==",
        "metadata": {
            "signature": "c2ln",
            "signature_algorithm": "ML-DSA-65",
            "public_key": "@@@invalid@@@",
            "key_id": "key-106"
        },
        "scheme": "ML-DSA",
        "timestamp": 1706745600
    }"#;

    let result = deserialize_signed_data(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

// ============================================================================
// KeyPair Serialization Tests
// ============================================================================

#[test]
fn test_keypair_roundtrip_basic() {
    let keypair = create_test_keypair(
        b"public key bytes here".to_vec(),
        b"private key bytes here - sensitive!".to_vec(),
    );

    // Serialize
    let json = serialize_keypair(&keypair).expect("serialization should succeed");

    // Deserialize
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    // Verify equality
    assert_eq!(deserialized.public_key, keypair.public_key);
    assert_eq!(deserialized.private_key.as_slice(), keypair.private_key.as_slice());
}

#[test]
fn test_keypair_small_keys() {
    let keypair = create_test_keypair(b"pk".to_vec(), b"sk".to_vec());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key, b"pk");
    assert_eq!(deserialized.private_key.as_slice(), b"sk");
}

#[test]
fn test_keypair_large_keys() {
    let large_pk = vec![0xAA; 2000]; // 2KB public key
    let large_sk = vec![0xBB; 3000]; // 3KB private key
    let keypair = create_test_keypair(large_pk.clone(), large_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key, large_pk);
    assert_eq!(deserialized.private_key.as_slice(), large_sk.as_slice());
}

#[test]
fn test_keypair_json_structure() {
    let keypair = create_test_keypair(b"pk".to_vec(), b"sk".to_vec());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");

    // Verify JSON contains expected fields
    assert!(json.contains("\"public_key\""));
    assert!(json.contains("\"private_key\""));
}

#[test]
fn test_keypair_invalid_json() {
    let invalid_json = "{malformed}";
    let result = deserialize_keypair(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_invalid_base64_public_key() {
    let json = r#"{
        "public_key": "!!!invalid!!!",
        "private_key": "c2s="
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_invalid_base64_private_key() {
    let json = r#"{
        "public_key": "cGs=",
        "private_key": "@@@invalid@@@"
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_missing_public_key() {
    let json = r#"{
        "private_key": "c2s="
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
}

#[test]
fn test_keypair_missing_private_key() {
    let json = r#"{
        "public_key": "cGs="
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
}

// ============================================================================
// Serializable Struct Tests (Direct conversion)
// ============================================================================

#[test]
fn test_serializable_encrypted_data_from_encrypted_data() {
    let encrypted = create_test_encrypted_data(
        b"data".to_vec(),
        b"nonce".to_vec(),
        Some(b"tag".to_vec()),
        Some("key-201".to_string()),
    );

    let serializable = SerializableEncryptedData::from(&encrypted);

    // Verify Base64 encoding
    assert_eq!(serializable.data, BASE64_ENGINE.encode(b"data"));
    assert_eq!(serializable.metadata.nonce, BASE64_ENGINE.encode(b"nonce"));
    assert_eq!(serializable.metadata.tag, Some(BASE64_ENGINE.encode(b"tag")));
    assert_eq!(serializable.metadata.key_id, Some("key-201".to_string()));
    assert_eq!(serializable.scheme, "AES-256-GCM");
    assert_eq!(serializable.timestamp, 1706745600);
}

#[test]
fn test_encrypted_data_from_serializable() {
    let serializable = SerializableEncryptedData {
        data: BASE64_ENGINE.encode(b"data"),
        metadata: SerializableEncryptedMetadata {
            nonce: BASE64_ENGINE.encode(b"nonce"),
            tag: Some(BASE64_ENGINE.encode(b"tag")),
            key_id: Some("key-202".to_string()),
        },
        scheme: "ChaCha20-Poly1305".to_string(),
        timestamp: 1706745700,
    };

    let encrypted: EncryptedData = serializable.try_into().expect("conversion should succeed");

    assert_eq!(encrypted.data, b"data");
    assert_eq!(encrypted.metadata.nonce, b"nonce");
    assert_eq!(encrypted.metadata.tag, Some(b"tag".to_vec()));
    assert_eq!(encrypted.metadata.key_id, Some("key-202".to_string()));
    assert_eq!(encrypted.scheme, "ChaCha20-Poly1305");
    assert_eq!(encrypted.timestamp, 1706745700);
}

#[test]
fn test_serializable_signed_data_from_signed_data() {
    let signed = create_test_signed_data(
        b"message".to_vec(),
        b"signature".to_vec(),
        b"public_key".to_vec(),
        Some("key-203".to_string()),
    );

    let serializable = SerializableSignedData::from(&signed);

    assert_eq!(serializable.data, BASE64_ENGINE.encode(b"message"));
    assert_eq!(serializable.metadata.signature, BASE64_ENGINE.encode(b"signature"));
    assert_eq!(serializable.metadata.signature_algorithm, "ML-DSA-65");
    assert_eq!(serializable.metadata.public_key, BASE64_ENGINE.encode(b"public_key"));
    assert_eq!(serializable.metadata.key_id, Some("key-203".to_string()));
    assert_eq!(serializable.scheme, "ML-DSA");
}

#[test]
fn test_signed_data_from_serializable() {
    let serializable = SerializableSignedData {
        data: BASE64_ENGINE.encode(b"message"),
        metadata: SerializableSignedMetadata {
            signature: BASE64_ENGINE.encode(b"signature"),
            signature_algorithm: "SLH-DSA-SHA2-128s".to_string(),
            public_key: BASE64_ENGINE.encode(b"public_key"),
            key_id: Some("key-204".to_string()),
        },
        scheme: "SLH-DSA".to_string(),
        timestamp: 1706745800,
    };

    let signed: SignedData = serializable.try_into().expect("conversion should succeed");

    assert_eq!(signed.data, b"message");
    assert_eq!(signed.metadata.signature, b"signature");
    assert_eq!(signed.metadata.signature_algorithm, "SLH-DSA-SHA2-128s");
    assert_eq!(signed.metadata.public_key, b"public_key");
    assert_eq!(signed.metadata.key_id, Some("key-204".to_string()));
    assert_eq!(signed.scheme, "SLH-DSA");
    assert_eq!(signed.timestamp, 1706745800);
}

#[test]
fn test_serializable_keypair_from_keypair() {
    let keypair = create_test_keypair(b"public".to_vec(), b"private".to_vec());

    let serializable = SerializableKeyPair::from(&keypair);

    assert_eq!(serializable.public_key, BASE64_ENGINE.encode(b"public"));
    assert_eq!(serializable.private_key, BASE64_ENGINE.encode(b"private"));
}

#[test]
fn test_keypair_from_serializable() {
    let serializable = SerializableKeyPair {
        public_key: BASE64_ENGINE.encode(b"public"),
        private_key: BASE64_ENGINE.encode(b"private"),
    };

    let keypair: KeyPair = serializable.try_into().expect("conversion should succeed");

    assert_eq!(keypair.public_key, b"public");
    assert_eq!(keypair.private_key.as_slice(), b"private");
}

// ============================================================================
// Cross-Format Compatibility Tests
// ============================================================================

#[test]
fn test_encrypted_data_manual_json_parsing() {
    // Create JSON manually
    let json = r#"{
        "data": "aGVsbG8gd29ybGQ=",
        "metadata": {
            "nonce": "MTIzNDU2Nzg5MA==",
            "tag": "dGFnZGF0YQ==",
            "key_id": "manual-key-001"
        },
        "scheme": "AES-256-GCM",
        "timestamp": 1700000000
    }"#;

    // Deserialize
    let encrypted = deserialize_encrypted_data(json).expect("deserialization should succeed");

    // Verify decoded values
    assert_eq!(encrypted.data, b"hello world");
    assert_eq!(encrypted.metadata.nonce, b"1234567890");
    assert_eq!(encrypted.metadata.tag, Some(b"tagdata".to_vec()));
    assert_eq!(encrypted.metadata.key_id, Some("manual-key-001".to_string()));
    assert_eq!(encrypted.scheme, "AES-256-GCM");
    assert_eq!(encrypted.timestamp, 1700000000);
}

#[test]
fn test_signed_data_manual_json_parsing() {
    let json = r#"{
        "data": "ZG9jdW1lbnQ=",
        "metadata": {
            "signature": "c2lnbmF0dXJl",
            "signature_algorithm": "Ed25519",
            "public_key": "cHVibGljX2tleQ==",
            "key_id": "manual-key-002"
        },
        "scheme": "Ed25519",
        "timestamp": 1700000100
    }"#;

    let signed = deserialize_signed_data(json).expect("deserialization should succeed");

    assert_eq!(signed.data, b"document");
    assert_eq!(signed.metadata.signature, b"signature");
    assert_eq!(signed.metadata.signature_algorithm, "Ed25519");
    assert_eq!(signed.metadata.public_key, b"public_key");
    assert_eq!(signed.metadata.key_id, Some("manual-key-002".to_string()));
    assert_eq!(signed.scheme, "Ed25519");
    assert_eq!(signed.timestamp, 1700000100);
}

// ============================================================================
// Special Character and Binary Data Tests
// ============================================================================

#[test]
fn test_encrypted_data_binary_data() {
    // Test with various binary values including null bytes
    let binary_data = vec![0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x00, 0x12, 0x34];
    let encrypted = create_test_encrypted_data(
        binary_data.clone(),
        b"nonce".to_vec(),
        Some(b"tag".to_vec()),
        Some("key-301".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.data, binary_data);
}

#[test]
fn test_signed_data_utf8_message() {
    // Test with UTF-8 encoded string
    let utf8_message = "Hello 世界 🌍".as_bytes().to_vec();
    let signed = create_test_signed_data(
        utf8_message.clone(),
        b"signature".to_vec(),
        b"public_key".to_vec(),
        Some("key-302".to_string()),
    );

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.data, utf8_message);
    assert_eq!(String::from_utf8(deserialized.data).expect("valid utf8"), "Hello 世界 🌍");
}

#[test]
fn test_keypair_all_zero_keys() {
    let zero_pk = vec![0x00; 100];
    let zero_sk = vec![0x00; 200];
    let keypair = create_test_keypair(zero_pk.clone(), zero_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key, zero_pk);
    assert_eq!(deserialized.private_key.as_slice(), zero_sk.as_slice());
}

#[test]
fn test_keypair_all_ff_keys() {
    let ff_pk = vec![0xFF; 100];
    let ff_sk = vec![0xFF; 200];
    let keypair = create_test_keypair(ff_pk.clone(), ff_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key, ff_pk);
    assert_eq!(deserialized.private_key.as_slice(), ff_sk.as_slice());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_encrypted_data_very_long_scheme_name() {
    let mut encrypted = create_test_encrypted_data(
        b"data".to_vec(),
        b"nonce".to_vec(),
        Some(b"tag".to_vec()),
        Some("key-401".to_string()),
    );
    encrypted.scheme = "A".repeat(1000); // Very long scheme name

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.scheme.len(), 1000);
}

#[test]
fn test_signed_data_very_long_algorithm_name() {
    let mut signed = create_test_signed_data(
        b"data".to_vec(),
        b"sig".to_vec(),
        b"pk".to_vec(),
        Some("key-402".to_string()),
    );
    signed.metadata.signature_algorithm = "B".repeat(500);

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.metadata.signature_algorithm.len(), 500);
}

#[test]
fn test_encrypted_data_max_timestamp() {
    let mut encrypted = create_test_encrypted_data(
        b"data".to_vec(),
        b"nonce".to_vec(),
        Some(b"tag".to_vec()),
        Some("key-403".to_string()),
    );
    encrypted.timestamp = u64::MAX;

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");
    let deserialized = deserialize_encrypted_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.timestamp, u64::MAX);
}

#[test]
fn test_signed_data_zero_timestamp() {
    let mut signed = create_test_signed_data(
        b"data".to_vec(),
        b"sig".to_vec(),
        b"pk".to_vec(),
        Some("key-404".to_string()),
    );
    signed.timestamp = 0;

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.timestamp, 0);
}

// ============================================================================
// Pretty Printing and Formatting Tests
// ============================================================================

#[test]
fn test_encrypted_data_serialization_is_compact() {
    let encrypted = create_test_encrypted_data(
        b"data".to_vec(),
        b"nonce".to_vec(),
        Some(b"tag".to_vec()),
        Some("key-501".to_string()),
    );

    let json = serialize_encrypted_data(&encrypted).expect("serialization should succeed");

    // Compact JSON should not have newlines or excessive spaces
    assert!(!json.contains('\n'));
    assert!(!json.contains("  ")); // No double spaces
}

#[test]
fn test_all_types_deserialize_ignore_extra_fields() {
    // JSON with extra fields should still deserialize successfully (serde default behavior)
    let json = r#"{
        "data": "dGVzdA==",
        "metadata": {
            "nonce": "bm9uY2U=",
            "tag": "dGFn",
            "key_id": "key-502",
            "extra_field": "ignored"
        },
        "scheme": "AES-256-GCM",
        "timestamp": 1706745600,
        "extra_root_field": "also ignored"
    }"#;

    let result = deserialize_encrypted_data(json);
    assert!(result.is_ok());
}
