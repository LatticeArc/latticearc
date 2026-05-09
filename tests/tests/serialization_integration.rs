//! Integration tests for the JSON serialization utilities in
//! `latticearc::unified_api::serialization`. Covers `SignedData` and `KeyPair`
//! roundtrips, error handling for invalid input, and JSON structure
//! validation. (`EncryptedData` is exercised separately via
//! `serialize_encrypted_output` / `deserialize_encrypted_output`.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::arithmetic_side_effects)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use latticearc::unified_api::{
    error::CoreError,
    serialization::{
        SerializableKeyPair, SerializableSignedData, SerializableSignedMetadata,
        deserialize_keypair, deserialize_signed_data, serialize_keypair, serialize_signed_data,
    },
    types::{KeyPair, PrivateKey, SignedData, SignedMetadata},
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Creates a test SignedData instance
fn create_test_signed_data(
    data: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    key_id: Option<String>,
) -> SignedData {
    // S4: deserializer requires `scheme == signature_algorithm`,
    // mirroring the production sign path (`signature_algorithm: scheme.clone()`).
    SignedData::new(
        data,
        SignedMetadata::new(signature, "ML-DSA-65".to_string(), public_key, key_id),
        "ML-DSA-65".to_string(),
        1706745600,
    )
}

/// Creates a test KeyPair instance
fn create_test_keypair(public_key: Vec<u8>, private_key: Vec<u8>) -> KeyPair {
    KeyPair::new(latticearc::PublicKey::new(public_key), PrivateKey::new(private_key))
}

// ============================================================================
// SignedData Serialization Tests
// ============================================================================

#[test]
fn test_signed_data_roundtrip_basic_roundtrip() {
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
fn test_signed_data_without_key_id_roundtrip_succeeds() {
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
fn test_signed_data_empty_message_roundtrip_succeeds() {
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
fn test_signed_data_large_signature_roundtrip_succeeds() {
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
fn test_signed_data_json_structure_has_correct_format() {
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
fn test_signed_data_invalid_json_returns_error() {
    let invalid_json = "not valid json";
    let result = deserialize_signed_data(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_signed_data_invalid_base64_signature_returns_error() {
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
fn test_signed_data_invalid_base64_public_key_returns_error() {
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
fn test_keypair_roundtrip_basic_roundtrip() {
    let keypair = create_test_keypair(
        b"public key bytes here".to_vec(),
        b"private key bytes here - sensitive!".to_vec(),
    );

    // Serialize
    let json = serialize_keypair(&keypair).expect("serialization should succeed");

    // Deserialize
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    // Verify equality
    assert_eq!(deserialized.public_key(), keypair.public_key());
    assert_eq!(deserialized.private_key().expose_secret(), keypair.private_key().expose_secret());
}

#[test]
fn test_keypair_small_keys_roundtrip_succeeds() {
    let keypair = create_test_keypair(b"pk".to_vec(), b"sk".to_vec());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key().as_slice(), b"pk");
    assert_eq!(deserialized.private_key().expose_secret(), b"sk");
}

#[test]
fn test_keypair_large_keys_roundtrip_succeeds() {
    let large_pk = vec![0xAA; 2000]; // 2KB public key
    let large_sk = vec![0xBB; 3000]; // 3KB private key
    let keypair = create_test_keypair(large_pk.clone(), large_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key().as_slice(), large_pk.as_slice());
    assert_eq!(deserialized.private_key().expose_secret(), large_sk.as_slice());
}

#[test]
fn test_keypair_json_structure_has_correct_format() {
    let keypair = create_test_keypair(b"pk".to_vec(), b"sk".to_vec());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");

    // Verify JSON contains expected fields
    assert!(json.contains("\"public_key\""));
    assert!(json.contains("\"private_key\""));
}

#[test]
fn test_keypair_invalid_json_returns_error() {
    let invalid_json = "{malformed}";
    let result = deserialize_keypair(invalid_json);

    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_invalid_base64_public_key_returns_error() {
    let json = r#"{
        "public_key": "!!!invalid!!!",
        "private_key": "c2s="
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_invalid_base64_private_key_returns_error() {
    let json = r#"{
        "public_key": "cGs=",
        "private_key": "@@@invalid@@@"
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
    assert!(matches!(result, Err(CoreError::SerializationError(_))));
}

#[test]
fn test_keypair_missing_public_key_returns_error() {
    let json = r#"{
        "private_key": "c2s="
    }"#;

    let result = deserialize_keypair(json);
    assert!(result.is_err());
}

#[test]
fn test_keypair_missing_private_key_returns_error() {
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
fn test_serializable_signed_data_from_signed_data_succeeds() {
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
    assert_eq!(serializable.scheme, "ML-DSA-65");
}

#[test]
fn test_signed_data_from_serializable_succeeds() {
    let serializable = SerializableSignedData {
        data: BASE64_ENGINE.encode(b"message"),
        metadata: SerializableSignedMetadata {
            signature: BASE64_ENGINE.encode(b"signature"),
            signature_algorithm: "SLH-DSA-SHA2-128s".to_string(),
            public_key: BASE64_ENGINE.encode(b"public_key"),
            key_id: Some("key-204".to_string()),
        },
        scheme: "SLH-DSA-SHA2-128s".to_string(),
        timestamp: 1706745800,
    };

    let signed: SignedData = serializable.try_into().expect("conversion should succeed");

    assert_eq!(signed.data, b"message");
    assert_eq!(signed.metadata.signature, b"signature");
    assert_eq!(signed.metadata.signature_algorithm, "SLH-DSA-SHA2-128s");
    assert_eq!(signed.metadata.public_key, b"public_key");
    assert_eq!(signed.metadata.key_id, Some("key-204".to_string()));
    assert_eq!(signed.scheme, "SLH-DSA-SHA2-128s");
    assert_eq!(signed.timestamp, 1706745800);
}

#[test]
fn test_serializable_keypair_from_keypair_succeeds() {
    let keypair = create_test_keypair(b"public".to_vec(), b"private".to_vec());

    let serializable = SerializableKeyPair::from(&keypair);

    assert_eq!(serializable.public_key(), BASE64_ENGINE.encode(b"public"));
    assert_eq!(serializable.private_key(), BASE64_ENGINE.encode(b"private"));
}

#[test]
fn test_keypair_from_serializable_succeeds() {
    let serializable =
        SerializableKeyPair::new(BASE64_ENGINE.encode(b"public"), BASE64_ENGINE.encode(b"private"));

    let keypair: KeyPair = serializable.try_into().expect("conversion should succeed");

    assert_eq!(keypair.public_key().as_slice(), b"public");
    assert_eq!(keypair.private_key().expose_secret(), b"private");
}

// ============================================================================
// Cross-Format Compatibility Tests
// ============================================================================

#[test]
fn test_signed_data_manual_json_parsing_succeeds() {
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
fn test_signed_data_utf8_message_roundtrip_succeeds() {
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
fn test_keypair_all_zero_keys_roundtrip_succeeds() {
    let zero_pk = vec![0x00; 100];
    let zero_sk = vec![0x00; 200];
    let keypair = create_test_keypair(zero_pk.clone(), zero_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key().as_slice(), zero_pk.as_slice());
    assert_eq!(deserialized.private_key().expose_secret(), zero_sk.as_slice());
}

#[test]
fn test_keypair_all_ff_keys_roundtrip_succeeds() {
    let ff_pk = vec![0xFF; 100];
    let ff_sk = vec![0xFF; 200];
    let keypair = create_test_keypair(ff_pk.clone(), ff_sk.clone());

    let json = serialize_keypair(&keypair).expect("serialization should succeed");
    let deserialized = deserialize_keypair(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.public_key().as_slice(), ff_pk.as_slice());
    assert_eq!(deserialized.private_key().expose_secret(), ff_sk.as_slice());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_signed_data_very_long_algorithm_name_roundtrip_succeeds() {
    let mut signed = create_test_signed_data(
        b"data".to_vec(),
        b"sig".to_vec(),
        b"pk".to_vec(),
        Some("key-402".to_string()),
    );
    // S4: `signature_algorithm == scheme` is enforced on
    // deserialize. Update both halves so the roundtrip exercises a
    // long-but-consistent algorithm name.
    let long_name = "B".repeat(500);
    signed.metadata.signature_algorithm = long_name.clone();
    signed.scheme = long_name;

    let json = serialize_signed_data(&signed).expect("serialization should succeed");
    let deserialized = deserialize_signed_data(&json).expect("deserialization should succeed");

    assert_eq!(deserialized.metadata.signature_algorithm.len(), 500);
}

#[test]
fn test_signed_data_zero_timestamp_roundtrip_succeeds() {
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

// ============================================================================
// EncryptedOutput round-trip — `to_json` / `from_json` and `to_bytes` /
// `from_bytes` ergonomic methods (audit-batch fix #11).
//
// The original free-function path (`serialize_encrypted_output` /
// `deserialize_encrypted_output`) has its own roundtrip coverage in
// `latticearc/src/unified_api/serialization.rs`. This file pins the
// inherent-method shape so the convenience contract stays honest.
// ============================================================================

mod encrypted_output_roundtrip {
    use latticearc::unified_api::crypto_types::{
        EncryptedOutput, EncryptionScheme, HybridComponents,
    };
    use proptest::prelude::*;

    fn arb_aes_gcm_output() -> impl Strategy<Value = EncryptedOutput> {
        // AES-256-GCM wire format on the unified API surface packs
        // `nonce(12) || actual_ct || tag(16)` into the `ciphertext`
        // field AND duplicates `nonce` / `tag` into the top-level
        // fields. The TryFrom path enforces those duplicates match
        // the embedded copies (M5 consistency check), so the proptest
        // generator must produce data that satisfies the same
        // invariant — generating independent random `ct` / `nonce` /
        // `tag` would never pass deserialize.
        (
            proptest::collection::vec(any::<u8>(), 0usize..512), // inner ct
            proptest::collection::vec(any::<u8>(), 12usize..=12),
            proptest::collection::vec(any::<u8>(), 16usize..=16),
            any::<u64>(),
            proptest::option::of("[A-Za-z0-9_-]{1,32}"),
        )
            .prop_map(|(inner_ct, nonce, tag, ts, key_id)| {
                let mut ct = Vec::with_capacity(nonce.len() + inner_ct.len() + tag.len());
                ct.extend_from_slice(&nonce);
                ct.extend_from_slice(&inner_ct);
                ct.extend_from_slice(&tag);
                EncryptedOutput::new(EncryptionScheme::Aes256Gcm, ct, nonce, tag, None, ts, key_id)
                    .expect("Aes256Gcm + None hybrid_data is always a valid shape")
            })
    }

    fn arb_hybrid_output() -> impl Strategy<Value = EncryptedOutput> {
        (
            proptest::collection::vec(any::<u8>(), 0usize..512),
            proptest::collection::vec(any::<u8>(), 12usize..=12),
            proptest::collection::vec(any::<u8>(), 16usize..=16),
            proptest::collection::vec(any::<u8>(), 1088usize..=1088),
            proptest::collection::vec(any::<u8>(), 32usize..=32),
            any::<u64>(),
            proptest::option::of("[A-Za-z0-9_-]{1,32}"),
        )
            .prop_map(|(ct, nonce, tag, ml_kem_ct, ecdh_pk, ts, key_id)| {
                let hybrid = HybridComponents::new(ml_kem_ct, ecdh_pk);
                EncryptedOutput::new(
                    EncryptionScheme::HybridMlKem768Aes256Gcm,
                    ct,
                    nonce,
                    tag,
                    Some(hybrid),
                    ts,
                    key_id,
                )
                .expect("HybridMlKem768Aes256Gcm + populated hybrid_data is a valid shape")
            })
    }

    proptest! {
        // Pattern 15 mandates 1000 cases for roundtrip
        // properties. EncryptedOutput JSON+CBOR roundtrip is fast
        // (microseconds per case), so 1000 cases is ~tens of ms overhead
        // — worth it for ser/deser symmetry that protocol implementations
        // depend on.
        #![proptest_config(ProptestConfig::with_cases(1000))]

        /// Round-trip via the JSON-string inherent methods preserves equality
        /// for any well-formed AES-GCM `EncryptedOutput`.
        #[test]
        fn aes_gcm_json_roundtrip_preserves_equality(out in arb_aes_gcm_output()) {
            let s = out.to_json().expect("to_json must succeed");
            let parsed = EncryptedOutput::from_json(&s).expect("from_json must succeed");
            prop_assert_eq!(out, parsed);
        }

        /// Round-trip via the byte-string inherent methods (currently
        /// JSON-as-bytes per the audit-batch doc) preserves
        /// equality for any well-formed AES-GCM `EncryptedOutput`.
        #[test]
        fn aes_gcm_bytes_roundtrip_preserves_equality(out in arb_aes_gcm_output()) {
            let bytes = out.to_bytes().expect("to_bytes must succeed");
            let parsed = EncryptedOutput::from_bytes(&bytes).expect("from_bytes must succeed");
            prop_assert_eq!(out, parsed);
        }

        /// Round-trip via the byte-string methods works for the hybrid
        /// shape (HybridComponents present) too.
        #[test]
        fn hybrid_bytes_roundtrip_preserves_equality(out in arb_hybrid_output()) {
            let bytes = out.to_bytes().expect("to_bytes must succeed");
            let parsed = EncryptedOutput::from_bytes(&bytes).expect("from_bytes must succeed");
            prop_assert_eq!(out, parsed);
        }
    }

    #[test]
    fn from_bytes_rejects_non_utf8_input() {
        // 0xFF is not valid UTF-8 leading byte
        let bad = vec![0xFFu8, 0xFE, 0xFD];
        let err = EncryptedOutput::from_bytes(&bad).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("UTF-8") || msg.contains("Invalid") || msg.contains("Serialization"),
            "from_bytes(non-UTF-8) should surface a serialization-class error, got: {msg}"
        );
    }

    #[test]
    fn from_json_rejects_invalid_json() {
        let err = EncryptedOutput::from_json("not json").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Invalid") || msg.contains("Serialization") || msg.contains("expected"),
            "from_json(invalid) should surface a parse error, got: {msg}"
        );
    }
}
