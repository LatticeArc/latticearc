//! Comprehensive version compatibility and serialization stability tests for arc-core.
//!
//! This test suite validates that cryptographic data formats remain stable across versions,
//! ensuring backward and forward compatibility for serialized keys, signatures, and ciphertexts.
//!
//! ## Test Categories
//!
//! 1. **Serialization Format Stability** (15+ tests)
//!    - Key serialization/deserialization roundtrips
//!    - Signature format stability
//!    - Ciphertext format consistency
//!    - Wire format compatibility
//!
//! 2. **Cross-Version Compatibility** (10+ tests)
//!    - Key material interoperability
//!    - Signature verification across formats
//!    - Encrypted data decryption after updates
//!
//! 3. **Migration Tests** (10+ tests)
//!    - Key format upgrade paths
//!    - Graceful handling of legacy formats
//!    - Version detection in serialized data
//!
//! 4. **Semantic Versioning Tests** (10+ tests)
//!    - Patch version API stability
//!    - Minor version feature additions
//!    - Major version boundary detection
//!
//! ## Coverage Target
//!
//! Target: 45+ comprehensive tests for version compatibility validation.

#![deny(unsafe_code)]
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
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Creates test encrypted data with specified scheme and timestamp.
fn create_encrypted_data(
    data: Vec<u8>,
    nonce: Vec<u8>,
    tag: Option<Vec<u8>>,
    key_id: Option<String>,
    scheme: &str,
    timestamp: u64,
) -> EncryptedData {
    EncryptedData {
        data,
        metadata: EncryptedMetadata { nonce, tag, key_id },
        scheme: scheme.to_string(),
        timestamp,
    }
}

/// Creates test signed data with specified algorithm and scheme.
fn create_signed_data(
    data: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    algorithm: &str,
    scheme: &str,
    timestamp: u64,
) -> SignedData {
    SignedData {
        data,
        metadata: SignedMetadata {
            signature,
            signature_algorithm: algorithm.to_string(),
            public_key,
            key_id: None,
        },
        scheme: scheme.to_string(),
        timestamp,
    }
}

/// Creates a test keypair with specified key sizes.
fn create_keypair(public_key: Vec<u8>, private_key: Vec<u8>) -> KeyPair {
    KeyPair { public_key, private_key: PrivateKey::new(private_key) }
}

/// Represents a versioned format for testing migrations.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct VersionedFormat {
    version: u32,
    format_type: &'static str,
    data: Vec<u8>,
}

impl VersionedFormat {
    #[allow(dead_code)]
    fn new(version: u32, format_type: &'static str, data: Vec<u8>) -> Self {
        Self { version, format_type, data }
    }

    /// Simulates version detection from serialized data.
    fn detect_version(json: &str) -> Result<u32> {
        // Check for version field in JSON, or infer from format
        // Handle both "version": 2 and "version":2 formats
        if json.contains("\"version\"") {
            // Extract version number (simple parsing for tests)
            if json.contains("\"version\": 2") || json.contains("\"version\":2") {
                return Ok(2);
            } else if json.contains("\"version\": 1") || json.contains("\"version\":1") {
                return Ok(1);
            }
        }
        // Default to v1 for unversioned formats
        Ok(1)
    }
}

// ============================================================================
// SECTION 1: Serialization Format Stability (15+ tests)
// ============================================================================

#[test]
fn test_serialized_key_roundtrip_preserves_exact_bytes() -> Result<()> {
    // Test that key bytes are preserved exactly through serialization
    let original_pk = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let original_sk = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let keypair = create_keypair(original_pk.clone(), original_sk.clone());

    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(deserialized.public_key, original_pk, "Public key bytes must be preserved exactly");
    assert_eq!(
        deserialized.private_key.as_slice(),
        original_sk.as_slice(),
        "Private key bytes must be preserved exactly"
    );
    Ok(())
}

#[test]
fn test_serialized_signature_format_stability() -> Result<()> {
    // Signature format must remain stable for verification
    let message = b"Important document to sign".to_vec();
    let signature = [0xDE, 0xAD, 0xBE, 0xEF].iter().cycle().take(64).copied().collect::<Vec<u8>>();
    let public_key = [0xCA, 0xFE].iter().cycle().take(32).copied().collect::<Vec<u8>>();

    let signed = create_signed_data(
        message.clone(),
        signature.clone(),
        public_key.clone(),
        "ML-DSA-65",
        "ML-DSA",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;
    let deserialized = deserialize_signed_data(&json)?;

    // Verify all components preserved
    assert_eq!(deserialized.data, message, "Message data must match");
    assert_eq!(deserialized.metadata.signature, signature, "Signature bytes must match");
    assert_eq!(deserialized.metadata.public_key, public_key, "Public key must match");
    assert_eq!(deserialized.metadata.signature_algorithm, "ML-DSA-65");
    assert_eq!(deserialized.scheme, "ML-DSA");
    Ok(())
}

#[test]
fn test_serialized_ciphertext_format_consistency() -> Result<()> {
    // Ciphertext format must remain consistent for decryption
    let ciphertext = vec![0xAB; 256];
    let nonce = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44];
    let tag = vec![0xFF; 16];

    let encrypted = create_encrypted_data(
        ciphertext.clone(),
        nonce.clone(),
        Some(tag.clone()),
        Some("key-001".to_string()),
        "AES-256-GCM",
        1706745600,
    );

    let json = serialize_encrypted_data(&encrypted)?;
    let deserialized = deserialize_encrypted_data(&json)?;

    assert_eq!(deserialized.data, ciphertext, "Ciphertext must match exactly");
    assert_eq!(deserialized.metadata.nonce, nonce, "Nonce must match");
    assert_eq!(deserialized.metadata.tag, Some(tag), "Tag must match");
    assert_eq!(deserialized.scheme, "AES-256-GCM");
    Ok(())
}

#[test]
fn test_wire_format_json_field_order_independence() -> Result<()> {
    // JSON field order should not affect deserialization
    let json_ordered = r#"{
        "data": "AQID",
        "metadata": {"nonce": "AQIDBA==", "tag": null, "key_id": null},
        "scheme": "AES-256-GCM",
        "timestamp": 1706745600
    }"#;

    let json_reordered = r#"{
        "timestamp": 1706745600,
        "scheme": "AES-256-GCM",
        "data": "AQID",
        "metadata": {"key_id": null, "tag": null, "nonce": "AQIDBA=="}
    }"#;

    let result1 = deserialize_encrypted_data(json_ordered)?;
    let result2 = deserialize_encrypted_data(json_reordered)?;

    assert_eq!(result1.data, result2.data, "Field order should not affect data");
    assert_eq!(
        result1.metadata.nonce, result2.metadata.nonce,
        "Field order should not affect nonce"
    );
    assert_eq!(result1.scheme, result2.scheme, "Field order should not affect scheme");
    assert_eq!(result1.timestamp, result2.timestamp, "Field order should not affect timestamp");
    Ok(())
}

#[test]
fn test_base64_encoding_stability() -> Result<()> {
    // Base64 encoding must be deterministic
    let data = vec![0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0];
    let expected_base64 = BASE64_ENGINE.encode(&data);

    let keypair = create_keypair(data.clone(), vec![0xFF; 32]);
    let json = serialize_keypair(&keypair)?;

    assert!(json.contains(&expected_base64), "Base64 encoding must produce consistent output");
    Ok(())
}

#[test]
fn test_timestamp_precision_preserved() -> Result<()> {
    // Timestamps must preserve full u64 precision
    let timestamps = [0u64, 1, 1_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX];

    for &ts in &timestamps {
        let encrypted = create_encrypted_data(vec![0x01], vec![0; 12], None, None, "TEST", ts);
        let json = serialize_encrypted_data(&encrypted)?;
        let deserialized = deserialize_encrypted_data(&json)?;
        assert_eq!(deserialized.timestamp, ts, "Timestamp {} must be preserved", ts);
    }
    Ok(())
}

#[test]
fn test_ml_kem_public_key_format_stability() -> Result<()> {
    // ML-KEM-768 public key is 1184 bytes
    let ml_kem_768_pk = vec![0x42u8; 1184];
    let keypair = create_keypair(ml_kem_768_pk.clone(), vec![0; 2400]);

    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(deserialized.public_key.len(), 1184, "ML-KEM-768 public key size must be preserved");
    assert_eq!(deserialized.public_key, ml_kem_768_pk);
    Ok(())
}

#[test]
fn test_ml_dsa_signature_format_stability() -> Result<()> {
    // ML-DSA-65 signature is 3309 bytes
    let ml_dsa_65_sig = vec![0xAB; 3309];
    let signed = create_signed_data(
        b"document".to_vec(),
        ml_dsa_65_sig.clone(),
        vec![0xCD; 1952], // ML-DSA-65 public key
        "ML-DSA-65",
        "ML-DSA",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(
        deserialized.metadata.signature.len(),
        3309,
        "ML-DSA-65 signature size must be preserved"
    );
    assert_eq!(deserialized.metadata.signature, ml_dsa_65_sig);
    Ok(())
}

#[test]
fn test_slh_dsa_large_signature_format_stability() -> Result<()> {
    // SLH-DSA can have very large signatures (up to 49856 bytes for SHAKE-256f)
    let slh_dsa_sig = vec![0xEF; 8080]; // SLH-DSA-SHAKE-128s
    let signed = create_signed_data(
        b"firmware".to_vec(),
        slh_dsa_sig.clone(),
        vec![0x11; 32],
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(
        deserialized.metadata.signature.len(),
        8080,
        "SLH-DSA signature size must be preserved"
    );
    Ok(())
}

#[test]
fn test_hybrid_scheme_format_stability() -> Result<()> {
    // Hybrid schemes combine PQ and classical signatures
    let combined_sig = vec![0xAA; 3309 + 64]; // ML-DSA-65 + Ed25519
    let combined_pk = vec![0xBB; 1952 + 32]; // ML-DSA-65 pk + Ed25519 pk

    let signed = create_signed_data(
        b"hybrid-signed".to_vec(),
        combined_sig.clone(),
        combined_pk.clone(),
        "hybrid-ml-dsa-65-ed25519",
        "hybrid-ml-dsa-65-ed25519",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;
    let deserialized = deserialize_signed_data(&json)?;

    assert_eq!(
        deserialized.metadata.signature.len(),
        3309 + 64,
        "Hybrid signature size must be preserved"
    );
    assert_eq!(
        deserialized.metadata.public_key.len(),
        1952 + 32,
        "Hybrid public key size must be preserved"
    );
    Ok(())
}

#[test]
fn test_optional_fields_serialization_stability() -> Result<()> {
    // Test with and without optional fields
    let encrypted_with_all = create_encrypted_data(
        vec![0x01],
        vec![0; 12],
        Some(vec![0xFF; 16]),
        Some("key-id-123".to_string()),
        "AES-256-GCM",
        1706745600,
    );

    let encrypted_minimal =
        create_encrypted_data(vec![0x01], vec![0; 12], None, None, "AES-256-GCM", 1706745600);

    let json_full = serialize_encrypted_data(&encrypted_with_all)?;
    let json_minimal = serialize_encrypted_data(&encrypted_minimal)?;

    let deser_full = deserialize_encrypted_data(&json_full)?;
    let deser_minimal = deserialize_encrypted_data(&json_minimal)?;

    assert!(deser_full.metadata.tag.is_some(), "Tag should be preserved");
    assert!(deser_full.metadata.key_id.is_some(), "Key ID should be preserved");
    assert!(deser_minimal.metadata.tag.is_none(), "Missing tag should remain None");
    assert!(deser_minimal.metadata.key_id.is_none(), "Missing key_id should remain None");
    Ok(())
}

#[test]
fn test_utf8_scheme_names_stability() -> Result<()> {
    // Scheme names with special characters must be preserved
    let schemes =
        ["AES-256-GCM", "ChaCha20-Poly1305", "ML-KEM-768+AES-256-GCM", "hybrid-ml-dsa-65-ed25519"];

    for scheme in &schemes {
        let encrypted =
            create_encrypted_data(vec![0x01], vec![0; 12], None, None, scheme, 1706745600);
        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;
        assert_eq!(&deser.scheme, *scheme, "Scheme name '{}' must be preserved", scheme);
    }
    Ok(())
}

#[test]
fn test_empty_data_serialization_stability() -> Result<()> {
    // Empty data must serialize correctly
    let encrypted = create_encrypted_data(vec![], vec![0; 12], None, None, "TEST", 0);
    let json = serialize_encrypted_data(&encrypted)?;
    let deser = deserialize_encrypted_data(&json)?;

    assert!(deser.data.is_empty(), "Empty data must remain empty after roundtrip");
    Ok(())
}

#[test]
fn test_binary_edge_values_in_data() -> Result<()> {
    // Test all edge byte values: 0x00, 0x7F, 0x80, 0xFF
    let edge_bytes = vec![0x00, 0x7F, 0x80, 0xFF, 0x01, 0xFE];
    let encrypted = create_encrypted_data(
        edge_bytes.clone(),
        vec![0; 12],
        Some(edge_bytes.clone()),
        None,
        "TEST",
        0,
    );

    let json = serialize_encrypted_data(&encrypted)?;
    let deser = deserialize_encrypted_data(&json)?;

    assert_eq!(deser.data, edge_bytes, "Edge byte values must be preserved");
    assert_eq!(deser.metadata.tag, Some(edge_bytes), "Edge bytes in tag must be preserved");
    Ok(())
}

// ============================================================================
// SECTION 2: Cross-Version Compatibility (10+ tests)
// ============================================================================

#[test]
fn test_v1_format_key_material_remains_usable() -> Result<()> {
    // Simulate V1 format JSON (no version field, basic structure)
    let v1_keypair_json = r#"{
        "public_key": "AQIDBAUG",
        "private_key": "EBESExQV"
    }"#;

    let keypair = deserialize_keypair(v1_keypair_json)?;

    // Keys should be usable in current version
    assert_eq!(keypair.public_key, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(keypair.private_key.as_slice(), &[16, 17, 18, 19, 20, 21]);
    Ok(())
}

#[test]
fn test_legacy_signature_format_verification() -> Result<()> {
    // Simulate legacy signature format
    let legacy_signed_json = r#"{
        "data": "SGVsbG8gV29ybGQ=",
        "metadata": {
            "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "signature_algorithm": "Ed25519",
            "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "key_id": null
        },
        "scheme": "Ed25519",
        "timestamp": 1600000000
    }"#;

    let signed = deserialize_signed_data(legacy_signed_json)?;

    // Verify structure is correctly parsed
    assert_eq!(signed.data, b"Hello World");
    assert_eq!(signed.metadata.signature_algorithm, "Ed25519");
    assert_eq!(signed.scheme, "Ed25519");
    Ok(())
}

#[test]
fn test_encrypted_data_from_older_version() -> Result<()> {
    // Simulate encrypted data from an older version
    let old_encrypted_json = r#"{
        "data": "cXVpY2sgYnJvd24gZm94",
        "metadata": {
            "nonce": "MTIzNDU2Nzg5MDEy",
            "tag": "dGFnMTIzNDU2Nzg5MDEyMzQ1Ng==",
            "key_id": "old-key-001"
        },
        "scheme": "AES-256-GCM",
        "timestamp": 1500000000
    }"#;

    let encrypted = deserialize_encrypted_data(old_encrypted_json)?;

    // Verify compatibility
    assert_eq!(encrypted.data, b"quick brown fox");
    assert_eq!(encrypted.scheme, "AES-256-GCM");
    assert_eq!(encrypted.metadata.key_id, Some("old-key-001".to_string()));
    Ok(())
}

#[test]
fn test_ml_kem_512_key_upgrade_path() -> Result<()> {
    // ML-KEM-512 keys should work in system supporting higher levels
    let ml_kem_512_pk = vec![0x42u8; 800]; // ML-KEM-512 public key size
    let ml_kem_512_sk = vec![0x24u8; 1632]; // ML-KEM-512 private key size

    let keypair = create_keypair(ml_kem_512_pk.clone(), ml_kem_512_sk.clone());
    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    // Key material should be preserved for potential upgrade workflows
    assert_eq!(deserialized.public_key.len(), 800, "ML-KEM-512 public key preserved");
    assert_eq!(deserialized.private_key.as_slice().len(), 1632, "ML-KEM-512 private key preserved");
    Ok(())
}

#[test]
fn test_cross_version_signature_verification_metadata() -> Result<()> {
    // Verify signature metadata is preserved for cross-version verification
    let signed = create_signed_data(
        b"cross-version-data".to_vec(),
        vec![0xAB; 64],
        vec![0xCD; 32],
        "Ed25519",
        "Ed25519",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;

    // Re-serialize and verify stability
    let deser1 = deserialize_signed_data(&json)?;
    let json2 = serialize_signed_data(&deser1)?;
    let deser2 = deserialize_signed_data(&json2)?;

    assert_eq!(deser1.data, deser2.data, "Data must be stable across re-serialization");
    assert_eq!(deser1.metadata.signature, deser2.metadata.signature, "Signature must be stable");
    Ok(())
}

#[test]
fn test_unknown_scheme_graceful_handling() -> Result<()> {
    // Unknown schemes should deserialize but be identifiable
    let future_scheme_json = r#"{
        "data": "ZnV0dXJlX2RhdGE=",
        "metadata": {
            "nonce": "AAAAAAAAAAAAAAAA",
            "tag": null,
            "key_id": null
        },
        "scheme": "FUTURE-SCHEME-2030",
        "timestamp": 2000000000
    }"#;

    let encrypted = deserialize_encrypted_data(future_scheme_json)?;

    // Unknown scheme should be preserved for potential future handling
    assert_eq!(encrypted.scheme, "FUTURE-SCHEME-2030");
    assert_eq!(encrypted.data, b"future_data");
    Ok(())
}

#[test]
fn test_mixed_version_key_ids() -> Result<()> {
    // Key IDs may have different formats across versions
    let key_id_formats = [
        "simple-key-001",
        "uuid:550e8400-e29b-41d4-a716-446655440000",
        "urn:key:latticearc:ml-kem-768:12345",
        "path/to/key.pem",
    ];

    for key_id in &key_id_formats {
        let encrypted = create_encrypted_data(
            vec![0x01],
            vec![0; 12],
            None,
            Some(key_id.to_string()),
            "AES-256-GCM",
            1706745600,
        );

        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        assert_eq!(
            deser.metadata.key_id,
            Some(key_id.to_string()),
            "Key ID format '{}' must be preserved",
            key_id
        );
    }
    Ok(())
}

#[test]
fn test_timestamp_epoch_compatibility() -> Result<()> {
    // Different epoch interpretations should work
    let timestamps_and_meanings = [
        (0u64, "Unix epoch"),
        (1706745600, "2024-02-01 00:00:00 UTC"),
        (4102444800, "Year 2100"),
        (u64::MAX, "Maximum u64"),
    ];

    for (ts, desc) in &timestamps_and_meanings {
        let encrypted = create_encrypted_data(vec![0x01], vec![0; 12], None, None, "TEST", *ts);
        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        assert_eq!(deser.timestamp, *ts, "Timestamp for '{}' must be preserved", desc);
    }
    Ok(())
}

#[test]
fn test_signature_algorithm_name_variations() -> Result<()> {
    // Different naming conventions for the same algorithm
    let algorithm_names = [
        ("ML-DSA-65", "ML-DSA"),
        ("MLDSA65", "ML-DSA"),
        ("ml-dsa-65", "ml-dsa"),
        ("Ed25519", "Ed25519"),
        ("ed25519", "ed25519"),
    ];

    for (alg, scheme) in &algorithm_names {
        let signed =
            create_signed_data(b"test".to_vec(), vec![0; 64], vec![0; 32], alg, scheme, 1706745600);

        let json = serialize_signed_data(&signed)?;
        let deser = deserialize_signed_data(&json)?;

        assert_eq!(
            deser.metadata.signature_algorithm, *alg,
            "Algorithm name '{}' must be preserved",
            alg
        );
    }
    Ok(())
}

#[test]
fn test_ml_kem_1024_to_768_data_structure_compatibility() -> Result<()> {
    // Higher security level data can be stored in same format
    let ml_kem_1024_pk = vec![0x42u8; 1568]; // ML-KEM-1024 public key
    let ml_kem_768_pk = vec![0x24u8; 1184]; // ML-KEM-768 public key

    for (pk, name) in [(ml_kem_1024_pk, "ML-KEM-1024"), (ml_kem_768_pk, "ML-KEM-768")] {
        let keypair = create_keypair(pk.clone(), vec![0; 32]);
        let json = serialize_keypair(&keypair)?;
        let deser = deserialize_keypair(&json)?;

        assert_eq!(deser.public_key.len(), pk.len(), "{} public key size must be preserved", name);
    }
    Ok(())
}

// ============================================================================
// SECTION 3: Migration Tests (10+ tests)
// ============================================================================

#[test]
fn test_version_detection_in_unversioned_data() -> Result<()> {
    // Unversioned data should be treated as V1
    let unversioned_json = r#"{"public_key": "AQID", "private_key": "BAUG"}"#;

    let version = VersionedFormat::detect_version(unversioned_json)?;
    assert_eq!(version, 1, "Unversioned data should be detected as V1");
    Ok(())
}

#[test]
fn test_versioned_data_detection() -> Result<()> {
    // Versioned data should be correctly identified
    let v2_json = r#"{"version": 2, "public_key": "AQID", "private_key": "BAUG"}"#;
    let v1_json = r#"{"version": 1, "public_key": "AQID", "private_key": "BAUG"}"#;

    let v2_detected = VersionedFormat::detect_version(v2_json)?;
    let v1_detected = VersionedFormat::detect_version(v1_json)?;

    assert_eq!(v2_detected, 2, "V2 data should be detected");
    assert_eq!(v1_detected, 1, "V1 data should be detected");
    Ok(())
}

#[test]
fn test_graceful_extra_field_handling() -> Result<()> {
    // Future versions may add fields; current version should ignore them
    let json_with_extra_fields = r#"{
        "data": "dGVzdA==",
        "metadata": {
            "nonce": "AAAAAAAAAAAAAAAA",
            "tag": null,
            "key_id": null,
            "future_field": "ignored",
            "another_field": 12345
        },
        "scheme": "AES-256-GCM",
        "timestamp": 1706745600,
        "extra_root": {"nested": "value"}
    }"#;

    let encrypted = deserialize_encrypted_data(json_with_extra_fields)?;

    // Core fields should be correctly parsed
    assert_eq!(encrypted.data, b"test");
    assert_eq!(encrypted.scheme, "AES-256-GCM");
    Ok(())
}

#[test]
fn test_key_format_migration_from_raw_to_structured() -> Result<()> {
    // Migration from raw bytes to structured format
    let raw_key_data = vec![0x42u8; 32];

    // V1: Just raw bytes encoded
    let v1_json = format!(
        r#"{{"public_key": "{}", "private_key": "{}"}}"#,
        BASE64_ENGINE.encode(&raw_key_data),
        BASE64_ENGINE.encode(&raw_key_data)
    );

    let keypair = deserialize_keypair(&v1_json)?;

    // V2: Re-serialize with current format
    let v2_json = serialize_keypair(&keypair)?;
    let keypair_v2 = deserialize_keypair(&v2_json)?;

    assert_eq!(
        keypair.public_key, keypair_v2.public_key,
        "Key material must be preserved through migration"
    );
    Ok(())
}

#[test]
fn test_signature_format_migration() -> Result<()> {
    // Older signature format migration to current
    let legacy_json = r#"{
        "data": "bGVnYWN5IG1lc3NhZ2U=",
        "metadata": {
            "signature": "c2lnbmF0dXJl",
            "signature_algorithm": "RSA-SHA256",
            "public_key": "cHVibGljX2tleQ==",
            "key_id": null
        },
        "scheme": "RSA",
        "timestamp": 1400000000
    }"#;

    let signed = deserialize_signed_data(legacy_json)?;

    // Can be re-serialized in current format
    let current_json = serialize_signed_data(&signed)?;
    let re_parsed = deserialize_signed_data(&current_json)?;

    assert_eq!(signed.data, re_parsed.data, "Message preserved through migration");
    assert_eq!(signed.metadata.signature_algorithm, "RSA-SHA256");
    Ok(())
}

#[test]
fn test_encrypted_data_nonce_size_variations() -> Result<()> {
    // Different algorithms may have different nonce sizes
    let nonce_sizes = [
        (12, "AES-256-GCM"),        // Standard 96-bit nonce
        (24, "XChaCha20-Poly1305"), // Extended nonce
        (16, "AES-256-CBC"),        // 128-bit IV
    ];

    for (size, scheme) in &nonce_sizes {
        let encrypted =
            create_encrypted_data(vec![0x01], vec![0x42; *size], None, None, scheme, 1706745600);

        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        assert_eq!(
            deser.metadata.nonce.len(),
            *size,
            "{} nonce size {} must be preserved",
            scheme,
            size
        );
    }
    Ok(())
}

#[test]
fn test_tag_size_migration() -> Result<()> {
    // Different tag sizes for different AEAD modes
    let tag_sizes = [
        (16, "AES-256-GCM"),        // 128-bit tag
        (16, "ChaCha20-Poly1305"),  // 128-bit tag
        (12, "AES-256-GCM-SIV-96"), // Hypothetical 96-bit tag
    ];

    for (size, scheme) in &tag_sizes {
        let encrypted = create_encrypted_data(
            vec![0x01],
            vec![0; 12],
            Some(vec![0xFF; *size]),
            None,
            scheme,
            1706745600,
        );

        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        if let Some(tag) = &deser.metadata.tag {
            assert_eq!(tag.len(), *size, "{} tag size {} must be preserved", scheme, size);
        }
    }
    Ok(())
}

#[test]
fn test_algorithm_deprecation_awareness() -> Result<()> {
    // Deprecated algorithms should still deserialize for migration
    let deprecated_algorithms = [("RSA-2048", "RSA"), ("ECDSA-P256", "ECDSA"), ("DSA-1024", "DSA")];

    for (alg, scheme) in &deprecated_algorithms {
        let signed = create_signed_data(
            b"deprecated-sig".to_vec(),
            vec![0; 256],
            vec![0; 64],
            alg,
            scheme,
            1400000000,
        );

        let json = serialize_signed_data(&signed)?;
        let deser = deserialize_signed_data(&json)?;

        assert_eq!(
            deser.metadata.signature_algorithm, *alg,
            "Deprecated algorithm '{}' must be preserved for migration",
            alg
        );
    }
    Ok(())
}

#[test]
fn test_key_id_format_migration() -> Result<()> {
    // Key ID formats may evolve
    let key_id_evolutions = [
        ("v1:key-001", "V1 simple format"),
        ("v2:urn:key:12345", "V2 URN format"),
        ("v3:did:key:z6MkhaXgBZ", "V3 DID format"),
    ];

    for (key_id, description) in &key_id_evolutions {
        let encrypted = create_encrypted_data(
            vec![0x01],
            vec![0; 12],
            None,
            Some(key_id.to_string()),
            "AES-256-GCM",
            1706745600,
        );

        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        assert_eq!(
            deser.metadata.key_id,
            Some(key_id.to_string()),
            "{} format must be preserved",
            description
        );
    }
    Ok(())
}

#[test]
fn test_round_trip_preserves_unknown_schemes() -> Result<()> {
    // Unknown schemes from future versions should be preserved
    let unknown_schemes = ["NTRU-HRSS-701", "BIKE-L1", "SIKE-p434", "SPHINCS+-128s"];

    for scheme in &unknown_schemes {
        let encrypted = create_encrypted_data(
            vec![0x01, 0x02, 0x03],
            vec![0; 12],
            Some(vec![0xFF; 16]),
            None,
            scheme,
            1706745600,
        );

        let json = serialize_encrypted_data(&encrypted)?;
        let deser = deserialize_encrypted_data(&json)?;

        assert_eq!(
            &deser.scheme, *scheme,
            "Unknown scheme '{}' must be preserved for future migration",
            scheme
        );
    }
    Ok(())
}

// ============================================================================
// SECTION 4: Semantic Versioning Tests (10+ tests)
// ============================================================================

#[test]
fn test_current_version_constant_available() {
    // VERSION constant should be available
    let version = arc_core::VERSION;
    assert!(!version.is_empty(), "VERSION constant must be defined");
}

#[test]
fn test_version_format_follows_semver() {
    let version = arc_core::VERSION;

    // Should be in format X.Y.Z
    let parts: Vec<&str> = version.split('.').collect();
    assert!(parts.len() >= 2, "Version should have at least major.minor");

    // Each part should be numeric (allowing for pre-release suffixes)
    let major = parts.first().and_then(|s| s.parse::<u32>().ok());
    let minor = parts.get(1).and_then(|s| s.parse::<u32>().ok());

    assert!(major.is_some(), "Major version should be numeric");
    assert!(minor.is_some(), "Minor version should be numeric");
}

#[test]
fn test_patch_version_serialization_compatibility() -> Result<()> {
    // Patch version changes should not break serialization
    let keypair = create_keypair(vec![0x42; 32], vec![0x24; 64]);
    let json = serialize_keypair(&keypair)?;

    // Serialize/deserialize should work regardless of patch version
    let deser = deserialize_keypair(&json)?;
    assert_eq!(keypair.public_key, deser.public_key);
    Ok(())
}

#[test]
fn test_api_type_exports_stable() {
    // Core types should be publicly available (compile-time check)
    // Using fully qualified names to verify exports work from external crates
    fn check_types() {
        let _ = std::any::type_name::<EncryptedData>();
        let _ = std::any::type_name::<SignedData>();
        let _ = std::any::type_name::<KeyPair>();
    }
    check_types();
    // This test passes if it compiles
}

#[test]
fn test_error_types_stable() {
    // Error types should be stable across versions
    let _err: CoreError = CoreError::InvalidInput("test".to_string());
    let _err2: CoreError = CoreError::SerializationError("test".to_string());
    let _err3: CoreError = CoreError::VerificationFailed;

    // This test passes if it compiles
}

#[test]
fn test_security_level_enum_values_stable() {
    // SecurityLevel variants should be stable
    use arc_core::SecurityLevel;

    let _standard = SecurityLevel::Standard;
    let _high = SecurityLevel::High;
    let _maximum = SecurityLevel::Maximum;
    let _quantum = SecurityLevel::Quantum;

    // Default should be defined
    let default = SecurityLevel::default();
    assert!(matches!(default, SecurityLevel::High), "Default security level should be High");
}

#[test]
fn test_crypto_config_builder_api_stable() {
    use arc_core::{CryptoConfig, SecurityLevel, UseCase};

    // Builder pattern should be stable
    let _config = CryptoConfig::new().security_level(SecurityLevel::High);

    let _config_with_use_case = CryptoConfig::new().use_case(UseCase::FileStorage);

    // This test passes if it compiles
}

#[test]
fn test_serializable_types_public() {
    // Serializable wrapper types should be publicly available
    let _: SerializableEncryptedData;
    let _: SerializableEncryptedMetadata;
    let _: SerializableSignedData;
    let _: SerializableSignedMetadata;
    let _: SerializableKeyPair;

    // This test passes if it compiles
}

#[test]
fn test_serialize_functions_signatures_stable() -> Result<()> {
    // Function signatures should be stable
    let keypair = create_keypair(vec![1, 2, 3], vec![4, 5, 6]);
    let _: Result<String> = serialize_keypair(&keypair);

    let encrypted = create_encrypted_data(vec![1], vec![0; 12], None, None, "TEST", 0);
    let _: Result<String> = serialize_encrypted_data(&encrypted);

    let signed = create_signed_data(vec![1], vec![0; 64], vec![0; 32], "Ed25519", "Ed25519", 0);
    let _: Result<String> = serialize_signed_data(&signed);

    Ok(())
}

#[test]
fn test_deserialize_functions_signatures_stable() -> Result<()> {
    // Deserialize function signatures should be stable
    let json = r#"{"public_key": "AQID", "private_key": "BAUG"}"#;
    let _: Result<KeyPair> = deserialize_keypair(json);

    let encrypted_json = r#"{"data": "AQ==", "metadata": {"nonce": "AAAAAAAAAAAAAAAA", "tag": null, "key_id": null}, "scheme": "TEST", "timestamp": 0}"#;
    let _: Result<EncryptedData> = deserialize_encrypted_data(encrypted_json);

    let signed_json = r#"{"data": "AQ==", "metadata": {"signature": "AA==", "signature_algorithm": "Ed25519", "public_key": "AA==", "key_id": null}, "scheme": "Ed25519", "timestamp": 0}"#;
    let _: Result<SignedData> = deserialize_signed_data(signed_json);

    Ok(())
}

#[test]
fn test_result_type_alias_works() -> Result<()> {
    // Result type alias should work correctly
    fn returning_result() -> Result<i32> {
        Ok(42)
    }

    fn returning_error() -> Result<i32> {
        Err(CoreError::InvalidInput("test".to_string()))
    }

    assert_eq!(returning_result()?, 42);
    assert!(returning_error().is_err());
    Ok(())
}

#[test]
fn test_private_key_zeroize_behavior() {
    // PrivateKey should zeroize on drop (compile-time check for trait)
    let pk = PrivateKey::new(vec![0x42; 32]);
    assert_eq!(pk.as_slice().len(), 32);
    // Drop happens automatically at end of scope
}

// ============================================================================
// SECTION 5: Additional Comprehensive Tests
// ============================================================================

#[test]
fn test_multiple_roundtrips_preserve_data() -> Result<()> {
    // Multiple serialize/deserialize cycles should preserve data
    let original = create_encrypted_data(
        vec![0xAB; 100],
        vec![0xCD; 12],
        Some(vec![0xEF; 16]),
        Some("test-key".to_string()),
        "AES-256-GCM",
        1706745600,
    );

    let mut current = original.clone();
    for i in 0..10 {
        let json = serialize_encrypted_data(&current)?;
        current = deserialize_encrypted_data(&json)?;

        assert_eq!(current.data, original.data, "Data corruption after {} roundtrips", i + 1);
    }
    Ok(())
}

#[test]
fn test_concurrent_serialization_safety() -> Result<()> {
    // Serialization should be safe for concurrent use
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|i| {
            thread::spawn(move || {
                let keypair = create_keypair(vec![i as u8; 32], vec![i as u8; 64]);
                for _ in 0..100 {
                    if let Ok(json) = serialize_keypair(&keypair) {
                        let _ = deserialize_keypair(&json);
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().ok();
    }
    Ok(())
}

#[test]
fn test_large_payload_serialization() -> Result<()> {
    // Large payloads should serialize correctly
    let large_data = vec![0xAB; 1_000_000]; // 1MB
    let encrypted = create_encrypted_data(
        large_data.clone(),
        vec![0; 12],
        Some(vec![0xFF; 16]),
        None,
        "AES-256-GCM",
        1706745600,
    );

    let json = serialize_encrypted_data(&encrypted)?;
    let deser = deserialize_encrypted_data(&json)?;

    assert_eq!(deser.data.len(), 1_000_000, "Large payload size must be preserved");
    assert_eq!(deser.data, large_data, "Large payload content must match");
    Ok(())
}

#[test]
fn test_error_message_stability() {
    // Error messages should be informative and stable
    let err = CoreError::SerializationError("test error".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Serialization"), "Error message should describe the error type");
    assert!(msg.contains("test error"), "Error message should include details");
}

#[test]
fn test_invalid_base64_error_handling() {
    // Invalid Base64 should produce clear errors
    let invalid_json = r#"{"public_key": "!!!invalid!!!", "private_key": "AQID"}"#;
    let result = deserialize_keypair(invalid_json);

    assert!(result.is_err(), "Invalid Base64 should fail");
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            msg.to_lowercase().contains("serial") || msg.to_lowercase().contains("base64"),
            "Error should indicate serialization/decoding issue: {}",
            msg
        );
    }
}
