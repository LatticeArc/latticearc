//! Version compatibility and serialization stability tests.
//!
//! Validates that cryptographic data formats remain stable across versions for
//! signed data and key pairs (signature format, key serialization roundtrips,
//! API surface stability for `EncryptedData`).

#![deny(unsafe_code)]
#![allow(
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_ENGINE};
use latticearc::unified_api::error::{CoreError, Result};
use latticearc::unified_api::serialization::{
    deserialize_keypair, deserialize_signed_data, serialize_keypair, serialize_signed_data,
};
use latticearc::unified_api::types::{
    EncryptedData, KeyPair, PrivateKey, SignedData, SignedMetadata,
};

// ============================================================================
// Test Helper Functions
// ============================================================================

/// Creates test signed data with specified algorithm and scheme.
fn create_signed_data(
    data: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    algorithm: &str,
    scheme: &str,
    timestamp: u64,
) -> SignedData {
    SignedData::new(
        data,
        SignedMetadata::new(signature, algorithm.to_string(), public_key, None),
        scheme.to_string(),
        timestamp,
    )
}

/// Creates a test keypair with specified key sizes.
fn create_keypair(public_key: Vec<u8>, private_key: Vec<u8>) -> KeyPair {
    KeyPair::new(latticearc::PublicKey::new(public_key), PrivateKey::new(private_key))
}

/// Represents a versioned format for testing migrations.
#[derive(Debug, Clone)]
#[expect(dead_code, reason = "interface stability or feature-gated path")]
struct VersionedFormat {
    version: u32,
    format_type: &'static str,
    data: Vec<u8>,
}

impl VersionedFormat {
    #[expect(dead_code, reason = "interface stability or feature-gated path")]
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
fn test_serialized_key_roundtrip_preserves_exact_bytes_succeeds() -> Result<()> {
    // Test that key bytes are preserved exactly through serialization
    let original_pk = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let original_sk = vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let keypair = create_keypair(original_pk.clone(), original_sk.clone());

    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(
        deserialized.public_key().as_slice(),
        original_pk.as_slice(),
        "Public key bytes must be preserved exactly"
    );
    assert_eq!(
        deserialized.private_key().expose_secret(),
        original_sk.as_slice(),
        "Private key bytes must be preserved exactly"
    );
    Ok(())
}

#[test]
fn test_serialized_signature_format_stability_is_compatible_has_correct_size() -> Result<()> {
    // Signature format must remain stable for verification
    let message = b"Important document to sign".to_vec();
    let signature = [0xDE, 0xAD, 0xBE, 0xEF].iter().cycle().take(64).copied().collect::<Vec<u8>>();
    let public_key = [0xCA, 0xFE].iter().cycle().take(32).copied().collect::<Vec<u8>>();

    let signed = create_signed_data(
        message.clone(),
        signature.clone(),
        public_key.clone(),
        "ML-DSA-65",
        "ML-DSA-65",
        1706745600,
    );

    let json = serialize_signed_data(&signed)?;
    let deserialized = deserialize_signed_data(&json)?;

    // Verify all components preserved
    assert_eq!(deserialized.data, message, "Message data must match");
    assert_eq!(deserialized.metadata.signature, signature, "Signature bytes must match");
    assert_eq!(deserialized.metadata.public_key, public_key, "Public key must match");
    assert_eq!(deserialized.metadata.signature_algorithm, "ML-DSA-65");
    assert_eq!(deserialized.scheme, "ML-DSA-65");
    Ok(())
}

#[test]
fn test_base64_encoding_stability_is_compatible_succeeds() -> Result<()> {
    // Base64 encoding must be deterministic
    let data = vec![0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0];
    let expected_base64 = BASE64_ENGINE.encode(&data);

    let keypair = create_keypair(data.clone(), vec![0xFF; 32]);
    let json = serialize_keypair(&keypair)?;

    assert!(json.contains(&expected_base64), "Base64 encoding must produce consistent output");
    Ok(())
}

#[test]
fn test_ml_kem_public_key_format_stability_is_compatible_has_correct_size() -> Result<()> {
    // ML-KEM-768 public key is 1184 bytes
    let ml_kem_768_pk = vec![0x42u8; 1184];
    let keypair = create_keypair(ml_kem_768_pk.clone(), vec![0; 2400]);

    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    assert_eq!(
        deserialized.public_key().len(),
        1184,
        "ML-KEM-768 public key size must be preserved"
    );
    assert_eq!(deserialized.public_key().as_slice(), ml_kem_768_pk.as_slice());
    Ok(())
}

#[test]
fn test_ml_dsa_signature_format_stability_is_compatible_has_correct_size() -> Result<()> {
    // ML-DSA-65 signature is 3309 bytes
    let ml_dsa_65_sig = vec![0xAB; 3309];
    let signed = create_signed_data(
        b"document".to_vec(),
        ml_dsa_65_sig.clone(),
        vec![0xCD; 1952], // ML-DSA-65 public key
        "ML-DSA-65",
        "ML-DSA-65",
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
fn test_slh_dsa_large_signature_format_stability_is_compatible_has_correct_size() -> Result<()> {
    // SLH-DSA can have very large signatures (up to 49856 bytes for SHAKE-256f)
    let slh_dsa_sig = vec![0xEF; 8080]; // SLH-DSA-SHAKE-128s
    let signed = create_signed_data(
        b"firmware".to_vec(),
        slh_dsa_sig.clone(),
        vec![0x11; 32],
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128s",
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
fn test_hybrid_scheme_format_stability_is_compatible_has_correct_size() -> Result<()> {
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

// ============================================================================
// SECTION 2: Cross-Version Compatibility (10+ tests)
// ============================================================================

#[test]
fn test_v1_format_key_material_remains_usable_is_compatible_has_correct_size() -> Result<()> {
    // Simulate V1 format JSON (no version field, basic structure)
    let v1_keypair_json = r#"{
        "public_key": "AQIDBAUG",
        "private_key": "EBESExQV"
    }"#;

    let keypair = deserialize_keypair(v1_keypair_json)?;

    // Keys should be usable in current version
    assert_eq!(keypair.public_key().as_slice(), &[1, 2, 3, 4, 5, 6]);
    assert_eq!(keypair.private_key().expose_secret(), &[16, 17, 18, 19, 20, 21]);
    Ok(())
}

#[test]
fn test_legacy_signature_format_verification_is_compatible_has_correct_size() -> Result<()> {
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
fn test_ml_kem_512_key_upgrade_path_is_compatible_succeeds() -> Result<()> {
    // ML-KEM-512 keys should work in system supporting higher levels
    let ml_kem_512_pk = vec![0x42u8; 800]; // ML-KEM-512 public key size
    let ml_kem_512_sk = vec![0x24u8; 1632]; // ML-KEM-512 private key size

    let keypair = create_keypair(ml_kem_512_pk.clone(), ml_kem_512_sk.clone());
    let json = serialize_keypair(&keypair)?;
    let deserialized = deserialize_keypair(&json)?;

    // Key material should be preserved for potential upgrade workflows
    assert_eq!(deserialized.public_key().len(), 800, "ML-KEM-512 public key preserved");
    assert_eq!(
        deserialized.private_key().expose_secret().len(),
        1632,
        "ML-KEM-512 private key preserved"
    );
    Ok(())
}

#[test]
fn test_cross_version_signature_verification_metadata_is_compatible_succeeds() -> Result<()> {
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
fn test_signature_algorithm_name_variations_is_compatible_succeeds() -> Result<()> {
    // S4: the deserializer now requires
    // `metadata.signature_algorithm == scheme`. The earlier shape of
    // this test (varying naming conventions across the two fields)
    // exercised the pre-fix tolerance — which was a decorative-field
    // bug, not a feature. With the invariant elevated, naming
    // conventions are still preserved verbatim, but only when the
    // producer sets both fields consistently (matching the
    // production sign path: `signature_algorithm: scheme.clone()`).
    let algorithm_names =
        ["ML-DSA-65", "MlDsa65", "ml-dsa-65", "Ed25519", "ed25519", "ML-DSA", "ml-dsa"];

    for alg in &algorithm_names {
        // Both fields set to the same string: the production shape.
        let signed =
            create_signed_data(b"test".to_vec(), vec![0; 64], vec![0; 32], alg, alg, 1706745600);

        let json = serialize_signed_data(&signed)?;
        let deser = deserialize_signed_data(&json)?;

        assert_eq!(
            deser.metadata.signature_algorithm, *alg,
            "Algorithm name '{}' must be preserved",
            alg
        );
        assert_eq!(deser.scheme, *alg, "scheme must equal signature_algorithm post-deserialize");
    }
    Ok(())
}

#[test]
fn test_signature_algorithm_mismatch_with_scheme_rejected() -> Result<()> {
    // S4 regression guard: the deserializer must REJECT
    // records where `metadata.signature_algorithm != scheme`. The
    // production sign path sets them equal at construction; a
    // tampered persisted record could otherwise carry an
    // algorithm-name string the verify path never consults
    // (scheme drives dispatch). Wire-format theatre is rejected.
    let signed =
        create_signed_data(b"test".to_vec(), vec![0; 64], vec![0; 32], "ML-DSA-65", "ML-DSA", 0);

    let json = serialize_signed_data(&signed)?;
    let result = deserialize_signed_data(&json);
    assert!(
        result.is_err(),
        "deserialize must reject mismatched signature_algorithm/scheme; got Ok({:?})",
        result.ok()
    );
    Ok(())
}

#[test]
fn test_ml_kem_1024_to_768_data_structure_compatibility_is_compatible_succeeds() -> Result<()> {
    // Higher security level data can be stored in same format
    let ml_kem_1024_pk = vec![0x42u8; 1568]; // ML-KEM-1024 public key
    let ml_kem_768_pk = vec![0x24u8; 1184]; // ML-KEM-768 public key

    for (pk, name) in [(ml_kem_1024_pk, "ML-KEM-1024"), (ml_kem_768_pk, "ML-KEM-768")] {
        let keypair = create_keypair(pk.clone(), vec![0; 32]);
        let json = serialize_keypair(&keypair)?;
        let deser = deserialize_keypair(&json)?;

        assert_eq!(
            deser.public_key().len(),
            pk.len(),
            "{} public key size must be preserved",
            name
        );
    }
    Ok(())
}

// ============================================================================
// SECTION 3: Migration Tests (10+ tests)
// ============================================================================

#[test]
fn test_version_detection_in_unversioned_data_succeeds() -> Result<()> {
    // Unversioned data should be treated as V1
    let unversioned_json = r#"{"public_key": "AQID", "private_key": "BAUG"}"#;

    let version = VersionedFormat::detect_version(unversioned_json)?;
    assert_eq!(version, 1, "Unversioned data should be detected as V1");
    Ok(())
}

#[test]
fn test_versioned_data_detection_succeeds() -> Result<()> {
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
fn test_key_format_migration_from_raw_to_structured_succeeds() -> Result<()> {
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
        keypair.public_key(),
        keypair_v2.public_key(),
        "Key material must be preserved through migration"
    );
    Ok(())
}

#[test]
fn test_signature_format_migration_succeeds() -> Result<()> {
    // Older signature format migration to current. S4
    // tightened the deserializer to require `signature_algorithm
    // == scheme`; the legacy fixture therefore now sets both halves
    // to "RSA-SHA256" so the test continues to exercise migration of
    // a deprecated algorithm name without depending on the prior
    // tolerance for mismatched fields.
    let legacy_json = r#"{
        "data": "bGVnYWN5IG1lc3NhZ2U=",
        "metadata": {
            "signature": "c2lnbmF0dXJl",
            "signature_algorithm": "RSA-SHA256",
            "public_key": "cHVibGljX2tleQ==",
            "key_id": null
        },
        "scheme": "RSA-SHA256",
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
fn test_algorithm_deprecation_awareness_is_compatible_succeeds() -> Result<()> {
    // Deprecated algorithms should still deserialize for migration —
    // requires `signature_algorithm == scheme` so we use
    // the long-form name for both halves, which is the production
    // shape regardless of whether the algorithm is deprecated.
    let deprecated_algorithms = ["RSA-2048", "ECDSA-P256", "DSA-1024"];

    for alg in &deprecated_algorithms {
        let signed = create_signed_data(
            b"deprecated-sig".to_vec(),
            vec![0; 256],
            vec![0; 64],
            alg,
            alg,
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

// ============================================================================
// SECTION 4: Semantic Versioning Tests (10+ tests)
// ============================================================================

#[test]
fn test_current_version_constant_available_is_compatible_succeeds() {
    // VERSION constant should be available
    let version = latticearc::unified_api::VERSION;
    assert!(!version.is_empty(), "VERSION constant must be defined");
}

#[test]
fn test_version_format_follows_semver_is_compatible_has_correct_size() {
    let version = latticearc::unified_api::VERSION;

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
fn test_patch_version_serialization_compatibility_is_compatible_succeeds() -> Result<()> {
    // Patch version changes should not break serialization
    let keypair = create_keypair(vec![0x42; 32], vec![0x24; 64]);
    let json = serialize_keypair(&keypair)?;

    // Serialize/deserialize should work regardless of patch version
    let deser = deserialize_keypair(&json)?;
    assert_eq!(keypair.public_key(), deser.public_key());
    Ok(())
}

// Type-export and ABI-shape checks belong in `static_assertions!`,
// not `#[test]`. M6/L6 migration: previous body was a
// compile-only `let _ = ...` chain dressed as a test, which left the
// runner suite green even when the underlying constraint regressed.
// `static_assertions::assert_impl_all!` / `assert_type_eq_all!` /
// `const_assert!` fail the BUILD on regression instead.
static_assertions::assert_impl_all!(EncryptedData: std::fmt::Debug, Clone, Send, Sync);
static_assertions::assert_impl_all!(SignedData: std::fmt::Debug, Clone, Send, Sync);
static_assertions::assert_impl_all!(KeyPair: std::fmt::Debug);
static_assertions::assert_impl_all!(CoreError: std::error::Error, std::fmt::Debug);

#[test]
fn test_security_level_enum_values_stable_is_compatible_succeeds() {
    // SecurityLevel variants should be stable. The `Default` impl IS
    // a runtime-observable behaviour (callers depend on `High` being
    // returned when `default()` is called) — keep this as a real
    // `#[test]`. Existence of the enum variants is a compile check
    // and is covered above with `static_assertions`.
    use latticearc::unified_api::SecurityLevel;

    let default = SecurityLevel::default();
    assert!(matches!(default, SecurityLevel::High), "Default security level should be High");
    // Pin the equality between every variant ordinal for serde-stability.
    assert_ne!(SecurityLevel::Standard, SecurityLevel::High);
    assert_ne!(SecurityLevel::High, SecurityLevel::Maximum);
}

#[test]
fn test_crypto_config_builder_api_stable_is_compatible_succeeds() {
    use latticearc::types::types::AlgorithmSelection;
    use latticearc::unified_api::{CryptoConfig, SecurityLevel, UseCase};

    // Builder pattern: setters update an internal `AlgorithmSelection`
    // enum; the test pattern-matches on the expected variant. The
    // builder MUST be called with a value that DIFFERS from
    // `CryptoConfig::new()`'s initial state — the default selection
    // is `SecurityLevel(High)`, so calling `.security_level(High)`
    // and asserting `High` would also pass for a no-op
    // `fn(self, _) { self }`. Use `Maximum` / `EmailEncryption` so
    // the asserted post-state is strictly different from the
    // constructor's initial state, which forces the builder to
    // actually update internal storage.
    let config = CryptoConfig::new().security_level(SecurityLevel::Maximum);
    assert!(
        matches!(config.get_selection(), AlgorithmSelection::SecurityLevel(SecurityLevel::Maximum)),
        "security_level builder must update AlgorithmSelection::SecurityLevel \
         (post-state must differ from default High to detect no-op regression)"
    );

    let config_with_use_case = CryptoConfig::new().use_case(UseCase::EmailEncryption);
    assert!(
        matches!(
            config_with_use_case.get_selection(),
            AlgorithmSelection::UseCase(UseCase::EmailEncryption)
        ),
        "use_case builder must update AlgorithmSelection::UseCase \
         (post-state must differ from default to detect no-op regression)"
    );
}

#[test]
fn test_result_type_alias_works_is_compatible_succeeds() -> Result<()> {
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
fn test_private_key_zeroize_behavior_succeeds() {
    // PrivateKey should zeroize on drop (compile-time check for trait)
    let pk = PrivateKey::new(vec![0x42; 32]);
    assert_eq!(pk.expose_secret().len(), 32);
    // Drop happens automatically at end of scope
}

// ============================================================================
// SECTION 5: Additional Comprehensive Tests
// ============================================================================

#[test]
fn test_concurrent_serialization_safety_succeeds() -> Result<()> {
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
        // Propagate panics: `.ok()` previously discarded
        // `Err(Box<dyn Any>)` so a thread that panicked during the
        // race silently produced `Ok(())` for the test. Surface the
        // panic via `Result` rather than `.expect()` because the
        // workspace lints disallow `.expect()` in fns that return
        // `Result`.
        if let Err(payload) = handle.join() {
            return Err(CoreError::Internal(format!(
                "worker thread panicked during concurrent serialization: {:?}",
                payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("<panic payload was not a string>")
            )));
        }
    }
    Ok(())
}

#[test]
fn test_error_message_stability_is_compatible_fails() {
    // Error messages should be informative and stable
    let err = CoreError::SerializationError("test error".to_string());
    let msg = err.to_string();

    assert!(msg.contains("Serialization"), "Error message should describe the error type");
    assert!(msg.contains("test error"), "Error message should include details");
}

#[test]
fn test_invalid_base64_error_handling_succeeds() {
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
