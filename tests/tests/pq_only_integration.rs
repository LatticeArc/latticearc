#![allow(clippy::unwrap_used)]
//! PQ-Only Integration Tests — CryptoMode::PqOnly through the unified API.
//!
//! These tests exercise the full PQ-only encryption path as an external consumer
//! of the `latticearc` crate, covering:
//! - Roundtrip encrypt→decrypt at all 3 ML-KEM levels
//! - Cross-mode rejection (PQ key + hybrid scheme and vice versa)
//! - EncryptionScheme::parse_str roundtrip for PQ variants
//! - Serialization preserves PQ scheme
//! - CNSA 2.0 + PqOnly validation
//!
//! Run: `cargo test --test pq_only_integration --all-features --release`

use latticearc::primitives::kem::ml_kem::MlKemSecurityLevel;
use latticearc::{
    CryptoConfig, CryptoMode, DecryptKey, EncryptKey, EncryptionScheme, SecurityLevel, decrypt,
    encrypt, generate_pq_keypair, generate_pq_keypair_with_level,
};

// ============================================================================
// Roundtrip: encrypt → decrypt at all 3 PQ-only levels
// ============================================================================

#[test]
fn test_pq_only_roundtrip_512_external() {
    let (pk, sk) = generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem512).unwrap();
    let data = b"PQ-only 512 integration test";
    let config =
        CryptoConfig::new().crypto_mode(CryptoMode::PqOnly).security_level(SecurityLevel::Standard);
    let encrypted = encrypt(data, EncryptKey::PqOnly(&pk), config.clone()).unwrap();
    assert_eq!(encrypted.scheme(), &EncryptionScheme::PqMlKem512Aes256Gcm);
    let decrypted = decrypt(&encrypted, DecryptKey::PqOnly(&sk), config).unwrap();
    assert_eq!(decrypted.as_slice(), data.as_slice());
}

#[test]
fn test_pq_only_roundtrip_768_external() {
    let (pk, sk) = generate_pq_keypair().unwrap();
    let data = b"PQ-only 768 integration test";
    let config =
        CryptoConfig::new().crypto_mode(CryptoMode::PqOnly).security_level(SecurityLevel::High);
    let encrypted = encrypt(data, EncryptKey::PqOnly(&pk), config.clone()).unwrap();
    assert_eq!(encrypted.scheme(), &EncryptionScheme::PqMlKem768Aes256Gcm);
    let decrypted = decrypt(&encrypted, DecryptKey::PqOnly(&sk), config).unwrap();
    assert_eq!(decrypted.as_slice(), data.as_slice());
}

#[test]
fn test_pq_only_roundtrip_1024_external() {
    let (pk, sk) = generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem1024).unwrap();
    let data = b"PQ-only 1024 integration test";
    let config =
        CryptoConfig::new().crypto_mode(CryptoMode::PqOnly).security_level(SecurityLevel::Maximum);
    let encrypted = encrypt(data, EncryptKey::PqOnly(&pk), config.clone()).unwrap();
    assert_eq!(encrypted.scheme(), &EncryptionScheme::PqMlKem1024Aes256Gcm);
    let decrypted = decrypt(&encrypted, DecryptKey::PqOnly(&sk), config).unwrap();
    assert_eq!(decrypted.as_slice(), data.as_slice());
}

// ============================================================================
// Cross-mode rejection
// ============================================================================

#[test]
fn test_pq_key_hybrid_mode_rejected_external() {
    let (pk, _sk) = generate_pq_keypair().unwrap();
    // Default config = Hybrid mode → PQ key should be rejected
    let result = encrypt(b"test", EncryptKey::PqOnly(&pk), CryptoConfig::new());
    assert!(result.is_err(), "PQ key + hybrid mode must fail");
}

#[test]
fn test_hybrid_key_pq_mode_rejected_external() {
    let (pk, _sk) = latticearc::generate_hybrid_keypair().unwrap();
    let config =
        CryptoConfig::new().crypto_mode(CryptoMode::PqOnly).security_level(SecurityLevel::High);
    let result = encrypt(b"test", EncryptKey::Hybrid(&pk), config);
    assert!(result.is_err(), "Hybrid key + PQ-only mode must fail");
}

// ============================================================================
// EncryptionScheme::parse_str roundtrip for PQ variants
// ============================================================================

#[test]
fn test_pq_encryption_scheme_parse_str_roundtrip_external() {
    let schemes = [
        ("pq-ml-kem-512-aes-256-gcm", EncryptionScheme::PqMlKem512Aes256Gcm),
        ("pq-ml-kem-768-aes-256-gcm", EncryptionScheme::PqMlKem768Aes256Gcm),
        ("pq-ml-kem-1024-aes-256-gcm", EncryptionScheme::PqMlKem1024Aes256Gcm),
    ];
    for (s, expected) in &schemes {
        let parsed = EncryptionScheme::parse_str(s).unwrap();
        assert_eq!(&parsed, expected);
        assert_eq!(parsed.as_str(), *s);
        assert!(parsed.requires_pq_key());
        assert!(!parsed.requires_hybrid_key());
        assert!(!parsed.requires_symmetric_key());
    }
}

// ============================================================================
// Serialization preserves PQ scheme
// ============================================================================

#[test]
fn test_pq_encrypted_output_serialization_preserves_scheme() {
    let (pk, sk) = generate_pq_keypair().unwrap();
    let config =
        CryptoConfig::new().crypto_mode(CryptoMode::PqOnly).security_level(SecurityLevel::High);
    let encrypted = encrypt(b"serialize test", EncryptKey::PqOnly(&pk), config.clone()).unwrap();

    // Serialize → deserialize roundtrip
    let json =
        latticearc::unified_api::serialization::serialize_encrypted_output(&encrypted).unwrap();
    let deserialized =
        latticearc::unified_api::serialization::deserialize_encrypted_output(&json).unwrap();

    assert_eq!(deserialized.scheme(), &EncryptionScheme::PqMlKem768Aes256Gcm);

    // Verify it still decrypts
    let decrypted = decrypt(&deserialized, DecryptKey::PqOnly(&sk), config).unwrap();
    assert_eq!(decrypted.as_slice(), b"serialize test");
}

// ============================================================================
// CNSA 2.0 + PqOnly validation
// ============================================================================

#[test]
fn test_cnsa_pq_only_validation_passes() {
    use latticearc::ComplianceMode;
    let config = CryptoConfig::new()
        .compliance(ComplianceMode::Cnsa2_0)
        .crypto_mode(CryptoMode::PqOnly)
        .security_level(SecurityLevel::Maximum);
    // Validation fails on FIPS feature check (not on CNSA mode check)
    let result = config.validate();
    if cfg!(feature = "fips") {
        assert!(result.is_ok());
    } else {
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("fips"), "Should fail on FIPS availability, not CNSA mode: {}", err);
    }
}

// `ComplianceMode::Cnsa2_0` requires the
// `fips` cargo feature; the default `cargo test --workspace` (no
// features) panics with `FeatureNotAvailable`. CI ran clean only because
// `--all-features` masked the gap. Cfg-gate so the default test command
// works on a clean checkout.
#[cfg(feature = "fips")]
#[test]
fn test_cnsa_hybrid_mode_rejected() {
    use latticearc::ComplianceMode;
    let config = CryptoConfig::new()
        .compliance(ComplianceMode::Cnsa2_0)
        .security_level(SecurityLevel::Maximum);
    // Default mode is Hybrid → CNSA 2.0 should reject
    let result = config.validate();
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("PqOnly") || err.contains("CNSA"),
        "Should fail on CNSA 2.0 requiring PqOnly: {}",
        err
    );
}

// ============================================================================
// Use case + PqOnly produces correct scheme
// ============================================================================

// same gating rationale as
// `test_cnsa_hybrid_mode_rejected` above — this test instantiates a
// `compliance(Cnsa2_0)` path indirectly via the convenience API, which
// requires the `fips` feature.
#[cfg(feature = "fips")]
#[test]
fn test_use_case_with_pq_only_mode_produces_pq_scheme() {
    use latticearc::UseCase;
    let (pk, sk) = generate_pq_keypair_with_level(MlKemSecurityLevel::MlKem1024).unwrap();
    let config =
        CryptoConfig::new().use_case(UseCase::GovernmentClassified).crypto_mode(CryptoMode::PqOnly);
    let encrypted = encrypt(b"classified", EncryptKey::PqOnly(&pk), config.clone()).unwrap();
    // GovernmentClassified selects ML-KEM-1024 → PQ-only should give PqMlKem1024
    assert_eq!(encrypted.scheme(), &EncryptionScheme::PqMlKem1024Aes256Gcm);
    let decrypted = decrypt(&encrypted, DecryptKey::PqOnly(&sk), config).unwrap();
    assert_eq!(decrypted.as_slice(), b"classified");
}
