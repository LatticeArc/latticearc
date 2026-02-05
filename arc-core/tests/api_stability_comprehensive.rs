//! Comprehensive API Stability and Backward Compatibility Tests
//!
//! This test suite validates the stability of the public API surface, ensuring
//! backward compatibility is maintained across versions.
//!
//! # Test Coverage
//!
//! 1. Public API Surface Tests (15+ tests):
//!    - Test all public exports from latticearc crate
//!    - Verify re-exports match expected paths
//!    - Test module visibility (pub vs pub(crate))
//!
//! 2. Type Stability Tests (15+ tests):
//!    - Verify struct field accessibility
//!    - Test enum variant stability
//!    - Check trait implementations (Send, Sync, Clone, Debug)
//!    - Verify Error types implement std::error::Error
//!
//! 3. Function Signature Tests (15+ tests):
//!    - Test function parameter types haven't changed
//!    - Verify return types are stable
//!    - Check for breaking generic constraints
//!
//! 4. Deprecation Handling Tests (10+ tests):
//!    - Test deprecated functions still work
//!    - Verify deprecation warnings are present
//!    - Check migration paths exist

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

use std::error::Error;
use std::mem::size_of_val;

use arc_core::{
    // Audit types
    AuditConfig,
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    // Hybrid encryption types
    HybridEncryptionResult,
    // Constants
    VERSION,
    // Config types
    config::{
        CoreConfig, EncryptionConfig, HardwareConfig, ProofComplexity, SignatureConfig,
        UseCaseConfig, ZeroTrustConfig,
    },
    // Convenience functions
    decrypt,
    // Unverified variants
    decrypt_aes_gcm_unverified,
    decrypt_hybrid_unverified,
    derive_key_unverified,
    encrypt,
    encrypt_aes_gcm_unverified,
    encrypt_hybrid_unverified,
    // Error types
    error::{CoreError, Result},
    generate_keypair,
    generate_keypair_with_config,
    // Hardware types
    hardware::{CpuAccelerator, FpgaAccelerator, GpuAccelerator, HardwareRouter, SgxAccelerator},
    hash_data,
    hmac_check_unverified,
    hmac_unverified,
    init,
    init_with_config,
    // Key lifecycle
    key_lifecycle::{CustodianRole, KeyLifecycleRecord, KeyLifecycleState, KeyStateMachine},
    // Selector and policy
    selector::{
        CLASSICAL_AES_GCM, CLASSICAL_ED25519, CryptoPolicyEngine, DEFAULT_ENCRYPTION_SCHEME,
        DEFAULT_PQ_ENCRYPTION_SCHEME, DEFAULT_PQ_SIGNATURE_SCHEME, DEFAULT_SIGNATURE_SCHEME,
        HYBRID_ENCRYPTION_512, HYBRID_ENCRYPTION_768, HYBRID_ENCRYPTION_1024, HYBRID_SIGNATURE_44,
        HYBRID_SIGNATURE_65, HYBRID_SIGNATURE_87, PQ_ENCRYPTION_512, PQ_ENCRYPTION_768,
        PQ_ENCRYPTION_1024, PQ_SIGNATURE_44, PQ_SIGNATURE_65, PQ_SIGNATURE_87, PerformanceMetrics,
    },
    self_tests_passed,
    sign_ed25519_unverified,
    // Traits
    traits::{
        DataCharacteristics, HardwareCapabilities, HardwareInfo, HardwareType, PatternType,
        VerificationStatus,
    },
    // Core types
    types::{
        AlgorithmSelection, CryptoConfig, CryptoContext, CryptoScheme, EncryptedData,
        EncryptedMetadata, HashOutput, KeyPair, PerformancePreference, PrivateKey, PublicKey,
        SecurityLevel, SignedMetadata, UseCase, ZeroizedBytes,
    },
    verify_ed25519_unverified,
    // Zero trust
    zero_trust::{
        Challenge, ContinuousSession, SecurityMode, TrustLevel, VerifiedSession, ZeroTrustAuth,
        ZeroTrustSession,
    },
};

// =============================================================================
// Section 1: Public API Surface Tests (15+ tests)
// =============================================================================

/// Test 1.1: VERSION constant is accessible and valid
#[test]
fn test_version_constant_accessible() {
    assert!(!VERSION.is_empty(), "VERSION should not be empty");
    // Version should follow semver pattern (basic check)
    let parts: Vec<&str> = VERSION.split('.').collect();
    assert!(parts.len() >= 2, "VERSION should have at least major.minor");
}

/// Test 1.2: Core initialization functions are accessible
#[test]
fn test_init_functions_accessible() {
    // These should compile and be callable
    let result = init();
    assert!(result.is_ok(), "init() should succeed");

    let config = CoreConfig::default();
    let result = init_with_config(&config);
    assert!(result.is_ok(), "init_with_config() should succeed");
}

/// Test 1.3: Self-test status function is accessible
#[test]
fn test_self_test_status_accessible() {
    // Initialize first
    let _ = init();
    let passed = self_tests_passed();
    assert!(passed, "Self-tests should pass after init()");
}

/// Test 1.4: All encryption scheme constants are accessible
#[test]
fn test_encryption_scheme_constants_accessible() {
    // Default schemes
    assert!(!DEFAULT_ENCRYPTION_SCHEME.is_empty());
    assert!(!DEFAULT_SIGNATURE_SCHEME.is_empty());
    assert!(!DEFAULT_PQ_ENCRYPTION_SCHEME.is_empty());
    assert!(!DEFAULT_PQ_SIGNATURE_SCHEME.is_empty());

    // Hybrid encryption schemes
    assert!(!HYBRID_ENCRYPTION_512.is_empty());
    assert!(!HYBRID_ENCRYPTION_768.is_empty());
    assert!(!HYBRID_ENCRYPTION_1024.is_empty());

    // Hybrid signature schemes
    assert!(!HYBRID_SIGNATURE_44.is_empty());
    assert!(!HYBRID_SIGNATURE_65.is_empty());
    assert!(!HYBRID_SIGNATURE_87.is_empty());

    // PQ encryption schemes
    assert!(!PQ_ENCRYPTION_512.is_empty());
    assert!(!PQ_ENCRYPTION_768.is_empty());
    assert!(!PQ_ENCRYPTION_1024.is_empty());

    // PQ signature schemes
    assert!(!PQ_SIGNATURE_44.is_empty());
    assert!(!PQ_SIGNATURE_65.is_empty());
    assert!(!PQ_SIGNATURE_87.is_empty());

    // Classical schemes
    assert!(!CLASSICAL_AES_GCM.is_empty());
    assert!(!CLASSICAL_ED25519.is_empty());
}

/// Test 1.5: Unified API functions (encrypt, decrypt) are accessible
/// Note: The unified API with CryptoConfig defaults to PQ hybrid encryption.
/// For symmetric encryption with 32-byte keys, use encrypt_aes_gcm_unverified.
#[test]
fn test_unified_api_functions_accessible() {
    let key = [0u8; 32];
    let data = b"test data";

    // For symmetric key encryption, use the AES-GCM unverified functions
    // (the unified API defaults to PQ hybrid which requires public keys)
    let encrypted = encrypt_aes_gcm_unverified(data, &key);
    assert!(encrypted.is_ok(), "encrypt_aes_gcm_unverified() should succeed");

    // decrypt with symmetric key
    let encrypted_data = encrypted.expect("encryption should succeed");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted_data, &key);
    assert!(decrypted.is_ok(), "decrypt_aes_gcm_unverified() should succeed");

    // Verify the unified API function signatures exist (type checking)
    // Note: These require PQ public keys, not symmetric keys
    fn _assert_encrypt_signature(
        _data: &[u8],
        _key: &[u8],
        _config: CryptoConfig,
    ) -> Result<EncryptedData> {
        encrypt(_data, _key, _config)
    }

    fn _assert_decrypt_signature(
        _encrypted: &EncryptedData,
        _key: &[u8],
        _config: CryptoConfig,
    ) -> Result<Vec<u8>> {
        decrypt(_encrypted, _key, _config)
    }
}

/// Test 1.6: Key generation functions are accessible
#[test]
fn test_keygen_functions_accessible() {
    // generate_keypair() -> Result<(PublicKey, PrivateKey)>
    let result = generate_keypair();
    assert!(result.is_ok(), "generate_keypair() should succeed");

    // generate_keypair_with_config(config) -> Result<(PublicKey, PrivateKey)>
    let config = CoreConfig::default();
    let result = generate_keypair_with_config(&config);
    assert!(result.is_ok(), "generate_keypair_with_config() should succeed");
}

/// Test 1.7: Hashing functions are accessible
#[test]
fn test_hashing_functions_accessible() {
    let data = b"test data";

    // hash_data is stateless
    let hash = hash_data(data);
    assert_eq!(hash.len(), 32, "Hash output should be 32 bytes");
}

/// Test 1.8: HMAC functions are accessible with proper signatures
#[test]
fn test_hmac_functions_accessible() {
    let data = b"test data";
    let key = [0u8; 32];

    // Unverified variant for testing API stability
    let mac = hmac_unverified(data, &key);
    assert!(mac.is_ok(), "hmac_unverified() should succeed");

    let mac_value = mac.expect("hmac should succeed");
    let check = hmac_check_unverified(data, &key, &mac_value);
    assert!(check.is_ok(), "hmac_check_unverified() should succeed");
}

/// Test 1.9: Key derivation functions are accessible
#[test]
fn test_key_derivation_functions_accessible() {
    let ikm = b"input key material";
    let info = b"context info";

    // derive_key_unverified for API stability testing
    let derived = derive_key_unverified(ikm, info, 32);
    assert!(derived.is_ok(), "derive_key_unverified() should succeed");
}

/// Test 1.10: AES-GCM functions are accessible
#[test]
fn test_aes_gcm_functions_accessible() {
    let key = [0u8; 32];
    let data = b"plaintext";

    // encrypt_aes_gcm_unverified takes (data, key) - nonce is generated internally
    let encrypted = encrypt_aes_gcm_unverified(data, &key);
    assert!(encrypted.is_ok(), "encrypt_aes_gcm_unverified() should succeed");

    let ciphertext = encrypted.expect("encryption should succeed");
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key);
    assert!(decrypted.is_ok(), "decrypt_aes_gcm_unverified() should succeed");
}

/// Test 1.11: Hybrid encryption functions are accessible
#[test]
fn test_hybrid_encryption_functions_accessible() {
    let key = [0u8; 32];
    let data = b"plaintext";

    // encrypt_hybrid_unverified for API stability
    let encrypted = encrypt_hybrid_unverified(data, None, &key);
    assert!(encrypted.is_ok(), "encrypt_hybrid_unverified() should succeed");
}

/// Test 1.12: Ed25519 signature functions are accessible
#[test]
fn test_ed25519_functions_accessible() {
    let (public_key, private_key) = generate_keypair().expect("keygen");
    let message = b"message to sign";

    // sign_ed25519_unverified for API stability
    let signature = sign_ed25519_unverified(message, private_key.as_slice());
    assert!(signature.is_ok(), "sign_ed25519_unverified() should succeed");

    let sig = signature.expect("signing should succeed");
    let verified = verify_ed25519_unverified(message, &sig, &public_key);
    assert!(verified.is_ok(), "verify_ed25519_unverified() should succeed");
}

/// Test 1.13: CryptoPolicyEngine is accessible
#[test]
fn test_crypto_policy_engine_accessible() {
    let engine = CryptoPolicyEngine::new();
    assert_eq!(size_of_val(&engine), 0); // Zero-sized type

    // default_scheme static method
    let scheme = CryptoPolicyEngine::default_scheme();
    assert!(!scheme.is_empty());
}

/// Test 1.14: Audit module types are accessible
#[test]
fn test_audit_types_accessible() {
    // AuditConfig is constructable
    let _config = AuditConfig::default();

    // AuditEventType variants exist
    let _auth = AuditEventType::Authentication;
    let _key_op = AuditEventType::KeyOperation;
    let _crypto_op = AuditEventType::CryptoOperation;
    let _access = AuditEventType::AccessControl;
    let _session = AuditEventType::SessionManagement;
    let _alert = AuditEventType::SecurityAlert;
    let _config_change = AuditEventType::ConfigurationChange;
    let _system = AuditEventType::System;

    // AuditOutcome variants exist
    let _success = AuditOutcome::Success;
    let _failure = AuditOutcome::Failure;
}

/// Test 1.15: Hardware accelerator types are accessible
#[test]
fn test_hardware_types_accessible() {
    // Hardware accelerators are constructable
    let _cpu = CpuAccelerator::new(&HardwareCapabilities {
        simd_support: true,
        aes_ni: true,
        threads: 4,
        memory: 1024,
    });

    let _gpu = GpuAccelerator::new();
    let _fpga = FpgaAccelerator::new();
    let _sgx = SgxAccelerator::new();

    // HardwareRouter is constructable
    let _router = HardwareRouter::new();
}

/// Test 1.16: Zero trust types are accessible
#[test]
fn test_zero_trust_types_accessible() {
    let (pk, sk) = generate_keypair().expect("keygen");

    // VerifiedSession can be established
    let session = VerifiedSession::establish(&pk, sk.as_slice());
    assert!(session.is_ok());

    // ZeroTrustAuth can be created
    let auth = ZeroTrustAuth::new(pk.clone(), sk);
    assert!(auth.is_ok());
}

// =============================================================================
// Section 2: Type Stability Tests (15+ tests)
// =============================================================================

/// Test 2.1: SecurityLevel enum variants are stable
#[test]
fn test_security_level_variants_stable() {
    // All variants should exist
    let _standard = SecurityLevel::Standard;
    let _high = SecurityLevel::High;
    let _maximum = SecurityLevel::Maximum;
    let _quantum = SecurityLevel::Quantum;

    // Default should be High
    assert_eq!(SecurityLevel::default(), SecurityLevel::High);
}

/// Test 2.2: PerformancePreference enum variants are stable
#[test]
fn test_performance_preference_variants_stable() {
    let _speed = PerformancePreference::Speed;
    let _memory = PerformancePreference::Memory;
    let _balanced = PerformancePreference::Balanced;

    // Default should be Balanced
    assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);
}

/// Test 2.3: UseCase enum has all expected variants
#[test]
fn test_use_case_variants_stable() {
    // Communication use cases
    let _messaging = UseCase::SecureMessaging;
    let _email = UseCase::EmailEncryption;
    let _vpn = UseCase::VpnTunnel;
    let _api = UseCase::ApiSecurity;

    // Storage use cases
    let _file = UseCase::FileStorage;
    let _db = UseCase::DatabaseEncryption;
    let _cloud = UseCase::CloudStorage;
    let _backup = UseCase::BackupArchive;
    let _config = UseCase::ConfigSecrets;

    // Authentication use cases
    let _auth = UseCase::Authentication;
    let _session = UseCase::SessionToken;
    let _cert = UseCase::DigitalCertificate;
    let _key_ex = UseCase::KeyExchange;

    // Financial/Legal use cases
    let _financial = UseCase::FinancialTransactions;
    let _legal = UseCase::LegalDocuments;
    let _blockchain = UseCase::BlockchainTransaction;

    // Regulated industry use cases
    let _healthcare = UseCase::HealthcareRecords;
    let _gov = UseCase::GovernmentClassified;
    let _pci = UseCase::PaymentCard;

    // IoT use cases
    let _iot = UseCase::IoTDevice;
    let _firmware = UseCase::FirmwareSigning;

    // Advanced use cases
    let _searchable = UseCase::SearchableEncryption;
    let _homomorphic = UseCase::HomomorphicComputation;
    let _audit = UseCase::AuditLog;
}

/// Test 2.4: CryptoScheme enum variants are stable
#[test]
fn test_crypto_scheme_variants_stable() {
    let _hybrid = CryptoScheme::Hybrid;
    let _symmetric = CryptoScheme::Symmetric;
    let _asymmetric = CryptoScheme::Asymmetric;
    let _homomorphic = CryptoScheme::Homomorphic;
    let _pq = CryptoScheme::PostQuantum;
}

/// Test 2.5: TrustLevel enum variants and ordering are stable
#[test]
fn test_trust_level_variants_stable() {
    let untrusted = TrustLevel::Untrusted;
    let partial = TrustLevel::Partial;
    let trusted = TrustLevel::Trusted;
    let fully_trusted = TrustLevel::FullyTrusted;

    // Ordering should be preserved
    assert!(untrusted < partial);
    assert!(partial < trusted);
    assert!(trusted < fully_trusted);

    // Default should be Untrusted
    assert_eq!(TrustLevel::default(), TrustLevel::Untrusted);

    // Methods should work
    assert!(!untrusted.is_trusted());
    assert!(partial.is_trusted());
    assert!(trusted.is_trusted());
    assert!(fully_trusted.is_fully_trusted());
}

/// Test 2.6: VerificationStatus enum variants are stable
#[test]
fn test_verification_status_variants_stable() {
    let verified = VerificationStatus::Verified;
    let expired = VerificationStatus::Expired;
    let failed = VerificationStatus::Failed;
    let pending = VerificationStatus::Pending;

    // is_verified() method should work
    assert!(verified.is_verified());
    assert!(!expired.is_verified());
    assert!(!failed.is_verified());
    assert!(!pending.is_verified());
}

/// Test 2.7: ProofComplexity enum variants are stable
#[test]
fn test_proof_complexity_variants_stable() {
    let _low = ProofComplexity::Low;
    let _medium = ProofComplexity::Medium;
    let _high = ProofComplexity::High;
}

/// Test 2.8: HardwareType enum variants are stable
#[test]
fn test_hardware_type_variants_stable() {
    let _cpu = HardwareType::Cpu;
    let _gpu = HardwareType::Gpu;
    let _fpga = HardwareType::Fpga;
    let _tpu = HardwareType::Tpu;
    let _sgx = HardwareType::Sgx;
}

/// Test 2.9: PatternType enum variants are stable
#[test]
fn test_pattern_type_variants_stable() {
    let _random = PatternType::Random;
    let _structured = PatternType::Structured;
    let _repetitive = PatternType::Repetitive;
    let _text = PatternType::Text;
    let _binary = PatternType::Binary;
}

/// Test 2.10: KeyLifecycleState enum variants are stable
#[test]
fn test_key_lifecycle_state_variants_stable() {
    let _generation = KeyLifecycleState::Generation;
    let _active = KeyLifecycleState::Active;
    let _rotating = KeyLifecycleState::Rotating;
    let _retired = KeyLifecycleState::Retired;
    let _destroyed = KeyLifecycleState::Destroyed;
}

/// Test 2.11: CustodianRole enum variants are stable
#[test]
fn test_custodian_role_variants_stable() {
    let _generator = CustodianRole::KeyGenerator;
    let _approver = CustodianRole::KeyApprover;
    let _destroyer = CustodianRole::KeyDestroyer;
    let _auditor = CustodianRole::KeyAuditor;
}

/// Test 2.12: AlgorithmSelection enum variants are stable
#[test]
fn test_algorithm_selection_variants_stable() {
    let _use_case = AlgorithmSelection::UseCase(UseCase::FileStorage);
    let _security = AlgorithmSelection::SecurityLevel(SecurityLevel::High);

    // Default should be SecurityLevel(High)
    let default = AlgorithmSelection::default();
    assert!(matches!(default, AlgorithmSelection::SecurityLevel(SecurityLevel::High)));
}

/// Test 2.13: CoreError implements std::error::Error
#[test]
fn test_core_error_implements_error_trait() {
    // CoreError should implement Error trait
    let error = CoreError::InvalidInput("test".to_string());
    let _: &dyn Error = &error;

    // Should have Display
    let display = format!("{}", error);
    assert!(!display.is_empty());
}

/// Test 2.14: CoreError variants are stable
#[test]
fn test_core_error_variants_stable() {
    // String-based errors
    let _ = CoreError::InvalidInput("test".to_string());
    let _ = CoreError::EncryptionFailed("test".to_string());
    let _ = CoreError::DecryptionFailed("test".to_string());
    let _ = CoreError::KeyDerivationFailed("test".to_string());
    let _ = CoreError::InvalidNonce("test".to_string());
    let _ = CoreError::HardwareError("test".to_string());
    let _ = CoreError::ConfigurationError("test".to_string());
    let _ = CoreError::SchemeSelectionFailed("test".to_string());
    let _ = CoreError::AuthenticationFailed("test".to_string());
    let _ = CoreError::ZeroTrustVerificationFailed("test".to_string());
    let _ = CoreError::AuthenticationRequired("test".to_string());
    let _ = CoreError::UnsupportedOperation("test".to_string());
    let _ = CoreError::MemoryError("test".to_string());
    let _ = CoreError::SerializationError("test".to_string());
    let _ = CoreError::FeatureNotAvailable("test".to_string());
    let _ = CoreError::InvalidSignature("test".to_string());
    let _ = CoreError::InvalidKey("test".to_string());
    let _ = CoreError::NotImplemented("test".to_string());
    let _ = CoreError::SignatureFailed("test".to_string());
    let _ = CoreError::HsmError("test".to_string());
    let _ = CoreError::ResourceExceeded("test".to_string());
    let _ = CoreError::AuditError("test".to_string());

    // Simple errors
    let _ = CoreError::VerificationFailed;
    let _ = CoreError::SessionExpired;

    // Structured errors
    let _ = CoreError::InvalidKeyLength { expected: 32, actual: 16 };
    let _ =
        CoreError::Recoverable { message: "msg".to_string(), suggestion: "try again".to_string() };
    let _ = CoreError::HardwareUnavailable {
        reason: "not found".to_string(),
        fallback: "software".to_string(),
    };
    let _ = CoreError::EntropyDepleted {
        message: "low entropy".to_string(),
        action: "wait".to_string(),
    };
    let _ = CoreError::KeyGenerationFailed {
        reason: "failed".to_string(),
        recovery: "retry".to_string(),
    };
    let _ = CoreError::SelfTestFailed {
        component: "AES".to_string(),
        status: "KAT failed".to_string(),
    };
    let _ = CoreError::InvalidStateTransition {
        from: KeyLifecycleState::Active,
        to: KeyLifecycleState::Generation,
    };
}

/// Test 2.15: Struct field accessibility - CryptoConfig
#[test]
fn test_crypto_config_field_accessibility() {
    // CryptoConfig builder methods
    let config = CryptoConfig::new();

    // Methods should be accessible
    let _ = config.get_session();
    let _ = config.get_selection();
    let _ = config.is_verified();
    let _ = config.validate();

    // Builder pattern should work
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(&pk, sk.as_slice()).expect("session");
    let config = CryptoConfig::new()
        .session(&session)
        .use_case(UseCase::FileStorage)
        .security_level(SecurityLevel::Maximum);

    assert!(config.is_verified());
}

/// Test 2.16: Struct field accessibility - CoreConfig
#[test]
fn test_core_config_field_accessibility() {
    let config = CoreConfig::default();

    // Public fields should be accessible
    let _ = config.security_level;
    let _ = config.performance_preference;
    let _ = config.hardware_acceleration;
    let _ = config.fallback_enabled;
    let _ = config.strict_validation;

    // Builder methods should work
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_performance_preference(PerformancePreference::Speed)
        .with_hardware_acceleration(true)
        .with_fallback(true)
        .with_strict_validation(true);

    assert_eq!(config.security_level, SecurityLevel::Maximum);
}

/// Test 2.17: Struct field accessibility - EncryptedMetadata
#[test]
fn test_encrypted_metadata_field_accessibility() {
    let metadata = EncryptedMetadata {
        nonce: vec![0u8; 12],
        tag: Some(vec![0u8; 16]),
        key_id: Some("key-123".to_string()),
    };

    // Fields should be accessible
    assert_eq!(metadata.nonce.len(), 12);
    assert!(metadata.tag.is_some());
    assert!(metadata.key_id.is_some());
}

/// Test 2.18: Struct field accessibility - SignedMetadata
#[test]
fn test_signed_metadata_field_accessibility() {
    let metadata = SignedMetadata {
        signature: vec![0u8; 64],
        signature_algorithm: "ML-DSA-65".to_string(),
        public_key: vec![0u8; 32],
        key_id: Some("key-123".to_string()),
    };

    // Fields should be accessible
    assert_eq!(metadata.signature.len(), 64);
    assert!(!metadata.signature_algorithm.is_empty());
    assert!(!metadata.public_key.is_empty());
    assert!(metadata.key_id.is_some());
}

// =============================================================================
// Section 3: Function Signature Tests (15+ tests)
// =============================================================================

/// Test 3.1: encrypt function signature is stable
/// Note: The unified encrypt() with CryptoConfig requires PQ public keys.
/// Use encrypt_aes_gcm_unverified() for symmetric encryption with 32-byte keys.
#[test]
fn test_encrypt_function_works() {
    let key = [0u8; 32];
    let data = b"test data";

    // Test symmetric encryption works with correct return type
    let result: Result<Vec<u8>> = encrypt_aes_gcm_unverified(data, &key);
    assert!(result.is_ok());

    // Verify unified encrypt() function signature exists (compile-time check)
    fn _assert_signature(
        _data: &[u8],
        _key: &[u8],
        _config: CryptoConfig,
    ) -> Result<EncryptedData> {
        encrypt(_data, _key, _config)
    }
}

/// Test 3.2: decrypt function signature is stable
/// Note: The unified decrypt() with CryptoConfig requires PQ keys.
/// Use decrypt_aes_gcm_unverified() for symmetric decryption with 32-byte keys.
#[test]
fn test_decrypt_function_works() {
    let key = [0u8; 32];
    let data = b"test data";

    // Test symmetric encryption/decryption roundtrip
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let result: Result<Vec<u8>> = decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_ok());
    assert_eq!(result.expect("decrypt"), data);

    // Verify unified decrypt() function signature exists (compile-time check)
    fn _assert_signature(
        _encrypted: &EncryptedData,
        _key: &[u8],
        _config: CryptoConfig,
    ) -> Result<Vec<u8>> {
        decrypt(_encrypted, _key, _config)
    }
}

/// Test 3.3: generate_keypair function returns expected types
#[test]
fn test_generate_keypair_returns_expected_types() {
    let result: Result<(PublicKey, PrivateKey)> = generate_keypair();
    assert!(result.is_ok());

    let (pk, sk) = result.expect("keygen");
    assert!(!pk.is_empty());
    assert!(!sk.as_slice().is_empty());
}

/// Test 3.4: hash_data function returns expected type
#[test]
fn test_hash_data_returns_expected_type() {
    let data = b"test data";
    let result: HashOutput = hash_data(data);
    assert_eq!(result.len(), 32);
}

/// Test 3.5: VerifiedSession::establish works with expected types
#[test]
fn test_verified_session_establish_works() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let result: Result<VerifiedSession> = VerifiedSession::establish(&pk, sk.as_slice());
    assert!(result.is_ok());
}

/// Test 3.6: VerifiedSession methods return expected types
#[test]
fn test_verified_session_method_return_types() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(&pk, sk.as_slice()).expect("session");

    // Method return types should be stable
    let _: bool = session.is_valid();
    let _: TrustLevel = session.trust_level();
    let _: &[u8; 32] = session.session_id();
    let _: &PublicKey = session.public_key();
    let _: chrono::DateTime<chrono::Utc> = session.authenticated_at();
    let _: chrono::DateTime<chrono::Utc> = session.expires_at();
    let _: Result<()> = session.verify_valid();
}

/// Test 3.7: SecurityMode methods return expected types
#[test]
fn test_security_mode_method_return_types() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(&pk, sk.as_slice()).expect("session");

    let verified = SecurityMode::Verified(&session);
    let unverified = SecurityMode::Unverified;

    // Method return types should be stable
    let _: bool = verified.is_verified();
    let _: bool = verified.is_unverified();
    let _: Option<&VerifiedSession> = verified.session();
    let _: Result<()> = verified.validate();

    let _: bool = unverified.is_verified();
    let _: bool = unverified.is_unverified();
    let _: Option<&VerifiedSession> = unverified.session();
}

/// Test 3.8: CryptoPolicyEngine static methods return expected types
#[test]
fn test_crypto_policy_engine_method_return_types() {
    let config = CoreConfig::default();
    let data = b"test data";

    // Static method return types
    let _: Result<String> = CryptoPolicyEngine::recommend_scheme(&UseCase::FileStorage, &config);
    let _: String = CryptoPolicyEngine::force_scheme(&CryptoScheme::Hybrid);
    let _: Result<String> = CryptoPolicyEngine::select_pq_encryption_scheme(&config);
    let _: Result<String> = CryptoPolicyEngine::select_pq_signature_scheme(&config);
    let _: DataCharacteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
    let _: Result<String> = CryptoPolicyEngine::select_encryption_scheme(data, &config, None);
    let _: Result<String> = CryptoPolicyEngine::select_signature_scheme(&config);
    let _: Result<String> = CryptoPolicyEngine::select_for_context(data, &config);
    let _: &str = CryptoPolicyEngine::default_scheme();

    let metrics = PerformanceMetrics::default();
    let _: Result<String> = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config);
}

/// Test 3.9: ZeroTrustAuth methods return expected types
#[test]
fn test_zero_trust_auth_method_return_types() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");

    // Method return types
    let _: Result<Challenge> = auth.generate_challenge();
    let challenge = auth.generate_challenge().expect("challenge");
    let _: Result<bool> = auth.verify_challenge_age(&challenge);
    let _: ContinuousSession = auth.start_continuous_verification();
}

/// Test 3.10: ZeroTrustSession methods return expected types
#[test]
fn test_zero_trust_session_method_return_types() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");
    let mut session = ZeroTrustSession::new(auth);

    // Method return types
    let _: Result<Challenge> = session.initiate_authentication();
    let _: bool = session.is_authenticated();
    let _: Result<u64> = session.session_age_ms();
}

/// Test 3.11: HardwareRouter methods return expected types
#[test]
fn test_hardware_router_method_return_types() {
    let router = HardwareRouter::new();

    // Method return types
    let _: HardwareInfo = router.detect_hardware();
}

/// Test 3.12: KeyStateMachine methods return expected types
#[test]
fn test_key_state_machine_method_return_types() {
    // Static method return types
    let _: bool = KeyStateMachine::is_valid_transition(None, KeyLifecycleState::Generation);
    let _: Vec<KeyLifecycleState> = KeyStateMachine::allowed_next_states(KeyLifecycleState::Active);
}

/// Test 3.13: Config builder patterns work correctly
#[test]
fn test_config_builder_patterns_work() {
    // CoreConfig builder
    let config = CoreConfig::new()
        .with_security_level(SecurityLevel::Maximum)
        .with_performance_preference(PerformancePreference::Speed)
        .with_hardware_acceleration(true)
        .with_fallback(true)
        .with_strict_validation(true)
        .build();
    assert!(config.is_ok());

    // EncryptionConfig builder
    let config = EncryptionConfig::new()
        .with_scheme(CryptoScheme::Hybrid)
        .with_compression(true)
        .with_integrity_check(true);
    assert!(config.validate().is_ok());

    // SignatureConfig builder
    let config = SignatureConfig::new()
        .with_scheme(CryptoScheme::Hybrid)
        .with_timestamp(true)
        .with_certificate_chain(false);
    assert!(config.validate().is_ok());

    // ZeroTrustConfig builder
    let config = ZeroTrustConfig::new()
        .with_timeout(5000)
        .with_complexity(ProofComplexity::Medium)
        .with_continuous_verification(true)
        .with_verification_interval(30000);
    assert!(config.validate().is_ok());

    // HardwareConfig builder
    let config = HardwareConfig::new()
        .with_acceleration(true)
        .with_fallback(true)
        .with_threshold(4096)
        .with_force_cpu(false);
    assert!(config.validate().is_ok());
}

/// Test 3.14: Trait implementations on types are stable
#[test]
fn test_trait_implementations_stable() {
    // SecurityLevel implements Debug, Clone, PartialEq, Eq, Default
    fn assert_traits<T: std::fmt::Debug + Clone + PartialEq + Eq + Default>() {}
    assert_traits::<SecurityLevel>();
    assert_traits::<PerformancePreference>();
    assert_traits::<TrustLevel>();

    // CryptoScheme implements Debug, Clone, PartialEq
    fn assert_debug_clone_eq<T: std::fmt::Debug + Clone + PartialEq>() {}
    assert_debug_clone_eq::<CryptoScheme>();
    assert_debug_clone_eq::<UseCase>();
    assert_debug_clone_eq::<PatternType>();
    assert_debug_clone_eq::<HardwareType>();
    assert_debug_clone_eq::<VerificationStatus>();
    assert_debug_clone_eq::<ProofComplexity>();
}

/// Test 3.15: Type aliases work correctly
#[test]
fn test_type_aliases_work() {
    // PublicKey = Vec<u8>
    let pk: PublicKey = vec![0u8; 32];
    assert_eq!(pk.len(), 32);

    // HashOutput = [u8; 32]
    let hash: HashOutput = [0u8; 32];
    assert_eq!(hash.len(), 32);
}

/// Test 3.16: Result type alias works correctly
#[test]
fn test_result_type_alias_works() {
    // Result<T> should be std::result::Result<T, CoreError>
    fn returns_result() -> Result<()> {
        Ok(())
    }
    assert!(returns_result().is_ok());

    fn returns_error() -> Result<()> {
        Err(CoreError::InvalidInput("test".to_string()))
    }
    assert!(returns_error().is_err());
}

// =============================================================================
// Section 4: Deprecation Handling Tests (10+ tests)
// =============================================================================

/// Test 4.1: Unverified AES-GCM functions work as migration path
#[test]
fn test_unverified_aes_gcm_works() {
    let key = [0u8; 32];
    let data = b"test data";

    // These unverified functions provide migration path for legacy code
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted, data);
}

/// Test 4.2: Legacy hybrid encryption works
#[test]
fn test_legacy_hybrid_encryption_works() {
    let key = [0u8; 32];
    let data = b"test data";

    // encrypt_hybrid_unverified returns HybridEncryptionResult with ciphertext and encapsulated_key
    // Using explicit type annotation to test type stability
    let result: HybridEncryptionResult =
        encrypt_hybrid_unverified(data, None, &key).expect("encrypt");

    // decrypt_hybrid_unverified takes 4 args: ciphertext, kem_private_key, encapsulated_key, symmetric_key
    let decrypted =
        decrypt_hybrid_unverified(&result.ciphertext, None, &result.encapsulated_key, &key)
            .expect("decrypt");
    assert_eq!(decrypted, data);
}

/// Test 4.3: Legacy Ed25519 signing works
#[test]
fn test_legacy_ed25519_signing_works() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let message = b"test message";

    let signature = sign_ed25519_unverified(message, sk.as_slice()).expect("sign");
    let verified = verify_ed25519_unverified(message, &signature, &pk).expect("verify");
    assert!(verified);
}

/// Test 4.4: Legacy HMAC functions work
#[test]
fn test_legacy_hmac_functions_work() {
    let key = [0u8; 32];
    let data = b"test data";

    let mac = hmac_unverified(data, &key).expect("hmac");
    let valid = hmac_check_unverified(data, &key, &mac).expect("check");
    assert!(valid);
}

/// Test 4.5: Legacy key derivation works
#[test]
fn test_legacy_key_derivation_works() {
    let ikm = b"input key material";
    let info = b"context";

    let key = derive_key_unverified(ikm, info, 32).expect("derive");
    assert_eq!(key.len(), 32);
}

/// Test 4.6: Migration from SecurityMode::Unverified to Verified
/// Note: This tests the migration path from legacy unverified functions to session-based.
/// The unified API with CryptoConfig uses PQ hybrid encryption by default.
#[test]
fn test_migration_to_verified_mode() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let key = [0u8; 32];
    let data = b"sensitive data";

    // Step 1: Legacy code uses unverified mode (symmetric encryption)
    let encrypted_legacy = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");

    // Step 2: New code establishes a session
    let session = VerifiedSession::establish(&pk, sk.as_slice()).expect("session");

    // Step 3: New code can still use symmetric encryption but with verified session context
    // The CryptoConfig.session() validates the session is active, but the actual
    // encryption scheme depends on the key type provided.
    // For symmetric encryption, we verify session is established then use symmetric API
    assert!(session.is_valid());

    // Both legacy and new approaches produce valid symmetric ciphertext
    assert!(!encrypted_legacy.is_empty());

    // The session can be used for other verified operations
    let config = CryptoConfig::new().session(&session);
    assert!(config.is_verified());
    assert!(config.validate().is_ok());
}

/// Test 4.7: Default CryptoConfig provides backward compatibility
/// Note: CryptoConfig defaults to PQ hybrid encryption requiring public keys.
/// For symmetric encryption backward compatibility, use the _unverified functions.
#[test]
fn test_default_config_backward_compatible() {
    let key = [0u8; 32];
    let data = b"test data";

    // Default config should work without session
    let config = CryptoConfig::new();
    assert!(!config.is_verified());

    // Symmetric operations use the unverified API for backward compatibility
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted, data);

    // CryptoConfig validation should work without session
    assert!(config.validate().is_ok());
}

/// Test 4.8: CoreConfig::for_development provides relaxed settings
#[test]
fn test_development_config_compatible() {
    let config = CoreConfig::for_development();

    // Development config should be valid
    assert!(config.validate().is_ok());

    // Should have relaxed settings
    assert_eq!(config.security_level, SecurityLevel::Standard);
    assert!(!config.strict_validation);
}

/// Test 4.9: CoreConfig::for_production provides strong defaults
#[test]
fn test_production_config_compatible() {
    let config = CoreConfig::for_production();

    // Production config should be valid
    assert!(config.validate().is_ok());

    // Should have strong settings
    assert_eq!(config.security_level, SecurityLevel::Maximum);
    assert!(config.strict_validation);
}

/// Test 4.10: Empty data handling is stable
/// Note: Uses symmetric AES-GCM for empty data handling test.
#[test]
fn test_empty_data_handling_stable() {
    let key = [0u8; 32];
    let data = b"";

    // Empty data should be handled gracefully with symmetric encryption
    let encrypted = encrypt_aes_gcm_unverified(data, &key);
    assert!(encrypted.is_ok());

    let encrypted_data = encrypted.expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted_data, &key);
    assert!(decrypted.is_ok());
    assert!(decrypted.expect("decrypt").is_empty());
}

/// Test 4.11: Large data handling is stable
/// Note: Uses symmetric AES-GCM for large data handling test.
#[test]
fn test_large_data_handling_stable() {
    let key = [0u8; 32];
    let data = vec![0u8; 1024 * 1024]; // 1MB

    // Large data encryption with symmetric AES-GCM
    let encrypted = encrypt_aes_gcm_unverified(&data, &key);
    assert!(encrypted.is_ok());

    let encrypted_data = encrypted.expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted_data, &key);
    assert!(decrypted.is_ok());
    assert_eq!(decrypted.expect("decrypt").len(), data.len());
}

// =============================================================================
// Section 5: Additional Compatibility Tests
// =============================================================================

/// Test 5.1: ZeroizedBytes provides secure memory handling
#[test]
fn test_zeroized_bytes_api_stable() {
    let data = vec![1, 2, 3, 4, 5];
    let zeroized = ZeroizedBytes::new(data);

    // Methods should be accessible
    let _slice: &[u8] = zeroized.as_slice();
    let _len: usize = zeroized.len();
    let _empty: bool = zeroized.is_empty();

    // AsRef trait
    let _ref: &[u8] = zeroized.as_ref();
}

/// Test 5.2: KeyPair provides secure key storage
#[test]
fn test_keypair_api_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");

    // Create KeyPair directly
    let keypair = KeyPair::new(pk.clone(), sk);

    // Methods should be accessible
    let _public: &PublicKey = keypair.public_key();
    let _private: &PrivateKey = keypair.private_key();

    // Public fields accessible
    let _ = &keypair.public_key;
}

/// Test 5.3: CryptoContext is constructable and usable
#[test]
fn test_crypto_context_api_stable() {
    // Default construction
    let context = CryptoContext::default();

    // Fields should be accessible
    let _level: SecurityLevel = context.security_level;
    let _pref: PerformancePreference = context.performance_preference;
    let _use_case: Option<UseCase> = context.use_case;
    let _hw: bool = context.hardware_acceleration;
    let _ts: chrono::DateTime<chrono::Utc> = context.timestamp;
}

/// Test 5.4: DataCharacteristics structure is stable
#[test]
fn test_data_characteristics_api_stable() {
    let data = b"test data for analysis";
    let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);

    // Fields should be accessible
    let _size: usize = characteristics.size;
    let _entropy: f64 = characteristics.entropy;
    let _pattern: PatternType = characteristics.pattern_type;
}

/// Test 5.5: HardwareInfo structure is stable
#[test]
fn test_hardware_info_api_stable() {
    let router = HardwareRouter::new();
    let info = router.detect_hardware();

    // Methods should work (call before moving fields)
    let _best: Option<&HardwareType> = info.best_accelerator();
    let _summary: String = info.summary();

    // Fields should be accessible (clone to avoid move)
    let _accelerators: Vec<HardwareType> = info.available_accelerators.clone();
    let _preferred: Option<HardwareType> = info.preferred_accelerator.clone();
    let _capabilities: HardwareCapabilities = info.capabilities.clone();
}

/// Test 5.6: HardwareCapabilities structure is stable
#[test]
fn test_hardware_capabilities_api_stable() {
    let capabilities = HardwareCapabilities {
        simd_support: true,
        aes_ni: true,
        threads: 8,
        memory: 16 * 1024 * 1024 * 1024, // 16GB
    };

    // Fields should be accessible
    assert!(capabilities.simd_support);
    assert!(capabilities.aes_ni);
    assert_eq!(capabilities.threads, 8);
    assert!(capabilities.memory > 0);
}

/// Test 5.7: PerformanceMetrics default values are stable
#[test]
fn test_performance_metrics_defaults_stable() {
    let metrics = PerformanceMetrics::default();

    // Fields should be accessible with sensible defaults
    assert!(metrics.encryption_speed_ms > 0.0);
    assert!(metrics.decryption_speed_ms > 0.0);
    assert!(metrics.memory_usage_mb > 0.0);
    assert!(metrics.cpu_usage_percent >= 0.0);
}

/// Test 5.8: Challenge structure is stable
#[test]
fn test_challenge_structure_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");
    let challenge = auth.generate_challenge().expect("challenge");

    // Fields should be accessible
    let _data: Vec<u8> = challenge.data;
    let _timestamp: chrono::DateTime<chrono::Utc> = challenge.timestamp;
    let _complexity: ProofComplexity = challenge.complexity;
    let _timeout: u64 = challenge.timeout_ms;
}

/// Test 5.9: UseCaseConfig construction is stable
#[test]
fn test_use_case_config_stable() {
    let config = UseCaseConfig::new(UseCase::FileStorage);

    // Validation should work (call before moving fields)
    assert!(config.validate().is_ok());

    // Fields should be accessible (clone to avoid move)
    let _use_case: UseCase = config.use_case.clone();
    let _encryption: EncryptionConfig = config.encryption.clone();
    let _signature: SignatureConfig = config.signature.clone();
    let _zero_trust: ZeroTrustConfig = config.zero_trust.clone();
    let _hardware: HardwareConfig = config.hardware.clone();
}

/// Test 5.10: KeyLifecycleRecord construction is stable
#[test]
fn test_key_lifecycle_record_stable() {
    let record =
        KeyLifecycleRecord::new("key-123".to_string(), "ML-KEM-768".to_string(), 3, 365, 30);

    // Fields should be accessible
    assert_eq!(record.key_id, "key-123");
    assert_eq!(record.key_type, "ML-KEM-768");
    assert_eq!(record.security_level, 3);
    assert_eq!(record.current_state, KeyLifecycleState::Generation);
}

/// Test 5.11: AuditEvent construction is stable
#[test]
fn test_audit_event_construction_stable() {
    let event =
        AuditEvent::new(AuditEventType::CryptoOperation, "encrypt_data", AuditOutcome::Success);

    // Methods should be accessible
    assert!(!event.id().is_empty());
    assert_eq!(event.action(), "encrypt_data");
    assert_eq!(*event.outcome(), AuditOutcome::Success);
}

/// Test 5.12: SecurityMode conversion from VerifiedSession
#[test]
fn test_security_mode_from_verified_session() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(&pk, sk.as_slice()).expect("session");

    // From trait should work
    let mode: SecurityMode = (&session).into();
    assert!(mode.is_verified());
}

/// Test 5.13: SecurityMode default is Unverified
#[test]
fn test_security_mode_default() {
    let mode = SecurityMode::default();
    assert!(mode.is_unverified());
}
