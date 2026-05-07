//! Public-API surface snapshot — audit follow-up #13.
//!
//! ## What this file IS
//!
//! A compile-time snapshot of the public API surface of the `latticearc`
//! crate **as of the current tree**. Each test below imports a `pub`
//! item, exercises it in a representative way, and asserts a property
//! (trait impl, return type, accessor visibility, etc.). Failure to
//! compile or a failed runtime assertion signals that the public
//! surface drifted within the same version branch.
//!
//! ## What this file IS NOT
//!
//! Despite the historical "API Stability and Backward Compatibility"
//! framing, this suite does **not** compare against any previously-
//! released version's surface. There is no semver-diff machinery here.
//! A genuine cross-version compatibility check would require either
//! `cargo-semver-checks` in CI (which we run separately) or a vendored
//! `latticearc-X.Y` crate to compile this file against — neither is
//! present today. The earlier doc-comment overstated scope and was
//! corrected as part of the prior audit response.
//!
//! ## Coverage categories
//!
//! 1. **Public exports** (15+ tests): every documented re-export
//!    resolves and the module visibility is `pub` (not `pub(crate)`).
//! 2. **Type-level invariants** (15+ tests): structs are constructible,
//!    enums are matchable, error types implement `std::error::Error`,
//!    and `Send + Sync + Debug` hold where promised.
//! 3. **Function signatures** (15+ tests): parameter and return types
//!    of the documented public functions compile against representative
//!    inputs.

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

use latticearc::unified_api::{
    // Audit types
    AuditConfig,
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    // Config types
    CoreConfig,
    // Key lifecycle (re-exported at crate::unified_api level)
    CustodianRole,
    // Traits (re-exported at unified_api root)
    DataCharacteristics,
    HardwareCapabilities,
    HardwareInfo,
    HardwareType,
    KeyLifecycleRecord,
    KeyLifecycleState,
    KeyStateMachine,
    PatternType,
    ProofComplexity,
    // Constants
    VERSION,
    VerificationStatus,
    // Convenience functions
    decrypt,
    // Unverified variants
    decrypt_aes_gcm_unverified,
    derive_key_unverified,
    encrypt,
    encrypt_aes_gcm_unverified,
    // Error types
    error::{CoreError, Result, TypeError},
    generate_hybrid_keypair,
    generate_keypair,
    generate_keypair_with_config,
    // Hardware types are imported from traits:: below
    hash_data,
    hmac_check_unverified,
    hmac_unverified,
    init,
    init_with_config,
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
    // Core types
    types::{
        AlgorithmSelection, CryptoConfig, CryptoContext, CryptoScheme, DecryptKey, EncryptKey,
        EncryptedMetadata, EncryptedOutput, HashOutput, KeyPair, PerformancePreference, PrivateKey,
        PublicKey, SecretVec, SecurityLevel, SignedMetadata, UseCase,
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
fn test_version_constant_accessible_is_stable() {
    assert!(!VERSION.is_empty(), "VERSION should not be empty");
    // Version should follow semver pattern (basic check)
    let parts: Vec<&str> = VERSION.split('.').collect();
    assert!(parts.len() >= 2, "VERSION should have at least major.minor");
}

/// Test 1.2: Core initialization functions are accessible
#[test]
fn test_init_functions_accessible_are_stable() {
    // These should compile and be callable
    let result = init();
    assert!(result.is_ok(), "init() should succeed");

    let config = CoreConfig::default();
    let result = init_with_config(&config);
    assert!(result.is_ok(), "init_with_config() should succeed");
}

/// Test 1.3: Self-test status function is accessible
#[test]
fn test_self_test_status_accessible_is_stable() {
    // Initialize first
    let _ = init();
    let passed = self_tests_passed();
    assert!(passed, "Self-tests should pass after init()");
}

/// Test 1.4: All encryption scheme constants are accessible
#[test]
fn test_encryption_scheme_constants_accessible_are_stable() {
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
fn test_unified_api_functions_accessible_are_stable() {
    let key = [0x42u8; 32];
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
    // Note: These require EncryptKey/DecryptKey wrappers, not raw &[u8]
    fn _assert_encrypt_signature(
        _data: &[u8],
        _key: EncryptKey<'_>,
        _config: CryptoConfig,
    ) -> Result<EncryptedOutput> {
        encrypt(_data, _key, _config)
    }

    fn _assert_decrypt_signature(
        _encrypted: &EncryptedOutput,
        _key: DecryptKey<'_>,
        _config: CryptoConfig,
    ) -> Result<latticearc::Zeroizing<Vec<u8>>> {
        decrypt(_encrypted, _key, _config)
    }
}

/// Test 1.6: Key generation functions are accessible
#[test]
fn test_keygen_functions_accessible_are_stable() {
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
fn test_hashing_functions_accessible_are_stable() {
    let data = b"test data";

    // hash_data is stateless
    let hash = hash_data(data);
    assert_eq!(hash.len(), 32, "Hash output should be 32 bytes");
}

/// Test 1.8: HMAC functions are accessible with proper signatures
#[test]
fn test_hmac_functions_accessible_are_stable() {
    let data = b"test data";
    let key = [0x42u8; 32];

    // Unverified variant for testing API stability
    let mac = hmac_unverified(data, &key);
    assert!(mac.is_ok(), "hmac_unverified() should succeed");

    let mac_value = mac.expect("hmac should succeed");
    let check = hmac_check_unverified(data, &key, &mac_value);
    assert!(check.is_ok(), "hmac_check_unverified() should succeed");
}

/// Test 1.9: Key derivation functions are accessible
#[test]
fn test_key_derivation_functions_accessible_are_stable() {
    let ikm = b"input key material";
    let info = b"context info";

    // derive_key_unverified for API stability testing
    let derived = derive_key_unverified(ikm, info, 32);
    assert!(derived.is_ok(), "derive_key_unverified() should succeed");
}

/// Test 1.10: AES-GCM functions are accessible
#[test]
fn test_aes_gcm_functions_accessible_are_stable() {
    let key = [0x42u8; 32];
    let data = b"plaintext";

    // encrypt_aes_gcm_unverified takes (data, key) - nonce is generated internally
    let encrypted = encrypt_aes_gcm_unverified(data, &key);
    assert!(encrypted.is_ok(), "encrypt_aes_gcm_unverified() should succeed");

    let ciphertext = encrypted.expect("encryption should succeed");
    let decrypted = decrypt_aes_gcm_unverified(&ciphertext, &key);
    assert!(decrypted.is_ok(), "decrypt_aes_gcm_unverified() should succeed");
}

/// Test 1.11: Hybrid encryption functions are accessible via unified API
#[test]
fn test_hybrid_encryption_functions_accessible_are_stable() {
    let data = b"plaintext";

    // generate_hybrid_keypair + unified encrypt for API stability
    let (pk, _sk) = generate_hybrid_keypair().expect("keygen");
    let encrypted = encrypt(data, EncryptKey::Hybrid(&pk), CryptoConfig::new());
    assert!(encrypted.is_ok(), "encrypt(Hybrid) should succeed");
}

/// Test 1.12: Ed25519 signature functions are accessible
#[test]
fn test_ed25519_functions_accessible_are_stable() {
    let (public_key, private_key) = generate_keypair().expect("keygen");
    let message = b"message to sign";

    // sign_ed25519_unverified for API stability
    let signature = sign_ed25519_unverified(message, private_key.expose_secret());
    assert!(signature.is_ok(), "sign_ed25519_unverified() should succeed");

    let sig = signature.expect("signing should succeed");
    let verified = verify_ed25519_unverified(message, &sig, public_key.as_slice());
    assert!(verified.is_ok(), "verify_ed25519_unverified() should succeed");
}

/// Test 1.13: CryptoPolicyEngine is accessible
#[test]
fn test_crypto_policy_engine_accessible_is_stable() {
    let engine = CryptoPolicyEngine::new();
    assert_eq!(size_of_val(&engine), 0); // Zero-sized type

    // default_scheme static method
    let scheme = CryptoPolicyEngine::default_scheme();
    assert!(!scheme.is_empty());
}

/// Test 1.14: Audit module types are accessible
#[test]
fn test_audit_types_accessible_are_stable() {
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
fn test_hardware_types_accessible_are_stable() {
    // Hardware type definitions are accessible (stubs removed — real detection in enterprise)
    let _info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 4,
            memory: 1024,
        },
    };
    assert!(_info.best_accelerator().is_some());
}

/// Test 1.16: Zero trust types are accessible
#[test]
fn test_zero_trust_types_accessible_are_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");

    // VerifiedSession can be established
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret());
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
fn test_security_level_variants_are_stable() {
    // All variants should exist
    let _standard = SecurityLevel::Standard;
    let _high = SecurityLevel::High;
    let _maximum = SecurityLevel::Maximum;

    // Default should be High
    assert_eq!(SecurityLevel::default(), SecurityLevel::High);
}

/// Test 2.2: PerformancePreference enum variants are stable
#[test]
fn test_performance_preference_variants_are_stable() {
    let _speed = PerformancePreference::Speed;
    let _memory = PerformancePreference::Memory;
    let _balanced = PerformancePreference::Balanced;

    // Default should be Balanced
    assert_eq!(PerformancePreference::default(), PerformancePreference::Balanced);
}

/// Test 2.3: UseCase enum has all expected variants
#[test]
fn test_use_case_variants_are_stable() {
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

    // General Purpose
    let _audit = UseCase::AuditLog;
}

/// Test 2.4: CryptoScheme enum variants are stable
#[test]
fn test_crypto_scheme_variants_are_stable() {
    let _hybrid = CryptoScheme::Hybrid;
    let _symmetric = CryptoScheme::Symmetric;
    let _asymmetric = CryptoScheme::Asymmetric;
    let _pq = CryptoScheme::PostQuantum;
}

/// Test 2.5: TrustLevel enum variants and ordering are stable
#[test]
fn test_trust_level_variants_are_stable() {
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
fn test_verification_status_variants_are_stable() {
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
fn test_proof_complexity_variants_are_stable() {
    let _low = ProofComplexity::Low;
    let _medium = ProofComplexity::Medium;
    let _high = ProofComplexity::High;
}

/// Test 2.8: HardwareType enum variants are stable
#[test]
fn test_hardware_type_variants_are_stable() {
    let _cpu = HardwareType::Cpu;
    let _gpu = HardwareType::Gpu;
    let _fpga = HardwareType::Fpga;
    let _tpu = HardwareType::Tpu;
    let _sgx = HardwareType::Sgx;
}

/// Test 2.9: PatternType enum variants are stable
#[test]
fn test_pattern_type_variants_are_stable() {
    let _random = PatternType::Random;
    let _structured = PatternType::Structured;
    let _repetitive = PatternType::Repetitive;
    let _text = PatternType::Text;
    let _binary = PatternType::Binary;
}

/// Test 2.10: KeyLifecycleState enum variants are stable
#[test]
fn test_key_lifecycle_state_variants_are_stable() {
    let _generation = KeyLifecycleState::Generation;
    let _active = KeyLifecycleState::Active;
    let _rotating = KeyLifecycleState::Rotating;
    let _retired = KeyLifecycleState::Retired;
    let _destroyed = KeyLifecycleState::Destroyed;
}

/// Test 2.11: CustodianRole enum variants are stable
#[test]
fn test_custodian_role_variants_are_stable() {
    let _generator = CustodianRole::KeyGenerator;
    let _approver = CustodianRole::KeyApprover;
    let _destroyer = CustodianRole::KeyDestroyer;
    let _auditor = CustodianRole::KeyAuditor;
}

/// Test 2.12: AlgorithmSelection enum variants are stable
#[test]
fn test_algorithm_selection_variants_are_stable() {
    let _use_case = AlgorithmSelection::UseCase(UseCase::FileStorage);
    let _security = AlgorithmSelection::SecurityLevel(SecurityLevel::High);

    // Default should be SecurityLevel(High)
    let default = AlgorithmSelection::default();
    assert!(matches!(default, AlgorithmSelection::SecurityLevel(SecurityLevel::High)));
}

/// Test 2.13: CoreError implements std::error::Error
#[test]
fn test_core_error_implements_error_trait_correctly_fails() {
    // CoreError should implement Error trait
    let error = CoreError::InvalidInput("test".to_string());
    let _: &dyn Error = &error;

    // Should have Display
    let display = format!("{}", error);
    assert!(!display.is_empty());
}

/// Test 2.14: CoreError variants are stable.
///
/// L6: previously this was `let _ = CoreError::Foo(...)` per
/// variant — a compile-time exhaustiveness check dressed as a
/// `#[test]`. The body was vacuous at runtime: every `let _ = ...`
/// passes if the type-checker accepts it. Migrated to assertions
/// that ALSO catch behavioural drift (Display string format, error
/// trait conformance) so a regression where `Display` started
/// emitting ANSI codes or stripping the variant name would fail
/// the test, not just the type-checker.
#[test]
fn test_core_error_variants_are_stable() {
    fn check_variant(err: CoreError, must_contain: &str) {
        let s = err.to_string();
        // Use `{err:?}` so a regression that returns an empty Display
        // string identifies the specific variant (e.g.
        // `VerificationFailed`) rather than the parent type name.
        assert!(!s.is_empty(), "CoreError::{err:?} produced an empty Display string");
        assert!(
            s.contains(must_contain),
            "Display for {err:?} should mention {must_contain:?} for log/audit attribution; got {s:?}",
        );
        // `error::Error` trait conformance — `source()` should not panic,
        // and the type must be `Send + Sync` for cross-thread propagation.
        let _: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&err);
        fn require_send_sync<T: Send + Sync>(_: &T) {}
        require_send_sync(&err);
    }

    // String-based errors
    check_variant(CoreError::InvalidInput("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::EncryptionFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::DecryptionFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::KeyDerivationFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::InvalidNonce("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::HardwareError("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::ConfigurationError("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::SchemeSelectionFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::AuthenticationFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::ZeroTrustVerificationFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::AuthenticationRequired("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::UnsupportedOperation("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::MemoryError("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::SerializationError("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::FeatureNotAvailable("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::InvalidSignature("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::InvalidKey("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::NotImplemented("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::SignatureFailed("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::HsmError("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::ResourceExceeded("probe-msg".to_string()), "probe-msg");
    check_variant(CoreError::AuditError("probe-msg".to_string()), "probe-msg");

    // Unit-struct variants must exercise the same Display +
    // Error::source + Send/Sync surface as the data-carrying variants
    // — `Send`/`source()` regressions on these two variants would
    // otherwise go undetected (a bespoke `is_empty()`-only assertion
    // doesn't cover the trait surface).
    check_variant(CoreError::VerificationFailed, "verification");
    check_variant(CoreError::SessionExpired, "expired");

    // Structured errors — Display must include the structural fields
    // so log/audit consumers can attribute the failure.
    check_variant(CoreError::InvalidKeyLength { expected: 32, actual: 16 }, "32");
    check_variant(CoreError::InvalidKeyLength { expected: 32, actual: 16 }, "16");
    check_variant(
        CoreError::Recoverable {
            message: "probe-rec".to_string(),
            suggestion: "try again".to_string(),
        },
        "probe-rec",
    );
    check_variant(
        CoreError::HardwareUnavailable {
            reason: "probe-hw".to_string(),
            fallback: "software".to_string(),
        },
        "probe-hw",
    );
    check_variant(
        CoreError::EntropyDepleted { message: "probe-ent".to_string(), action: "wait".to_string() },
        "probe-ent",
    );
    check_variant(
        CoreError::KeyGenerationFailed {
            reason: "probe-kg".to_string(),
            recovery: "retry".to_string(),
        },
        "probe-kg",
    );
    check_variant(
        CoreError::SelfTestFailed {
            component: "probe-AES".to_string(),
            status: "KAT failed".to_string(),
        },
        "probe-AES",
    );
    check_variant(
        CoreError::InvalidStateTransition {
            from: KeyLifecycleState::Active,
            to: KeyLifecycleState::Generation,
        },
        "Active",
    );
}

/// Test 2.15: Struct field accessibility - CryptoConfig
#[test]
fn test_crypto_config_field_accessibility_is_stable() {
    // CryptoConfig builder methods
    let config = CryptoConfig::new();

    // Methods should be accessible
    let _ = config.get_session();
    let _ = config.get_selection();
    let _ = config.is_verified();
    let _ = config.validate();

    // Builder pattern should work
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session");
    let config = CryptoConfig::new()
        .session(&session)
        .use_case(UseCase::FileStorage)
        .security_level(SecurityLevel::Maximum);

    assert!(config.is_verified());
}

/// Test 2.16: Struct field accessibility - CoreConfig
#[test]
fn test_core_config_field_accessibility_is_stable() {
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
fn test_encrypted_metadata_field_accessibility_is_stable() {
    let metadata = EncryptedMetadata::symmetric(
        vec![0u8; 12],
        Some(vec![0u8; 16]),
        Some("key-123".to_string()),
    );

    // Fields should be accessible
    assert_eq!(metadata.nonce.len(), 12);
    assert!(metadata.tag.is_some());
    assert!(metadata.key_id.is_some());
}

/// Test 2.18: Struct field accessibility - SignedMetadata
#[test]
fn test_signed_metadata_field_accessibility_is_stable() {
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
fn test_encrypt_function_works_correctly_succeeds() {
    let key = [0x42u8; 32];
    let data = b"test data";

    // Test symmetric encryption works with correct return type
    let result: Result<Vec<u8>> = encrypt_aes_gcm_unverified(data, &key);
    assert!(result.is_ok());

    // Verify unified encrypt() function signature exists (compile-time check)
    fn _assert_signature(
        _data: &[u8],
        _key: EncryptKey<'_>,
        _config: CryptoConfig,
    ) -> Result<EncryptedOutput> {
        encrypt(_data, _key, _config)
    }
}

/// Test 3.2: decrypt function signature is stable
/// Note: The unified decrypt() with CryptoConfig requires PQ keys.
/// Use decrypt_aes_gcm_unverified() for symmetric decryption with 32-byte keys.
#[test]
fn test_decrypt_function_works_correctly_succeeds() {
    let key = [0x42u8; 32];
    let data = b"test data";

    // Test symmetric encryption/decryption roundtrip
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let result: Result<latticearc::Zeroizing<Vec<u8>>> =
        decrypt_aes_gcm_unverified(&encrypted, &key);
    assert!(result.is_ok());
    assert_eq!(result.expect("decrypt").as_slice(), data.as_slice());

    // Verify unified decrypt() function signature exists (compile-time check)
    fn _assert_signature(
        _encrypted: &EncryptedOutput,
        _key: DecryptKey<'_>,
        _config: CryptoConfig,
    ) -> Result<latticearc::Zeroizing<Vec<u8>>> {
        decrypt(_encrypted, _key, _config)
    }
}

/// Test 3.3: generate_keypair function returns expected types
#[test]
fn test_generate_keypair_returns_expected_types_correctly_succeeds() {
    let result: Result<(PublicKey, PrivateKey)> = generate_keypair();
    assert!(result.is_ok());

    let (pk, sk) = result.expect("keygen");
    assert!(!pk.is_empty());
    assert!(!sk.expose_secret().is_empty());
}

/// Test 3.4: hash_data function returns expected type
#[test]
fn test_hash_data_returns_expected_type_correctly_succeeds() {
    let data = b"test data";
    let raw: [u8; 32] = hash_data(data);
    let result = HashOutput::new(raw);
    assert_eq!(result.as_slice().len(), 32);
}

/// Test 3.5: VerifiedSession::establish works with expected types
#[test]
fn test_verified_session_establish_works_correctly_succeeds() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let result: Result<VerifiedSession> =
        VerifiedSession::establish(pk.as_slice(), sk.expose_secret());
    assert!(result.is_ok());
}

/// Test 3.6: VerifiedSession methods return expected types
#[test]
fn test_verified_session_method_return_types_are_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session");

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
fn test_security_mode_method_return_types_are_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session");

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
fn test_crypto_policy_engine_method_return_types_are_stable() {
    let config = CoreConfig::default();
    let data = b"test data";

    // Static method return types (CryptoPolicyEngine returns TypeError, not CoreError)
    type TypeResult<T> = std::result::Result<T, TypeError>;
    let _: TypeResult<String> =
        CryptoPolicyEngine::recommend_scheme(&UseCase::FileStorage, &config);
    let _: String = CryptoPolicyEngine::force_scheme(&CryptoScheme::Hybrid);
    let _: TypeResult<String> = CryptoPolicyEngine::select_pq_encryption_scheme(&config);
    let _: TypeResult<String> = CryptoPolicyEngine::select_pq_signature_scheme(&config);
    let _: DataCharacteristics = CryptoPolicyEngine::analyze_data_characteristics(data);
    let _: TypeResult<String> = CryptoPolicyEngine::select_encryption_scheme(data, &config, None);
    let _: TypeResult<String> = CryptoPolicyEngine::select_signature_scheme(&config);
    let _: TypeResult<String> = CryptoPolicyEngine::select_encryption_scheme(data, &config, None);
    let _: &str = CryptoPolicyEngine::default_scheme();

    let metrics = PerformanceMetrics::default();
    let _: TypeResult<String> = CryptoPolicyEngine::adaptive_selection(data, &metrics, &config);
}

/// Test 3.9: ZeroTrustAuth methods return expected types
#[test]
fn test_zero_trust_auth_method_return_types_are_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");

    // Method return types
    let _: Result<Challenge> = auth.generate_challenge();
    let challenge = auth.generate_challenge().expect("challenge");
    let _: Result<bool> = auth.verify_challenge_age(&challenge);
    // `start_continuous_verification` now returns `Result` to enforce
    // the precondition that a successful proof has been verified
    // (rejects fresh `ZeroTrustAuth` instances). Pin the new type.
    let _: Result<ContinuousSession> = auth.start_continuous_verification();
}

/// Test 3.10: ZeroTrustSession methods return expected types
#[test]
fn test_zero_trust_session_method_return_types_are_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");
    let mut session = ZeroTrustSession::new(auth);

    // Method return types
    let _: Result<Challenge> = session.initiate_authentication();
    let _: bool = session.is_authenticated();
    let _: Result<u64> = session.session_age_ms();
}

/// Test 3.11: HardwareInfo methods return expected types
#[test]
fn test_hardware_info_method_return_types_are_stable() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 1,
            memory: 0,
        },
    };

    // Method return types
    let _: Option<&HardwareType> = info.best_accelerator();
    let _: String = info.summary();
}

/// Test 3.12: KeyStateMachine methods return expected types
#[test]
fn test_key_state_machine_method_return_types_are_stable() {
    // Static method return types
    let _: bool = KeyStateMachine::is_valid_transition(None, KeyLifecycleState::Generation);
    let _: Vec<KeyLifecycleState> = KeyStateMachine::allowed_next_states(KeyLifecycleState::Active);
}

/// Test 3.14: Trait implementations on types are stable
#[test]
fn test_trait_implementations_are_stable() {
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

/// Test 3.15: Public type newtypes work correctly
#[test]
fn test_type_aliases_work_correctly_succeeds() {
    // PublicKey wraps Vec<u8>
    let pk: PublicKey = PublicKey::new(vec![0u8; 32]);
    assert_eq!(pk.len(), 32);

    // HashOutput wraps [u8; 32]
    let hash: HashOutput = HashOutput::new([0u8; 32]);
    assert_eq!(hash.as_slice().len(), 32);
}

/// Test 3.16: Result type alias works correctly
#[test]
fn test_result_type_alias_works_correctly_succeeds() {
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
fn test_unverified_aes_gcm_works_correctly_succeeds() {
    let key = [0x42u8; 32];
    let data = b"test data";

    // These unverified functions provide migration path for legacy code
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted.as_slice(), data.as_slice());
}

/// Test 4.2: Hybrid encryption works (ML-KEM-768 + X25519 + HKDF + AES-GCM)
#[test]
fn test_hybrid_encryption_works_correctly_succeeds() {
    let data = b"test data";

    // generate_hybrid_keypair + unified encrypt/decrypt roundtrip
    let (pk, sk) = generate_hybrid_keypair().expect("keygen");
    let encrypted: EncryptedOutput =
        encrypt(data, EncryptKey::Hybrid(&pk), CryptoConfig::new()).expect("encrypt");

    // EncryptedOutput has hybrid_data with ml_kem_ciphertext, ecdh_ephemeral_pk
    let hybrid = encrypted.hybrid_data().expect("hybrid_data must be present");
    assert_eq!(hybrid.ml_kem_ciphertext().len(), 1088, "ML-KEM-768 CT");
    assert_eq!(hybrid.ecdh_ephemeral_pk().len(), 32, "X25519 PK");

    let decrypted =
        decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new()).expect("decrypt");
    assert_eq!(decrypted.as_slice(), data);
}

/// Test 4.3: Legacy Ed25519 signing works
#[test]
fn test_legacy_ed25519_signing_works_correctly_succeeds() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let message = b"test message";

    let signature = sign_ed25519_unverified(message, sk.expose_secret()).expect("sign");
    let verified = verify_ed25519_unverified(message, &signature, pk.as_slice()).expect("verify");
    assert!(verified);
}

/// Test 4.4: Legacy HMAC functions work
#[test]
fn test_legacy_hmac_functions_work_correctly_succeeds() {
    let key = [0x42u8; 32];
    let data = b"test data";

    let mac = hmac_unverified(data, &key).expect("hmac");
    let valid = hmac_check_unverified(data, &key, &mac).expect("check");
    assert!(valid);
}

/// Test 4.5: Legacy key derivation works
#[test]
fn test_legacy_key_derivation_works_correctly_succeeds() {
    let ikm = b"input key material";
    let info = b"context";

    let key = derive_key_unverified(ikm, info, 32).expect("derive");
    assert_eq!(key.len(), 32);
}

/// Test 4.6: Migration from SecurityMode::Unverified to Verified
/// Note: This tests the migration path from legacy unverified functions to session-based.
/// The unified API with CryptoConfig uses PQ hybrid encryption by default.
#[test]
fn test_migration_to_verified_mode_succeeds() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let key = [0x42u8; 32];
    let data = b"sensitive data";

    // Step 1: Legacy code uses unverified mode (symmetric encryption)
    let encrypted_legacy = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");

    // Step 2: New code establishes a session
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session");

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
fn test_default_config_backward_compatible_is_stable() {
    let key = [0x42u8; 32];
    let data = b"test data";

    // Default config should work without session
    let config = CryptoConfig::new();
    assert!(!config.is_verified());

    // Symmetric operations use the unverified API for backward compatibility
    let encrypted = encrypt_aes_gcm_unverified(data, &key).expect("encrypt");
    let decrypted = decrypt_aes_gcm_unverified(&encrypted, &key).expect("decrypt");
    assert_eq!(decrypted.as_slice(), data.as_slice());

    // CryptoConfig validation should work without session
    assert!(config.validate().is_ok());
}

/// Test 4.8: CoreConfig::for_development provides relaxed settings
#[test]
fn test_development_config_compatible_is_stable() {
    let config = CoreConfig::for_development();

    // Development config should be valid
    assert!(config.validate().is_ok());

    // Should have relaxed settings
    assert_eq!(config.security_level, SecurityLevel::Standard);
    assert!(!config.strict_validation);
}

/// Test 4.9: CoreConfig::for_production provides strong defaults
#[test]
fn test_production_config_compatible_is_stable() {
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
fn test_empty_data_handling_is_stable() {
    let key = [0x42u8; 32];
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
fn test_large_data_handling_is_stable() {
    let key = [0x42u8; 32];
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

/// Test 5.1: `SecretVec` provides secure memory handling.
///
/// Replaces the 0.7.x `test_zeroized_bytes_api_is_stable` test; `ZeroizedBytes`
/// was consolidated into `SecretVec` in 0.8.0. `SecretVec` does not implement
/// `AsRef<[u8]>` (invariant I-8) — byte access is via `expose_secret()` only.
#[test]
fn test_secret_vec_api_is_stable() {
    let data = vec![1, 2, 3, 4, 5];
    let sv = SecretVec::new(data);

    let _slice: &[u8] = sv.expose_secret();
    let _len: usize = sv.len();
    let _empty: bool = sv.is_empty();
}

/// Test 5.2: KeyPair provides secure key storage
#[test]
fn test_keypair_api_is_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");

    // Create KeyPair directly
    let keypair = KeyPair::new(pk.clone(), sk);

    // Methods should be accessible
    let _public: &PublicKey = keypair.public_key();
    let _private: &PrivateKey = keypair.private_key();

    // Public key accessible via method
    let _ = keypair.public_key();
}

/// Test 5.3: CryptoContext is constructable and usable
#[test]
fn test_crypto_context_api_is_stable() {
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
fn test_data_characteristics_api_is_stable() {
    let data = b"test data for analysis";
    let characteristics = CryptoPolicyEngine::analyze_data_characteristics(data);

    // Fields should be accessible
    let _size: usize = characteristics.size;
    let _entropy: f64 = characteristics.entropy;
    let _pattern: PatternType = characteristics.pattern_type;
}

/// Test 5.5: HardwareInfo structure is stable
#[test]
fn test_hardware_info_api_is_stable() {
    let info = HardwareInfo {
        available_accelerators: vec![HardwareType::Cpu],
        preferred_accelerator: Some(HardwareType::Cpu),
        capabilities: HardwareCapabilities {
            simd_support: true,
            aes_ni: true,
            threads: 8,
            memory: 0,
        },
    };

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
fn test_hardware_capabilities_api_is_stable() {
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
fn test_performance_metrics_defaults_are_stable() {
    let metrics = PerformanceMetrics::default();

    // Fields should be accessible with sensible defaults
    assert!(metrics.encryption_speed_ms > 0.0);
    assert!(metrics.memory_usage_mb > 0.0);
}

/// Test 5.8: Challenge structure is stable
#[test]
fn test_challenge_structure_is_stable() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let auth = ZeroTrustAuth::new(pk, sk).expect("auth");
    let challenge = auth.generate_challenge().expect("challenge");

    // Fields should be accessible via methods
    let _data: &[u8] = challenge.data();
    let _timestamp: chrono::DateTime<chrono::Utc> = challenge.timestamp();
    let _complexity: &ProofComplexity = challenge.complexity();
    let _timeout: u64 = challenge.timeout_ms();
}

/// Test 5.10: KeyLifecycleRecord construction is stable
#[test]
fn test_key_lifecycle_record_is_stable() {
    let record =
        KeyLifecycleRecord::new("key-123".to_string(), "ML-KEM-768".to_string(), 3, 365, 30);

    // Fields should be accessible
    assert_eq!(record.key_id, "key-123");
    assert_eq!(record.key_type, "ML-KEM-768");
    assert_eq!(record.security_level, 3);
    // Lifecycle state-machine fields are private; read via accessors.
    assert_eq!(record.current_state(), KeyLifecycleState::Generation);
}

/// Test 5.11: AuditEvent construction is stable
#[test]
fn test_audit_event_construction_is_stable() {
    let event =
        AuditEvent::new(AuditEventType::CryptoOperation, "encrypt_data", AuditOutcome::Success);

    // Methods should be accessible
    assert!(!event.id().is_empty());
    assert_eq!(event.action(), "encrypt_data");
    assert_eq!(*event.outcome(), AuditOutcome::Success);
}

/// Test 5.12: SecurityMode conversion from VerifiedSession
#[test]
fn test_security_mode_from_verified_session_succeeds() {
    let (pk, sk) = generate_keypair().expect("keygen");
    let session = VerifiedSession::establish(pk.as_slice(), sk.expose_secret()).expect("session");

    // From trait should work
    let mode: SecurityMode = (&session).into();
    assert!(mode.is_verified());
}

/// Test 5.13: SecurityMode default is Unverified
#[test]
fn test_security_mode_default_is_correct() {
    let mode = SecurityMode::Unverified;
    assert!(mode.is_unverified());
}
