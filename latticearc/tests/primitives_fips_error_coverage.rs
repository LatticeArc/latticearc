#![deny(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(missing_docs)]

//! Coverage tests for fips_error.rs
//!
//! Targets all FipsErrorCode variants, methods, and FipsError type.

use latticearc::primitives::fips_error::{FipsCompliantError, FipsError, FipsErrorCode};

// ============================================================================
// FipsErrorCode::code() - all variants
// ============================================================================

#[test]
fn test_error_code_values() {
    // Self-test codes (0x0001-0x00FF)
    assert_eq!(FipsErrorCode::SelfTestFailed.code(), 0x0001);
    assert_eq!(FipsErrorCode::IntegrityCheckFailed.code(), 0x0002);
    assert_eq!(FipsErrorCode::ConditionalTestFailed.code(), 0x0003);
    assert_eq!(FipsErrorCode::KatFailed.code(), 0x0004);
    assert_eq!(FipsErrorCode::ContinuousRngTestFailed.code(), 0x0005);

    // Algorithm codes (0x0100-0x01FF)
    assert_eq!(FipsErrorCode::InvalidKeyLength.code(), 0x0100);
    assert_eq!(FipsErrorCode::InvalidNonce.code(), 0x0101);
    assert_eq!(FipsErrorCode::DecryptionFailed.code(), 0x0102);
    assert_eq!(FipsErrorCode::SignatureInvalid.code(), 0x0103);
    assert_eq!(FipsErrorCode::InvalidParameter.code(), 0x0104);
    assert_eq!(FipsErrorCode::UnsupportedAlgorithm.code(), 0x0105);
    assert_eq!(FipsErrorCode::KeyGenerationFailed.code(), 0x0106);
    assert_eq!(FipsErrorCode::EncapsulationFailed.code(), 0x0107);
    assert_eq!(FipsErrorCode::DecapsulationFailed.code(), 0x0108);
    assert_eq!(FipsErrorCode::SigningFailed.code(), 0x0109);
    assert_eq!(FipsErrorCode::InvalidCiphertext.code(), 0x010A);
    assert_eq!(FipsErrorCode::InvalidPublicKey.code(), 0x010B);
    assert_eq!(FipsErrorCode::InvalidSecretKey.code(), 0x010C);
    assert_eq!(FipsErrorCode::EncryptionFailed.code(), 0x010D);
    assert_eq!(FipsErrorCode::HashFailed.code(), 0x010E);
    assert_eq!(FipsErrorCode::MacFailed.code(), 0x010F);
    assert_eq!(FipsErrorCode::KeyDerivationFailed.code(), 0x0110);

    // Operational codes (0x0200-0x02FF)
    assert_eq!(FipsErrorCode::RngFailure.code(), 0x0200);
    assert_eq!(FipsErrorCode::ZeroizationFailed.code(), 0x0201);
    assert_eq!(FipsErrorCode::ResourceExhausted.code(), 0x0202);
    assert_eq!(FipsErrorCode::InternalError.code(), 0x0203);
    assert_eq!(FipsErrorCode::IoError.code(), 0x0204);
    assert_eq!(FipsErrorCode::SerializationFailed.code(), 0x0205);
    assert_eq!(FipsErrorCode::DeserializationFailed.code(), 0x0206);
    assert_eq!(FipsErrorCode::BufferTooSmall.code(), 0x0207);
    assert_eq!(FipsErrorCode::Timeout.code(), 0x0208);

    // Status codes (0x0300-0x03FF)
    assert_eq!(FipsErrorCode::ModuleNotInitialized.code(), 0x0300);
    assert_eq!(FipsErrorCode::OperationNotPermitted.code(), 0x0301);
    assert_eq!(FipsErrorCode::ModuleInErrorState.code(), 0x0302);
    assert_eq!(FipsErrorCode::FeatureNotAvailable.code(), 0x0303);
    assert_eq!(FipsErrorCode::KeyValidationFailed.code(), 0x0304);
    assert_eq!(FipsErrorCode::WeakKeyDetected.code(), 0x0305);
}

// ============================================================================
// FipsErrorCode::message() - all variants
// ============================================================================

#[test]
fn test_error_messages() {
    assert_eq!(FipsErrorCode::SelfTestFailed.message(), "Power-up self-test failed");
    assert_eq!(FipsErrorCode::IntegrityCheckFailed.message(), "Integrity check failed");
    assert_eq!(FipsErrorCode::ConditionalTestFailed.message(), "Conditional self-test failed");
    assert_eq!(FipsErrorCode::KatFailed.message(), "Known answer test failed");
    assert_eq!(FipsErrorCode::ContinuousRngTestFailed.message(), "Continuous RNG test failed");
    assert_eq!(FipsErrorCode::InvalidKeyLength.message(), "Invalid key length");
    assert_eq!(FipsErrorCode::InvalidNonce.message(), "Invalid nonce or IV");
    assert_eq!(FipsErrorCode::DecryptionFailed.message(), "Decryption authentication failed");
    assert_eq!(FipsErrorCode::SignatureInvalid.message(), "Signature verification failed");
    assert_eq!(FipsErrorCode::InvalidParameter.message(), "Invalid parameter");
    assert_eq!(FipsErrorCode::UnsupportedAlgorithm.message(), "Unsupported algorithm");
    assert_eq!(FipsErrorCode::KeyGenerationFailed.message(), "Key generation failed");
    assert_eq!(FipsErrorCode::EncapsulationFailed.message(), "Encapsulation failed");
    assert_eq!(FipsErrorCode::DecapsulationFailed.message(), "Decapsulation failed");
    assert_eq!(FipsErrorCode::SigningFailed.message(), "Signing failed");
    assert_eq!(FipsErrorCode::InvalidCiphertext.message(), "Invalid ciphertext");
    assert_eq!(FipsErrorCode::InvalidPublicKey.message(), "Invalid public key");
    assert_eq!(FipsErrorCode::InvalidSecretKey.message(), "Invalid secret key");
    assert_eq!(FipsErrorCode::EncryptionFailed.message(), "Encryption failed");
    assert_eq!(FipsErrorCode::HashFailed.message(), "Hash operation failed");
    assert_eq!(FipsErrorCode::MacFailed.message(), "MAC operation failed");
    assert_eq!(FipsErrorCode::KeyDerivationFailed.message(), "Key derivation failed");
    assert_eq!(FipsErrorCode::RngFailure.message(), "Random number generation failed");
    assert_eq!(FipsErrorCode::ZeroizationFailed.message(), "Key zeroization failed");
    assert_eq!(FipsErrorCode::ResourceExhausted.message(), "Resource exhausted");
    assert_eq!(FipsErrorCode::InternalError.message(), "Internal error");
    assert_eq!(FipsErrorCode::IoError.message(), "I/O error");
    assert_eq!(FipsErrorCode::SerializationFailed.message(), "Serialization failed");
    assert_eq!(FipsErrorCode::DeserializationFailed.message(), "Deserialization failed");
    assert_eq!(FipsErrorCode::BufferTooSmall.message(), "Buffer too small");
    assert_eq!(FipsErrorCode::Timeout.message(), "Operation timeout");
    assert_eq!(FipsErrorCode::ModuleNotInitialized.message(), "Module not initialized");
    assert_eq!(FipsErrorCode::OperationNotPermitted.message(), "Operation not permitted");
    assert_eq!(FipsErrorCode::ModuleInErrorState.message(), "Module in error state");
    assert_eq!(FipsErrorCode::FeatureNotAvailable.message(), "Feature not available");
    assert_eq!(FipsErrorCode::KeyValidationFailed.message(), "Key validation failed");
    assert_eq!(FipsErrorCode::WeakKeyDetected.message(), "Weak key detected");
}

// ============================================================================
// FipsErrorCode::is_critical()
// ============================================================================

#[test]
fn test_is_critical() {
    // Critical codes
    assert!(FipsErrorCode::SelfTestFailed.is_critical());
    assert!(FipsErrorCode::IntegrityCheckFailed.is_critical());
    assert!(FipsErrorCode::ConditionalTestFailed.is_critical());
    assert!(FipsErrorCode::KatFailed.is_critical());
    assert!(FipsErrorCode::ContinuousRngTestFailed.is_critical());
    assert!(FipsErrorCode::ModuleInErrorState.is_critical());

    // Non-critical codes
    assert!(!FipsErrorCode::InvalidKeyLength.is_critical());
    assert!(!FipsErrorCode::RngFailure.is_critical());
    assert!(!FipsErrorCode::ModuleNotInitialized.is_critical());
    assert!(!FipsErrorCode::WeakKeyDetected.is_critical());
}

// ============================================================================
// FipsErrorCode range checks
// ============================================================================

#[test]
fn test_is_self_test_error() {
    assert!(FipsErrorCode::SelfTestFailed.is_self_test_error());
    assert!(FipsErrorCode::KatFailed.is_self_test_error());
    assert!(FipsErrorCode::ContinuousRngTestFailed.is_self_test_error());
    assert!(!FipsErrorCode::InvalidKeyLength.is_self_test_error());
    assert!(!FipsErrorCode::RngFailure.is_self_test_error());
    assert!(!FipsErrorCode::ModuleNotInitialized.is_self_test_error());
}

#[test]
fn test_is_algorithm_error() {
    assert!(FipsErrorCode::InvalidKeyLength.is_algorithm_error());
    assert!(FipsErrorCode::DecryptionFailed.is_algorithm_error());
    assert!(FipsErrorCode::SigningFailed.is_algorithm_error());
    assert!(FipsErrorCode::KeyDerivationFailed.is_algorithm_error());
    assert!(!FipsErrorCode::SelfTestFailed.is_algorithm_error());
    assert!(!FipsErrorCode::RngFailure.is_algorithm_error());
}

#[test]
fn test_is_operational_error() {
    assert!(FipsErrorCode::RngFailure.is_operational_error());
    assert!(FipsErrorCode::ZeroizationFailed.is_operational_error());
    assert!(FipsErrorCode::ResourceExhausted.is_operational_error());
    assert!(FipsErrorCode::Timeout.is_operational_error());
    assert!(!FipsErrorCode::InvalidKeyLength.is_operational_error());
    assert!(!FipsErrorCode::ModuleNotInitialized.is_operational_error());
}

#[test]
fn test_is_status_code() {
    assert!(FipsErrorCode::ModuleNotInitialized.is_status_code());
    assert!(FipsErrorCode::OperationNotPermitted.is_status_code());
    assert!(FipsErrorCode::ModuleInErrorState.is_status_code());
    assert!(FipsErrorCode::FeatureNotAvailable.is_status_code());
    assert!(FipsErrorCode::KeyValidationFailed.is_status_code());
    assert!(FipsErrorCode::WeakKeyDetected.is_status_code());
    assert!(!FipsErrorCode::InvalidKeyLength.is_status_code());
    assert!(!FipsErrorCode::RngFailure.is_status_code());
}

// ============================================================================
// FipsErrorCode::category()
// ============================================================================

#[test]
fn test_category() {
    assert_eq!(FipsErrorCode::SelfTestFailed.category(), "SELF_TEST");
    assert_eq!(FipsErrorCode::InvalidKeyLength.category(), "ALGORITHM");
    assert_eq!(FipsErrorCode::RngFailure.category(), "OPERATIONAL");
    assert_eq!(FipsErrorCode::ModuleNotInitialized.category(), "STATUS");
}

// ============================================================================
// FipsErrorCode Display
// ============================================================================

#[test]
fn test_display_format() {
    let code = FipsErrorCode::InvalidKeyLength;
    let display = format!("{}", code);
    assert!(display.starts_with("FIPS-0100:"));
    assert!(display.contains("Invalid key length"));
}

#[test]
fn test_display_critical() {
    let code = FipsErrorCode::SelfTestFailed;
    let display = format!("{}", code);
    assert!(display.starts_with("FIPS-0001:"));
}

// ============================================================================
// FipsErrorCode Debug, Clone, Copy, Eq, Hash
// ============================================================================

#[test]
fn test_debug() {
    let code = FipsErrorCode::DecryptionFailed;
    let debug = format!("{:?}", code);
    assert!(debug.contains("DecryptionFailed"));
}

#[test]
fn test_clone_copy() {
    let code = FipsErrorCode::RngFailure;
    let cloned = code;
    assert_eq!(code, cloned);
}

#[test]
fn test_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(FipsErrorCode::SelfTestFailed);
    set.insert(FipsErrorCode::InvalidKeyLength);
    set.insert(FipsErrorCode::SelfTestFailed); // Duplicate
    assert_eq!(set.len(), 2);
}

// ============================================================================
// FipsCompliantError type
// ============================================================================

#[test]
fn test_fips_compliant_error_new() {
    let err = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength);
    assert_eq!(err.code(), FipsErrorCode::InvalidKeyLength);
    assert!(err.context().is_none());
}

#[test]
fn test_fips_compliant_error_with_context() {
    let err =
        FipsCompliantError::new(FipsErrorCode::DecryptionFailed).with_context("auth tag mismatch");
    assert_eq!(err.code(), FipsErrorCode::DecryptionFailed);
    assert_eq!(err.context(), Some("auth tag mismatch"));
}

#[test]
fn test_fips_compliant_error_display_no_context() {
    let err = FipsCompliantError::new(FipsErrorCode::RngFailure);
    let display = format!("{}", err);
    assert!(display.contains("FIPS-0200"));
}

#[test]
fn test_fips_compliant_error_display_with_context() {
    let err =
        FipsCompliantError::new(FipsErrorCode::DecryptionFailed).with_context("auth tag mismatch");
    let display = format!("{}", err);
    assert!(display.contains("FIPS-0102"));
    assert!(display.contains("auth tag mismatch"));
}

#[test]
fn test_fips_compliant_error_debug() {
    let err = FipsCompliantError::new(FipsErrorCode::RngFailure).with_context("entropy low");
    let debug = format!("{:?}", err);
    assert!(debug.contains("FipsCompliantError"));
}

#[test]
fn test_fips_compliant_error_is_critical() {
    let critical = FipsCompliantError::new(FipsErrorCode::SelfTestFailed);
    let non_critical = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength);
    assert!(critical.is_critical());
    assert!(!non_critical.is_critical());
}

#[test]
fn test_fips_compliant_error_clone_eq() {
    let err = FipsCompliantError::new(FipsErrorCode::Timeout).with_context("took too long");
    let cloned = err.clone();
    assert_eq!(err, cloned);
    assert_eq!(err.code(), cloned.code());
    assert_eq!(err.context(), cloned.context());
}

// ============================================================================
// FipsError trait methods
// ============================================================================

#[test]
fn test_fips_error_trait_fips_code() {
    let err = FipsCompliantError::new(FipsErrorCode::BufferTooSmall);
    assert_eq!(err.fips_code(), FipsErrorCode::BufferTooSmall);
}

#[test]
fn test_fips_error_trait_fips_message() {
    let err = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength);
    let msg = err.fips_message();
    assert!(msg.contains("FIPS-0100"));
    assert!(msg.contains("Invalid key length"));
}

#[test]
fn test_fips_error_trait_is_fips_critical() {
    let critical = FipsCompliantError::new(FipsErrorCode::IntegrityCheckFailed);
    let non_critical = FipsCompliantError::new(FipsErrorCode::IoError);
    assert!(critical.is_fips_critical());
    assert!(!non_critical.is_fips_critical());
}
