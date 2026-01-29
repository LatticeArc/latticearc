//! FIPS 140-3 Compliant Error Codes
//!
//! This module provides FIPS 140-3 compliant error codes for cryptographic module
//! status indication, as required by FIPS 140-3 Section 7.10.2 (Error Indicator).
//!
//! # Error Code Ranges
//!
//! - `0x0001-0x00FF`: Self-test and integrity errors
//! - `0x0100-0x01FF`: Algorithm errors
//! - `0x0200-0x02FF`: Operational errors
//! - `0x0300-0x03FF`: Status codes
//!
//! # FIPS 140-3 Compliance
//!
//! Per FIPS 140-3 requirements:
//! - Error messages do not reveal sensitive cryptographic information
//! - Critical errors (self-test, integrity) require module shutdown
//! - All errors are logged with sanitized output suitable for audit trails

use core::fmt;

/// FIPS 140-3 compliant error codes for cryptographic module status indication.
///
/// These codes follow the FIPS 140-3 error reporting requirements and provide
/// standardized error identification without revealing sensitive information.
///
/// # Error Code Ranges
///
/// - `0x0001-0x00FF`: Self-test and integrity errors (critical)
/// - `0x0100-0x01FF`: Algorithm errors
/// - `0x0200-0x02FF`: Operational errors
/// - `0x0300-0x03FF`: Status codes
///
/// # Example
///
/// ```
/// use arc_primitives::fips_error::{FipsErrorCode, FipsError};
///
/// let code = FipsErrorCode::InvalidKeyLength;
/// assert_eq!(code.code(), 0x0100);
/// assert!(!code.is_critical());
///
/// // Display as FIPS-formatted string
/// let msg = format!("{}", code);
/// assert!(msg.starts_with("FIPS-0100:"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum FipsErrorCode {
    // ========================================================================
    // Self-test and Integrity Errors (0x0001-0x00FF) - CRITICAL
    // ========================================================================
    /// Power-up self-test failed.
    ///
    /// The cryptographic module failed its power-up self-tests as required by
    /// FIPS 140-3 Section 9.1. The module must not perform any cryptographic
    /// operations until the self-test passes.
    SelfTestFailed = 0x0001,

    /// Software/firmware integrity check failed.
    ///
    /// The integrity verification of the cryptographic module's code failed.
    /// This indicates potential tampering or corruption.
    IntegrityCheckFailed = 0x0002,

    /// Conditional self-test failed.
    ///
    /// A conditional self-test (e.g., pairwise consistency test, continuous
    /// RNG test) failed during operation.
    ConditionalTestFailed = 0x0003,

    /// Known Answer Test (KAT) failed.
    ///
    /// A Known Answer Test during self-test produced incorrect results,
    /// indicating the algorithm implementation may be compromised.
    KatFailed = 0x0004,

    /// Continuous RNG test failed.
    ///
    /// The continuous random number generator test detected repeated output
    /// or other anomalies in the RNG.
    ContinuousRngTestFailed = 0x0005,

    // ========================================================================
    // Algorithm Errors (0x0100-0x01FF)
    // ========================================================================
    /// Invalid key length for the algorithm.
    ///
    /// The provided key does not meet the length requirements for the
    /// specified algorithm.
    InvalidKeyLength = 0x0100,

    /// Invalid nonce or initialization vector.
    ///
    /// The provided nonce/IV is invalid (wrong length, reused, or malformed).
    InvalidNonce = 0x0101,

    /// Decryption failed due to authentication tag mismatch.
    ///
    /// The ciphertext authentication failed, indicating the data was
    /// tampered with or the wrong key was used.
    DecryptionFailed = 0x0102,

    /// Digital signature verification failed.
    ///
    /// The signature does not match the message and public key, indicating
    /// the message was modified or the signature is invalid.
    SignatureInvalid = 0x0103,

    /// Invalid parameter provided to algorithm.
    ///
    /// A parameter provided to the cryptographic operation does not meet
    /// the algorithm's requirements.
    InvalidParameter = 0x0104,

    /// Algorithm not supported or not approved.
    ///
    /// The requested algorithm is not available in this module configuration
    /// or is not FIPS-approved.
    UnsupportedAlgorithm = 0x0105,

    /// Key generation failed.
    ///
    /// The cryptographic key generation operation failed.
    KeyGenerationFailed = 0x0106,

    /// KEM encapsulation failed.
    ///
    /// The Key Encapsulation Mechanism encapsulation operation failed.
    EncapsulationFailed = 0x0107,

    /// KEM decapsulation failed.
    ///
    /// The Key Encapsulation Mechanism decapsulation operation failed.
    DecapsulationFailed = 0x0108,

    /// Signing operation failed.
    ///
    /// The digital signature generation operation failed.
    SigningFailed = 0x0109,

    /// Invalid ciphertext.
    ///
    /// The ciphertext is malformed or has an invalid length.
    InvalidCiphertext = 0x010A,

    /// Invalid public key.
    ///
    /// The public key is malformed, has invalid length, or failed validation.
    InvalidPublicKey = 0x010B,

    /// Invalid secret key.
    ///
    /// The secret/private key is malformed, has invalid length, or failed
    /// validation.
    InvalidSecretKey = 0x010C,

    /// Encryption operation failed.
    ///
    /// The encryption operation failed due to an internal error.
    EncryptionFailed = 0x010D,

    /// Hash operation failed.
    ///
    /// The hash/digest operation failed.
    HashFailed = 0x010E,

    /// MAC operation failed.
    ///
    /// The Message Authentication Code operation failed.
    MacFailed = 0x010F,

    /// Key derivation failed.
    ///
    /// The key derivation function operation failed.
    KeyDerivationFailed = 0x0110,

    // ========================================================================
    // Operational Errors (0x0200-0x02FF)
    // ========================================================================
    /// Random number generation failed.
    ///
    /// The cryptographic random number generator failed to produce output.
    /// This may indicate an entropy source failure.
    RngFailure = 0x0200,

    /// Key zeroization failed.
    ///
    /// The secure erasure of key material from memory could not be verified.
    ZeroizationFailed = 0x0201,

    /// Resource exhausted.
    ///
    /// A required resource (memory, handles, etc.) is exhausted.
    ResourceExhausted = 0x0202,

    /// Internal error.
    ///
    /// An unexpected internal error occurred in the cryptographic module.
    InternalError = 0x0203,

    /// Input/output error.
    ///
    /// An I/O operation required by the cryptographic module failed.
    IoError = 0x0204,

    /// Serialization failed.
    ///
    /// Failed to serialize cryptographic data to the specified format.
    SerializationFailed = 0x0205,

    /// Deserialization failed.
    ///
    /// Failed to deserialize cryptographic data from the input.
    DeserializationFailed = 0x0206,

    /// Buffer too small.
    ///
    /// The output buffer provided is too small for the operation result.
    BufferTooSmall = 0x0207,

    /// Operation timeout.
    ///
    /// The cryptographic operation exceeded the allowed time limit.
    Timeout = 0x0208,

    // ========================================================================
    // Status Codes (0x0300-0x03FF)
    // ========================================================================
    /// Module not initialized.
    ///
    /// The cryptographic module has not been initialized. Self-tests must
    /// complete before operations can be performed.
    ModuleNotInitialized = 0x0300,

    /// Operation not permitted in current state.
    ///
    /// The requested operation is not allowed in the module's current
    /// operational state.
    OperationNotPermitted = 0x0301,

    /// Module in error state.
    ///
    /// The cryptographic module is in an error state and cannot perform
    /// operations. A module reset may be required.
    ModuleInErrorState = 0x0302,

    /// Feature not available.
    ///
    /// The requested feature is not available in this build configuration.
    FeatureNotAvailable = 0x0303,

    /// Key validation failed.
    ///
    /// The key failed validation checks (e.g., weak key detection).
    KeyValidationFailed = 0x0304,

    /// Weak key detected.
    ///
    /// The key was detected as cryptographically weak and rejected.
    WeakKeyDetected = 0x0305,
}

impl FipsErrorCode {
    /// Returns the numeric error code.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert_eq!(FipsErrorCode::SelfTestFailed.code(), 0x0001);
    /// assert_eq!(FipsErrorCode::InvalidKeyLength.code(), 0x0100);
    /// ```
    #[must_use]
    pub const fn code(&self) -> u32 {
        *self as u32
    }

    /// Returns a FIPS-compliant error message.
    ///
    /// These messages are designed to be safe for logging and do not
    /// reveal sensitive cryptographic information.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// let msg = FipsErrorCode::DecryptionFailed.message();
    /// assert_eq!(msg, "Decryption authentication failed");
    /// ```
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            // Self-test and integrity errors
            Self::SelfTestFailed => "Power-up self-test failed",
            Self::IntegrityCheckFailed => "Integrity check failed",
            Self::ConditionalTestFailed => "Conditional self-test failed",
            Self::KatFailed => "Known answer test failed",
            Self::ContinuousRngTestFailed => "Continuous RNG test failed",

            // Algorithm errors
            Self::InvalidKeyLength => "Invalid key length",
            Self::InvalidNonce => "Invalid nonce or IV",
            Self::DecryptionFailed => "Decryption authentication failed",
            Self::SignatureInvalid => "Signature verification failed",
            Self::InvalidParameter => "Invalid parameter",
            Self::UnsupportedAlgorithm => "Unsupported algorithm",
            Self::KeyGenerationFailed => "Key generation failed",
            Self::EncapsulationFailed => "Encapsulation failed",
            Self::DecapsulationFailed => "Decapsulation failed",
            Self::SigningFailed => "Signing failed",
            Self::InvalidCiphertext => "Invalid ciphertext",
            Self::InvalidPublicKey => "Invalid public key",
            Self::InvalidSecretKey => "Invalid secret key",
            Self::EncryptionFailed => "Encryption failed",
            Self::HashFailed => "Hash operation failed",
            Self::MacFailed => "MAC operation failed",
            Self::KeyDerivationFailed => "Key derivation failed",

            // Operational errors
            Self::RngFailure => "Random number generation failed",
            Self::ZeroizationFailed => "Key zeroization failed",
            Self::ResourceExhausted => "Resource exhausted",
            Self::InternalError => "Internal error",
            Self::IoError => "I/O error",
            Self::SerializationFailed => "Serialization failed",
            Self::DeserializationFailed => "Deserialization failed",
            Self::BufferTooSmall => "Buffer too small",
            Self::Timeout => "Operation timeout",

            // Status codes
            Self::ModuleNotInitialized => "Module not initialized",
            Self::OperationNotPermitted => "Operation not permitted",
            Self::ModuleInErrorState => "Module in error state",
            Self::FeatureNotAvailable => "Feature not available",
            Self::KeyValidationFailed => "Key validation failed",
            Self::WeakKeyDetected => "Weak key detected",
        }
    }

    /// Checks if this is a critical error requiring module shutdown.
    ///
    /// Critical errors indicate fundamental failures in the cryptographic
    /// module that prevent secure operation. Per FIPS 140-3, the module
    /// must cease all cryptographic operations when a critical error occurs.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert!(FipsErrorCode::SelfTestFailed.is_critical());
    /// assert!(FipsErrorCode::IntegrityCheckFailed.is_critical());
    /// assert!(!FipsErrorCode::InvalidKeyLength.is_critical());
    /// ```
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::SelfTestFailed
                | Self::IntegrityCheckFailed
                | Self::ConditionalTestFailed
                | Self::KatFailed
                | Self::ContinuousRngTestFailed
                | Self::ModuleInErrorState
        )
    }

    /// Checks if this error is in the self-test/integrity range.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert!(FipsErrorCode::SelfTestFailed.is_self_test_error());
    /// assert!(!FipsErrorCode::InvalidKeyLength.is_self_test_error());
    /// ```
    #[must_use]
    pub const fn is_self_test_error(&self) -> bool {
        let code = self.code();
        code >= 0x0001 && code <= 0x00FF
    }

    /// Checks if this error is in the algorithm error range.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert!(FipsErrorCode::InvalidKeyLength.is_algorithm_error());
    /// assert!(FipsErrorCode::DecryptionFailed.is_algorithm_error());
    /// assert!(!FipsErrorCode::RngFailure.is_algorithm_error());
    /// ```
    #[must_use]
    pub const fn is_algorithm_error(&self) -> bool {
        let code = self.code();
        code >= 0x0100 && code <= 0x01FF
    }

    /// Checks if this error is in the operational error range.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert!(FipsErrorCode::RngFailure.is_operational_error());
    /// assert!(FipsErrorCode::ResourceExhausted.is_operational_error());
    /// assert!(!FipsErrorCode::InvalidKeyLength.is_operational_error());
    /// ```
    #[must_use]
    pub const fn is_operational_error(&self) -> bool {
        let code = self.code();
        code >= 0x0200 && code <= 0x02FF
    }

    /// Checks if this is a status code rather than an error.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert!(FipsErrorCode::ModuleNotInitialized.is_status_code());
    /// assert!(FipsErrorCode::FeatureNotAvailable.is_status_code());
    /// assert!(!FipsErrorCode::InvalidKeyLength.is_status_code());
    /// ```
    #[must_use]
    pub const fn is_status_code(&self) -> bool {
        let code = self.code();
        code >= 0x0300 && code <= 0x03FF
    }

    /// Returns the error category as a string.
    ///
    /// # Example
    ///
    /// ```
    /// use arc_primitives::fips_error::FipsErrorCode;
    ///
    /// assert_eq!(FipsErrorCode::SelfTestFailed.category(), "SELF_TEST");
    /// assert_eq!(FipsErrorCode::InvalidKeyLength.category(), "ALGORITHM");
    /// assert_eq!(FipsErrorCode::RngFailure.category(), "OPERATIONAL");
    /// assert_eq!(FipsErrorCode::ModuleNotInitialized.category(), "STATUS");
    /// ```
    #[must_use]
    pub const fn category(&self) -> &'static str {
        if self.is_self_test_error() {
            "SELF_TEST"
        } else if self.is_algorithm_error() {
            "ALGORITHM"
        } else if self.is_operational_error() {
            "OPERATIONAL"
        } else {
            "STATUS"
        }
    }
}

impl fmt::Display for FipsErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FIPS-{:04X}: {}", self.code(), self.message())
    }
}

/// Trait for errors that can be converted to FIPS error codes.
///
/// Implement this trait for error types to provide FIPS-compliant error
/// reporting. The implementation should map each error variant to the
/// most appropriate FIPS error code.
///
/// # Example
///
/// ```
/// use arc_primitives::fips_error::{FipsError, FipsErrorCode};
///
/// #[derive(Debug)]
/// enum MyError {
///     BadKey,
///     Timeout,
/// }
///
/// impl FipsError for MyError {
///     fn fips_code(&self) -> FipsErrorCode {
///         match self {
///             MyError::BadKey => FipsErrorCode::InvalidKeyLength,
///             MyError::Timeout => FipsErrorCode::Timeout,
///         }
///     }
/// }
/// ```
pub trait FipsError {
    /// Returns the FIPS error code for this error.
    fn fips_code(&self) -> FipsErrorCode;

    /// Returns the FIPS-formatted error string.
    ///
    /// This is a convenience method that formats the error code for logging.
    fn fips_message(&self) -> String {
        self.fips_code().to_string()
    }

    /// Checks if this error is critical and requires module shutdown.
    fn is_fips_critical(&self) -> bool {
        self.fips_code().is_critical()
    }
}

/// A FIPS-compliant error wrapper that includes both the FIPS code and
/// optional context.
///
/// This type can be used when you need to carry additional context with
/// a FIPS error while still providing compliant error reporting.
///
/// # Example
///
/// ```
/// use arc_primitives::fips_error::{FipsErrorCode, FipsCompliantError};
///
/// let error = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength)
///     .with_context("AES-256 requires 32-byte key");
///
/// assert_eq!(error.code(), FipsErrorCode::InvalidKeyLength);
/// assert!(error.context().is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FipsCompliantError {
    code: FipsErrorCode,
    context: Option<String>,
}

impl FipsCompliantError {
    /// Creates a new FIPS-compliant error with the given code.
    #[must_use]
    pub const fn new(code: FipsErrorCode) -> Self {
        Self { code, context: None }
    }

    /// Adds context to the error.
    ///
    /// Note: Context should not include sensitive cryptographic data.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Returns the FIPS error code.
    #[must_use]
    pub const fn code(&self) -> FipsErrorCode {
        self.code
    }

    /// Returns the error context, if any.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// Checks if this is a critical error.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.code.is_critical()
    }
}

impl fmt::Display for FipsCompliantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.context {
            Some(ctx) => write!(f, "{} ({})", self.code, ctx),
            None => write!(f, "{}", self.code),
        }
    }
}

impl std::error::Error for FipsCompliantError {}

impl FipsError for FipsCompliantError {
    fn fips_code(&self) -> FipsErrorCode {
        self.code
    }
}

// ============================================================================
// Implementations of FipsError for arc-primitives error types
// ============================================================================

impl FipsError for crate::error::Error {
    fn fips_code(&self) -> FipsErrorCode {
        match self {
            Self::FeatureNotAvailable(_) => FipsErrorCode::FeatureNotAvailable,
            Self::InvalidInput(_) => FipsErrorCode::InvalidParameter,
            Self::EncryptionFailed(_) => FipsErrorCode::EncryptionFailed,
            Self::DecryptionFailed(_) => FipsErrorCode::DecryptionFailed,
            Self::SerializationError(_) => FipsErrorCode::SerializationFailed,
            Self::DeserializationError(_) => FipsErrorCode::DeserializationFailed,
            Self::Other(_) => FipsErrorCode::InternalError,
            Self::MlKem(e) => e.fips_code(),
            Self::ResourceExceeded(_) => FipsErrorCode::ResourceExhausted,
            Self::KeyValidationFailed => FipsErrorCode::KeyValidationFailed,
            Self::WeakKey => FipsErrorCode::WeakKeyDetected,
            Self::InvalidKeyFormat => FipsErrorCode::InvalidParameter,
        }
    }
}

impl FipsError for crate::kem::ml_kem::MlKemError {
    fn fips_code(&self) -> FipsErrorCode {
        match self {
            Self::KeyGenerationError(_) => FipsErrorCode::KeyGenerationFailed,
            Self::EncapsulationError(_) => FipsErrorCode::EncapsulationFailed,
            Self::DecapsulationError(_) => FipsErrorCode::DecapsulationFailed,
            Self::InvalidKeyLength { .. } => FipsErrorCode::InvalidKeyLength,
            Self::InvalidCiphertextLength { .. } => FipsErrorCode::InvalidCiphertext,
            Self::UnsupportedSecurityLevel(_) => FipsErrorCode::UnsupportedAlgorithm,
            Self::CryptoError(_) => FipsErrorCode::InternalError,
        }
    }
}

// ============================================================================
// Conversion utilities
// ============================================================================

impl From<FipsErrorCode> for FipsCompliantError {
    fn from(code: FipsErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<&crate::error::Error> for FipsErrorCode {
    fn from(error: &crate::error::Error) -> Self {
        error.fips_code()
    }
}

impl From<&crate::kem::ml_kem::MlKemError> for FipsErrorCode {
    fn from(error: &crate::kem::ml_kem::MlKemError) -> Self {
        error.fips_code()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_values() {
        // Self-test errors: 0x0001-0x00FF
        assert_eq!(FipsErrorCode::SelfTestFailed.code(), 0x0001);
        assert_eq!(FipsErrorCode::IntegrityCheckFailed.code(), 0x0002);
        assert_eq!(FipsErrorCode::ConditionalTestFailed.code(), 0x0003);
        assert_eq!(FipsErrorCode::KatFailed.code(), 0x0004);
        assert_eq!(FipsErrorCode::ContinuousRngTestFailed.code(), 0x0005);

        // Algorithm errors: 0x0100-0x01FF
        assert_eq!(FipsErrorCode::InvalidKeyLength.code(), 0x0100);
        assert_eq!(FipsErrorCode::InvalidNonce.code(), 0x0101);
        assert_eq!(FipsErrorCode::DecryptionFailed.code(), 0x0102);
        assert_eq!(FipsErrorCode::SignatureInvalid.code(), 0x0103);

        // Operational errors: 0x0200-0x02FF
        assert_eq!(FipsErrorCode::RngFailure.code(), 0x0200);
        assert_eq!(FipsErrorCode::ZeroizationFailed.code(), 0x0201);
        assert_eq!(FipsErrorCode::ResourceExhausted.code(), 0x0202);

        // Status codes: 0x0300-0x03FF
        assert_eq!(FipsErrorCode::ModuleNotInitialized.code(), 0x0300);
        assert_eq!(FipsErrorCode::OperationNotPermitted.code(), 0x0301);
        assert_eq!(FipsErrorCode::ModuleInErrorState.code(), 0x0302);
    }

    #[test]
    fn test_critical_errors() {
        // Critical errors
        assert!(FipsErrorCode::SelfTestFailed.is_critical());
        assert!(FipsErrorCode::IntegrityCheckFailed.is_critical());
        assert!(FipsErrorCode::ConditionalTestFailed.is_critical());
        assert!(FipsErrorCode::KatFailed.is_critical());
        assert!(FipsErrorCode::ContinuousRngTestFailed.is_critical());
        assert!(FipsErrorCode::ModuleInErrorState.is_critical());

        // Non-critical errors
        assert!(!FipsErrorCode::InvalidKeyLength.is_critical());
        assert!(!FipsErrorCode::DecryptionFailed.is_critical());
        assert!(!FipsErrorCode::RngFailure.is_critical());
        assert!(!FipsErrorCode::ModuleNotInitialized.is_critical());
    }

    #[test]
    fn test_error_categories() {
        // Self-test errors
        assert!(FipsErrorCode::SelfTestFailed.is_self_test_error());
        assert!(FipsErrorCode::IntegrityCheckFailed.is_self_test_error());
        assert!(!FipsErrorCode::InvalidKeyLength.is_self_test_error());

        // Algorithm errors
        assert!(FipsErrorCode::InvalidKeyLength.is_algorithm_error());
        assert!(FipsErrorCode::DecryptionFailed.is_algorithm_error());
        assert!(FipsErrorCode::SignatureInvalid.is_algorithm_error());
        assert!(!FipsErrorCode::RngFailure.is_algorithm_error());

        // Operational errors
        assert!(FipsErrorCode::RngFailure.is_operational_error());
        assert!(FipsErrorCode::ResourceExhausted.is_operational_error());
        assert!(!FipsErrorCode::InvalidKeyLength.is_operational_error());

        // Status codes
        assert!(FipsErrorCode::ModuleNotInitialized.is_status_code());
        assert!(FipsErrorCode::FeatureNotAvailable.is_status_code());
        assert!(!FipsErrorCode::InvalidKeyLength.is_status_code());
    }

    #[test]
    fn test_category_strings() {
        assert_eq!(FipsErrorCode::SelfTestFailed.category(), "SELF_TEST");
        assert_eq!(FipsErrorCode::InvalidKeyLength.category(), "ALGORITHM");
        assert_eq!(FipsErrorCode::RngFailure.category(), "OPERATIONAL");
        assert_eq!(FipsErrorCode::ModuleNotInitialized.category(), "STATUS");
    }

    #[test]
    fn test_display_format() {
        let code = FipsErrorCode::InvalidKeyLength;
        let display = format!("{}", code);
        assert_eq!(display, "FIPS-0100: Invalid key length");

        let code = FipsErrorCode::SelfTestFailed;
        let display = format!("{}", code);
        assert_eq!(display, "FIPS-0001: Power-up self-test failed");
    }

    #[test]
    fn test_fips_compliant_error() {
        let error = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength);
        assert_eq!(error.code(), FipsErrorCode::InvalidKeyLength);
        assert!(error.context().is_none());
        assert!(!error.is_critical());

        let error_with_context = FipsCompliantError::new(FipsErrorCode::InvalidKeyLength)
            .with_context("Expected 32 bytes");
        assert_eq!(error_with_context.context(), Some("Expected 32 bytes"));

        let display = format!("{}", error_with_context);
        assert!(display.contains("FIPS-0100"));
        assert!(display.contains("Expected 32 bytes"));
    }

    #[test]
    fn test_fips_error_trait() {
        let error = crate::error::Error::InvalidInput("test".to_string());
        assert_eq!(error.fips_code(), FipsErrorCode::InvalidParameter);
        assert!(!error.is_fips_critical());

        let ml_kem_error = crate::kem::ml_kem::MlKemError::KeyGenerationError("test".to_string());
        assert_eq!(ml_kem_error.fips_code(), FipsErrorCode::KeyGenerationFailed);

        let ml_kem_unsupported =
            crate::kem::ml_kem::MlKemError::UnsupportedSecurityLevel("test".to_string());
        assert_eq!(ml_kem_unsupported.fips_code(), FipsErrorCode::UnsupportedAlgorithm);

        let ml_kem_crypto = crate::kem::ml_kem::MlKemError::CryptoError("test".to_string());
        assert_eq!(ml_kem_crypto.fips_code(), FipsErrorCode::InternalError);
    }

    #[test]
    fn test_error_from_conversions() {
        let error = crate::error::Error::DecryptionFailed("auth failed".to_string());
        let fips_code: FipsErrorCode = (&error).into();
        assert_eq!(fips_code, FipsErrorCode::DecryptionFailed);
    }

    #[test]
    fn test_messages_no_sensitive_data() {
        // Verify messages don't contain sensitive patterns
        let sensitive_patterns = ["key=", "password", "secret", "private", "0x"];

        for code in [
            FipsErrorCode::SelfTestFailed,
            FipsErrorCode::InvalidKeyLength,
            FipsErrorCode::DecryptionFailed,
            FipsErrorCode::RngFailure,
            FipsErrorCode::ModuleNotInitialized,
        ] {
            let message = code.message().to_lowercase();
            for pattern in &sensitive_patterns {
                assert!(
                    !message.contains(pattern),
                    "Message for {:?} contains sensitive pattern '{}': {}",
                    code,
                    pattern,
                    message
                );
            }
        }
    }

    #[test]
    fn test_error_code_uniqueness() {
        // Collect all error codes to verify uniqueness
        let codes = [
            FipsErrorCode::SelfTestFailed,
            FipsErrorCode::IntegrityCheckFailed,
            FipsErrorCode::ConditionalTestFailed,
            FipsErrorCode::KatFailed,
            FipsErrorCode::ContinuousRngTestFailed,
            FipsErrorCode::InvalidKeyLength,
            FipsErrorCode::InvalidNonce,
            FipsErrorCode::DecryptionFailed,
            FipsErrorCode::SignatureInvalid,
            FipsErrorCode::InvalidParameter,
            FipsErrorCode::UnsupportedAlgorithm,
            FipsErrorCode::KeyGenerationFailed,
            FipsErrorCode::EncapsulationFailed,
            FipsErrorCode::DecapsulationFailed,
            FipsErrorCode::SigningFailed,
            FipsErrorCode::InvalidCiphertext,
            FipsErrorCode::InvalidPublicKey,
            FipsErrorCode::InvalidSecretKey,
            FipsErrorCode::EncryptionFailed,
            FipsErrorCode::HashFailed,
            FipsErrorCode::MacFailed,
            FipsErrorCode::KeyDerivationFailed,
            FipsErrorCode::RngFailure,
            FipsErrorCode::ZeroizationFailed,
            FipsErrorCode::ResourceExhausted,
            FipsErrorCode::InternalError,
            FipsErrorCode::IoError,
            FipsErrorCode::SerializationFailed,
            FipsErrorCode::DeserializationFailed,
            FipsErrorCode::BufferTooSmall,
            FipsErrorCode::Timeout,
            FipsErrorCode::ModuleNotInitialized,
            FipsErrorCode::OperationNotPermitted,
            FipsErrorCode::ModuleInErrorState,
            FipsErrorCode::FeatureNotAvailable,
            FipsErrorCode::KeyValidationFailed,
            FipsErrorCode::WeakKeyDetected,
        ];

        let mut seen = std::collections::HashSet::new();
        for code in codes {
            assert!(seen.insert(code.code()), "Duplicate error code: {:04X}", code.code());
        }
    }
}
