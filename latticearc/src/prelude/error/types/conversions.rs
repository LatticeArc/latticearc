//! Error Type Conversions
//!
//! This module provides `From` implementations for converting external error types
//! to `LatticeArcError`, enabling seamless error propagation with the `?` operator.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use super::LatticeArcError;

impl From<std::io::Error> for LatticeArcError {
    fn from(err: std::io::Error) -> Self {
        LatticeArcError::IoError(err.to_string())
    }
}

impl From<getrandom::Error> for LatticeArcError {
    fn from(err: getrandom::Error) -> Self {
        // M3: surface the upstream error in tracing logs
        // so operators investigating entropy-failure incidents see
        // the underlying cause (e.g. `Error::UNSUPPORTED`,
        // `Error::UNEXPECTED`, or a custom code) instead of just
        // "RandomError". The user-facing variant stays unit-shaped
        // because no caller branches on the discrimination today.
        // `getrandom 0.3` removed the `.code()` accessor; rely on
        // `Display`/`Debug` of the error itself.
        tracing::debug!(getrandom_error = %err, "getrandom failed");
        LatticeArcError::RandomError
    }
}

impl From<aws_lc_rs::error::Unspecified> for LatticeArcError {
    fn from(_err: aws_lc_rs::error::Unspecified) -> Self {
        LatticeArcError::EncryptionError("aws-lc-rs cryptographic error".to_string())
    }
}

impl From<std::time::SystemTimeError> for LatticeArcError {
    fn from(err: std::time::SystemTimeError) -> Self {
        LatticeArcError::EncryptionError(format!("System time error: {err}"))
    }
}

impl From<serde_json::Error> for LatticeArcError {
    fn from(err: serde_json::Error) -> Self {
        LatticeArcError::SerializationError(format!("JSON error: {err}"))
    }
}

impl From<std::string::FromUtf8Error> for LatticeArcError {
    fn from(_err: std::string::FromUtf8Error) -> Self {
        LatticeArcError::SerializationError("UTF-8 conversion error".to_string())
    }
}

impl From<hex::FromHexError> for LatticeArcError {
    fn from(err: hex::FromHexError) -> Self {
        LatticeArcError::InvalidData(format!("Hex decoding error: {}", err))
    }
}

impl From<uuid::Error> for LatticeArcError {
    fn from(err: uuid::Error) -> Self {
        LatticeArcError::InvalidData(format!("UUID error: {}", err))
    }
}

impl From<aws_lc_rs::error::KeyRejected> for LatticeArcError {
    fn from(err: aws_lc_rs::error::KeyRejected) -> Self {
        // M4: route through `InvalidInput` with a stable
        // string format instead of the previous
        // `EncryptionError(format!("{:?}"))`. `KeyRejected` is a
        // key-parsing failure, not a runtime encryption failure;
        // and the `{:?}` form leaked debug-formatted upstream
        // internals into a user-visible string. The
        // `aws_lc_rs::error::KeyRejected` Display impl is the
        // stable surface; we use that.
        LatticeArcError::InvalidInput(format!("Key rejected by aws-lc-rs: {err}"))
    }
}

impl From<std::array::TryFromSliceError> for LatticeArcError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        LatticeArcError::InvalidData(format!("Slice conversion error: {err}"))
    }
}

impl From<std::alloc::LayoutError> for LatticeArcError {
    fn from(_err: std::alloc::LayoutError) -> Self {
        LatticeArcError::InvalidInput("Invalid memory layout".to_string())
    }
}

// M2: deleted the blanket `From<&str>` for
// `LatticeArcError`. It fired automatically on `?` for any
// `Result<_, &str>`, silently coercing string errors into
// `InvalidInput` and erasing the original error type. No production
// caller relied on it (verified via `grep`), and the implicit
// conversion is a landmine for any future dep that returns
// `Result<_, &str>`. Callers that genuinely want a string-based
// error should construct the variant explicitly:
//   `LatticeArcError::InvalidInput(msg.to_string())`

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test/bench code: unwrap is acceptable when inputs are statically known"
)]
#[expect(clippy::panic, reason = "test/bench/macro-expanded assertion path")]
mod tests {
    use super::*;

    #[test]
    fn test_from_io_error_produces_io_error_variant_fails() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: LatticeArcError = io_err.into();
        match err {
            LatticeArcError::IoError(msg) => assert!(msg.contains("file not found")),
            other => panic!("Expected IoError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_aws_lc_unspecified_produces_encryption_error_variant_fails() {
        let aws_err = aws_lc_rs::error::Unspecified;
        let err: LatticeArcError = aws_err.into();
        match err {
            LatticeArcError::EncryptionError(msg) => assert!(msg.contains("aws-lc-rs")),
            other => panic!("Expected EncryptionError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_system_time_error_produces_encryption_error_variant_fails() {
        use std::time::{Duration, SystemTime};
        let earlier = SystemTime::UNIX_EPOCH;
        // SystemTimeError is created by duration_since when called with a future time
        let time_err =
            earlier.duration_since(SystemTime::UNIX_EPOCH + Duration::from_secs(1)).unwrap_err();
        let err: LatticeArcError = time_err.into();
        match err {
            LatticeArcError::EncryptionError(msg) => assert!(msg.contains("System time error")),
            other => panic!("Expected EncryptionError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_serde_json_error_produces_serialization_error_variant_fails() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err: LatticeArcError = json_err.into();
        match err {
            LatticeArcError::SerializationError(msg) => assert!(msg.contains("JSON error")),
            other => panic!("Expected SerializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_utf8_error_produces_serialization_error_variant_fails() {
        let invalid_bytes = vec![0, 159, 146, 150];
        let utf8_err = String::from_utf8(invalid_bytes).unwrap_err();
        let err: LatticeArcError = utf8_err.into();
        match err {
            LatticeArcError::SerializationError(msg) => assert!(msg.contains("UTF-8")),
            other => panic!("Expected SerializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_hex_error_produces_invalid_data_variant_fails() {
        let hex_err = hex::decode("not_hex!").unwrap_err();
        let err: LatticeArcError = hex_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("Hex")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn test_from_uuid_error_produces_invalid_data_variant_fails() {
        let uuid_err = uuid::Uuid::parse_str("not-a-uuid").unwrap_err();
        let err: LatticeArcError = uuid_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("UUID")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn test_from_try_from_slice_error_produces_invalid_data_variant_fails() {
        let slice: &[u8] = &[1, 2, 3];
        let result: Result<[u8; 4], _> = slice.try_into();
        let slice_err = result.unwrap_err();
        let err: LatticeArcError = slice_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("Slice conversion")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    // M2: deleted `test_from_str_produces_invalid_input_variant_fails`
    // alongside the `From<&str>` impl removal.

    #[test]
    fn test_from_layout_error_produces_invalid_input_variant_fails() {
        // LayoutError is created from invalid layout parameters
        let layout_err = std::alloc::Layout::from_size_align(usize::MAX, 3).unwrap_err();
        let err: LatticeArcError = layout_err.into();
        match err {
            LatticeArcError::InvalidInput(msg) => assert!(msg.contains("memory layout")),
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_from_getrandom_error_produces_random_error_variant_fails() {
        // `getrandom 0.3` removed the `From<NonZeroU32> for Error` impl and
        // moved error construction onto associated constants (`UNSUPPORTED`,
        // `UNEXPECTED`, …) plus `Error::new_custom(u16)`. Use one of those
        // for the test fixture.
        let rand_err = getrandom::Error::UNSUPPORTED;
        let err: LatticeArcError = rand_err.into();
        match err {
            LatticeArcError::RandomError => {} // expected
            other => panic!("Expected RandomError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_key_rejected_produces_invalid_input_variant() {
        // M4: assertion updated to match the new mapping —
        // `KeyRejected` now produces `InvalidInput` (it's a parse
        // failure, not a runtime encryption failure).
        use aws_lc_rs::signature;
        let invalid_pkcs8 = [0u8; 10]; // Too short to be valid PKCS#8
        let key_err = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &invalid_pkcs8,
        )
        .unwrap_err();
        let err: LatticeArcError = key_err.into();
        match err {
            LatticeArcError::InvalidInput(msg) => assert!(msg.contains("Key rejected")),
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }
}
