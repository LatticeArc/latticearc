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
    fn from(_err: getrandom::Error) -> Self {
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
        LatticeArcError::EncryptionError(format!("Key rejected: {:?}", err))
    }
}

impl From<std::array::TryFromSliceError> for LatticeArcError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        LatticeArcError::InvalidData(format!("Slice conversion error: {err}"))
    }
}

impl From<tokio::task::JoinError> for LatticeArcError {
    fn from(err: tokio::task::JoinError) -> Self {
        LatticeArcError::AsyncError(format!("Join error: {err}"))
    }
}

#[cfg(feature = "database")]
impl From<rusqlite::Error> for LatticeArcError {
    fn from(err: rusqlite::Error) -> Self {
        LatticeArcError::DatabaseError(err.to_string())
    }
}
#[cfg(feature = "database")]
impl From<tokio_postgres::Error> for LatticeArcError {
    fn from(err: tokio_postgres::Error) -> Self {
        LatticeArcError::DatabaseError(err.to_string())
    }
}

impl From<std::alloc::LayoutError> for LatticeArcError {
    fn from(_err: std::alloc::LayoutError) -> Self {
        LatticeArcError::InvalidInput("Invalid memory layout".to_string())
    }
}

impl From<&str> for LatticeArcError {
    fn from(err: &str) -> Self {
        LatticeArcError::InvalidInput(err.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: LatticeArcError = io_err.into();
        match err {
            LatticeArcError::IoError(msg) => assert!(msg.contains("file not found")),
            other => panic!("Expected IoError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_aws_lc_unspecified() {
        let aws_err = aws_lc_rs::error::Unspecified;
        let err: LatticeArcError = aws_err.into();
        match err {
            LatticeArcError::EncryptionError(msg) => assert!(msg.contains("aws-lc-rs")),
            other => panic!("Expected EncryptionError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_system_time_error() {
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
    fn test_from_serde_json_error() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err: LatticeArcError = json_err.into();
        match err {
            LatticeArcError::SerializationError(msg) => assert!(msg.contains("JSON error")),
            other => panic!("Expected SerializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_utf8_error() {
        let invalid_bytes = vec![0, 159, 146, 150];
        let utf8_err = String::from_utf8(invalid_bytes).unwrap_err();
        let err: LatticeArcError = utf8_err.into();
        match err {
            LatticeArcError::SerializationError(msg) => assert!(msg.contains("UTF-8")),
            other => panic!("Expected SerializationError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_hex_error() {
        let hex_err = hex::decode("not_hex!").unwrap_err();
        let err: LatticeArcError = hex_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("Hex")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn test_from_uuid_error() {
        let uuid_err = uuid::Uuid::parse_str("not-a-uuid").unwrap_err();
        let err: LatticeArcError = uuid_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("UUID")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn test_from_try_from_slice_error() {
        let slice: &[u8] = &[1, 2, 3];
        let result: Result<[u8; 4], _> = slice.try_into();
        let slice_err = result.unwrap_err();
        let err: LatticeArcError = slice_err.into();
        match err {
            LatticeArcError::InvalidData(msg) => assert!(msg.contains("Slice conversion")),
            other => panic!("Expected InvalidData, got {:?}", other),
        }
    }

    #[test]
    fn test_from_str() {
        let err: LatticeArcError = "some error".into();
        match err {
            LatticeArcError::InvalidInput(msg) => assert_eq!(msg, "some error"),
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_from_layout_error() {
        // LayoutError is created from invalid layout parameters
        let layout_err = std::alloc::Layout::from_size_align(usize::MAX, 3).unwrap_err();
        let err: LatticeArcError = layout_err.into();
        match err {
            LatticeArcError::InvalidInput(msg) => assert!(msg.contains("memory layout")),
            other => panic!("Expected InvalidInput, got {:?}", other),
        }
    }

    #[test]
    fn test_from_getrandom_error() {
        let code = core::num::NonZeroU32::new(1).unwrap();
        let rand_err = getrandom::Error::from(code);
        let err: LatticeArcError = rand_err.into();
        match err {
            LatticeArcError::RandomError => {} // expected
            other => panic!("Expected RandomError, got {:?}", other),
        }
    }

    #[test]
    fn test_from_key_rejected() {
        // Create a KeyRejected error by using an invalid ECDSA key
        use aws_lc_rs::signature;
        let invalid_pkcs8 = [0u8; 10]; // Too short to be valid PKCS#8
        let key_err = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &invalid_pkcs8,
        )
        .unwrap_err();
        let err: LatticeArcError = key_err.into();
        match err {
            LatticeArcError::EncryptionError(msg) => assert!(msg.contains("Key rejected")),
            other => panic!("Expected EncryptionError, got {:?}", other),
        }
    }
}
