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

#[cfg(all(feature = "async", not(target_arch = "wasm32")))]
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
