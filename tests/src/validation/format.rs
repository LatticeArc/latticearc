#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Format validation for keys, ciphertexts, etc.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Invalid key size: {0} != {1}")]
    InvalidKeySize(usize, usize),
}

/// Validate that a key has the expected format (size).
///
/// # Errors
/// Returns an error if the key length does not match the expected size.
pub fn validate_key_format(key: &[u8], expected_size: usize) -> Result<(), FormatError> {
    if key.len() != expected_size {
        return Err(FormatError::InvalidKeySize(key.len(), expected_size));
    }
    Ok(())
}
