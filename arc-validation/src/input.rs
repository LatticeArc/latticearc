#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Input validation for cryptographic operations

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Input too small: {0} < {1}")]
    InputTooSmall(usize, usize),
    #[error("Input too large: {0} > {1}")]
    InputTooLarge(usize, usize),
}

/// Validate that an input size falls within the specified range.
///
/// # Errors
/// Returns an error if the input is smaller than `min` or larger than `max`.
pub fn validate_input_size(input: &[u8], min: usize, max: usize) -> Result<(), ValidationError> {
    if input.len() < min {
        return Err(ValidationError::InputTooSmall(input.len(), min));
    }
    if input.len() > max {
        return Err(ValidationError::InputTooLarge(input.len(), max));
    }
    Ok(())
}
