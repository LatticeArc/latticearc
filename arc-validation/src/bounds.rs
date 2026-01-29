#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Bounds checking for security

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BoundsError {
    #[error("Value too small: {0} < {1}")]
    ValueTooSmall(usize, usize),
    #[error("Value too large: {0} > {1}")]
    ValueTooLarge(usize, usize),
}

/// Validate that a value falls within the specified bounds.
///
/// # Errors
/// Returns an error if the value is smaller than `min` or larger than `max`.
pub fn validate_bounds(value: usize, min: usize, max: usize) -> Result<(), BoundsError> {
    if value < min {
        return Err(BoundsError::ValueTooSmall(value, min));
    }
    if value > max {
        return Err(BoundsError::ValueTooLarge(value, max));
    }
    Ok(())
}
