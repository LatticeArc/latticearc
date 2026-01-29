#![deny(unsafe_code)]
#![deny(missing_docs)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Output validation and bounds checking

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OutputError {
    #[error("Invalid output length: {0}")]
    InvalidLength(String),
    #[error("Output contains invalid byte at position: {position}, value: 0x{byte:02x}")]
    InvalidByte { position: usize, byte: u8 },
    #[error("Output too large: {size} bytes (maximum: {max} bytes)")]
    OutputTooLarge { size: usize, max: usize },
    #[error("Output is empty")]
    EmptyOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BoundsError {
    #[error("Value {actual} out of bounds (expected: {min}..={max})")]
    OutOfBounds { actual: usize, min: usize, max: usize },
    #[error("Invalid bounds: min {min} cannot be greater than max {max}")]
    InvalidBounds { min: usize, max: usize },
}

/// Trait for output validation.
pub trait OutputValidator {
    /// Validate the output data.
    ///
    /// # Errors
    /// Returns an error if the output is empty.
    fn validate_output(&self, output: &[u8]) -> Result<(), OutputError>;
}

/// Trait for bounds checking.
pub trait BoundsChecker {
    /// Check that a value's length falls within bounds.
    ///
    /// # Errors
    /// Returns an error if the length is outside the min/max range or bounds are invalid.
    fn check_bounds(&self, value: &[u8], min: usize, max: usize) -> Result<(), BoundsError>;
}

pub struct SimpleValidator;

impl Default for SimpleValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleValidator {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OutputValidator for SimpleValidator {
    fn validate_output(&self, output: &[u8]) -> Result<(), OutputError> {
        if output.is_empty() {
            return Err(OutputError::EmptyOutput);
        }

        let max_size = 10 * 1024 * 1024;
        if output.len() > max_size {
            return Err(OutputError::OutputTooLarge { size: output.len(), max: max_size });
        }

        for (i, byte) in output.iter().enumerate() {
            if *byte == 0xFF {
                return Err(OutputError::InvalidByte { position: i, byte: *byte });
            }
        }

        Ok(())
    }
}

impl BoundsChecker for SimpleValidator {
    fn check_bounds(&self, value: &[u8], min: usize, max: usize) -> Result<(), BoundsError> {
        if min > max {
            return Err(BoundsError::InvalidBounds { min, max });
        }

        if value.len() < min || value.len() > max {
            return Err(BoundsError::OutOfBounds { actual: value.len(), min, max });
        }

        Ok(())
    }
}
