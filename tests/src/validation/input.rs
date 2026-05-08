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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test/bench code: unwrap is acceptable when inputs are statically known"
)]
#[expect(clippy::panic, reason = "test/bench/macro-expanded assertion path")]
mod tests {
    use super::*;

    #[test]
    fn test_validate_input_size_ok_has_correct_size() {
        let input = [0u8; 16];
        assert!(validate_input_size(&input, 1, 32).is_ok());
    }

    #[test]
    fn test_validate_input_size_exact_min_has_correct_size() {
        let input = [0u8; 8];
        assert!(validate_input_size(&input, 8, 32).is_ok());
    }

    #[test]
    fn test_validate_input_size_exact_max_has_correct_size() {
        let input = [0u8; 32];
        assert!(validate_input_size(&input, 1, 32).is_ok());
    }

    #[test]
    fn test_validate_input_size_too_small_fails() {
        let input = [0u8; 4];
        let err = validate_input_size(&input, 8, 32).unwrap_err();
        match err {
            ValidationError::InputTooSmall(actual, min) => {
                assert_eq!(actual, 4);
                assert_eq!(min, 8);
            }
            other => panic!("Expected InputTooSmall, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_input_size_too_large_fails() {
        let input = [0u8; 64];
        let err = validate_input_size(&input, 1, 32).unwrap_err();
        match err {
            ValidationError::InputTooLarge(actual, max) => {
                assert_eq!(actual, 64);
                assert_eq!(max, 32);
            }
            other => panic!("Expected InputTooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_input_size_empty_ok_has_correct_size() {
        let input: &[u8] = &[];
        assert!(validate_input_size(input, 0, 100).is_ok());
    }

    #[test]
    fn test_validate_input_size_empty_too_small_fails() {
        let input: &[u8] = &[];
        assert!(validate_input_size(input, 1, 100).is_err());
    }

    #[test]
    fn test_validation_error_display_too_small_fails() {
        let err = ValidationError::InputTooSmall(4, 8);
        let msg = format!("{err}");
        assert!(msg.contains("4"));
        assert!(msg.contains("8"));
        assert!(msg.contains("too small"));
    }

    #[test]
    fn test_validation_error_display_too_large_fails() {
        let err = ValidationError::InputTooLarge(64, 32);
        let msg = format!("{err}");
        assert!(msg.contains("64"));
        assert!(msg.contains("32"));
        assert!(msg.contains("too large"));
    }

    #[test]
    fn test_validation_error_debug_fails() {
        let err = ValidationError::InputTooSmall(1, 2);
        let debug = format!("{err:?}");
        assert!(debug.contains("InputTooSmall"));
    }

    #[test]
    fn test_validate_min_equals_max_succeeds() {
        let input = [0u8; 16];
        assert!(validate_input_size(&input, 16, 16).is_ok());
    }
}
