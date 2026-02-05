//! Regression test for issue #001
//!
//! **Issue**: Empty ciphertext handling
//! **Link**: https://github.com/example/latticearc/issues/1
//!
//! ## Bug Description
//!
//! When an empty ciphertext was passed to `MlKemCiphertext::new()`, the error
//! message was unclear and didn't indicate the actual problem.
//!
//! ## Fix Description
//!
//! Added explicit check for empty input with descriptive error message
//! `InvalidCiphertextLength` that includes expected vs actual size.
//!
//! ## Test Strategy
//!
//! Verify that empty ciphertext is rejected with appropriate error type
//! and the error contains useful diagnostic information.

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use arc_primitives::kem::ml_kem::{MlKemCiphertext, MlKemError, MlKemSecurityLevel};

    #[test]
    fn regression_issue_001_empty_ciphertext_rejected() {
        let empty = vec![];
        let result = MlKemCiphertext::new(MlKemSecurityLevel::MlKem512, empty);

        assert!(result.is_err(), "Empty ciphertext should be rejected");

        match result {
            Err(MlKemError::InvalidCiphertextLength { variant, expected, actual }) => {
                assert_eq!(variant, "ML-KEM-512", "Should indicate ML-KEM-512 variant");
                assert_eq!(expected, 768, "Should show expected size");
                assert_eq!(actual, 0, "Should show actual size is 0");
            }
            Err(e) => panic!("Expected InvalidCiphertextLength, got: {:?}", e),
            Ok(_) => panic!("Should not succeed with empty ciphertext"),
        }
    }

    #[test]
    fn regression_issue_001_empty_ciphertext_all_levels() {
        let levels = [
            (MlKemSecurityLevel::MlKem512, 768),
            (MlKemSecurityLevel::MlKem768, 1088),
            (MlKemSecurityLevel::MlKem1024, 1568),
        ];

        for (level, expected_size) in levels {
            let empty = vec![];
            let result = MlKemCiphertext::new(level, empty);

            assert!(result.is_err(), "Empty ciphertext should be rejected for {:?}", level);

            if let Err(MlKemError::InvalidCiphertextLength { expected, actual, .. }) = result {
                assert_eq!(expected, expected_size);
                assert_eq!(actual, 0);
            }
        }
    }
}
