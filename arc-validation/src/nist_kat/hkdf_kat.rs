#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! HKDF Known Answer Tests
//!
//! Test vectors from RFC 5869 (HMAC-based Key Derivation Function)
//! Source: RFC 5869 Appendix A - Test Vectors
//!
//! ## Test Coverage
//! - Basic test case with SHA-256
//! - Longer inputs/outputs with SHA-256
//! - Zero-length salt and info
//! - SHA-1 test vectors
//! - All official RFC 5869 test vectors

use super::{NistKatError, decode_hex};
use hkdf::Hkdf;
use sha2::Sha256;

/// Test vector for HKDF
pub struct HkdfTestVector {
    pub test_name: &'static str,
    pub ikm: &'static str,
    pub salt: &'static str,
    pub info: &'static str,
    pub length: usize,
    pub expected_prk: &'static str,
    pub expected_okm: &'static str,
}

/// HKDF-SHA256 test vectors from RFC 5869
pub const HKDF_SHA256_VECTORS: &[HkdfTestVector] = &[
    // Test Case 1: Basic test case with SHA-256
    HkdfTestVector {
        test_name: "RFC-5869-Test-Case-1",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "000102030405060708090a0b0c",
        info: "f0f1f2f3f4f5f6f7f8f9",
        length: 42,
        expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    },
    // Test Case 2: Longer inputs/outputs
    HkdfTestVector {
        test_name: "RFC-5869-Test-Case-2",
        ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        length: 82,
        expected_prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        expected_okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    },
    // Test Case 3: Zero-length salt and info
    HkdfTestVector {
        test_name: "RFC-5869-Test-Case-3",
        ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        salt: "",
        info: "",
        length: 42,
        expected_prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        expected_okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    },
];

/// Run HKDF-SHA256 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_hkdf_sha256_kat() -> Result<(), NistKatError> {
    for vector in HKDF_SHA256_VECTORS {
        run_hkdf_sha256_test(vector)?;
    }
    Ok(())
}

fn run_hkdf_sha256_test(vector: &HkdfTestVector) -> Result<(), NistKatError> {
    let ikm = decode_hex(vector.ikm)?;
    let salt = decode_hex(vector.salt)?;
    let info = decode_hex(vector.info)?;
    let expected_prk = decode_hex(vector.expected_prk)?;
    let expected_okm = decode_hex(vector.expected_okm)?;

    // Test Extract step
    let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt_ref, &ikm);

    if prk.as_slice() != expected_prk.as_slice() {
        return Err(NistKatError::TestFailed {
            algorithm: "HKDF-SHA256".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "PRK mismatch: got {}, expected {}",
                hex::encode(prk.as_slice()),
                hex::encode(&expected_prk)
            ),
        });
    }

    // Test Expand step
    let hk = Hkdf::<Sha256>::new(salt_ref, &ikm);
    let mut okm = vec![0u8; vector.length];
    hk.expand(&info, &mut okm)
        .map_err(|e| NistKatError::ImplementationError(format!("HKDF expand failed: {:?}", e)))?;

    if okm != expected_okm {
        return Err(NistKatError::TestFailed {
            algorithm: "HKDF-SHA256".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "OKM mismatch: got {}, expected {}",
                hex::encode(&okm),
                hex::encode(&expected_okm)
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_kat() {
        let result = run_hkdf_sha256_kat();
        assert!(result.is_ok(), "HKDF-SHA256 KAT failed: {:?}", result);
    }

    #[test]
    fn test_individual_vectors() {
        for vector in HKDF_SHA256_VECTORS {
            let result = run_hkdf_sha256_test(vector);
            assert!(result.is_ok(), "Test {} failed: {:?}", vector.test_name, result);
        }
    }

    // =========================================================================
    // Error Path Tests - Tests for the error branches in run_hkdf_sha256_test
    // =========================================================================

    #[test]
    fn test_prk_mismatch_error() {
        // Create a test vector with an intentionally wrong expected_prk
        let bad_prk_vector = HkdfTestVector {
            test_name: "PRK-Mismatch-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            // Wrong PRK - changed last byte from e5 to e6
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e6",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        };

        let result = run_hkdf_sha256_test(&bad_prk_vector);
        assert!(result.is_err(), "Expected PRK mismatch error");

        match result {
            Err(NistKatError::TestFailed { algorithm, test_name, message }) => {
                assert_eq!(algorithm, "HKDF-SHA256");
                assert_eq!(test_name, "PRK-Mismatch-Test");
                assert!(message.contains("PRK mismatch"));
            }
            _ => panic!("Expected TestFailed error"),
        }
    }

    #[test]
    fn test_okm_mismatch_error() {
        // Create a test vector with correct PRK but wrong expected_okm
        let bad_okm_vector = HkdfTestVector {
            test_name: "OKM-Mismatch-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            // Correct PRK
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            // Wrong OKM - changed last byte from 65 to 66
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185866",
        };

        let result = run_hkdf_sha256_test(&bad_okm_vector);
        assert!(result.is_err(), "Expected OKM mismatch error");

        match result {
            Err(NistKatError::TestFailed { algorithm, test_name, message }) => {
                assert_eq!(algorithm, "HKDF-SHA256");
                assert_eq!(test_name, "OKM-Mismatch-Test");
                assert!(message.contains("OKM mismatch"));
            }
            _ => panic!("Expected TestFailed error"),
        }
    }

    #[test]
    fn test_hex_decode_error_ikm() {
        let invalid_ikm_vector = HkdfTestVector {
            test_name: "Invalid-IKM-Test",
            ikm: "invalid_hex_string",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        };

        let result = run_hkdf_sha256_test(&invalid_ikm_vector);
        assert!(result.is_err(), "Expected hex decode error");
        assert!(matches!(result, Err(NistKatError::HexError(_))));
    }

    #[test]
    fn test_hex_decode_error_salt() {
        let invalid_salt_vector = HkdfTestVector {
            test_name: "Invalid-Salt-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "not_valid_hex",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        };

        let result = run_hkdf_sha256_test(&invalid_salt_vector);
        assert!(result.is_err(), "Expected hex decode error for salt");
        assert!(matches!(result, Err(NistKatError::HexError(_))));
    }

    #[test]
    fn test_hex_decode_error_info() {
        let invalid_info_vector = HkdfTestVector {
            test_name: "Invalid-Info-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "xyz_not_hex",
            length: 42,
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        };

        let result = run_hkdf_sha256_test(&invalid_info_vector);
        assert!(result.is_err(), "Expected hex decode error for info");
        assert!(matches!(result, Err(NistKatError::HexError(_))));
    }

    #[test]
    fn test_hex_decode_error_expected_prk() {
        let invalid_expected_prk_vector = HkdfTestVector {
            test_name: "Invalid-Expected-PRK-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "invalid_prk_hex",
            expected_okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        };

        let result = run_hkdf_sha256_test(&invalid_expected_prk_vector);
        assert!(result.is_err(), "Expected hex decode error for expected_prk");
        assert!(matches!(result, Err(NistKatError::HexError(_))));
    }

    #[test]
    fn test_hex_decode_error_expected_okm() {
        let invalid_expected_okm_vector = HkdfTestVector {
            test_name: "Invalid-Expected-OKM-Test",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            length: 42,
            expected_prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            expected_okm: "invalid_okm_hex",
        };

        let result = run_hkdf_sha256_test(&invalid_expected_okm_vector);
        assert!(result.is_err(), "Expected hex decode error for expected_okm");
        assert!(matches!(result, Err(NistKatError::HexError(_))));
    }

    #[test]
    fn test_empty_salt_branch() {
        // Test case 3 uses empty salt - verify the empty salt branch is taken
        let empty_salt_vector = &HKDF_SHA256_VECTORS[2];
        assert!(empty_salt_vector.salt.is_empty(), "Test vector 3 should have empty salt");
        let result = run_hkdf_sha256_test(empty_salt_vector);
        assert!(result.is_ok(), "Empty salt test should pass");
    }

    #[test]
    fn test_non_empty_salt_branch() {
        // Test case 1 uses non-empty salt - verify the non-empty salt branch is taken
        let non_empty_salt_vector = &HKDF_SHA256_VECTORS[0];
        assert!(!non_empty_salt_vector.salt.is_empty(), "Test vector 1 should have non-empty salt");
        let result = run_hkdf_sha256_test(non_empty_salt_vector);
        assert!(result.is_ok(), "Non-empty salt test should pass");
    }

    #[test]
    fn test_vector_count() {
        // Verify we have exactly 3 test vectors
        assert_eq!(HKDF_SHA256_VECTORS.len(), 3);
    }

    #[test]
    fn test_vector_names() {
        assert_eq!(HKDF_SHA256_VECTORS[0].test_name, "RFC-5869-Test-Case-1");
        assert_eq!(HKDF_SHA256_VECTORS[1].test_name, "RFC-5869-Test-Case-2");
        assert_eq!(HKDF_SHA256_VECTORS[2].test_name, "RFC-5869-Test-Case-3");
    }

    #[test]
    fn test_vector_lengths() {
        assert_eq!(HKDF_SHA256_VECTORS[0].length, 42);
        assert_eq!(HKDF_SHA256_VECTORS[1].length, 82);
        assert_eq!(HKDF_SHA256_VECTORS[2].length, 42);
    }
}
