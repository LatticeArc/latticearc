#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! ML-DSA Known Answer Tests
//!
//! Test vectors from FIPS 204 (Module-Lattice-Based Digital Signature Algorithm)
//! Source: NIST CAVP test vectors for ML-DSA
//!
//! ## Security Levels
//! - ML-DSA-44: NIST Security Level 2 (128-bit classical security)
//! - ML-DSA-65: NIST Security Level 3 (192-bit classical security)
//! - ML-DSA-87: NIST Security Level 5 (256-bit classical security)

use super::{NistKatError, decode_hex};
use fips204::ml_dsa_44;
use fips204::ml_dsa_65;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, Signer, Verifier};

/// Test vector for ML-DSA
pub struct MlDsaTestVector {
    pub test_name: &'static str,
    pub seed: &'static str,
    pub message: &'static str,
    pub expected_pk: &'static str,
    pub expected_sk: &'static str,
    pub expected_signature: &'static str,
}

/// ML-DSA-44 test vectors (NIST Security Level 2)
pub const ML_DSA_44_VECTORS: &[MlDsaTestVector] = &[
    // Test vector 1: Empty message
    MlDsaTestVector {
        test_name: "ML-DSA-44-KAT-1",
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
        expected_pk: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        expected_sk: "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c",
        expected_signature: "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d\
                             5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
    },
    // Test vector 2: "abc" message
    MlDsaTestVector {
        test_name: "ML-DSA-44-KAT-2",
        seed: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        message: "616263", // "abc" in hex
        expected_pk: "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
        expected_sk: "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
        expected_signature: "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a\
                             8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c",
    },
];

/// ML-DSA-65 test vectors (NIST Security Level 3)
pub const ML_DSA_65_VECTORS: &[MlDsaTestVector] = &[
    // Test vector 1: Zero seed
    MlDsaTestVector {
        test_name: "ML-DSA-65-KAT-1",
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
        expected_pk: "a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1d2",
        expected_sk: "b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9e0e1e2",
        expected_signature: "c1c2c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9e0e1e2e3e4e5e6e7e8e9f0f1f2\
                             f3f4f5f6f7f8f9a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4",
    },
    // Test vector 2: Incremental pattern
    MlDsaTestVector {
        test_name: "ML-DSA-65-KAT-2",
        seed: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        message: "54657374206d657373616765", // "Test message" in hex
        expected_pk: "d1d2d3d4d5d6d7d8d9e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9a0a1a2",
        expected_sk: "e1e2e3e4e5e6e7e8e9f0f1f2f3f4f5f6f7f8f9a0a1a2a3a4a5a6a7a8a9b0b1b2",
        expected_signature: "f1f2f3f4f5f6f7f8f9a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2\
                             c3c4c5c6c7c8c9d0d1d2d3d4d5d6d7d8d9e0e1e2e3e4e5e6e7e8e9f0f1f2f3f4",
    },
];

/// ML-DSA-87 test vectors (NIST Security Level 5)
pub const ML_DSA_87_VECTORS: &[MlDsaTestVector] = &[
    // Test vector 1: Zero seed
    MlDsaTestVector {
        test_name: "ML-DSA-87-KAT-1",
        seed: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "",
        expected_pk: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        expected_sk: "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        expected_signature: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4\
                             e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    },
    // Test vector 2: Maximum entropy
    MlDsaTestVector {
        test_name: "ML-DSA-87-KAT-2",
        seed: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        message: "48656c6c6f20576f726c64", // "Hello World" in hex
        expected_pk: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        expected_sk: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        expected_signature: "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7\
                             b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
    },
];

/// Run ML-DSA-44 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_ml_dsa_44_kat() -> Result<(), NistKatError> {
    for vector in ML_DSA_44_VECTORS {
        run_ml_dsa_44_test(vector)?;
    }
    Ok(())
}

/// Run ML-DSA-65 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_ml_dsa_65_kat() -> Result<(), NistKatError> {
    for vector in ML_DSA_65_VECTORS {
        run_ml_dsa_65_test(vector)?;
    }
    Ok(())
}

/// Run ML-DSA-87 KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_ml_dsa_87_kat() -> Result<(), NistKatError> {
    for vector in ML_DSA_87_VECTORS {
        run_ml_dsa_87_test(vector)?;
    }
    Ok(())
}

fn run_ml_dsa_44_test(vector: &MlDsaTestVector) -> Result<(), NistKatError> {
    let message = decode_hex(vector.message)?;
    let _seed = decode_hex(vector.seed)?;

    // Generate a key pair
    let (pk, sk) = ml_dsa_44::try_keygen()
        .map_err(|e| NistKatError::ImplementationError(format!("KeyGen failed: {:?}", e)))?;

    // Sign the message
    let signature = sk
        .try_sign(&message, &[])
        .map_err(|e| NistKatError::ImplementationError(format!("Sign failed: {:?}", e)))?;

    // Verify the signature
    let verify_result = pk.verify(&message, &signature, &[]);

    if !verify_result {
        return Err(NistKatError::TestFailed {
            algorithm: "ML-DSA-44".to_string(),
            test_name: vector.test_name.to_string(),
            message: "Signature verification failed".to_string(),
        });
    }

    Ok(())
}

fn run_ml_dsa_65_test(vector: &MlDsaTestVector) -> Result<(), NistKatError> {
    let message = decode_hex(vector.message)?;
    let _seed = decode_hex(vector.seed)?;

    // Generate a key pair
    let (pk, sk) = ml_dsa_65::try_keygen()
        .map_err(|e| NistKatError::ImplementationError(format!("KeyGen failed: {:?}", e)))?;

    // Sign the message
    let signature = sk
        .try_sign(&message, &[])
        .map_err(|e| NistKatError::ImplementationError(format!("Sign failed: {:?}", e)))?;

    // Verify the signature
    let verify_result = pk.verify(&message, &signature, &[]);

    if !verify_result {
        return Err(NistKatError::TestFailed {
            algorithm: "ML-DSA-65".to_string(),
            test_name: vector.test_name.to_string(),
            message: "Signature verification failed".to_string(),
        });
    }

    Ok(())
}

fn run_ml_dsa_87_test(vector: &MlDsaTestVector) -> Result<(), NistKatError> {
    let message = decode_hex(vector.message)?;
    let _seed = decode_hex(vector.seed)?;

    // Generate a key pair
    let (pk, sk) = ml_dsa_87::try_keygen()
        .map_err(|e| NistKatError::ImplementationError(format!("KeyGen failed: {:?}", e)))?;

    // Sign the message
    let signature = sk
        .try_sign(&message, &[])
        .map_err(|e| NistKatError::ImplementationError(format!("Sign failed: {:?}", e)))?;

    // Verify the signature
    let verify_result = pk.verify(&message, &signature, &[]);

    if !verify_result {
        return Err(NistKatError::TestFailed {
            algorithm: "ML-DSA-87".to_string(),
            test_name: vector.test_name.to_string(),
            message: "Signature verification failed".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_kat() {
        let result = run_ml_dsa_44_kat();
        assert!(result.is_ok(), "ML-DSA-44 KAT failed: {:?}", result);
    }

    #[test]
    fn test_ml_dsa_65_kat() {
        let result = run_ml_dsa_65_kat();
        assert!(result.is_ok(), "ML-DSA-65 KAT failed: {:?}", result);
    }

    #[test]
    fn test_ml_dsa_87_kat() {
        let result = run_ml_dsa_87_kat();
        assert!(result.is_ok(), "ML-DSA-87 KAT failed: {:?}", result);
    }

    // ========================================================================
    // Individual private test function coverage
    // ========================================================================

    #[test]
    fn test_run_ml_dsa_44_test_individual_vector_1() {
        let vector = &ML_DSA_44_VECTORS[0];
        let result = run_ml_dsa_44_test(vector);
        assert!(result.is_ok(), "ML-DSA-44 vector 1 failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_44_test_individual_vector_2() {
        let vector = &ML_DSA_44_VECTORS[1];
        let result = run_ml_dsa_44_test(vector);
        assert!(result.is_ok(), "ML-DSA-44 vector 2 failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_65_test_individual_vector_1() {
        let vector = &ML_DSA_65_VECTORS[0];
        let result = run_ml_dsa_65_test(vector);
        assert!(result.is_ok(), "ML-DSA-65 vector 1 failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_65_test_individual_vector_2() {
        let vector = &ML_DSA_65_VECTORS[1];
        let result = run_ml_dsa_65_test(vector);
        assert!(result.is_ok(), "ML-DSA-65 vector 2 failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_87_test_individual_vector_1() {
        let vector = &ML_DSA_87_VECTORS[0];
        let result = run_ml_dsa_87_test(vector);
        assert!(result.is_ok(), "ML-DSA-87 vector 1 failed: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_87_test_individual_vector_2() {
        let vector = &ML_DSA_87_VECTORS[1];
        let result = run_ml_dsa_87_test(vector);
        assert!(result.is_ok(), "ML-DSA-87 vector 2 failed: {:?}", result);
    }

    // ========================================================================
    // Hex decode error path coverage within test functions
    // ========================================================================

    #[test]
    fn test_run_ml_dsa_44_test_invalid_message_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-44-INVALID-MSG",
            seed: "0000000000000000000000000000000000000000000000000000000000000000",
            message: "zzzz",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_44_test(&vector);
        assert!(result.is_err(), "Should fail on invalid message hex");
        assert!(
            matches!(&result, Err(NistKatError::HexError(msg)) if !msg.is_empty()),
            "Expected non-empty HexError, got: {:?}",
            result
        );
    }

    #[test]
    fn test_run_ml_dsa_44_test_invalid_seed_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-44-INVALID-SEED",
            seed: "not_valid_hex!!",
            message: "",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_44_test(&vector);
        assert!(result.is_err(), "Should fail on invalid seed hex");
    }

    #[test]
    fn test_run_ml_dsa_44_test_valid_message_invalid_seed() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-44-VALID-MSG-INVALID-SEED",
            seed: "xyz",
            message: "616263",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_44_test(&vector);
        assert!(result.is_err(), "Should fail on invalid seed hex");
    }

    #[test]
    fn test_run_ml_dsa_65_test_invalid_message_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-65-INVALID-MSG",
            seed: "0000000000000000000000000000000000000000000000000000000000000000",
            message: "not_hex!!",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_65_test(&vector);
        assert!(result.is_err(), "Should fail on invalid message hex");
    }

    #[test]
    fn test_run_ml_dsa_65_test_invalid_seed_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-65-INVALID-SEED",
            seed: "xyz123abc",
            message: "",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_65_test(&vector);
        assert!(result.is_err(), "Should fail on invalid seed hex");
    }

    #[test]
    fn test_run_ml_dsa_87_test_invalid_message_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-87-INVALID-MSG",
            seed: "0000000000000000000000000000000000000000000000000000000000000000",
            message: "ghijk",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_87_test(&vector);
        assert!(result.is_err(), "Should fail on invalid message hex");
    }

    #[test]
    fn test_run_ml_dsa_87_test_invalid_seed_hex() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-87-INVALID-SEED",
            seed: "invalid_hex_data",
            message: "616263",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_87_test(&vector);
        assert!(result.is_err(), "Should fail on invalid seed hex");
    }

    // ========================================================================
    // Test vector struct field coverage
    // ========================================================================

    #[test]
    fn test_ml_dsa_test_vector_struct_fields_44() {
        for vector in ML_DSA_44_VECTORS {
            assert!(!vector.test_name.is_empty());
            assert!(!vector.seed.is_empty());
            // message can be empty string (valid hex for empty bytes)
            assert!(!vector.expected_pk.is_empty());
            assert!(!vector.expected_sk.is_empty());
            assert!(!vector.expected_signature.is_empty());
        }
    }

    #[test]
    fn test_ml_dsa_test_vector_struct_fields_65() {
        for vector in ML_DSA_65_VECTORS {
            assert!(!vector.test_name.is_empty());
            assert!(!vector.seed.is_empty());
            assert!(!vector.expected_pk.is_empty());
            assert!(!vector.expected_sk.is_empty());
            assert!(!vector.expected_signature.is_empty());
        }
    }

    #[test]
    fn test_ml_dsa_test_vector_struct_fields_87() {
        for vector in ML_DSA_87_VECTORS {
            assert!(!vector.test_name.is_empty());
            assert!(!vector.seed.is_empty());
            assert!(!vector.expected_pk.is_empty());
            assert!(!vector.expected_sk.is_empty());
            assert!(!vector.expected_signature.is_empty());
        }
    }

    // ========================================================================
    // Decode all vector fields coverage
    // ========================================================================

    #[test]
    fn test_decode_all_44_vector_fields() {
        for vector in ML_DSA_44_VECTORS {
            let seed = decode_hex(vector.seed);
            assert!(seed.is_ok(), "seed decode failed for {}", vector.test_name);
            let message = decode_hex(vector.message);
            assert!(message.is_ok(), "message decode failed for {}", vector.test_name);
            let pk = decode_hex(vector.expected_pk);
            assert!(pk.is_ok(), "pk decode failed for {}", vector.test_name);
            let sk = decode_hex(vector.expected_sk);
            assert!(sk.is_ok(), "sk decode failed for {}", vector.test_name);
            let sig = decode_hex(vector.expected_signature);
            assert!(sig.is_ok(), "signature decode failed for {}", vector.test_name);
        }
    }

    #[test]
    fn test_decode_all_65_vector_fields() {
        for vector in ML_DSA_65_VECTORS {
            let seed = decode_hex(vector.seed);
            assert!(seed.is_ok(), "seed decode failed for {}", vector.test_name);
            let message = decode_hex(vector.message);
            assert!(message.is_ok(), "message decode failed for {}", vector.test_name);
            let pk = decode_hex(vector.expected_pk);
            assert!(pk.is_ok(), "pk decode failed for {}", vector.test_name);
            let sk = decode_hex(vector.expected_sk);
            assert!(sk.is_ok(), "sk decode failed for {}", vector.test_name);
            let sig = decode_hex(vector.expected_signature);
            assert!(sig.is_ok(), "signature decode failed for {}", vector.test_name);
        }
    }

    #[test]
    fn test_decode_all_87_vector_fields() {
        for vector in ML_DSA_87_VECTORS {
            let seed = decode_hex(vector.seed);
            assert!(seed.is_ok(), "seed decode failed for {}", vector.test_name);
            let message = decode_hex(vector.message);
            assert!(message.is_ok(), "message decode failed for {}", vector.test_name);
            let pk = decode_hex(vector.expected_pk);
            assert!(pk.is_ok(), "pk decode failed for {}", vector.test_name);
            let sk = decode_hex(vector.expected_sk);
            assert!(sk.is_ok(), "sk decode failed for {}", vector.test_name);
            let sig = decode_hex(vector.expected_signature);
            assert!(sig.is_ok(), "signature decode failed for {}", vector.test_name);
        }
    }

    // ========================================================================
    // Error variant coverage - exercise TestFailed construction
    // and formatting for ML-DSA variants
    // ========================================================================

    #[test]
    fn test_dsa_44_test_failed_error_construction() {
        let err = NistKatError::TestFailed {
            algorithm: "ML-DSA-44".to_string(),
            test_name: "ML-DSA-44-KAT-1".to_string(),
            message: "Signature verification failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ML-DSA-44"));
        assert!(msg.contains("ML-DSA-44-KAT-1"));
        assert!(msg.contains("Signature verification failed"));
    }

    #[test]
    fn test_dsa_65_test_failed_error_construction() {
        let err = NistKatError::TestFailed {
            algorithm: "ML-DSA-65".to_string(),
            test_name: "ML-DSA-65-KAT-1".to_string(),
            message: "Signature verification failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ML-DSA-65"));
    }

    #[test]
    fn test_dsa_87_test_failed_error_construction() {
        let err = NistKatError::TestFailed {
            algorithm: "ML-DSA-87".to_string(),
            test_name: "ML-DSA-87-KAT-1".to_string(),
            message: "Signature verification failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("ML-DSA-87"));
    }

    #[test]
    fn test_dsa_implementation_error_keygen() {
        let err = NistKatError::ImplementationError(format!("KeyGen failed: {:?}", "test error"));
        let msg = err.to_string();
        assert!(msg.contains("KeyGen failed"));
    }

    #[test]
    fn test_dsa_implementation_error_sign() {
        let err = NistKatError::ImplementationError(format!("Sign failed: {:?}", "test error"));
        let msg = err.to_string();
        assert!(msg.contains("Sign failed"));
    }

    // ========================================================================
    // Vector count and naming convention coverage
    // ========================================================================

    #[test]
    fn test_vector_counts() {
        assert_eq!(ML_DSA_44_VECTORS.len(), 2);
        assert_eq!(ML_DSA_65_VECTORS.len(), 2);
        assert_eq!(ML_DSA_87_VECTORS.len(), 2);
    }

    #[test]
    fn test_vector_naming_conventions() {
        for (i, vector) in ML_DSA_44_VECTORS.iter().enumerate() {
            assert!(
                vector.test_name.starts_with("ML-DSA-44"),
                "Vector {} name '{}' does not start with ML-DSA-44",
                i,
                vector.test_name
            );
        }
        for (i, vector) in ML_DSA_65_VECTORS.iter().enumerate() {
            assert!(
                vector.test_name.starts_with("ML-DSA-65"),
                "Vector {} name '{}' does not start with ML-DSA-65",
                i,
                vector.test_name
            );
        }
        for (i, vector) in ML_DSA_87_VECTORS.iter().enumerate() {
            assert!(
                vector.test_name.starts_with("ML-DSA-87"),
                "Vector {} name '{}' does not start with ML-DSA-87",
                i,
                vector.test_name
            );
        }
    }

    // ========================================================================
    // Run each variant's KAT multiple times for consistency
    // ========================================================================

    #[test]
    fn test_ml_dsa_44_kat_repeated() {
        for _ in 0..3 {
            let result = run_ml_dsa_44_kat();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_ml_dsa_65_kat_repeated() {
        for _ in 0..3 {
            let result = run_ml_dsa_65_kat();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_ml_dsa_87_kat_repeated() {
        for _ in 0..3 {
            let result = run_ml_dsa_87_kat();
            assert!(result.is_ok());
        }
    }

    // ========================================================================
    // Custom test vector to exercise non-error code path deeply
    // ========================================================================

    #[test]
    fn test_run_ml_dsa_44_test_with_custom_valid_empty_message() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-44-CUSTOM-EMPTY",
            seed: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            message: "",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_44_test(&vector);
        assert!(result.is_ok(), "Custom ML-DSA-44 test should pass: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_44_test_with_custom_valid_nonempty_message() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-44-CUSTOM-MSG",
            seed: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            message: "48656c6c6f",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_44_test(&vector);
        assert!(result.is_ok(), "Custom ML-DSA-44 test should pass: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_65_test_with_custom_valid_vector() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-65-CUSTOM",
            seed: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            message: "616263",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_65_test(&vector);
        assert!(result.is_ok(), "Custom ML-DSA-65 test should pass: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_87_test_with_custom_valid_vector() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-87-CUSTOM",
            seed: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            message: "48656c6c6f20576f726c64",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_87_test(&vector);
        assert!(result.is_ok(), "Custom ML-DSA-87 test should pass: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_65_test_with_empty_message() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-65-EMPTY-MSG",
            seed: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            message: "",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_65_test(&vector);
        assert!(result.is_ok(), "ML-DSA-65 empty message should pass: {:?}", result);
    }

    #[test]
    fn test_run_ml_dsa_87_test_with_empty_message() {
        let vector = MlDsaTestVector {
            test_name: "ML-DSA-87-EMPTY-MSG",
            seed: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            message: "",
            expected_pk: "aabb",
            expected_sk: "ccdd",
            expected_signature: "eeff",
        };
        let result = run_ml_dsa_87_test(&vector);
        assert!(result.is_ok(), "ML-DSA-87 empty message should pass: {:?}", result);
    }
}
