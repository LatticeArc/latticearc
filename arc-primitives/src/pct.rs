//! FIPS 140-3 Pairwise Consistency Tests (PCT)
//!
//! This module implements Pairwise Consistency Tests as required by FIPS 140-3 for
//! digital signature algorithms. PCT is a conditional self-test that must be performed
//! immediately after key generation to detect any corruption in the generated keypair.
//!
//! ## FIPS 140-3 Requirements
//!
//! According to FIPS 140-3 IG 10.3.A, a PCT for digital signature algorithms consists of:
//! 1. Signing a known test message with the newly generated secret key
//! 2. Verifying the signature with the corresponding public key
//! 3. If verification fails, the module must enter an error state
//!
//! ## Supported Algorithms
//!
//! - **ML-DSA** (FIPS 204): Module-Lattice-Based Digital Signature Algorithm
//! - **SLH-DSA** (FIPS 205): Stateless Hash-Based Digital Signature Algorithm
//! - **FN-DSA** (FIPS 206): Few-Time Digital Signature Algorithm
//!
//! ## Usage
//!
//! PCT functions are called automatically by the key generation functions when
//! the `fips-self-test` feature is enabled. They can also be called manually:
//!
//! ```no_run
//! use arc_primitives::pct::{pct_ml_dsa, PctError};
//! use arc_primitives::sig::ml_dsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaParameterSet};
//!
//! // After generating keys...
//! // let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65)?;
//!
//! // Perform PCT
//! // pct_ml_dsa(&pk, &sk)?;
//! ```
//!
//! ## Security Considerations
//!
//! - PCT must be performed immediately after key generation, before the keys are used
//! - If PCT fails, the generated keys must not be used
//! - The test message is fixed to ensure deterministic testing

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

use thiserror::Error;

/// Fixed test message for PCT operations
///
/// This message is used for all PCT sign/verify operations.
/// Using a fixed message ensures consistent, deterministic testing.
pub const PCT_TEST_MESSAGE: &[u8] = b"FIPS PCT test";

/// Empty context for PCT operations (required by some signature APIs)
pub const PCT_EMPTY_CONTEXT: &[u8] = &[];

/// Error types for Pairwise Consistency Test operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PctError {
    /// Signing operation failed during PCT
    #[error("PCT signing failed: {0}")]
    SigningFailed(String),

    /// Verification operation failed during PCT
    #[error("PCT verification failed: {0}")]
    VerificationFailed(String),

    /// Signature verification returned false (key pair is inconsistent)
    #[error("PCT failed: signature verification returned false - key pair is inconsistent")]
    KeyPairInconsistent,

    /// Parameter mismatch between public and secret keys
    #[error("PCT failed: parameter mismatch between public and secret keys")]
    ParameterMismatch,
}

/// Result type for PCT operations
pub type PctResult<T> = Result<T, PctError>;

// =============================================================================
// ML-DSA Pairwise Consistency Test
// =============================================================================

/// Performs a Pairwise Consistency Test for ML-DSA keypairs
///
/// This function signs a fixed test message with the secret key and verifies
/// the signature with the public key. According to FIPS 140-3, this test must
/// pass before the keypair can be used for any cryptographic operations.
///
/// # Arguments
///
/// * `public_key` - The ML-DSA public key to test
/// * `secret_key` - The ML-DSA secret key to test
///
/// # Returns
///
/// * `Ok(())` - The keypair is consistent and passed PCT
/// * `Err(PctError)` - The keypair failed PCT and must not be used
///
/// # Errors
///
/// Returns `PctError::ParameterMismatch` if the keys have different parameter sets.
/// Returns `PctError::SigningFailed` if signing the test message fails.
/// Returns `PctError::VerificationFailed` if verification encounters an error.
/// Returns `PctError::KeyPairInconsistent` if verification returns false.
///
/// # Example
///
/// ```no_run
/// use arc_primitives::sig::ml_dsa::{generate_keypair, MlDsaParameterSet};
/// use arc_primitives::pct::pct_ml_dsa;
///
/// let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65)?;
/// pct_ml_dsa(&pk, &sk)?;
/// // Keys are now validated and safe to use
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn pct_ml_dsa(
    public_key: &crate::sig::ml_dsa::MlDsaPublicKey,
    secret_key: &crate::sig::ml_dsa::MlDsaSecretKey,
) -> PctResult<()> {
    use crate::sig::ml_dsa::{sign, verify};

    // Verify parameter sets match
    if public_key.parameter_set != secret_key.parameter_set() {
        return Err(PctError::ParameterMismatch);
    }

    // Sign the test message
    let signature = sign(secret_key, PCT_TEST_MESSAGE, PCT_EMPTY_CONTEXT)
        .map_err(|e| PctError::SigningFailed(e.to_string()))?;

    // Verify the signature
    let is_valid = verify(public_key, PCT_TEST_MESSAGE, &signature, PCT_EMPTY_CONTEXT)
        .map_err(|e| PctError::VerificationFailed(e.to_string()))?;

    if is_valid { Ok(()) } else { Err(PctError::KeyPairInconsistent) }
}

// =============================================================================
// SLH-DSA Pairwise Consistency Test
// =============================================================================

/// Performs a Pairwise Consistency Test for SLH-DSA keypairs
///
/// This function signs a fixed test message with the signing key and verifies
/// the signature with the verifying key. According to FIPS 140-3, this test must
/// pass before the keypair can be used for any cryptographic operations.
///
/// # Arguments
///
/// * `verifying_key` - The SLH-DSA verifying key (public key) to test
/// * `signing_key` - The SLH-DSA signing key (secret key) to test
///
/// # Returns
///
/// * `Ok(())` - The keypair is consistent and passed PCT
/// * `Err(PctError)` - The keypair failed PCT and must not be used
///
/// # Errors
///
/// Returns `PctError::ParameterMismatch` if the keys have different security levels.
/// Returns `PctError::SigningFailed` if signing the test message fails.
/// Returns `PctError::VerificationFailed` if verification encounters an error.
/// Returns `PctError::KeyPairInconsistent` if verification returns false.
///
/// # Example
///
/// ```no_run
/// use arc_primitives::sig::slh_dsa::{SigningKey, SecurityLevel};
/// use arc_primitives::pct::pct_slh_dsa;
///
/// let (sk, vk) = SigningKey::generate(SecurityLevel::Shake128s)?;
/// pct_slh_dsa(&vk, &sk)?;
/// // Keys are now validated and safe to use
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn pct_slh_dsa(
    verifying_key: &crate::sig::slh_dsa::VerifyingKey,
    signing_key: &crate::sig::slh_dsa::SigningKey,
) -> PctResult<()> {
    // Verify security levels match
    if verifying_key.security_level() != signing_key.security_level() {
        return Err(PctError::ParameterMismatch);
    }

    // Sign the test message (no context for PCT)
    let signature = signing_key
        .sign(PCT_TEST_MESSAGE, None)
        .map_err(|e| PctError::SigningFailed(e.to_string()))?;

    // Verify the signature
    let is_valid = verifying_key
        .verify(PCT_TEST_MESSAGE, &signature, None)
        .map_err(|e| PctError::VerificationFailed(e.to_string()))?;

    if is_valid { Ok(()) } else { Err(PctError::KeyPairInconsistent) }
}

// =============================================================================
// FN-DSA Pairwise Consistency Test
// =============================================================================

/// Performs a Pairwise Consistency Test for FN-DSA keypairs
///
/// This function signs a fixed test message with the signing key and verifies
/// the signature with the verifying key. According to FIPS 140-3, this test must
/// pass before the keypair can be used for any cryptographic operations.
///
/// # Arguments
///
/// * `verifying_key` - The FN-DSA verifying key (public key) to test
/// * `signing_key` - The FN-DSA signing key (secret key) to test
///
/// # Returns
///
/// * `Ok(())` - The keypair is consistent and passed PCT
/// * `Err(PctError)` - The keypair failed PCT and must not be used
///
/// # Errors
///
/// Returns `PctError::ParameterMismatch` if the keys have different security levels.
/// Returns `PctError::SigningFailed` if signing the test message fails.
/// Returns `PctError::VerificationFailed` if verification encounters an error.
/// Returns `PctError::KeyPairInconsistent` if verification returns false.
///
/// # Example
///
/// ```no_run
/// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
/// use arc_primitives::pct::pct_fn_dsa;
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
/// // Note: For FN-DSA, signing requires mutable access, so we use the keypair's sign method
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn pct_fn_dsa(
    verifying_key: &crate::sig::fndsa::VerifyingKey,
    signing_key: &mut crate::sig::fndsa::SigningKey,
) -> PctResult<()> {
    use rand::rngs::OsRng;

    // Verify security levels match
    if verifying_key.security_level() != signing_key.security_level() {
        return Err(PctError::ParameterMismatch);
    }

    // Sign the test message (FN-DSA requires an RNG for signing)
    let mut rng = OsRng;
    let signature = signing_key
        .sign(&mut rng, PCT_TEST_MESSAGE)
        .map_err(|e| PctError::SigningFailed(e.to_string()))?;

    // Verify the signature
    let is_valid = verifying_key
        .verify(PCT_TEST_MESSAGE, &signature)
        .map_err(|e| PctError::VerificationFailed(e.to_string()))?;

    if is_valid { Ok(()) } else { Err(PctError::KeyPairInconsistent) }
}

/// Performs a Pairwise Consistency Test for an FN-DSA KeyPair
///
/// This is a convenience function that performs PCT on a complete FN-DSA KeyPair
/// structure. It internally calls `pct_fn_dsa` with the keypair's components.
///
/// # Arguments
///
/// * `keypair` - The FN-DSA keypair to test (mutable because signing requires it)
///
/// # Returns
///
/// * `Ok(())` - The keypair is consistent and passed PCT
/// * `Err(PctError)` - The keypair failed PCT and must not be used
///
/// # Errors
///
/// Returns errors from the underlying `pct_fn_dsa` function.
///
/// # Example
///
/// ```no_run
/// use arc_primitives::sig::fndsa::{KeyPair, FNDsaSecurityLevel};
/// use arc_primitives::pct::pct_fn_dsa_keypair;
/// use rand::rngs::OsRng;
///
/// let mut rng = OsRng;
/// let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)?;
/// pct_fn_dsa_keypair(&mut keypair)?;
/// // Keypair is now validated and safe to use
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn pct_fn_dsa_keypair(keypair: &mut crate::sig::fndsa::KeyPair) -> PctResult<()> {
    use rand::rngs::OsRng;

    // Sign the test message
    let mut rng = OsRng;
    let signature = keypair
        .sign(&mut rng, PCT_TEST_MESSAGE)
        .map_err(|e| PctError::SigningFailed(e.to_string()))?;

    // Verify the signature
    let is_valid = keypair
        .verify(PCT_TEST_MESSAGE, &signature)
        .map_err(|e| PctError::VerificationFailed(e.to_string()))?;

    if is_valid { Ok(()) } else { Err(PctError::KeyPairInconsistent) }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use expect for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_pct_ml_dsa_44_passes() {
        use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

        let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation failed");
        let result = pct_ml_dsa(&pk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid ML-DSA-44 keypair");
    }

    #[test]
    fn test_pct_ml_dsa_65_passes() {
        use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

        let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA65).expect("Key generation failed");
        let result = pct_ml_dsa(&pk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid ML-DSA-65 keypair");
    }

    #[test]
    fn test_pct_ml_dsa_87_passes() {
        use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

        let (pk, sk) = generate_keypair(MlDsaParameterSet::MLDSA87).expect("Key generation failed");
        let result = pct_ml_dsa(&pk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid ML-DSA-87 keypair");
    }

    #[test]
    fn test_pct_ml_dsa_mismatched_keys_fails() {
        use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

        let (pk1, _sk1) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation failed");
        let (_pk2, sk2) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation failed");

        // Use public key from one keypair with secret key from another
        let result = pct_ml_dsa(&pk1, &sk2);
        assert!(
            matches!(result, Err(PctError::KeyPairInconsistent)),
            "PCT should fail for mismatched keys"
        );
    }

    #[test]
    fn test_pct_ml_dsa_parameter_mismatch() {
        use crate::sig::ml_dsa::{MlDsaParameterSet, generate_keypair};

        let (pk44, _) =
            generate_keypair(MlDsaParameterSet::MLDSA44).expect("Key generation failed");
        let (_, sk65) =
            generate_keypair(MlDsaParameterSet::MLDSA65).expect("Key generation failed");

        // Different parameter sets should fail
        let result = pct_ml_dsa(&pk44, &sk65);
        assert!(
            matches!(result, Err(PctError::ParameterMismatch)),
            "PCT should fail for parameter mismatch"
        );
    }

    #[test]
    fn test_pct_slh_dsa_shake128s_passes() {
        use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

        let (sk, vk) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let result = pct_slh_dsa(&vk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid SLH-DSA-SHAKE-128s keypair");
    }

    #[test]
    fn test_pct_slh_dsa_shake192s_passes() {
        use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

        let (sk, vk) =
            SigningKey::generate(SecurityLevel::Shake192s).expect("Key generation failed");
        let result = pct_slh_dsa(&vk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid SLH-DSA-SHAKE-192s keypair");
    }

    #[test]
    fn test_pct_slh_dsa_shake256s_passes() {
        use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

        let (sk, vk) =
            SigningKey::generate(SecurityLevel::Shake256s).expect("Key generation failed");
        let result = pct_slh_dsa(&vk, &sk);
        assert!(result.is_ok(), "PCT should pass for valid SLH-DSA-SHAKE-256s keypair");
    }

    #[test]
    fn test_pct_slh_dsa_mismatched_keys_fails() {
        use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

        let (sk1, _vk1) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let (_sk2, vk2) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");

        // Use verifying key from one keypair with signing key from another
        let result = pct_slh_dsa(&vk2, &sk1);
        assert!(
            matches!(result, Err(PctError::KeyPairInconsistent)),
            "PCT should fail for mismatched keys"
        );
    }

    #[test]
    fn test_pct_slh_dsa_parameter_mismatch() {
        use crate::sig::slh_dsa::{SecurityLevel, SigningKey};

        let (sk128, _) =
            SigningKey::generate(SecurityLevel::Shake128s).expect("Key generation failed");
        let (_, vk256) =
            SigningKey::generate(SecurityLevel::Shake256s).expect("Key generation failed");

        // Different security levels should fail
        let result = pct_slh_dsa(&vk256, &sk128);
        assert!(
            matches!(result, Err(PctError::ParameterMismatch)),
            "PCT should fail for parameter mismatch"
        );
    }

    #[test]
    fn test_pct_fn_dsa_512_passes() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::sig::fndsa::{FNDsaSecurityLevel, KeyPair};
                use rand::rngs::OsRng;

                let mut rng = OsRng;
                let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
                    .expect("Key generation failed");
                let result = pct_fn_dsa_keypair(&mut keypair);
                assert!(result.is_ok(), "PCT should pass for valid FN-DSA-512 keypair");
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_pct_fn_dsa_1024_passes() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::sig::fndsa::{FNDsaSecurityLevel, KeyPair};
                use rand::rngs::OsRng;

                let mut rng = OsRng;
                let mut keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
                    .expect("Key generation failed");
                let result = pct_fn_dsa_keypair(&mut keypair);
                assert!(result.is_ok(), "PCT should pass for valid FN-DSA-1024 keypair");
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_pct_fn_dsa_with_separate_keys_passes() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::sig::fndsa::{FNDsaSecurityLevel, KeyPair};
                use rand::rngs::OsRng;

                let mut rng = OsRng;
                let keypair = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
                    .expect("Key generation failed");

                // Get verifying key from the keypair
                let vk = keypair.verifying_key().clone();

                // Recreate signing key from bytes
                let sk_bytes = keypair.signing_key().to_bytes();
                let mut sk = crate::sig::fndsa::SigningKey::from_bytes(
                    sk_bytes,
                    FNDsaSecurityLevel::Level512,
                )
                .expect("SigningKey reconstruction failed");

                let result = pct_fn_dsa(&vk, &mut sk);
                assert!(result.is_ok(), "PCT should pass for valid FN-DSA keypair components");
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_pct_fn_dsa_parameter_mismatch() {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                use crate::sig::fndsa::{FNDsaSecurityLevel, KeyPair};
                use rand::rngs::OsRng;

                let mut rng = OsRng;
                let keypair512 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level512)
                    .expect("Key generation failed");
                let keypair1024 = KeyPair::generate(&mut rng, FNDsaSecurityLevel::Level1024)
                    .expect("Key generation failed");

                // Get verifying key from 1024 and signing key from 512
                let vk1024 = keypair1024.verifying_key().clone();
                let sk_bytes = keypair512.signing_key().to_bytes();
                let mut sk512 = crate::sig::fndsa::SigningKey::from_bytes(
                    sk_bytes,
                    FNDsaSecurityLevel::Level512,
                )
                .expect("SigningKey reconstruction failed");

                let result = pct_fn_dsa(&vk1024, &mut sk512);
                assert!(
                    matches!(result, Err(PctError::ParameterMismatch)),
                    "PCT should fail for parameter mismatch"
                );
            })
            .expect("Thread spawn failed")
            .join()
            .expect("Thread join failed");
    }

    #[test]
    fn test_pct_error_display() {
        let errors = vec![
            PctError::SigningFailed("test error".to_string()),
            PctError::VerificationFailed("test error".to_string()),
            PctError::KeyPairInconsistent,
            PctError::ParameterMismatch,
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty(), "Error display should not be empty");
        }
    }

    #[test]
    fn test_pct_constants() {
        assert_eq!(PCT_TEST_MESSAGE, b"FIPS PCT test");
        assert!(PCT_EMPTY_CONTEXT.is_empty());
    }
}
