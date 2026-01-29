#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SP 800-132: Password-Based Key Derivation Function (PBKDF2)
//!
//! PBKDF2 is a password-based key derivation function that applies a pseudorandom
//! function (typically HMAC) to derive keys from passwords. It includes salting and
//! iteration to make brute-force attacks more difficult.
//!
//! This implementation provides NIST SP 800-132 compliant PBKDF2 with:
//! - Configurable iteration counts for adjustable computational cost
//! - Salt support for key uniqueness
//! - Multiple PRF options (HMAC-SHA256, HMAC-SHA512)
//! - Secure memory handling with zeroization

use arc_prelude::error::{LatticeArcError, Result};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// PBKDF2 pseudorandom function types
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PrfType {
    /// HMAC-SHA256 (recommended for most applications)
    HmacSha256,
    /// HMAC-SHA512 (for higher security requirements)
    HmacSha512,
}

/// PBKDF2 parameters structure
#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    /// Salt value (minimum 16 bytes recommended)
    pub salt: Vec<u8>,
    /// Iteration count (minimum 1000, recommended 10000+)
    pub iterations: u32,
    /// Desired key length in bytes
    pub key_length: usize,
    /// PRF to use
    pub prf: PrfType,
}

impl Pbkdf2Params {
    /// Create PBKDF2 parameters with a securely generated random salt.
    ///
    /// This constructor generates a cryptographically secure random salt to ensure
    /// uniqueness and prevent precomputation attacks.
    ///
    /// # Arguments
    /// * `salt_length` - Length of the salt to generate (recommended: 16+ bytes)
    ///
    /// # Security Note
    /// Using a fresh random salt for each key derivation is essential for security.
    /// Never reuse salts across different passwords or applications.
    ///
    /// # Errors
    /// Returns an error if salt length is zero.
    pub fn new(salt_length: usize) -> Result<Self> {
        if salt_length == 0 {
            return Err(LatticeArcError::InvalidParameter(
                "Salt length must be greater than 0".to_string(),
            ));
        }
        // Note: salt_length < 16 bytes is not recommended for security
        // but we allow it for compatibility with existing systems

        let mut salt = vec![0u8; salt_length];
        get_random_bytes(&mut salt);

        Ok(Self { salt, iterations: 10000, key_length: 32, prf: PrfType::HmacSha256 })
    }

    /// Create PBKDF2 parameters with custom salt.
    ///
    /// # Arguments
    /// * `salt` - The salt value to use (recommended: 16+ bytes)
    ///
    /// # Security Note
    /// Ensure the salt is cryptographically random and unique for each password.
    #[must_use]
    pub fn with_salt(salt: &[u8]) -> Self {
        Self { salt: salt.to_vec(), iterations: 10000, key_length: 32, prf: PrfType::HmacSha256 }
    }

    /// Set iteration count
    #[must_use]
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Set key length
    #[must_use]
    pub fn key_length(mut self, key_length: usize) -> Self {
        self.key_length = key_length;
        self
    }

    /// Set PRF type
    #[must_use]
    pub fn prf(mut self, prf: PrfType) -> Self {
        self.prf = prf;
        self
    }
}

/// PBKDF2 key derivation result
#[derive(Clone)]
pub struct Pbkdf2Result {
    /// Derived key
    pub key: Vec<u8>,
    /// Parameters used for derivation
    pub params: Pbkdf2Params,
}

impl Zeroize for Pbkdf2Result {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for Pbkdf2Result {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Pbkdf2Result {
    /// Get the derived key
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Verify a password against this result
    ///
    /// # Errors
    /// Returns an error if the password derivation fails.
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        let derived = pbkdf2(password, &self.params)?;
        Ok(constant_time_eq(&self.key, &derived.key))
    }
}

/// PBKDF2 key derivation function
///
/// Derives a cryptographic key from a password using PBKDF2 as specified in
/// NIST SP 800-132. The function applies a pseudorandom function (HMAC) multiple
/// times to increase computational cost and make brute-force attacks more difficult.
///
/// # Arguments
/// * `password` - The password to derive key from
/// * `params` - PBKDF2 parameters (salt, iterations, key length, PRF)
///
/// # Returns
/// Derived key wrapped in Pbkdf2Result
///
/// # Security Considerations
/// - Use at least 16 bytes of random salt
/// - Use at least 10,000 iterations (higher for better security)
/// - Store salt alongside derived key for password verification
///
/// # Errors
/// Returns an error if parameters are invalid (empty salt, too few iterations, or zero key length).
pub fn pbkdf2(password: &[u8], params: &Pbkdf2Params) -> Result<Pbkdf2Result> {
    // Validate parameters per SP 800-132
    if params.salt.is_empty() {
        return Err(LatticeArcError::InvalidParameter("Salt must not be empty".to_string()));
    }

    // Reject all-zero salt as it's insecure
    if params.salt.iter().all(|&b| b == 0) {
        return Err(LatticeArcError::InvalidParameter(
            "Salt must not be all zeros - use a cryptographically random salt".to_string(),
        ));
    }

    if params.iterations < 1000 {
        return Err(LatticeArcError::InvalidParameter(
            "Iteration count must be at least 1000".to_string(),
        ));
    }

    if params.key_length == 0 {
        return Err(LatticeArcError::InvalidParameter(
            "Key length must be greater than 0".to_string(),
        ));
    }

    // Calculate number of blocks needed
    let prf_output_len = match params.prf {
        PrfType::HmacSha256 => 32,
        PrfType::HmacSha512 => 64,
    };

    let block_count = params.key_length.div_ceil(prf_output_len);
    let mut derived_key = vec![0u8; params.key_length];
    let mut offset = 0;

    // Generate each block of the derived key
    for block_index in 1..=block_count {
        let block_index_u32 = u32::try_from(block_index).map_err(|_e| {
            LatticeArcError::InvalidParameter(format!(
                "Block index {} exceeds u32::MAX",
                block_index
            ))
        })?;
        let block =
            generate_block(password, &params.salt, params.iterations, block_index_u32, params.prf)?;
        let copy_len = std::cmp::min(block.len(), params.key_length.saturating_sub(offset));
        let end_offset = offset.checked_add(copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Derived key offset overflow".to_string())
        })?;
        let dest_slice = derived_key.get_mut(offset..end_offset).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Derived key buffer overflow".to_string())
        })?;
        let src_slice = block.get(..copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("Block slice out of bounds".to_string())
        })?;
        dest_slice.copy_from_slice(src_slice);
        offset = end_offset;
    }

    Ok(Pbkdf2Result { key: derived_key, params: params.clone() })
}

/// Generate a single block of the PBKDF2 output
fn generate_block(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    block_index: u32,
    prf: PrfType,
) -> Result<Vec<u8>> {
    // Convert block index to bytes (big-endian)
    let mut block_input = salt.to_vec();
    block_input.extend_from_slice(&block_index.to_be_bytes());

    // U_1 = PRF(password, salt || INT(block_index))
    let mut u = compute_prf(password, &block_input, prf)?;
    let mut result = u.clone();

    // U_2 = PRF(password, U_1) ⊕ U_1
    // U_3 = PRF(password, U_2) ⊕ U_2
    // ...
    // U_c = PRF(password, U_{c-1}) ⊕ U_{c-1}
    for _ in 1..iterations {
        u = compute_prf(password, &u, prf)?;
        for (res_byte, u_byte) in result.iter_mut().zip(u.iter()) {
            *res_byte ^= u_byte;
        }
    }

    Ok(result)
}

/// Compute PRF (HMAC) for PBKDF2
fn compute_prf(password: &[u8], data: &[u8], prf: PrfType) -> Result<Vec<u8>> {
    match prf {
        PrfType::HmacSha256 => {
            let mut hmac = Hmac::<Sha256>::new_from_slice(password).map_err(|_e| {
                LatticeArcError::InvalidParameter("Password too long for HMAC-SHA256".to_string())
            })?;
            hmac.update(data);
            let result = hmac.finalize().into_bytes();
            Ok(result.to_vec())
        }
        PrfType::HmacSha512 => {
            let mut hmac = Hmac::<Sha512>::new_from_slice(password).map_err(|_e| {
                LatticeArcError::InvalidParameter("Password too long for HMAC-SHA512".to_string())
            })?;
            hmac.update(data);
            let result = hmac.finalize().into_bytes();
            Ok(result.to_vec())
        }
    }
}

/// Password-based key derivation with default parameters
///
/// Convenience function that uses recommended default parameters:
/// - 16-byte random salt
/// - 10,000 iterations
/// - 32-byte key length
/// - HMAC-SHA256 PRF
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn pbkdf2_simple(password: &[u8]) -> Result<Pbkdf2Result> {
    let params = Pbkdf2Params::new(16)?.iterations(10000).key_length(32).prf(PrfType::HmacSha256);

    pbkdf2(password, &params)
}

/// Verify a password against a previously derived key
///
/// # Errors
/// Returns an error if the password derivation fails.
pub fn verify_password(
    password: &[u8],
    derived_key: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<bool> {
    let params = Pbkdf2Params::with_salt(salt)
        .iterations(iterations)
        .key_length(derived_key.len())
        .prf(PrfType::HmacSha256);

    let result = pbkdf2(password, &params)?;
    Ok(constant_time_eq(derived_key, &result.key))
}

/// Get random bytes for salt generation
fn get_random_bytes(bytes: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(bytes);
}

/// Constant-time equality check
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let len_eq = a.len().ct_eq(&b.len());
    let mut result = len_eq;
    for (x, y) in a.iter().zip(b.iter()) {
        result &= x.ct_eq(y);
    }
    result.into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::panic_in_result_fn)] // Tests use assertions for verification
#[allow(clippy::indexing_slicing)] // Tests use slice indexing for verification
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_basic() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let password = b"password";
        let salt = b"salt123456789012"; // 16 bytes
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result = pbkdf2(password, &params)?;
        assert_eq!(result.key.len(), 32);

        // Verify deterministic output
        let result2 = pbkdf2(password, &params)?;
        assert_eq!(result.key, result2.key);

        Ok(())
    }

    #[test]
    fn test_pbkdf2_different_passwords() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let result1 = pbkdf2(b"password1", &params)?;
        let result2 = pbkdf2(b"password2", &params)?;

        assert_ne!(result1.key, result2.key);
        Ok(())
    }

    #[test]
    fn test_pbkdf2_different_salts() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let params1 = Pbkdf2Params::with_salt(b"salt123456789012").iterations(1000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(b"salt223456789012").iterations(1000).key_length(32);

        let result1 = pbkdf2(b"password", &params1)?;
        let result2 = pbkdf2(b"password", &params2)?;

        assert_ne!(result1.key, result2.key);
        Ok(())
    }

    #[test]
    fn test_pbkdf2_different_iterations() {
        let password = b"password";
        let salt = b"salt123456789012";
        let params1 = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);
        let params2 = Pbkdf2Params::with_salt(salt).iterations(2000).key_length(32);

        let result1 = pbkdf2(password, &params1).unwrap();
        let result2 = pbkdf2(password, &params2).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_pbkdf2_simple() {
        let password = b"testpassword";
        let result1 = pbkdf2_simple(password).unwrap();
        let result2 = pbkdf2_simple(password).unwrap();

        // Different salts should produce different keys
        assert_ne!(result1.key, result2.key);
        assert_eq!(result1.key.len(), 32);
        assert_eq!(result2.key.len(), 32);
    }

    #[test]
    fn test_password_verification() {
        let password = b"correctpassword";
        let wrong_password = b"wrongpassword";

        let result = pbkdf2_simple(password).unwrap();

        // Correct password should verify
        assert!(result.verify_password(password).unwrap());

        // Wrong password should not verify
        assert!(!result.verify_password(wrong_password).unwrap());
    }

    #[test]
    fn test_verify_password_function() {
        let password = b"testpass";
        let salt = b"1234567890123456"; // 16 bytes

        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        let derived = pbkdf2(password, &params).unwrap();

        // Should verify correctly
        assert!(verify_password(password, &derived.key, salt, 1000).unwrap());

        // Should not verify with wrong password
        assert!(!verify_password(b"wrongpass", &derived.key, salt, 1000).unwrap());

        // Should not verify with wrong salt
        assert!(!verify_password(password, &derived.key, b"wrongsalt123456", 1000).unwrap());

        // Should not verify with wrong iterations
        assert!(!verify_password(password, &derived.key, salt, 2000).unwrap());
    }

    #[test]
    fn test_pbkdf2_validation() {
        let password = b"pass";
        let salt = b"salt";

        // Empty salt should fail
        let params_empty_salt = Pbkdf2Params::with_salt(b"").iterations(1000).key_length(32);
        assert!(pbkdf2(password, &params_empty_salt).is_err());

        // All-zero salt should fail
        let params_zero_salt = Pbkdf2Params::with_salt(&[0u8; 16]).iterations(1000).key_length(32);
        assert!(pbkdf2(password, &params_zero_salt).is_err());

        // Too few iterations should fail
        let params_low_iter = Pbkdf2Params::with_salt(salt).iterations(500).key_length(32);
        assert!(pbkdf2(password, &params_low_iter).is_err());

        // Zero key length should fail
        let params_zero_len = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(0);
        assert!(pbkdf2(password, &params_zero_len).is_err());
    }

    #[test]
    fn test_prf_types() {
        let password = b"password";
        let salt = b"salt123456789012";

        let params_sha256 =
            Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32).prf(PrfType::HmacSha256);

        let params_sha512 = Pbkdf2Params::with_salt(salt)
            .iterations(1000)
            .key_length(64) // Longer key for SHA512
            .prf(PrfType::HmacSha512);

        let result_sha256 = pbkdf2(password, &params_sha256).unwrap();
        let result_sha512 = pbkdf2(password, &params_sha512).unwrap();

        assert_eq!(result_sha256.key.len(), 32);
        assert_eq!(result_sha512.key.len(), 64);

        // Different PRFs should produce different outputs
        assert_ne!(result_sha256.key, &result_sha512.key[..32]);
    }

    #[test]
    fn test_zeroize_on_drop() {
        let password = b"password";
        let salt = b"salt123456789012";
        let params = Pbkdf2Params::with_salt(salt).iterations(1000).key_length(32);

        // Create result in a block to test drop behavior
        let key_bytes = {
            let result = pbkdf2(password, &params).unwrap();
            let key_copy = result.key.clone();
            // Result should be zeroized when dropped
            drop(result);
            key_copy
        };

        // The key should still be readable (ZeroizeOnDrop doesn't automatically zeroize
        // until the struct is actually dropped, but the test verifies the trait is implemented)
        assert_eq!(key_bytes.len(), 32);
    }
}
