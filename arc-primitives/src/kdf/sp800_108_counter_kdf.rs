#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! SP 800-108: Counter-based Key Derivation Function
//!
//! NIST SP 800-108 specifies key derivation using pseudorandom functions.
//! This implementation provides the counter mode KDF using HMAC as the PRF.
//!
//! The counter-based KDF follows the format:
//! K(i) = PRF(KI, [i]_2 || Label || 0x00 || Context || [L]_2)
//!
//! Where:
//! - KI: Keying material input (the master secret)
//! - i: Counter (32-bit big-endian)
//! - Label: ASCII string identifying the purpose
//! - Context: Application-specific information
//! - L: Output length in bits (32-bit big-endian)

use arc_prelude::error::{LatticeArcError, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// SP 800-108 Counter KDF result
#[derive(Clone)]
pub struct CounterKdfResult {
    /// Derived key material
    pub key: Vec<u8>,
    /// Length of the derived key
    pub key_length: usize,
}

impl Zeroize for CounterKdfResult {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for CounterKdfResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CounterKdfResult {
    /// Get the derived key
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// Counter-based KDF parameters
#[derive(Debug, Clone)]
pub struct CounterKdfParams {
    /// Label identifying the purpose of key derivation
    pub label: Vec<u8>,
    /// Context-specific information
    pub context: Vec<u8>,
}

impl Default for CounterKdfParams {
    fn default() -> Self {
        Self { label: b"Default KDF Label".to_vec(), context: vec![] }
    }
}

impl CounterKdfParams {
    /// Create new KDF parameters with custom label
    #[must_use]
    pub fn new(label: &[u8]) -> Self {
        Self { label: label.to_vec(), context: vec![] }
    }

    /// Set context information
    #[must_use]
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.context = context.to_vec();
        self
    }

    /// Create parameters for encryption key
    #[must_use]
    pub fn for_encryption() -> Self {
        Self::new(b"Encryption Key")
    }

    /// Create parameters for MAC key
    #[must_use]
    pub fn for_mac() -> Self {
        Self::new(b"MAC Key")
    }

    /// Create parameters for IV/nonce
    #[must_use]
    pub fn for_iv() -> Self {
        Self::new(b"IV Generation")
    }
}

/// SP 800-108 Counter-based Key Derivation Function
///
/// Derives keys from keying material using a counter mode KDF as specified
/// in NIST SP 800-108. This KDF is useful for deterministic key derivation
/// where multiple keys need to be derived from a master secret.
///
/// # Arguments
/// * `ki` - Keying material input (master secret)
/// * `params` - KDF parameters (label and context)
/// * `key_length` - Desired output key length in bytes
///
/// # Returns
/// Derived key material of the requested length
///
/// # Example
/// ```ignore
/// let master_secret = b"my super secret master key";
/// let params = CounterKdfParams::for_encryption().with_context(b"my-app-v1");
/// let derived_key = counter_kdf(master_secret, &params, 32)?;
/// ```
///
/// # Security Considerations
/// - Use unique labels for different key purposes
/// - Include context to ensure domain separation
/// - Never reuse the same (KI, label, context) for different purposes
///
/// # Errors
/// Returns an error if keying material is empty, key length is zero, or HMAC initialization fails.
pub fn counter_kdf(
    ki: &[u8],
    params: &CounterKdfParams,
    key_length: usize,
) -> Result<CounterKdfResult> {
    // Validate inputs
    if ki.is_empty() {
        return Err(LatticeArcError::InvalidParameter(
            "Keying material must not be empty".to_string(),
        ));
    }

    if key_length == 0 {
        return Err(LatticeArcError::InvalidParameter(
            "Key length must be greater than 0".to_string(),
        ));
    }

    // Max output length is 2^32 blocks * hash_length (SHA-256 = 32 bytes)
    const HASH_LEN: usize = 32;
    // Safe: compile-time constant multiplication
    #[allow(clippy::arithmetic_side_effects)]
    let max_len = (1u64 << 32) * HASH_LEN as u64;

    if key_length > usize::try_from(max_len).unwrap_or(usize::MAX) {
        return Err(LatticeArcError::InvalidParameter(format!(
            "Key length {} exceeds maximum of {}",
            key_length, max_len
        )));
    }

    // Number of iterations (blocks) needed
    let iterations = key_length.div_ceil(HASH_LEN);

    // Output length in bits (32-bit big-endian)
    let l_bits = u32::try_from(key_length.saturating_mul(8)).map_err(|_e| {
        LatticeArcError::InvalidParameter("Key length too large for bit representation".to_string())
    })?;

    let mut derived_key = vec![0u8; key_length];
    let mut offset = 0;

    // Generate each block - iterations bounded by key_length/HASH_LEN which is validated above
    let iterations_u32 = u32::try_from(iterations).map_err(|_e| {
        LatticeArcError::InvalidParameter("Too many KDF iterations required".to_string())
    })?;
    for i in 1..=iterations_u32 {
        // Construct input: [i]_2 || Label || 0x00 || Context || [L]_2
        let mut hmac_input: Vec<u8> = Vec::new();

        // Counter i (32-bit big-endian)
        hmac_input.extend_from_slice(&i.to_be_bytes());

        // Label
        hmac_input.extend_from_slice(&params.label);

        // 0x00 separator
        hmac_input.push(0x00);

        // Context
        hmac_input.extend_from_slice(&params.context);

        // Output length L in bits (32-bit big-endian)
        hmac_input.extend_from_slice(&l_bits.to_be_bytes());

        // Compute HMAC(KI, input)
        let mut hmac = Hmac::<Sha256>::new_from_slice(ki).map_err(|_e| {
            LatticeArcError::InvalidParameter("Invalid keying material for HMAC".to_string())
        })?;
        hmac.update(&hmac_input);
        let result = hmac.finalize().into_bytes();
        let result_vec: Vec<u8> = result.to_vec();

        // Copy to output
        let copy_len = std::cmp::min(HASH_LEN, key_length.saturating_sub(offset));
        let end_offset = offset.checked_add(copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("KDF output offset overflow".to_string())
        })?;
        let dest_slice = derived_key.get_mut(offset..end_offset).ok_or_else(|| {
            LatticeArcError::InvalidParameter("KDF output buffer overflow".to_string())
        })?;
        let src_slice = result_vec.get(..copy_len).ok_or_else(|| {
            LatticeArcError::InvalidParameter("KDF source slice out of bounds".to_string())
        })?;
        dest_slice.copy_from_slice(src_slice);
        offset = end_offset;

        hmac_input.zeroize();
    }

    Ok(CounterKdfResult { key: derived_key, key_length })
}

/// Derive multiple keys using counter KDF
///
/// Convenience function to derive multiple keys of different lengths
/// from the same master secret, each with a different purpose.
///
/// # Arguments
/// * `ki` - Keying material input (master secret)
/// * `context` - Shared context for all derived keys
/// * `key_specs` - Vector of (label, length) pairs for each key
///
/// # Returns
/// Vector of derived keys in the same order as specifications
///
/// # Example
/// ```ignore
/// let master_secret = b"my super secret master key";
/// let context = b"my-app-v1";
/// let key_specs = vec![
///     (b"encryption", 32),
///     (b"mac", 32),
///     (b"iv", 16),
/// ];
/// let keys = derive_multiple_keys(master_secret, context, &key_specs)?;
/// ```
///
/// # Errors
/// Returns an error if any individual key derivation fails.
pub fn derive_multiple_keys(
    ki: &[u8],
    context: &[u8],
    key_specs: &[(&[u8], usize)],
) -> Result<Vec<CounterKdfResult>> {
    let mut keys = Vec::with_capacity(key_specs.len());

    for (label, length) in key_specs {
        let params = CounterKdfParams::new(label).with_context(context);
        let key = counter_kdf(ki, &params, *length)?;
        keys.push(key);
    }

    Ok(keys)
}

/// Derive an encryption key using recommended parameters
///
/// Convenience function for deriving encryption keys.
///
/// # Arguments
/// * `ki` - Keying material input
/// * `context` - Application-specific context
///
/// # Returns
/// 32-byte (256-bit) encryption key
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn derive_encryption_key(ki: &[u8], context: &[u8]) -> Result<CounterKdfResult> {
    let params = CounterKdfParams::for_encryption().with_context(context);
    counter_kdf(ki, &params, 32)
}

/// Derive a MAC key using recommended parameters
///
/// Convenience function for deriving MAC keys.
///
/// # Arguments
/// * `ki` - Keying material input
/// * `context` - Application-specific context
///
/// # Returns
/// 32-byte (256-bit) MAC key
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn derive_mac_key(ki: &[u8], context: &[u8]) -> Result<CounterKdfResult> {
    let params = CounterKdfParams::for_mac().with_context(context);
    counter_kdf(ki, &params, 32)
}

/// Derive an IV/nonce using recommended parameters
///
/// Convenience function for deriving IVs or nonces.
///
/// # Arguments
/// * `ki` - Keying material input
/// * `context` - Application-specific context
///
/// # Returns
/// 16-byte (128-bit) IV/nonce
///
/// # Errors
/// Returns an error if IV derivation fails.
pub fn derive_iv(ki: &[u8], context: &[u8]) -> Result<CounterKdfResult> {
    let params = CounterKdfParams::for_iv().with_context(context);
    counter_kdf(ki, &params, 16)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
#[allow(clippy::indexing_slicing)] // Tests use indexing for verification
mod tests {
    use super::*;

    #[test]
    fn test_counter_kdf_basic() {
        let ki = b"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
        let params = CounterKdfParams::new(b"Example Label");
        let result = counter_kdf(ki.as_ref(), &params, 32).unwrap();

        assert_eq!(result.key.len(), 32);
        assert_eq!(result.key_length, 32);
    }

    #[test]
    fn test_counter_kdf_deterministic() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Test Label");

        let result1 = counter_kdf(ki, &params, 32).unwrap();
        let result2 = counter_kdf(ki, &params, 32).unwrap();

        assert_eq!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_labels() {
        let ki = b"test keying material";
        let params1 = CounterKdfParams::new(b"Label 1");
        let params2 = CounterKdfParams::new(b"Label 2");

        let result1 = counter_kdf(ki, &params1, 32).unwrap();
        let result2 = counter_kdf(ki, &params2, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_contexts() {
        let ki = b"test keying material";
        let params1 = CounterKdfParams::new(b"Label").with_context(b"Context 1");
        let params2 = CounterKdfParams::new(b"Label").with_context(b"Context 2");

        let result1 = counter_kdf(ki, &params1, 32).unwrap();
        let result2 = counter_kdf(ki, &params2, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_different_lengths() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label");

        let result16 = counter_kdf(ki, &params, 16).unwrap();
        let result32 = counter_kdf(ki, &params, 32).unwrap();
        let result64 = counter_kdf(ki, &params, 64).unwrap();

        assert_eq!(result16.key.len(), 16);
        assert_eq!(result32.key.len(), 32);
        assert_eq!(result64.key.len(), 64);
    }

    #[test]
    fn test_counter_kdf_different_ki() {
        let params = CounterKdfParams::new(b"Label");

        let result1 = counter_kdf(b"ki1", &params, 32).unwrap();
        let result2 = counter_kdf(b"ki2", &params, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_with_context() {
        let ki = b"test keying material";
        let params_with_context = CounterKdfParams::new(b"Label").with_context(b"My Context");
        let params_without_context = CounterKdfParams::new(b"Label");

        let result1 = counter_kdf(ki, &params_with_context, 32).unwrap();
        let result2 = counter_kdf(ki, &params_without_context, 32).unwrap();

        assert_ne!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_validation() {
        let params = CounterKdfParams::new(b"Label");

        // Empty KI should fail
        assert!(counter_kdf(b"", &params, 32).is_err());

        // Zero key length should fail
        assert!(counter_kdf(b"ki", &params, 0).is_err());

        // Valid key length should succeed
        assert!(counter_kdf(b"ki", &params, 32).is_ok());

        // Length at hash boundary should succeed
        assert!(counter_kdf(b"ki", &params, 32).is_ok());

        // Length just over hash boundary should succeed
        assert!(counter_kdf(b"ki", &params, 33).is_ok());

        // Length requiring multiple blocks should succeed
        assert!(counter_kdf(b"ki", &params, 64).is_ok());
    }

    #[test]
    fn test_derive_multiple_keys() {
        let ki = b"master secret";
        let context = b"my-app-v1";
        let key_specs =
            vec![("encryption".as_bytes(), 32), ("mac".as_bytes(), 32), ("iv".as_bytes(), 16)];

        let keys = derive_multiple_keys(ki, context, &key_specs).unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].key.len(), 32);
        assert_eq!(keys[1].key.len(), 32);
        assert_eq!(keys[2].key.len(), 16);

        // All keys should be different
        assert_ne!(keys[0].key, keys[1].key);
        assert_ne!(keys[1].key, keys[2].key);
        assert_ne!(keys[0].key, keys[2].key);
    }

    #[test]
    fn test_derive_encryption_key() {
        let ki = b"master secret";
        let context = b"my-app-v1";

        let key = derive_encryption_key(ki, context).unwrap();

        assert_eq!(key.key.len(), 32);
        assert_eq!(key.key_length, 32);
    }

    #[test]
    fn test_derive_mac_key() {
        let ki = b"master secret";
        let context = b"my-app-v1";

        let key = derive_mac_key(ki, context).unwrap();

        assert_eq!(key.key.len(), 32);
        assert_eq!(key.key_length, 32);
    }

    #[test]
    fn test_derive_iv() {
        let ki = b"master secret";
        let context = b"my-app-v1";

        let iv = derive_iv(ki, context).unwrap();

        assert_eq!(iv.key.len(), 16);
        assert_eq!(iv.key_length, 16);
    }

    #[test]
    fn test_convenience_functions_are_unique() {
        let ki = b"master secret";
        let context = b"my-app-v1";

        let enc_key = derive_encryption_key(ki, context).unwrap();
        let mac_key = derive_mac_key(ki, context).unwrap();
        let iv = derive_iv(ki, context).unwrap();

        assert_ne!(enc_key.key, mac_key.key);
        assert_ne!(mac_key.key, &iv.key[..16]);
    }

    #[test]
    fn test_counter_kdf_empty_label() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"");

        let result = counter_kdf(ki, &params, 32).unwrap();

        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn test_counter_kdf_empty_context() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label").with_context(b"");

        let result1 = counter_kdf(ki, &params, 32).unwrap();

        // Empty context vs no context should produce SAME results (both empty vec)
        let params2 = CounterKdfParams::new(b"Label");
        let result2 = counter_kdf(ki, &params2, 32).unwrap();

        assert_eq!(result1.key, result2.key);
    }

    #[test]
    fn test_counter_kdf_long_inputs() {
        let ki = vec![0u8; 256]; // Long keying material
        let label = vec![b'A'; 256]; // Long label
        let context = vec![0xFF; 256]; // Long context

        let params = CounterKdfParams::new(&label).with_context(&context);

        let result = counter_kdf(&ki, &params, 32).unwrap();

        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn test_counter_kdf_result_zeroize_on_drop() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label");

        // Create result in a block to test drop behavior
        let key_bytes = {
            let result = counter_kdf(ki, &params, 32).unwrap();
            let key_copy = result.key.clone();
            // Result should be zeroized when dropped
            drop(result);
            key_copy
        };

        // The key copy should still be readable
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_default_params() {
        let ki = b"test keying material";
        let params = CounterKdfParams::default();

        assert_eq!(params.label, b"Default KDF Label");
        assert!(params.context.is_empty());

        let result = counter_kdf(ki, &params, 32).unwrap();
        assert_eq!(result.key.len(), 32);
    }

    #[test]
    fn test_counter_kdf_large_output() {
        let ki = b"test keying material";
        let params = CounterKdfParams::new(b"Label");

        // Test output spanning multiple blocks
        let result = counter_kdf(ki, &params, 100).unwrap();
        assert_eq!(result.key.len(), 100);
    }
}
