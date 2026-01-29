#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
// JUSTIFICATION: CMAC block cipher mode arithmetic.
// - Fixed 16-byte AES block size arithmetic
// - Index calculations bounded by message length
#![allow(clippy::arithmetic_side_effects)]

//! CMAC (Cipher-based Message Authentication Code)
//!
//! This module provides CMAC (AES-CMAC) implementation as specified in
//! NIST SP 800-38B: Recommendation for Block Cipher Modes of Operation:
//! The CMAC Mode for Authentication.
//!
//! CMAC provides data integrity and authenticity verification for AES-encrypted data.
//! This implementation follows the full NIST SP 800-38B specification including:
//! - Subkey generation (K1, K2) from encryption key K
//! - Proper padding and block processing
//! - Constant-time operations to prevent timing attacks

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use thiserror::Error;

/// Error types for CMAC operations
#[derive(Debug, Error)]
pub enum CmacError {
    /// The provided key has an invalid length for CMAC operations.
    #[error("Invalid key length: CMAC keys must be 16, 24, or 32 bytes")]
    InvalidKeyLength {
        /// The actual length of the key provided.
        actual: usize,
    },
    /// CMAC computation failed during processing.
    #[error("CMAC computation failed: {0}")]
    ComputationError(String),
}

/// CMAC-128 (using AES-128)
#[derive(Debug, Clone)]
pub struct Cmac128 {
    tag: [u8; 16],
}

/// CMAC-256 (using AES-256)
#[derive(Debug, Clone)]
pub struct Cmac256 {
    tag: [u8; 16],
}

/// CMAC-192 (using AES-192)
#[derive(Debug, Clone)]
pub struct Cmac192 {
    tag: [u8; 16],
}

/// CMAC subkeys K1 and K2 for padding operations
#[derive(Debug, Clone)]
struct CmacSubkeys {
    k1: [u8; 16],
    k2: [u8; 16],
}

/// Constant-time XOR of two byte arrays
#[inline(always)]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    // Perform constant-time XOR operation using iterator pattern
    for (a_byte, b_byte) in a.iter_mut().zip(b.iter()) {
        *a_byte ^= b_byte;
    }
}

/// Left shift a 128-bit block by 1 bit (constant-time)
///
/// Returns the MSB that was shifted out (0 or 1)
///
/// Bitwise shifts in Rust are safe and cannot overflow - they are defined
/// to shift in zeros and the result fits in the same integer type.
#[inline(always)]
#[allow(clippy::arithmetic_side_effects)]
fn left_shift_block(block: &[u8; 16]) -> ([u8; 16], u8) {
    let mut result = [0u8; 16];
    let mut overflow = 0u8;

    // Process bytes with carry propagation for left shift (reverse iteration)
    for (i, &current_byte) in block.iter().enumerate().rev() {
        let new_byte = (current_byte << 1) | overflow;
        if let Some(r) = result.get_mut(i) {
            *r = new_byte;
        }
        overflow = (current_byte >> 7) & 1;
    }

    (result, overflow)
}

/// Generate CMAC subkeys K1 and K2 from the encryption key
///
/// # Algorithm (NIST SP 800-38B Section 5.3)
/// 1. L = AES_K(0^128) - encrypt a zero block
/// 2. K1 = (L << 1) XOR R_b (where R_b = 0x87 if MSB(L) = 1)
/// 3. K2 = (K1 << 1) XOR R_b (where R_b = 0x87 if MSB(K1) = 1)
///
/// # Arguments
/// * `key` - The encryption key (16, 24, or 32 bytes for AES-128/192/256)
///
/// # Returns
/// CmacSubkeys containing K1 and K2
///
/// # Errors
/// Returns InvalidKeyLength if key length is not 16, 24, or 32 bytes
fn generate_subkeys(key: &[u8]) -> Result<CmacSubkeys, CmacError> {
    // Validate key length
    match key.len() {
        16 | 24 | 32 => {}
        _ => return Err(CmacError::InvalidKeyLength { actual: key.len() }),
    }

    // Step 1: Compute L = AES_K(0^128)
    let l_block = match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key)
                .map_err(|e| CmacError::ComputationError(e.to_string()))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
        24 => {
            // AES-192 requires 24-byte keys
            let cipher = Aes192::new_from_slice(key)
                .map_err(|e| CmacError::ComputationError(e.to_string()))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
        32 => {
            let cipher = Aes256::new_from_slice(key)
                .map_err(|e| CmacError::ComputationError(e.to_string()))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
        _ => return Err(CmacError::InvalidKeyLength { actual: key.len() }),
    };

    // RB constant for 128-bit blocks = 0x87
    const RB: [u8; 16] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x87,
    ];

    // Step 2: Derive K1
    let (k1_shifted, k1_msb) = left_shift_block(&l_block);
    let mut k1 = k1_shifted;

    // If MSB(L) was 1, XOR with RB
    if k1_msb == 1 {
        xor_block(&mut k1, &RB);
    }

    // Step 3: Derive K2
    let (k2_shifted, k2_msb) = left_shift_block(&k1);
    let mut k2 = k2_shifted;

    // If MSB(K1) was 1, XOR with RB
    if k2_msb == 1 {
        xor_block(&mut k2, &RB);
    }

    Ok(CmacSubkeys { k1, k2 })
}

/// Apply padding and compute CMAC tag
///
/// # Algorithm (NIST SP 800-38B Section 6)
/// 1. If message length is a multiple of block size:
///    - Pad last block: M_n XOR K1, then CBC-MAC
/// 2. If message length is NOT a multiple of block size:
///    - Pad incomplete block with 10...0, then XOR with K2, then CBC-MAC
///
/// # Arguments
/// * `key` - The encryption key (16, 24, or 32 bytes)
/// * `data` - The message to authenticate
///
/// # Returns
/// The 16-byte CMAC tag
fn compute_cmac_internal(key: &[u8], data: &[u8]) -> Result<[u8; 16], CmacError> {
    // Validate key length
    match key.len() {
        16 | 24 | 32 => {}
        _ => return Err(CmacError::InvalidKeyLength { actual: key.len() }),
    }

    // Generate subkeys K1 and K2
    let subkeys = generate_subkeys(key)?;

    // Initialize cipher for CBC-MAC
    let cipher = match key.len() {
        16 => CipherType::Aes128(
            Aes128::new_from_slice(key).map_err(|e| CmacError::ComputationError(e.to_string()))?,
        ),
        24 => CipherType::Aes192(
            Aes192::new_from_slice(key).map_err(|e| CmacError::ComputationError(e.to_string()))?,
        ),
        32 => CipherType::Aes256(
            Aes256::new_from_slice(key).map_err(|e| CmacError::ComputationError(e.to_string()))?,
        ),
        _ => return Err(CmacError::InvalidKeyLength { actual: key.len() }),
    };

    let data_len = data.len();
    let num_complete_blocks = data_len / 16;
    let incomplete_block_size = data_len % 16;

    // CBC-MAC state: C_0 = 0^128
    let mut c_i = [0u8; 16];

    // Determine how many blocks to process as regular CBC blocks
    // All blocks except the last one are processed normally
    let total_blocks = if data_len == 0 { 1 } else { data_len.div_ceil(16) };

    if total_blocks > 1 {
        for i in 0..(total_blocks - 1) {
            let mut block = [0u8; 16];
            let start = i * 16;
            let end = (i + 1) * 16;
            let data_slice = data
                .get(start..end)
                .ok_or_else(|| CmacError::ComputationError(format!("Block {} out of bounds", i)))?;
            block.copy_from_slice(data_slice);
            xor_block(&mut block, &c_i);

            match &cipher {
                CipherType::Aes128(c) => c.encrypt_block((&mut block).into()),
                CipherType::Aes192(c) => c.encrypt_block((&mut block).into()),
                CipherType::Aes256(c) => c.encrypt_block((&mut block).into()),
            }

            c_i = block;
        }
    }

    // Process final block with padding
    let mut final_block = [0u8; 16];

    if data_len == 0 {
        // Empty message: pad with 10...0 and XOR with K2
        final_block[0] = 0x80;
        xor_block(&mut final_block, &subkeys.k2);
    } else if incomplete_block_size == 0 {
        // Message is multiple of block size
        // Last block is the nth block, XOR with K1
        let block_idx = num_complete_blocks - 1;
        let start = block_idx * 16;
        let end = (block_idx + 1) * 16;
        let data_slice = data
            .get(start..end)
            .ok_or_else(|| CmacError::ComputationError("Final block out of bounds".to_string()))?;
        final_block.copy_from_slice(data_slice);
        xor_block(&mut final_block, &c_i);
        xor_block(&mut final_block, &subkeys.k1);
    } else {
        // Message has incomplete final block
        // Pad with 10...0 and XOR with K2
        let start = num_complete_blocks * 16;
        let incomplete_data = data.get(start..).ok_or_else(|| {
            CmacError::ComputationError("Incomplete block out of bounds".to_string())
        })?;
        let dest_slice = final_block.get_mut(..incomplete_block_size).ok_or_else(|| {
            CmacError::ComputationError("Final block slice out of bounds".to_string())
        })?;
        dest_slice.copy_from_slice(incomplete_data);
        // Safe: incomplete_block_size = data_len % 16, always < 16
        if let Some(pad_byte) = final_block.get_mut(incomplete_block_size) {
            *pad_byte = 0x80; // Padding with 1 bit followed by zeros
        }
        xor_block(&mut final_block, &c_i);
        xor_block(&mut final_block, &subkeys.k2);
    }

    // Encrypt final block
    match &cipher {
        CipherType::Aes128(c) => c.encrypt_block((&mut final_block).into()),
        CipherType::Aes192(c) => c.encrypt_block((&mut final_block).into()),
        CipherType::Aes256(c) => c.encrypt_block((&mut final_block).into()),
    }

    Ok(final_block)
}

/// Enum to hold different AES cipher types
enum CipherType {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

/// Compute AES-128-CMAC for given data
///
/// # NIST SP 800-38B Specification
/// - Key length: 128 bits (16 bytes)
/// - Tag length: 128 bits (16 bytes)
/// - Block size: 128 bits (16 bytes)
///
/// # Security Requirements
/// - The key must be cryptographically secure
/// - Use fresh keys for each context (never reuse keys across applications)
/// - This implementation uses constant-time operations to prevent timing attacks
///
/// # Example
/// ```no_run
/// use arc_primitives::mac::cmac::{cmac_128, CmacError};
///
/// let key = [0u8; 16]; // 128-bit key
/// let data = b"message to authenticate";
///
/// let result = cmac_128(&key, data);
/// assert!(result.is_ok());
/// ```
///
/// # Errors
/// Returns an error if the key length is not exactly 16 bytes.
pub fn cmac_128(key: &[u8], data: &[u8]) -> Result<Cmac128, CmacError> {
    // Input validation - key must be exactly 16 bytes
    if key.len() != 16 {
        return Err(CmacError::InvalidKeyLength { actual: key.len() });
    }

    // Compute CMAC tag using AES-128
    let tag = compute_cmac_internal(key, data)?;

    Ok(Cmac128 { tag })
}

/// Compute AES-192-CMAC for given data
///
/// # NIST SP 800-38B Specification
/// - Key length: 192 bits (24 bytes)
/// - Tag length: 128 bits (16 bytes)
/// - Block size: 128 bits (16 bytes)
///
/// # Security Requirements
/// - The key must be cryptographically secure
/// - Use fresh keys for each context (never reuse keys across applications)
/// - This implementation uses constant-time operations to prevent timing attacks
///
/// # Example
/// ```no_run
/// use arc_primitives::mac::cmac::{cmac_192, CmacError};
///
/// let key = [0u8; 24]; // 192-bit key
/// let data = b"message to authenticate";
///
/// let result = cmac_192(&key, data);
/// assert!(result.is_ok());
/// ```
///
/// # Errors
/// Returns an error if the key length is not exactly 24 bytes.
pub fn cmac_192(key: &[u8], data: &[u8]) -> Result<Cmac192, CmacError> {
    // Input validation - key must be exactly 24 bytes
    if key.len() != 24 {
        return Err(CmacError::InvalidKeyLength { actual: key.len() });
    }

    // Compute CMAC tag using AES-192
    let tag = compute_cmac_internal(key, data)?;

    Ok(Cmac192 { tag })
}

/// Compute AES-256-CMAC for given data
///
/// # NIST SP 800-38B Specification
/// - Key length: 256 bits (32 bytes)
/// - Tag length: 128 bits (16 bytes)
/// - Block size: 128 bits (16 bytes)
///
/// # Security Requirements
/// - The key must be cryptographically secure
/// - Use fresh keys for each context (never reuse keys across applications)
/// - This implementation uses constant-time operations to prevent timing attacks
///
/// # Example
/// ```no_run
/// use arc_primitives::mac::cmac::{cmac_256, CmacError};
///
/// let key = [0u8; 32]; // 256-bit key
/// let data = b"message to authenticate";
///
/// let result = cmac_256(&key, data);
/// assert!(result.is_ok());
/// ```
///
/// # Errors
/// Returns an error if the key length is not exactly 32 bytes.
pub fn cmac_256(key: &[u8], data: &[u8]) -> Result<Cmac256, CmacError> {
    // Input validation - key must be exactly 32 bytes
    if key.len() != 32 {
        return Err(CmacError::InvalidKeyLength { actual: key.len() });
    }

    // Compute CMAC tag using AES-256
    let tag = compute_cmac_internal(key, data)?;

    Ok(Cmac256 { tag })
}

/// Verify CMAC-128 tag using constant-time comparison
///
/// This function computes the CMAC tag for the given data and compares it
/// with the provided tag in constant-time to prevent timing attacks.
///
/// # Security Notice
/// Always use constant-time comparison for tag verification to prevent timing attacks.
///
/// # Arguments
/// * `key` - The AES-128 key (16 bytes)
/// * `data` - The message to verify
/// * `tag` - The CMAC tag to verify against (16 bytes)
///
/// # Returns
/// `true` if the tag is valid, `false` otherwise
///
/// # Example
/// ```ignore
/// use arc_primitives::mac::cmac::{cmac_128, verify_cmac_128};
///
/// let key = [0u8; 16];
/// let data = b"message to authenticate";
///
/// let cmac = cmac_128(&key, data)?;
/// let is_valid = verify_cmac_128(&key, data, &cmac.tag);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_cmac_128(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    let tag_valid: bool = tag.len().ct_eq(&16).into();
    if !tag_valid {
        return false;
    }

    let expected_tag = match cmac_128(key, data) {
        Ok(cmac) => cmac.tag,
        Err(_) => return false,
    };

    expected_tag.ct_eq(tag).into()
}

/// Verify CMAC-192 tag using constant-time comparison
///
/// This function computes the CMAC tag for the given data and compares it
/// with the provided tag in constant-time to prevent timing attacks.
///
/// # Security Notice
/// Always use constant-time comparison for tag verification to prevent timing attacks.
///
/// # Arguments
/// * `key` - The AES-192 key (24 bytes)
/// * `data` - The message to verify
/// * `tag` - The CMAC tag to verify against (16 bytes)
///
/// # Returns
/// `true` if the tag is valid, `false` otherwise
///
/// # Example
/// ```ignore
/// use arc_primitives::mac::cmac::{cmac_192, verify_cmac_192};
///
/// let key = [0u8; 24];
/// let data = b"message to authenticate";
///
/// let cmac = cmac_192(&key, data)?;
/// let is_valid = verify_cmac_192(&key, data, &cmac.tag);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_cmac_192(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    let tag_valid: bool = tag.len().ct_eq(&16).into();
    if !tag_valid {
        return false;
    }

    let expected_tag = match cmac_192(key, data) {
        Ok(cmac) => cmac.tag,
        Err(_) => return false,
    };

    expected_tag.ct_eq(tag).into()
}

/// Verify CMAC-256 tag using constant-time comparison
///
/// This function computes the CMAC tag for the given data and compares it
/// with the provided tag in constant-time to prevent timing attacks.
///
/// # Security Notice
/// Always use constant-time comparison for tag verification to prevent timing attacks.
///
/// # Arguments
/// * `key` - The AES-256 key (32 bytes)
/// * `data` - The message to verify
/// * `tag` - The CMAC tag to verify against (16 bytes)
///
/// # Returns
/// `true` if the tag is valid, `false` otherwise
///
/// # Example
/// ```ignore
/// use arc_primitives::mac::cmac::{cmac_256, verify_cmac_256};
///
/// let key = [0u8; 32];
/// let data = b"message to authenticate";
///
/// let cmac = cmac_256(&key, data)?;
/// let is_valid = verify_cmac_256(&key, data, &cmac.tag);
/// assert!(is_valid);
/// ```
#[must_use]
pub fn verify_cmac_256(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    let tag_valid: bool = tag.len().ct_eq(&16).into();
    if !tag_valid {
        return false;
    }

    let expected_tag = match cmac_256(key, data) {
        Ok(cmac) => cmac.tag,
        Err(_) => return false,
    };

    expected_tag.ct_eq(tag).into()
}

#[cfg(test)]
#[allow(clippy::panic)] // Tests use panic for error verification
#[allow(clippy::unwrap_used)] // Tests use unwrap for simplicity
mod tests {
    use super::*;

    #[test]
    fn test_cmac_128_key_length() {
        let key = vec![0u8; 16];
        let data = b"test data";

        let result = cmac_128(&key, data);
        assert!(result.is_ok(), "CMAC-128 should succeed with 16-byte key");
    }

    #[test]
    fn test_cmac_128_invalid_key() {
        let key = vec![0u8; 32]; // Wrong length
        let data = b"test data";

        let result = cmac_128(&key, data);
        assert!(result.is_err(), "CMAC-128 should fail with 32-byte key");

        match result {
            Err(CmacError::InvalidKeyLength { actual: 32 }) => {}
            _ => panic!("Expected InvalidKeyLength error"),
        }
    }

    #[test]
    fn test_cmac_192_key_length() {
        let key = vec![0u8; 24];
        let data = b"test data";

        let result = cmac_192(&key, data);
        assert!(result.is_ok(), "CMAC-192 should succeed with 24-byte key");
    }

    #[test]
    fn test_cmac_192_invalid_key() {
        let key = vec![0u8; 32]; // Wrong length
        let data = b"test data";

        let result = cmac_192(&key, data);
        assert!(result.is_err(), "CMAC-192 should fail with 32-byte key");

        match result {
            Err(CmacError::InvalidKeyLength { actual: 32 }) => {}
            Err(e) => panic!("Unexpected CMAC error: {:?}", e),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn test_cmac_256_key_length() {
        let key = vec![0u8; 32];
        let data = b"test data";

        let result = cmac_256(&key, data);
        assert!(result.is_ok(), "CMAC-256 should succeed with 32-byte key");
    }

    #[test]
    fn test_cmac_256_invalid_key() {
        let key = vec![0u8; 16]; // Wrong length
        let data = b"test data";

        let result = cmac_256(&key, data);
        assert!(result.is_err(), "CMAC-256 should fail with 16-byte key");

        match result {
            Err(CmacError::InvalidKeyLength { actual: 16 }) => {}
            Err(e) => panic!("Unexpected CMAC error: {:?}", e),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[test]
    fn test_cmac_different_data() {
        let key = vec![0u8; 32];
        let data1 = b"data one";
        let data2 = b"data two";

        let tag1 = cmac_256(&key, data1).unwrap().tag;
        let tag2 = cmac_256(&key, data2).unwrap().tag;

        // Different data should produce different tags (with high probability)
        assert_ne!(tag1, tag2, "Different data should produce different tags");
    }

    #[test]
    fn test_cmac_tag_length() {
        let key = vec![0u8; 32];
        let data = b"test data";

        let result = cmac_256(&key, data);
        assert!(result.is_ok(), "CMAC-256 should succeed");

        let tag = result.unwrap().tag;
        assert_eq!(tag.len(), 16, "Tag should be 16 bytes");
    }

    #[test]
    fn test_cmac_same_key_different_key_sizes() {
        let key128 = [0u8; 16];
        let key192 = [0u8; 24];
        let key256 = [0u8; 32];
        let data = b"test data";

        let tag128 = cmac_128(&key128, data).unwrap().tag;
        let tag192 = cmac_192(&key192, data).unwrap().tag;
        let tag256 = cmac_256(&key256, data).unwrap().tag;

        // Each key size produces different tags
        assert_ne!(tag128, tag192, "Different key sizes should produce different tags");
        assert_ne!(tag192, tag256, "Different key sizes should produce different tags");
    }

    #[test]
    fn test_verify_cmac_128() {
        let key = vec![0u8; 16];
        let data = b"test data";

        let cmac = cmac_128(&key, data).unwrap();

        // Valid tag should verify
        assert!(verify_cmac_128(&key, data, &cmac.tag));

        // Invalid tag should not verify
        let mut invalid_tag = cmac.tag;
        invalid_tag[0] ^= 0xFF;
        assert!(!verify_cmac_128(&key, data, &invalid_tag));

        // Different data should not verify
        assert!(!verify_cmac_128(&key, b"different data", &cmac.tag));
    }

    #[test]
    fn test_verify_cmac_192() {
        let key = vec![0u8; 24];
        let data = b"test data";

        let cmac = cmac_192(&key, data).unwrap();

        // Valid tag should verify
        assert!(verify_cmac_192(&key, data, &cmac.tag));

        // Invalid tag should not verify
        let mut invalid_tag = cmac.tag;
        invalid_tag[0] ^= 0xFF;
        assert!(!verify_cmac_192(&key, data, &invalid_tag));

        // Different data should not verify
        assert!(!verify_cmac_192(&key, b"different data", &cmac.tag));
    }

    #[test]
    fn test_verify_cmac_256() {
        let key = vec![0u8; 32];
        let data = b"test data";

        let cmac = cmac_256(&key, data).unwrap();

        // Valid tag should verify
        assert!(verify_cmac_256(&key, data, &cmac.tag));

        // Invalid tag should not verify
        let mut invalid_tag = cmac.tag;
        invalid_tag[0] ^= 0xFF;
        assert!(!verify_cmac_256(&key, data, &invalid_tag));

        // Different data should not verify
        assert!(!verify_cmac_256(&key, b"different data", &cmac.tag));
    }

    #[test]
    fn test_cmac_empty_data() {
        let key128 = vec![0u8; 16];
        let key192 = vec![0u8; 24];
        let key256 = vec![0u8; 32];

        let data = b"";

        // Empty data should still produce a valid tag
        assert!(cmac_128(&key128, data).is_ok());
        assert!(cmac_192(&key192, data).is_ok());
        assert!(cmac_256(&key256, data).is_ok());
    }

    #[test]
    fn test_cmac_block_aligned() {
        let key = vec![0u8; 16];
        // Exactly 16 bytes (one block)
        let data = [1u8; 16];

        let result = cmac_128(&key, &data);
        assert!(result.is_ok());

        // Exactly 32 bytes (two blocks)
        let data2 = [2u8; 32];

        let result2 = cmac_128(&key, &data2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_cmac_not_block_aligned() {
        let key = vec![0u8; 16];
        // 15 bytes (one incomplete block)
        let data = [1u8; 15];

        let result = cmac_128(&key, &data);
        assert!(result.is_ok());

        // 17 bytes (one complete block + one incomplete block)
        let data2 = [2u8; 17];

        let result2 = cmac_128(&key, &data2);
        assert!(result2.is_ok());
    }

    // NIST SP 800-38B test vectors
    // These test cases verify the implementation against known values
    #[test]
    fn test_cmac_nist_test_vectors() {
        // Test case 1: AES-128, empty message
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = b"";

        let cmac = cmac_128(&key, data).unwrap();
        let expected = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-128 test vector 1 failed");
        assert!(verify_cmac_128(&key, data, &expected));

        // Test case 2: AES-128, single block (16 bytes)
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let cmac = cmac_128(&key, &data).unwrap();
        let expected = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-128 test vector 2 failed");
        assert!(verify_cmac_128(&key, &data, &expected));

        // Test case 3: AES-128, two blocks (32 bytes)
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];

        let cmac = cmac_128(&key, &data).unwrap();
        // Verified with OpenSSL: openssl dgst -mac cmac -macopt cipher:aes-128-cbc
        let expected = [
            0xce, 0x0c, 0xbf, 0x17, 0x38, 0xf4, 0xdf, 0x64, 0x28, 0xb1, 0xd9, 0x3b, 0xf1, 0x20,
            0x81, 0xc9,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-128 test vector 3 failed");
        assert!(verify_cmac_128(&key, &data, &expected));

        // Test case 4: AES-128, incomplete block (20 bytes)
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
        ];

        let cmac = cmac_128(&key, &data).unwrap();
        // Verified with OpenSSL: openssl dgst -mac cmac -macopt cipher:aes-128-cbc
        let expected = [
            0x7d, 0x85, 0x44, 0x9e, 0xa6, 0xea, 0x19, 0xc8, 0x23, 0xa7, 0xbf, 0x78, 0x83, 0x7d,
            0xfa, 0xde,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-128 test vector 4 failed");
        assert!(verify_cmac_128(&key, &data, &expected));
    }

    #[test]
    fn test_cmac_nist_test_vectors_192() {
        // Test case 1: AES-192, empty message
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let data = b"";

        let cmac = cmac_192(&key, data).unwrap();
        let expected = [
            0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5, 0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a,
            0x93, 0x67,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-192 test vector 1 failed");
        assert!(verify_cmac_192(&key, data, &expected));

        // Test case 2: AES-192, single block (16 bytes)
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let cmac = cmac_192(&key, &data).unwrap();
        // Verified with OpenSSL: openssl dgst -mac cmac -macopt cipher:aes-192-cbc
        let expected = [
            0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90, 0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c,
            0x51, 0x84,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-192 test vector 2 failed");
        assert!(verify_cmac_192(&key, &data, &expected));

        // Test case 3: AES-192, two blocks (32 bytes)
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];

        let cmac = cmac_192(&key, &data).unwrap();
        // Verified with OpenSSL: openssl dgst -mac cmac -macopt cipher:aes-192-cbc
        let expected = [
            0x9f, 0x1d, 0x26, 0xd1, 0x76, 0x38, 0x31, 0xa5, 0x8c, 0x40, 0x16, 0xc6, 0xa9, 0x7b,
            0x0d, 0x4e,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-192 test vector 3 failed");
        assert!(verify_cmac_192(&key, &data, &expected));
    }

    #[test]
    fn test_cmac_nist_test_vectors_256() {
        // Test case 1: AES-256, empty message
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let data = b"";

        let cmac = cmac_256(&key, data).unwrap();
        let expected = [
            0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e, 0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67,
            0xd9, 0x83,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-256 test vector 1 failed");
        assert!(verify_cmac_256(&key, data, &expected));

        // Test case 2: AES-256, single block (16 bytes)
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];

        let cmac = cmac_256(&key, &data).unwrap();
        let expected = [
            0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82, 0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37,
            0xc3, 0x5c,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-256 test vector 2 failed");
        assert!(verify_cmac_256(&key, &data, &expected));

        // Test case 3: AES-256, two blocks (32 bytes)
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];

        let cmac = cmac_256(&key, &data).unwrap();
        // Verified with OpenSSL: openssl dgst -mac cmac -macopt cipher:aes-256-cbc
        let expected = [
            0x5a, 0x72, 0x2d, 0x2d, 0x85, 0x16, 0xf8, 0x54, 0xb8, 0x67, 0x7a, 0x53, 0x7b, 0x1b,
            0x66, 0x9a,
        ];
        assert_eq!(cmac.tag, expected, "CMAC-256 test vector 3 failed");
        assert!(verify_cmac_256(&key, &data, &expected));
    }

    #[test]
    fn test_subkey_generation() {
        let key = [0u8; 16];
        let subkeys = generate_subkeys(&key).unwrap();

        // Verify subkeys are different
        assert_ne!(subkeys.k1, subkeys.k2, "K1 and K2 should be different");

        // Verify subkeys are non-zero (unless key produces zero L)
        assert!(
            subkeys.k1.iter().any(|&b| b != 0) || subkeys.k2.iter().any(|&b| b != 0),
            "At least one subkey should be non-zero"
        );
    }
}
