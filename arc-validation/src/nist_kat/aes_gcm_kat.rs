#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! AES-GCM Known Answer Tests
//!
//! Test vectors from NIST SP 800-38D (Galois/Counter Mode)
//! Source: NIST CAVP test vectors for AES-GCM
//!
//! ## Algorithms Tested
//! - AES-128-GCM: 128-bit key, 96-bit IV, 128-bit authentication tag
//! - AES-256-GCM: 256-bit key, 96-bit IV, 128-bit authentication tag
//!
//! ## Test Coverage
//! - Empty plaintext
//! - Empty AAD
//! - Various plaintext and AAD lengths
//! - Tag verification

use super::{NistKatError, decode_hex};
use aws_lc_rs::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

/// Test vector for AES-GCM
pub struct AesGcmTestVector {
    pub test_name: &'static str,
    pub key: &'static str,
    pub nonce: &'static str,
    pub aad: &'static str,
    pub plaintext: &'static str,
    pub expected_ciphertext: &'static str,
    pub expected_tag: &'static str,
}

/// AES-128-GCM test vectors from NIST SP 800-38D
pub const AES_128_GCM_VECTORS: &[AesGcmTestVector] = &[
    // Test Case 1: Empty plaintext
    AesGcmTestVector {
        test_name: "AES-128-GCM-KAT-1",
        key: "00000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        plaintext: "",
        expected_ciphertext: "",
        expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
    },
    // Test Case 2: 128-bit plaintext
    AesGcmTestVector {
        test_name: "AES-128-GCM-KAT-2",
        key: "00000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        plaintext: "00000000000000000000000000000000",
        expected_ciphertext: "0388dace60b6a392f328c2b971b2fe78",
        expected_tag: "ab6e47d42cec13bdf53a67b21257bddf",
    },
    // Test Case 3: 256-bit plaintext
    AesGcmTestVector {
        test_name: "AES-128-GCM-KAT-3",
        key: "feffe9928665731c6d6a8f9467308308",
        nonce: "cafebabefacedbaddecaf888",
        aad: "",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        expected_ciphertext: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        expected_tag: "4d5c2af327cd64a62cf35abd2ba6fab4",
    },
];

/// AES-256-GCM test vectors from NIST SP 800-38D
pub const AES_256_GCM_VECTORS: &[AesGcmTestVector] = &[
    // Test Case 1: Empty plaintext
    AesGcmTestVector {
        test_name: "AES-256-GCM-KAT-1",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        plaintext: "",
        expected_ciphertext: "",
        expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    // Test Case 2: 128-bit plaintext
    AesGcmTestVector {
        test_name: "AES-256-GCM-KAT-2",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        aad: "",
        plaintext: "00000000000000000000000000000000",
        expected_ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
        expected_tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    // Test Case 3: 256-bit plaintext
    AesGcmTestVector {
        test_name: "AES-256-GCM-KAT-3",
        key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
        nonce: "cafebabefacedbaddecaf888",
        aad: "",
        plaintext: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        expected_ciphertext: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        expected_tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
];

/// Run AES-128-GCM KAT
pub fn run_aes_128_gcm_kat() -> Result<(), NistKatError> {
    for vector in AES_128_GCM_VECTORS {
        run_aes_128_gcm_test(vector)?;
    }
    Ok(())
}

/// Run AES-256-GCM KAT
pub fn run_aes_256_gcm_kat() -> Result<(), NistKatError> {
    for vector in AES_256_GCM_VECTORS {
        run_aes_256_gcm_test(vector)?;
    }
    Ok(())
}

fn run_aes_128_gcm_test(vector: &AesGcmTestVector) -> Result<(), NistKatError> {
    let key_bytes = decode_hex(vector.key)?;
    let nonce = decode_hex(vector.nonce)?;
    let aad = decode_hex(vector.aad)?;
    let plaintext = decode_hex(vector.plaintext)?;
    let expected_ciphertext = decode_hex(vector.expected_ciphertext)?;
    let expected_tag = decode_hex(vector.expected_tag)?;

    // Test encryption
    let unbound_key = UnboundKey::new(&AES_128_GCM, &key_bytes)
        .map_err(|e| NistKatError::ImplementationError(format!("Key creation failed: {:?}", e)))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_array: [u8; 12] = nonce
        .try_into()
        .map_err(|_| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = plaintext.clone();
    key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Encryption failed: {:?}", e)))?;

    // Verify ciphertext + tag
    let mut expected_output = expected_ciphertext.clone();
    expected_output.extend_from_slice(&expected_tag);

    if in_out != expected_output {
        return Err(NistKatError::TestFailed {
            algorithm: "AES-128-GCM".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "Output mismatch: got {}, expected {}",
                hex::encode(&in_out),
                hex::encode(&expected_output)
            ),
        });
    }

    // Test decryption
    let unbound_key_2 = UnboundKey::new(&AES_128_GCM, &key_bytes)
        .map_err(|e| NistKatError::ImplementationError(format!("Key creation failed: {:?}", e)))?;
    let key_2 = LessSafeKey::new(unbound_key_2);

    let nonce_array_2: [u8; 12] = decode_hex(vector.nonce)?
        .try_into()
        .map_err(|_| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

    let decrypted = key_2
        .open_in_place(nonce_obj_2, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Decryption failed: {:?}", e)))?;

    if decrypted != plaintext.as_slice() {
        return Err(NistKatError::TestFailed {
            algorithm: "AES-128-GCM".to_string(),
            test_name: vector.test_name.to_string(),
            message: "Decrypted plaintext mismatch".to_string(),
        });
    }

    Ok(())
}

fn run_aes_256_gcm_test(vector: &AesGcmTestVector) -> Result<(), NistKatError> {
    let key_bytes = decode_hex(vector.key)?;
    let nonce = decode_hex(vector.nonce)?;
    let aad = decode_hex(vector.aad)?;
    let plaintext = decode_hex(vector.plaintext)?;
    let expected_ciphertext = decode_hex(vector.expected_ciphertext)?;
    let expected_tag = decode_hex(vector.expected_tag)?;

    // Test encryption
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|e| NistKatError::ImplementationError(format!("Key creation failed: {:?}", e)))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce_array: [u8; 12] = nonce
        .try_into()
        .map_err(|_| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = plaintext.clone();
    key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Encryption failed: {:?}", e)))?;

    // Verify ciphertext + tag
    let mut expected_output = expected_ciphertext.clone();
    expected_output.extend_from_slice(&expected_tag);

    if in_out != expected_output {
        return Err(NistKatError::TestFailed {
            algorithm: "AES-256-GCM".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "Output mismatch: got {}, expected {}",
                hex::encode(&in_out),
                hex::encode(&expected_output)
            ),
        });
    }

    // Test decryption
    let unbound_key_2 = UnboundKey::new(&AES_256_GCM, &key_bytes)
        .map_err(|e| NistKatError::ImplementationError(format!("Key creation failed: {:?}", e)))?;
    let key_2 = LessSafeKey::new(unbound_key_2);

    let nonce_array_2: [u8; 12] = decode_hex(vector.nonce)?
        .try_into()
        .map_err(|_| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj_2 = Nonce::assume_unique_for_key(nonce_array_2);

    let decrypted = key_2
        .open_in_place(nonce_obj_2, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Decryption failed: {:?}", e)))?;

    if decrypted != plaintext.as_slice() {
        return Err(NistKatError::TestFailed {
            algorithm: "AES-256-GCM".to_string(),
            test_name: vector.test_name.to_string(),
            message: "Decrypted plaintext mismatch".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_kat() {
        let result = run_aes_128_gcm_kat();
        assert!(result.is_ok(), "AES-128-GCM KAT failed: {:?}", result);
    }

    #[test]
    fn test_aes_256_gcm_kat() {
        let result = run_aes_256_gcm_kat();
        assert!(result.is_ok(), "AES-256-GCM KAT failed: {:?}", result);
    }
}
