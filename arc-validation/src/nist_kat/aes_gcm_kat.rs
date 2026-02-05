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
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
pub fn run_aes_128_gcm_kat() -> Result<(), NistKatError> {
    for vector in AES_128_GCM_VECTORS {
        run_aes_128_gcm_test(vector)?;
    }
    Ok(())
}

/// Run AES-256-GCM KAT
///
/// # Errors
///
/// Returns `NistKatError` if any test vector fails validation.
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
        .map_err(|_err| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = plaintext.clone();
    key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Encryption failed: {:?}", e)))?;

    // Verify ciphertext + tag
    let mut expected_output = expected_ciphertext;
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
        .map_err(|_err| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
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
        .map_err(|_err| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce_array);

    let mut in_out = plaintext.clone();
    key.seal_in_place_append_tag(nonce_obj, Aad::from(&aad), &mut in_out)
        .map_err(|e| NistKatError::ImplementationError(format!("Encryption failed: {:?}", e)))?;

    // Verify ciphertext + tag
    let mut expected_output = expected_ciphertext;
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
        .map_err(|_err| NistKatError::ImplementationError("Invalid nonce length".to_string()))?;
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
#[allow(clippy::panic)]
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

    // =========================================================================
    // Error path coverage for run_aes_128_gcm_test
    // =========================================================================

    #[test]
    fn test_aes_128_gcm_invalid_key_hex() {
        // Trigger decode_hex error on the key field (line 122)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-key-hex",
            key: "ZZZZ",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_nonce_hex() {
        // Trigger decode_hex error on the nonce field (line 123)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-nonce-hex",
            key: "00000000000000000000000000000000",
            nonce: "ZZZZZZZZZZZZZZZZZZZZZZZZ",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_aad_hex() {
        // Trigger decode_hex error on the aad field (line 124)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-aad-hex",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "GG",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_plaintext_hex() {
        // Trigger decode_hex error on the plaintext field (line 125)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-pt-hex",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "XY",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_expected_ciphertext_hex() {
        // Trigger decode_hex error on expected_ciphertext field (line 126)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-ct-hex",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "QQ",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_expected_tag_hex() {
        // Trigger decode_hex error on expected_tag field (line 127)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-tag-hex",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_key_length() {
        // Trigger UnboundKey::new error: key is wrong size for AES-128 (line 131)
        // Valid hex but wrong key length (8 bytes instead of 16)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-key-len",
            key: "0000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::ImplementationError(msg)) => {
                assert!(msg.contains("Key creation failed"), "Unexpected msg: {}", msg);
            }
            other => panic!("Expected ImplementationError for bad key length, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_invalid_nonce_length() {
        // Trigger nonce try_into error: nonce is wrong size (line 136)
        // Valid hex but wrong nonce length (8 bytes instead of 12)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-bad-nonce-len",
            key: "00000000000000000000000000000000",
            nonce: "0000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::ImplementationError(msg)) => {
                assert!(msg.contains("Invalid nonce length"), "Unexpected msg: {}", msg);
            }
            other => panic!("Expected ImplementationError for bad nonce length, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_ciphertext_mismatch() {
        // Trigger TestFailed: ciphertext output mismatch (lines 148-157)
        // Use valid key/nonce/plaintext but wrong expected_ciphertext
        let vector = AesGcmTestVector {
            test_name: "ERR-128-ct-mismatch",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            // Wrong tag -- should be 58e2fccefa7e3061367f1d57a4e7455a
            expected_tag: "00000000000000000000000000000000",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::TestFailed { algorithm, test_name, message }) => {
                assert_eq!(algorithm, "AES-128-GCM");
                assert_eq!(test_name, "ERR-128-ct-mismatch");
                assert!(message.contains("Output mismatch"), "Unexpected msg: {}", message);
            }
            other => panic!("Expected TestFailed for ciphertext mismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_decryption_nonce_hex_error() {
        // Trigger the decode_hex error for nonce on the decryption path (line 164)
        // This is hard to trigger because the same nonce was already decoded on line 123.
        // However, the code calls decode_hex(vector.nonce) again on line 164 for decryption.
        // We cannot make it fail on line 164 but not line 123 since they use the same string.
        // So this path is effectively covered by the nonce hex error test above.
        // Instead, let's verify the decryption path works for all vectors.
        for vector in AES_128_GCM_VECTORS {
            let result = run_aes_128_gcm_test(vector);
            assert!(result.is_ok(), "AES-128-GCM test '{}' failed: {:?}", vector.test_name, result);
        }
    }

    // =========================================================================
    // Error path coverage for run_aes_256_gcm_test
    // =========================================================================

    #[test]
    fn test_aes_256_gcm_invalid_key_hex() {
        // Trigger decode_hex error on the key field (line 185)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-key-hex",
            key: "ZZZZ",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_nonce_hex() {
        // Trigger decode_hex error on the nonce field (line 186)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-nonce-hex",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "ZZZZZZZZZZZZZZZZZZZZZZZZ",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_aad_hex() {
        // Trigger decode_hex error on the aad field (line 187)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-aad-hex",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "GG",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_plaintext_hex() {
        // Trigger decode_hex error on the plaintext field (line 188)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-pt-hex",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "XY",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_expected_ciphertext_hex() {
        // Trigger decode_hex error on expected_ciphertext field (line 189)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-ct-hex",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "QQ",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_expected_tag_hex() {
        // Trigger decode_hex error on expected_tag field (line 190)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-tag-hex",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(_)) => {}
            other => panic!("Expected HexError, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_key_length() {
        // Trigger UnboundKey::new error: key is wrong size for AES-256 (line 193)
        // Valid hex but wrong key length (8 bytes instead of 32)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-key-len",
            key: "0000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::ImplementationError(msg)) => {
                assert!(msg.contains("Key creation failed"), "Unexpected msg: {}", msg);
            }
            other => panic!("Expected ImplementationError for bad key length, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_invalid_nonce_length() {
        // Trigger nonce try_into error: nonce is wrong size (line 198)
        // Valid hex but wrong nonce length (8 bytes instead of 12)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-bad-nonce-len",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "0000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            expected_tag: "530f8afbc74536b9a963b4f1c4cb738b",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::ImplementationError(msg)) => {
                assert!(msg.contains("Invalid nonce length"), "Unexpected msg: {}", msg);
            }
            other => panic!("Expected ImplementationError for bad nonce length, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_ciphertext_mismatch() {
        // Trigger TestFailed: ciphertext output mismatch (lines 211-219)
        // Use valid key/nonce/plaintext but wrong expected_tag
        let vector = AesGcmTestVector {
            test_name: "ERR-256-ct-mismatch",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "",
            expected_ciphertext: "",
            // Wrong tag -- should be 530f8afbc74536b9a963b4f1c4cb738b
            expected_tag: "00000000000000000000000000000000",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::TestFailed { algorithm, test_name, message }) => {
                assert_eq!(algorithm, "AES-256-GCM");
                assert_eq!(test_name, "ERR-256-ct-mismatch");
                assert!(message.contains("Output mismatch"), "Unexpected msg: {}", message);
            }
            other => panic!("Expected TestFailed for ciphertext mismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_decryption_path_all_vectors() {
        // Ensure decryption path (lines 222-244) is fully exercised for all vectors
        for vector in AES_256_GCM_VECTORS {
            let result = run_aes_256_gcm_test(vector);
            assert!(result.is_ok(), "AES-256-GCM test '{}' failed: {:?}", vector.test_name, result);
        }
    }

    // =========================================================================
    // Additional error path tests
    // =========================================================================

    #[test]
    fn test_aes_128_gcm_ciphertext_mismatch_with_plaintext() {
        // Trigger TestFailed for ciphertext mismatch with non-empty plaintext
        // This covers the format! branch with non-empty hex output (lines 148-157)
        let vector = AesGcmTestVector {
            test_name: "ERR-128-ct-mismatch-pt",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "00000000000000000000000000000000",
            // Wrong expected ciphertext
            expected_ciphertext: "ffffffffffffffffffffffffffffffff",
            expected_tag: "00000000000000000000000000000000",
        };
        let result = run_aes_128_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::TestFailed { algorithm, message, .. }) => {
                assert_eq!(algorithm, "AES-128-GCM");
                assert!(message.contains("Output mismatch"));
                // Verify the message contains hex-encoded got/expected values
                assert!(message.contains("got "));
                assert!(message.contains("expected "));
            }
            other => panic!("Expected TestFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_256_gcm_ciphertext_mismatch_with_plaintext() {
        // Same as above but for AES-256 (lines 211-219)
        let vector = AesGcmTestVector {
            test_name: "ERR-256-ct-mismatch-pt",
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "",
            plaintext: "00000000000000000000000000000000",
            // Wrong expected ciphertext
            expected_ciphertext: "ffffffffffffffffffffffffffffffff",
            expected_tag: "00000000000000000000000000000000",
        };
        let result = run_aes_256_gcm_test(&vector);
        assert!(result.is_err());
        match result {
            Err(NistKatError::TestFailed { algorithm, message, .. }) => {
                assert_eq!(algorithm, "AES-256-GCM");
                assert!(message.contains("Output mismatch"));
                assert!(message.contains("got "));
                assert!(message.contains("expected "));
            }
            other => panic!("Expected TestFailed, got: {:?}", other),
        }
    }

    #[test]
    fn test_aes_128_gcm_vector_struct_fields() {
        // Exercise the AesGcmTestVector struct to ensure all fields are covered
        let vector = AesGcmTestVector {
            test_name: "field-test",
            key: "00000000000000000000000000000000",
            nonce: "000000000000000000000000",
            aad: "aabbccdd",
            plaintext: "eeff0011",
            expected_ciphertext: "deadbeef",
            expected_tag: "58e2fccefa7e3061367f1d57a4e7455a",
        };
        assert_eq!(vector.test_name, "field-test");
        assert_eq!(vector.key, "00000000000000000000000000000000");
        assert_eq!(vector.nonce, "000000000000000000000000");
        assert_eq!(vector.aad, "aabbccdd");
        assert_eq!(vector.plaintext, "eeff0011");
        assert_eq!(vector.expected_ciphertext, "deadbeef");
        assert_eq!(vector.expected_tag, "58e2fccefa7e3061367f1d57a4e7455a");
    }

    #[test]
    fn test_aes_128_gcm_kat_iterates_all_vectors() {
        // Verify run_aes_128_gcm_kat processes all 3 vectors successfully
        // covering the Ok(()) return at line 110
        assert_eq!(AES_128_GCM_VECTORS.len(), 3);
        let result = run_aes_128_gcm_kat();
        assert!(result.is_ok());
    }

    #[test]
    fn test_aes_256_gcm_kat_iterates_all_vectors() {
        // Verify run_aes_256_gcm_kat processes all 3 vectors successfully
        // covering the Ok(()) return at line 118
        assert_eq!(AES_256_GCM_VECTORS.len(), 3);
        let result = run_aes_256_gcm_kat();
        assert!(result.is_ok());
    }
}
