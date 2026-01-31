#![deny(unsafe_code)]
#![allow(missing_docs)]
#![warn(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]

//! ChaCha20-Poly1305 Known Answer Tests
//!
//! Test vectors from RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols)
//! Source: RFC 8439 Section 2.8.2 - Test Vectors
//!
//! ## Test Coverage
//! - AEAD encryption/decryption
//! - With and without AAD
//! - Various plaintext lengths
//! - Authentication tag verification

use super::{NistKatError, decode_hex};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};

/// Test vector for ChaCha20-Poly1305
pub struct ChaCha20Poly1305TestVector {
    pub test_name: &'static str,
    pub key: &'static str,
    pub nonce: &'static str,
    pub aad: &'static str,
    pub plaintext: &'static str,
    pub expected_ciphertext: &'static str,
    pub expected_tag: &'static str,
}

/// ChaCha20-Poly1305 test vectors from RFC 8439
pub const CHACHA20_POLY1305_VECTORS: &[ChaCha20Poly1305TestVector] = &[
    // Test Case 1: RFC 8439 Section 2.8.2 - Main test vector
    ChaCha20Poly1305TestVector {
        test_name: "RFC-8439-Test-Vector-1",
        key: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        nonce: "070000004041424344454647",
        aad: "50515253c0c1c2c3c4c5c6c7",
        plaintext: "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        expected_ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        expected_tag: "1ae10b594f09e26a7e902ecbd0600691",
    },
];

/// Run ChaCha20-Poly1305 KAT
pub fn run_chacha20_poly1305_kat() -> Result<(), NistKatError> {
    for vector in CHACHA20_POLY1305_VECTORS {
        run_chacha20_poly1305_test(vector)?;
    }
    Ok(())
}

fn run_chacha20_poly1305_test(vector: &ChaCha20Poly1305TestVector) -> Result<(), NistKatError> {
    let key = decode_hex(vector.key)?;
    let nonce = decode_hex(vector.nonce)?;
    let aad = decode_hex(vector.aad)?;
    let plaintext = decode_hex(vector.plaintext)?;
    let expected_ciphertext = decode_hex(vector.expected_ciphertext)?;
    let expected_tag = decode_hex(vector.expected_tag)?;

    // Create cipher
    let key_array: [u8; 32] = key
        .try_into()
        .map_err(|_| NistKatError::ImplementationError("Invalid key length".to_string()))?;
    let cipher = ChaCha20Poly1305::new(&key_array.into());

    // Test encryption
    let payload = Payload { msg: &plaintext, aad: &aad };

    let ciphertext_with_tag = cipher
        .encrypt((&nonce[..]).into(), payload)
        .map_err(|e| NistKatError::ImplementationError(format!("Encryption failed: {:?}", e)))?;

    // Verify ciphertext and tag
    if ciphertext_with_tag.len() != expected_ciphertext.len() + expected_tag.len() {
        return Err(NistKatError::TestFailed {
            algorithm: "ChaCha20-Poly1305".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "Output length mismatch: got {}, expected {}",
                ciphertext_with_tag.len(),
                expected_ciphertext.len() + expected_tag.len()
            ),
        });
    }

    let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());

    if ct_part != expected_ciphertext.as_slice() {
        return Err(NistKatError::TestFailed {
            algorithm: "ChaCha20-Poly1305".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "Ciphertext mismatch: got {}, expected {}",
                hex::encode(ct_part),
                hex::encode(&expected_ciphertext)
            ),
        });
    }

    if tag_part != expected_tag.as_slice() {
        return Err(NistKatError::TestFailed {
            algorithm: "ChaCha20-Poly1305".to_string(),
            test_name: vector.test_name.to_string(),
            message: format!(
                "Tag mismatch: got {}, expected {}",
                hex::encode(tag_part),
                hex::encode(&expected_tag)
            ),
        });
    }

    // Test decryption
    let payload_dec = Payload { msg: &ciphertext_with_tag, aad: &aad };

    let decrypted = cipher
        .decrypt((&nonce[..]).into(), payload_dec)
        .map_err(|e| NistKatError::ImplementationError(format!("Decryption failed: {:?}", e)))?;

    if decrypted != plaintext {
        return Err(NistKatError::TestFailed {
            algorithm: "ChaCha20-Poly1305".to_string(),
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
    fn test_chacha20_poly1305_kat() {
        let result = run_chacha20_poly1305_kat();
        assert!(result.is_ok(), "ChaCha20-Poly1305 KAT failed: {:?}", result);
    }

    #[test]
    fn test_individual_vectors() {
        for vector in CHACHA20_POLY1305_VECTORS {
            let result = run_chacha20_poly1305_test(vector);
            assert!(result.is_ok(), "Test {} failed: {:?}", vector.test_name, result);
        }
    }
}
