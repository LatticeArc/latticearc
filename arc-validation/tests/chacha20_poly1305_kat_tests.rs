#![deny(unsafe_code)]
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    clippy::redundant_closure,
    clippy::redundant_clone,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::single_match_else,
    clippy::default_constructed_unit_structs,
    clippy::manual_is_multiple_of,
    clippy::needless_borrows_for_generic_args,
    clippy::print_stdout,
    clippy::unnecessary_unwrap,
    clippy::unnecessary_literal_unwrap,
    clippy::to_string_in_format_args,
    clippy::expect_fun_call,
    clippy::clone_on_copy,
    clippy::cast_precision_loss,
    clippy::useless_format,
    clippy::assertions_on_constants,
    clippy::drop_non_drop,
    clippy::redundant_closure_for_method_calls,
    clippy::unnecessary_map_or,
    clippy::print_stderr,
    clippy::inconsistent_digit_grouping,
    clippy::useless_vec
)]

//! Comprehensive Tests for ChaCha20-Poly1305 Known Answer Tests
//!
//! This module provides extensive test coverage for the ChaCha20-Poly1305 KAT implementation
//! in `arc-validation/src/nist_kat/chacha20_poly1305_kat.rs`.
//!
//! ## Test Categories
//! 1. Public API functions (run_chacha20_poly1305_kat)
//! 2. Test vector validation and structure
//! 3. Error handling paths (all NistKatError variants)
//! 4. Edge cases and boundary conditions
//! 5. AEAD encryption/decryption verification

use arc_validation::nist_kat::chacha20_poly1305_kat::{
    CHACHA20_POLY1305_VECTORS, run_chacha20_poly1305_kat,
};
use arc_validation::nist_kat::{NistKatError, decode_hex};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};

// =============================================================================
// Public API Tests
// =============================================================================

mod public_api_tests {
    use super::*;

    #[test]
    fn test_run_chacha20_poly1305_kat_passes() {
        let result = run_chacha20_poly1305_kat();
        assert!(result.is_ok(), "ChaCha20-Poly1305 KAT should pass: {:?}", result.err());
    }

    #[test]
    fn test_run_chacha20_poly1305_kat_multiple_times() {
        // Running KAT multiple times should always succeed (deterministic)
        for _ in 0..5 {
            let result = run_chacha20_poly1305_kat();
            assert!(result.is_ok(), "ChaCha20-Poly1305 KAT should be deterministic");
        }
    }
}

// =============================================================================
// Test Vector Structure Tests
// =============================================================================

mod test_vector_structure_tests {
    use super::*;

    #[test]
    fn test_vector_count() {
        // Ensure we have at least one test vector
        assert!(!CHACHA20_POLY1305_VECTORS.is_empty(), "Should have at least one test vector");
    }

    #[test]
    fn test_vector_names_not_empty() {
        for vector in CHACHA20_POLY1305_VECTORS {
            assert!(!vector.test_name.is_empty(), "Test name should not be empty");
        }
    }

    #[test]
    fn test_vector_key_length() {
        // ChaCha20-Poly1305 requires 256-bit (32-byte) keys = 64 hex chars
        for vector in CHACHA20_POLY1305_VECTORS {
            assert_eq!(
                vector.key.len(),
                64,
                "Key should be 64 hex chars (32 bytes) for test '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_vector_nonce_length() {
        // ChaCha20-Poly1305 uses 96-bit (12-byte) nonces = 24 hex chars
        for vector in CHACHA20_POLY1305_VECTORS {
            assert_eq!(
                vector.nonce.len(),
                24,
                "Nonce should be 24 hex chars (12 bytes) for test '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_vector_tag_length() {
        // Poly1305 produces 128-bit (16-byte) tags = 32 hex chars
        for vector in CHACHA20_POLY1305_VECTORS {
            assert_eq!(
                vector.expected_tag.len(),
                32,
                "Tag should be 32 hex chars (16 bytes) for test '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_vector_ciphertext_length_matches_plaintext() {
        // Ciphertext length should equal plaintext length (stream cipher)
        for vector in CHACHA20_POLY1305_VECTORS {
            assert_eq!(
                vector.expected_ciphertext.len(),
                vector.plaintext.len(),
                "Ciphertext length should match plaintext length for test '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_vector_hex_strings_valid() {
        for vector in CHACHA20_POLY1305_VECTORS {
            assert!(
                decode_hex(vector.key).is_ok(),
                "Key should be valid hex for test '{}'",
                vector.test_name
            );
            assert!(
                decode_hex(vector.nonce).is_ok(),
                "Nonce should be valid hex for test '{}'",
                vector.test_name
            );
            assert!(
                decode_hex(vector.aad).is_ok(),
                "AAD should be valid hex for test '{}'",
                vector.test_name
            );
            assert!(
                decode_hex(vector.plaintext).is_ok(),
                "Plaintext should be valid hex for test '{}'",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_ciphertext).is_ok(),
                "Ciphertext should be valid hex for test '{}'",
                vector.test_name
            );
            assert!(
                decode_hex(vector.expected_tag).is_ok(),
                "Tag should be valid hex for test '{}'",
                vector.test_name
            );
        }
    }

    #[test]
    fn test_vector_struct_fields_accessible() {
        // Verify all struct fields are accessible
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let _name: &str = vector.test_name;
        let _key: &str = vector.key;
        let _nonce: &str = vector.nonce;
        let _aad: &str = vector.aad;
        let _plaintext: &str = vector.plaintext;
        let _ciphertext: &str = vector.expected_ciphertext;
        let _tag: &str = vector.expected_tag;
    }
}

// =============================================================================
// Individual Vector Validation Tests
// =============================================================================

mod vector_validation_tests {
    use super::*;

    #[test]
    fn test_rfc8439_test_vector_1() {
        // Manually verify RFC 8439 Section 2.8.2 test vector
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        assert_eq!(vector.test_name, "RFC-8439-Test-Vector-1");

        let key = decode_hex(vector.key).unwrap();
        let nonce = decode_hex(vector.nonce).unwrap();
        let aad = decode_hex(vector.aad).unwrap();
        let plaintext = decode_hex(vector.plaintext).unwrap();
        let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
        let expected_tag = decode_hex(vector.expected_tag).unwrap();

        // Create cipher
        let key_array: [u8; 32] = key.clone().try_into().expect("key is 32 bytes");
        let cipher = ChaCha20Poly1305::new(&key_array.into());

        // Test encryption
        let payload = Payload { msg: &plaintext, aad: &aad };
        let ciphertext_with_tag =
            cipher.encrypt((&nonce[..]).into(), payload).expect("encryption should succeed");

        // Verify ciphertext
        let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
        assert_eq!(ct_part, expected_ciphertext.as_slice());
        assert_eq!(tag_part, expected_tag.as_slice());
    }

    #[test]
    fn test_all_vectors_individually() {
        for vector in CHACHA20_POLY1305_VECTORS {
            let key = decode_hex(vector.key).unwrap();
            let nonce = decode_hex(vector.nonce).unwrap();
            let aad = decode_hex(vector.aad).unwrap();
            let plaintext = decode_hex(vector.plaintext).unwrap();
            let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
            let expected_tag = decode_hex(vector.expected_tag).unwrap();

            let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
            let cipher = ChaCha20Poly1305::new(&key_array.into());

            // Test encryption
            let payload = Payload { msg: &plaintext, aad: &aad };
            let ciphertext_with_tag =
                cipher.encrypt((&nonce[..]).into(), payload).expect("encryption should succeed");

            let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
            assert_eq!(
                ct_part,
                expected_ciphertext.as_slice(),
                "Ciphertext mismatch for test '{}'",
                vector.test_name
            );
            assert_eq!(
                tag_part,
                expected_tag.as_slice(),
                "Tag mismatch for test '{}'",
                vector.test_name
            );

            // Test decryption
            let payload_dec = Payload { msg: &ciphertext_with_tag, aad: &aad };
            let decrypted = cipher
                .decrypt((&nonce[..]).into(), payload_dec)
                .expect("decryption should succeed");

            assert_eq!(decrypted, plaintext, "Decryption mismatch for test '{}'", vector.test_name);
        }
    }
}

// =============================================================================
// AEAD Property Tests
// =============================================================================

mod aead_property_tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"test message for ChaCha20-Poly1305";
        let aad = b"additional authenticated data";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_empty_plaintext_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Empty plaintext produces only the 16-byte tag
        assert_eq!(ciphertext.len(), 16);

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_aad_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"message without aad";
        let aad = b"";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_both_empty_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"";
        let aad = b"";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        assert_eq!(ciphertext.len(), 16);

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = vec![0x61u8; 1024 * 64]; // 64 KB
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
            .expect("encryption should succeed");

        // Ciphertext = plaintext length + 16 byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_aad_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"message";
        let aad = vec![0x42u8; 1024 * 16]; // 16 KB AAD

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad: &aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad: &aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_ciphertext_length() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        // Test various plaintext lengths
        for len in [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256] {
            let plaintext = vec![0x61u8; len];
            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                .expect("encryption should succeed");

            assert_eq!(
                ciphertext.len(),
                len + 16,
                "Ciphertext should be plaintext length + 16 for {} byte plaintext",
                len
            );
        }
    }
}

// =============================================================================
// Authentication Tests
// =============================================================================

mod authentication_tests {
    use super::*;

    #[test]
    fn test_wrong_key_decryption_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32]; // Different key
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher1 = ChaCha20Poly1305::new(&key1.into());
        let cipher2 = ChaCha20Poly1305::new(&key2.into());

        let ciphertext = cipher1
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Decryption with wrong key should fail
        let result = cipher2.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_wrong_nonce_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12]; // Different nonce
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce1).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Decryption with wrong nonce should fail
        let result = cipher.decrypt((&nonce2).into(), Payload { msg: &ciphertext, aad });
        assert!(result.is_err(), "Decryption with wrong nonce should fail");
    }

    #[test]
    fn test_wrong_aad_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad1 = b"correct aad";
        let aad2 = b"wrong aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad: aad1 })
            .expect("encryption should succeed");

        // Decryption with wrong AAD should fail
        let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad: aad2 });
        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    fn test_tampered_ciphertext_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let mut ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Tamper with ciphertext
        ciphertext[0] ^= 0x01;

        // Decryption should fail
        let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
        assert!(result.is_err(), "Decryption of tampered ciphertext should fail");
    }

    #[test]
    fn test_tampered_tag_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let mut ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Tamper with tag (last 16 bytes)
        let tag_start = ciphertext.len() - 16;
        ciphertext[tag_start] ^= 0x01;

        // Decryption should fail
        let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
        assert!(result.is_err(), "Decryption with tampered tag should fail");
    }

    #[test]
    fn test_truncated_ciphertext_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Truncate ciphertext
        let truncated = &ciphertext[..ciphertext.len() - 1];

        // Decryption should fail
        let result = cipher.decrypt((&nonce).into(), Payload { msg: truncated, aad });
        assert!(result.is_err(), "Decryption of truncated ciphertext should fail");
    }

    #[test]
    fn test_extended_ciphertext_decryption_fails() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"secret message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let mut ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        // Extend ciphertext
        ciphertext.push(0x00);

        // Decryption should fail
        let result = cipher.decrypt((&nonce).into(), Payload { msg: &ciphertext, aad });
        assert!(result.is_err(), "Decryption of extended ciphertext should fail");
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_nist_kat_error_test_failed_display() {
        let error = NistKatError::TestFailed {
            algorithm: "ChaCha20-Poly1305".to_string(),
            test_name: "RFC-8439-Test-Vector-1".to_string(),
            message: "ciphertext mismatch".to_string(),
        };

        let display = format!("{}", error);
        assert!(display.contains("ChaCha20-Poly1305"));
        assert!(display.contains("RFC-8439-Test-Vector-1"));
        assert!(display.contains("ciphertext mismatch"));
    }

    #[test]
    fn test_nist_kat_error_hex_error_display() {
        let error = NistKatError::HexError("invalid hex character".to_string());

        let display = format!("{}", error);
        assert!(display.contains("Hex decode error"));
        assert!(display.contains("invalid hex character"));
    }

    #[test]
    fn test_nist_kat_error_implementation_error_display() {
        let error = NistKatError::ImplementationError("Invalid key length".to_string());

        let display = format!("{}", error);
        assert!(display.contains("Implementation error"));
        assert!(display.contains("Invalid key length"));
    }

    #[test]
    fn test_decode_hex_valid() {
        let result = decode_hex("616263");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x61, 0x62, 0x63]);
    }

    #[test]
    fn test_decode_hex_empty() {
        let result = decode_hex("");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_decode_hex_invalid_chars() {
        let result = decode_hex("GHIJ");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    #[test]
    fn test_decode_hex_odd_length() {
        let result = decode_hex("abc");
        assert!(result.is_err());
        match result {
            Err(NistKatError::HexError(msg)) => {
                println!("Got expected hex error for odd length: {}", msg);
            }
            _ => panic!("Expected HexError variant"),
        }
    }

    #[test]
    fn test_decode_hex_uppercase() {
        let result = decode_hex("ABCDEF");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_decode_hex_mixed_case() {
        let result = decode_hex("AbCdEf");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xAB, 0xCD, 0xEF]);
    }
}

// =============================================================================
// Edge Case Tests for KAT Validation
// =============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_single_byte_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0x61u8];
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
            .expect("encryption should succeed");

        assert_eq!(ciphertext.len(), 17); // 1 byte ciphertext + 16 byte tag

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), &plaintext);
    }

    #[test]
    fn test_all_zeros_key() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"test message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_all_ones_key() {
        let key = [0xFFu8; 32];
        let nonce = [0xFFu8; 12];
        let plaintext = b"test message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; 32];
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];
        let plaintext = b"same message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext1 = cipher
            .encrypt((&nonce1).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let ciphertext2 = cipher
            .encrypt((&nonce2).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        assert_ne!(
            ciphertext1, ciphertext2,
            "Different nonces should produce different ciphertexts"
        );
    }

    #[test]
    fn test_same_nonce_produces_same_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"same message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext1 = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let ciphertext2 = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        assert_eq!(ciphertext1, ciphertext2, "Same inputs should produce same ciphertext");
    }
}

// =============================================================================
// Boundary Condition Tests
// =============================================================================

mod boundary_tests {
    use super::*;

    #[test]
    fn test_block_boundary_plaintexts() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        // ChaCha20 has a 64-byte block size
        for len in [63, 64, 65, 127, 128, 129, 191, 192, 193] {
            let plaintext = vec![0x61u8; len];

            let ciphertext = cipher
                .encrypt((&nonce).into(), Payload { msg: &plaintext, aad })
                .expect("encryption should succeed");

            let decrypted = cipher
                .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
                .expect("decryption should succeed");

            assert_eq!(decrypted, plaintext, "Roundtrip failed for {} byte plaintext", len);
        }
    }

    #[test]
    fn test_maximum_nonce_value() {
        let key = [0x42u8; 32];
        let nonce = [0xFFu8; 12]; // Maximum nonce value
        let plaintext = b"test message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_minimum_nonce_value() {
        let key = [0x42u8; 32];
        let nonce = [0x00u8; 12]; // Minimum nonce value
        let plaintext = b"test message";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertext = cipher
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let decrypted = cipher
            .decrypt((&nonce).into(), Payload { msg: &ciphertext, aad })
            .expect("decryption should succeed");

        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_single_bit_difference_in_key() {
        let key1 = [0x42u8; 32];
        let mut key2 = key1;
        key2[0] ^= 0x01; // Single bit difference

        let nonce = [0u8; 12];
        let plaintext = b"test message";
        let aad = b"aad";

        let cipher1 = ChaCha20Poly1305::new(&key1.into());
        let cipher2 = ChaCha20Poly1305::new(&key2.into());

        let ciphertext1 = cipher1
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        let ciphertext2 = cipher2
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .expect("encryption should succeed");

        assert_ne!(
            ciphertext1, ciphertext2,
            "Single bit key difference should produce completely different ciphertext"
        );
    }
}

// =============================================================================
// Determinism Tests
// =============================================================================

mod determinism_tests {
    use super::*;

    #[test]
    fn test_encryption_is_deterministic() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"deterministic test";
        let aad = b"aad";

        let cipher = ChaCha20Poly1305::new(&key.into());

        let ciphertexts: Vec<Vec<u8>> = (0..10)
            .map(|_| {
                cipher
                    .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
                    .expect("encryption should succeed")
            })
            .collect();

        // All ciphertexts should be identical
        for ct in &ciphertexts[1..] {
            assert_eq!(ct, &ciphertexts[0], "Encryption should be deterministic");
        }
    }

    #[test]
    fn test_kat_is_deterministic() {
        // Run KAT multiple times and verify consistency
        for _ in 0..10 {
            let result = run_chacha20_poly1305_kat();
            assert!(result.is_ok(), "KAT should always pass");
        }
    }
}

// =============================================================================
// Integration with KatRunner Tests
// =============================================================================

mod integration_tests {
    use super::*;
    use arc_validation::nist_kat::{KatRunner, KatSummary};

    #[test]
    fn test_chacha20_poly1305_kat_runner_integration() {
        let mut runner = KatRunner::new();

        runner.run_test("ChaCha20-Poly1305", "AEAD", || run_chacha20_poly1305_kat());

        let summary: KatSummary = runner.finish();

        assert!(
            summary.all_passed(),
            "ChaCha20-Poly1305 KAT should pass. Failed: {}/{}",
            summary.failed,
            summary.total
        );
        assert_eq!(summary.total, 1, "Should have run 1 test");
    }
}

// =============================================================================
// RFC 8439 Compliance Tests
// =============================================================================

mod rfc8439_compliance_tests {
    use super::*;

    #[test]
    fn test_rfc8439_key_size() {
        // RFC 8439 specifies 256-bit keys
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let key = decode_hex(vector.key).unwrap();
        assert_eq!(key.len(), 32, "RFC 8439 requires 256-bit (32 byte) keys");
    }

    #[test]
    fn test_rfc8439_nonce_size() {
        // RFC 8439 specifies 96-bit nonces for IETF variant
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let nonce = decode_hex(vector.nonce).unwrap();
        assert_eq!(nonce.len(), 12, "RFC 8439 requires 96-bit (12 byte) nonces");
    }

    #[test]
    fn test_rfc8439_tag_size() {
        // RFC 8439 specifies 128-bit authentication tags
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let tag = decode_hex(vector.expected_tag).unwrap();
        assert_eq!(tag.len(), 16, "RFC 8439 requires 128-bit (16 byte) tags");
    }

    #[test]
    fn test_rfc8439_aead_construction() {
        // Verify the AEAD construction follows RFC 8439 Section 2.8
        let vector = &CHACHA20_POLY1305_VECTORS[0];

        let key = decode_hex(vector.key).unwrap();
        let nonce = decode_hex(vector.nonce).unwrap();
        let aad = decode_hex(vector.aad).unwrap();
        let plaintext = decode_hex(vector.plaintext).unwrap();

        let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
        let cipher = ChaCha20Poly1305::new(&key_array.into());

        let ciphertext = cipher
            .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
            .expect("encryption should succeed");

        // The ciphertext length should be plaintext + tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }
}

// =============================================================================
// Test Vector Content Verification
// =============================================================================

mod content_verification_tests {
    use super::*;

    #[test]
    fn test_rfc8439_plaintext_content() {
        // RFC 8439 Section 2.8.2 plaintext is the Sunscreen message
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let plaintext = decode_hex(vector.plaintext).unwrap();

        // The plaintext should decode to ASCII text
        let text = String::from_utf8(plaintext.clone());
        assert!(text.is_ok(), "Plaintext should be valid UTF-8");

        let text_str = text.unwrap();
        assert!(
            text_str.contains("Ladies and Gentlemen"),
            "Plaintext should contain the famous Sunscreen speech"
        );
        assert!(text_str.contains("sunscreen"), "Plaintext should mention sunscreen");
    }

    #[test]
    fn test_rfc8439_aad_content() {
        // RFC 8439 Section 2.8.2 AAD
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let aad = decode_hex(vector.aad).unwrap();

        // AAD should be 12 bytes as specified in the RFC
        assert_eq!(aad.len(), 12, "AAD should be 12 bytes");
    }

    #[test]
    fn test_rfc8439_nonce_content() {
        // RFC 8439 Section 2.8.2 nonce
        let vector = &CHACHA20_POLY1305_VECTORS[0];
        let nonce = decode_hex(vector.nonce).unwrap();

        // First 4 bytes should be common/constant prefix (07 00 00 00)
        assert_eq!(nonce[0], 0x07);
        assert_eq!(nonce[1], 0x00);
        assert_eq!(nonce[2], 0x00);
        assert_eq!(nonce[3], 0x00);
    }
}

// =============================================================================
// Cross-validation Tests
// =============================================================================

mod cross_validation_tests {
    use super::*;

    #[test]
    fn test_verify_against_known_chacha20_output() {
        // Additional verification using known test vectors
        let key =
            decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode_hex("070000004041424344454647").unwrap();
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plaintext = decode_hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .unwrap();
        let expected_ciphertext = decode_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        )
        .unwrap();
        let expected_tag = decode_hex("1ae10b594f09e26a7e902ecbd0600691").unwrap();

        let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
        let cipher = ChaCha20Poly1305::new(&key_array.into());

        let ciphertext_with_tag = cipher
            .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
            .expect("encryption should succeed");

        let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());

        assert_eq!(ct_part, expected_ciphertext.as_slice(), "Ciphertext mismatch");
        assert_eq!(tag_part, expected_tag.as_slice(), "Tag mismatch");
    }
}

// =============================================================================
// Comprehensive Summary Test
// =============================================================================

#[test]
fn test_chacha20_poly1305_comprehensive_summary() {
    println!("\n========================================");
    println!("ChaCha20-Poly1305 KAT Test Summary");
    println!("========================================\n");

    // Run main KAT
    let kat_result = run_chacha20_poly1305_kat();
    println!("Main KAT: {}", if kat_result.is_ok() { "PASS" } else { "FAIL" });
    assert!(kat_result.is_ok());

    // Count test vectors
    let vector_count = CHACHA20_POLY1305_VECTORS.len();
    println!("Test Vectors: {}", vector_count);

    // Verify all vectors
    for vector in CHACHA20_POLY1305_VECTORS {
        let key = decode_hex(vector.key).unwrap();
        let nonce = decode_hex(vector.nonce).unwrap();
        let aad = decode_hex(vector.aad).unwrap();
        let plaintext = decode_hex(vector.plaintext).unwrap();
        let expected_ciphertext = decode_hex(vector.expected_ciphertext).unwrap();
        let expected_tag = decode_hex(vector.expected_tag).unwrap();

        let key_array: [u8; 32] = key.try_into().expect("key is 32 bytes");
        let cipher = ChaCha20Poly1305::new(&key_array.into());

        let ciphertext_with_tag = cipher
            .encrypt((&nonce[..]).into(), Payload { msg: &plaintext, aad: &aad })
            .expect("encryption should succeed");

        let (ct_part, tag_part) = ciphertext_with_tag.split_at(expected_ciphertext.len());
        let ct_match = ct_part == expected_ciphertext.as_slice();
        let tag_match = tag_part == expected_tag.as_slice();

        println!(
            "  [{}] {} - CT: {} TAG: {}",
            if ct_match && tag_match { "PASS" } else { "FAIL" },
            vector.test_name,
            if ct_match { "OK" } else { "MISMATCH" },
            if tag_match { "OK" } else { "MISMATCH" }
        );

        assert!(ct_match, "Ciphertext mismatch for {}", vector.test_name);
        assert!(tag_match, "Tag mismatch for {}", vector.test_name);
    }

    println!("\n========================================");
    println!("All Tests Passed!");
    println!("========================================\n");
}
