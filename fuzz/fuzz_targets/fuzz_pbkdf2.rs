#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for PBKDF2 key derivation
//!
//! Tests that PBKDF2 operations handle arbitrary input data
//! without crashing and produce consistent outputs.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kdf::pbkdf2::{pbkdf2, pbkdf2_simple, Pbkdf2Params, PrfType};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    // Split input into password and salt
    let password = &data[..8.min(data.len())];
    let salt = data.get(8..24).unwrap_or(&[0u8; 16]);

    // Use a small iteration count for fuzzing (PBKDF2 is intentionally slow)
    // Real usage should use 100,000+ iterations
    let iterations = 1000;
    let key_len = 32;

    // Test PBKDF2 with parameters
    test_pbkdf2_with_params(password, salt, iterations, key_len);

    // Test simple PBKDF2
    test_pbkdf2_simple(password);
});

fn test_pbkdf2_with_params(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) {
    let params = Pbkdf2Params {
        salt: salt.to_vec(),
        iterations,
        key_length: key_len,
        prf: PrfType::HmacSha256,
    };

    match pbkdf2(password, &params) {
        Ok(result) => {
            // Verify output length
            assert_eq!(result.key.len(), key_len, "Output length must match requested");

            // Verify determinism
            if let Ok(result2) = pbkdf2(password, &params) {
                assert_eq!(result.key, result2.key, "PBKDF2 must be deterministic");
            }

            // Different password should produce different output
            let different_password = b"different";
            let params2 = Pbkdf2Params {
                salt: salt.to_vec(),
                iterations,
                key_length: key_len,
                prf: PrfType::HmacSha256,
            };
            if let Ok(result_diff) = pbkdf2(different_password, &params2) {
                if password != different_password {
                    assert_ne!(result.key, result_diff.key, "Different password should produce different output");
                }
            }

            // Different salt should produce different output
            let different_salt = b"different salt value";
            let params3 = Pbkdf2Params {
                salt: different_salt.to_vec(),
                iterations,
                key_length: key_len,
                prf: PrfType::HmacSha256,
            };
            if let Ok(result_diff) = pbkdf2(password, &params3) {
                if salt != different_salt {
                    assert_ne!(result.key, result_diff.key, "Different salt should produce different output");
                }
            }
        }
        Err(_) => {
            // PBKDF2 can fail for invalid parameters
        }
    }

    // Test with various output lengths
    for test_len in [16, 32, 64] {
        let params = Pbkdf2Params {
            salt: salt.to_vec(),
            iterations,
            key_length: test_len,
            prf: PrfType::HmacSha256,
        };
        if let Ok(result) = pbkdf2(password, &params) {
            assert_eq!(result.key.len(), test_len);
        }
    }

    // Test with empty password
    let empty_params = Pbkdf2Params {
        salt: salt.to_vec(),
        iterations,
        key_length: key_len,
        prf: PrfType::HmacSha256,
    };
    let _ = pbkdf2(&[], &empty_params);

    // Test with single iteration
    let single_iter_params = Pbkdf2Params {
        salt: salt.to_vec(),
        iterations: 1,
        key_length: key_len,
        prf: PrfType::HmacSha256,
    };
    let _ = pbkdf2(password, &single_iter_params);
}

fn test_pbkdf2_simple(password: &[u8]) {
    // Test simple PBKDF2 (default parameters)
    if let Ok(result) = pbkdf2_simple(password) {
        // Should produce output with default length
        assert!(!result.key.is_empty());

        // Verify determinism
        if let Ok(result2) = pbkdf2_simple(password) {
            assert_eq!(result.key, result2.key);
        }
    }
}
