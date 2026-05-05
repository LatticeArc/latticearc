#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for HKDF key derivation
//!
//! Tests that HKDF operations handle arbitrary input data
//! without crashing and produce consistent outputs.

use latticearc::primitives::kdf::hkdf::{hkdf, hkdf_expand, hkdf_extract, hkdf_simple};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Split input into IKM, salt, info
    let ikm = &data[..16.min(data.len())];
    let salt = data.get(16..32).map(|s| s);
    let info = data.get(32..).map(|s| s);

    // Test HKDF extract
    test_hkdf_extract_succeeds(ikm, salt);

    // Test HKDF expand (after extract)
    test_hkdf_expand_succeeds(ikm, salt, info);

    // Test full HKDF
    test_hkdf_full_succeeds(ikm, salt, info);

    // Test simple HKDF
    test_hkdf_simple_succeeds(ikm);
});

fn test_hkdf_extract_succeeds(ikm: &[u8], salt: Option<&[u8]>) {
    // HKDF Extract produces 32-byte PRK
    match hkdf_extract(salt, ikm) {
        Ok(prk) => {
            // Verify PRK length (32 bytes for SHA-256)
            assert_eq!(prk.len(), 32, "HKDF-Extract PRK must be 32 bytes");

            // Verify determinism
            if let Ok(prk2) = hkdf_extract(salt, ikm) {
                assert_eq!(prk, prk2, "HKDF-Extract must be deterministic");
            }
        }
        Err(_) => {
            // HKDF can fail for invalid parameters - acceptable
        }
    }

    // Test with no salt
    let _ = hkdf_extract(None, ikm);

    // Test with empty IKM
    let _ = hkdf_extract(salt, &[]);
}

fn test_hkdf_expand_succeeds(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>) {
    // First extract to get PRK
    if let Ok(prk) = hkdf_extract(salt, ikm) {
        // Test various output lengths
        for output_len in [16, 32, 48, 64, 128] {
            match hkdf_expand(&prk, info, output_len) {
                Ok(okm) => {
                    // Verify output length
                    assert_eq!(
                        okm.expose_secret().len(),
                        output_len,
                        "Output length must match requested"
                    );

                    // Verify determinism
                    if let Ok(okm2) = hkdf_expand(&prk, info, output_len) {
                        assert_eq!(
                            okm.expose_secret(),
                            okm2.expose_secret(),
                            "HKDF-Expand must be deterministic"
                        );
                    }
                }
                Err(_) => {}
            }
        }

        // Test maximum output length (255 * 32 = 8160 bytes for SHA-256)
        let max_len = 255 * 32;
        let result = hkdf_expand(&prk, info, max_len);
        assert!(result.is_ok(), "Max output length should succeed");

        // Test exceeding maximum output length
        let result = hkdf_expand(&prk, info, max_len + 1);
        assert!(result.is_err(), "Exceeding max output length should fail");
    }
}

fn test_hkdf_full_succeeds(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>) {
    // Test full HKDF (extract + expand)
    for output_len in [32, 64] {
        match hkdf(ikm, salt, info, output_len) {
            Ok(okm) => {
                assert_eq!(okm.expose_secret().len(), output_len);

                // Verify determinism
                if let Ok(okm2) = hkdf(ikm, salt, info, output_len) {
                    assert_eq!(
                        okm.expose_secret(),
                        okm2.expose_secret(),
                        "HKDF must be deterministic"
                    );
                }

                // Different info should produce different output
                let different_info = Some(b"different info string".as_slice());
                if info != different_info {
                    if let Ok(okm_diff) = hkdf(ikm, salt, different_info, output_len) {
                        assert_ne!(
                            okm.expose_secret(),
                            okm_diff.expose_secret(),
                            "Different info should produce different output"
                        );
                    }
                }
            }
            Err(_) => {}
        }
    }
}

fn test_hkdf_simple_succeeds(ikm: &[u8]) {
    // `hkdf_simple` uses a random salt internally (see its docstring),
    // so two calls on the same IKM return DIFFERENT outputs by design.
    // Determinism is therefore not a property to assert here; we only
    // check that the output length matches the requested length and
    // that the function does not crash on arbitrary fuzz input.
    let default_length = 32;
    if let Ok(result) = hkdf_simple(ikm, default_length) {
        assert_eq!(result.expose_secret().len(), default_length);
    }
}
