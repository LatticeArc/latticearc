//! Regression: the hybrid encrypt/decrypt flow must fit a 1 MiB thread stack.
//!
//! Windows gives the main thread a 1 MiB stack (Linux and macOS give 8 MiB).
//! The first FIPS-gated call runs the power-up self-tests on the calling
//! thread, and the ML-DSA / SLH-DSA known-answer tests used to need more
//! stack than that, so the documented hybrid example overflowed on Windows.
//!
//! This file deliberately holds a single test: the power-up self-tests run
//! once per process, and the point is that they are triggered from inside the
//! small thread rather than by an earlier test on a bigger one.
#![deny(unsafe_code)]

use latticearc::unified_api::crypto_types::{DecryptKey, EncryptKey};
use latticearc::unified_api::{CryptoConfig, UseCase, decrypt, encrypt};

const ONE_MIB: usize = 1 << 20;

#[test]
#[allow(clippy::unwrap_used)]
fn test_hybrid_keygen_encrypt_decrypt_fit_in_1_mib_stack_succeeds() {
    let handle = std::thread::Builder::new()
        .name("one-mib-stack".to_string())
        .stack_size(ONE_MIB)
        .spawn(|| -> Result<Vec<u8>, String> {
            let (pk, sk) = latticearc::generate_hybrid_keypair().map_err(|e| e.to_string())?;
            let encrypted = encrypt(
                b"secret",
                EncryptKey::Hybrid(&pk),
                CryptoConfig::new().use_case(UseCase::SecureMessaging),
            )
            .map_err(|e| e.to_string())?;
            decrypt(&encrypted, DecryptKey::Hybrid(&sk), CryptoConfig::new())
                .map_err(|e| e.to_string())
                .map(|p| p.to_vec())
        })
        .unwrap();
    let plaintext = handle.join().unwrap().unwrap();
    assert_eq!(plaintext, b"secret");
}
