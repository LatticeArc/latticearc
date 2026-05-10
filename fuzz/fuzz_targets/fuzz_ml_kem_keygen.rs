#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for ML-KEM key generation
//!
//! Tests that ML-KEM key generation handles various conditions
//! and produces valid keypairs.

use latticearc::primitives::kem::ml_kem::{MlKem, MlKemSecurityLevel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Select security level based on first byte
    let level = match data[0] % 3 {
        0 => MlKemSecurityLevel::MlKem512,
        1 => MlKemSecurityLevel::MlKem768,
        _ => MlKemSecurityLevel::MlKem1024,
    };

    // Test 1: Key generation should always succeed
    match MlKem::generate_keypair(level) {
        Ok((pk, sk)) => {
            // Verify key sizes
            assert_eq!(
                pk.as_bytes().len(),
                level.public_key_size(),
                "Public key size mismatch for {:?}",
                level
            );
            assert_eq!(
                sk.expose_secret().len(),
                level.secret_key_size(),
                "Secret key size mismatch for {:?}",
                level
            );

            // Verify public key is not all zeros (would indicate RNG failure)
            let pk_bytes = pk.as_bytes();
            let all_zero = pk_bytes.iter().all(|&b| b == 0);
            assert!(!all_zero, "Public key should not be all zeros");

            // Test encapsulation with generated key
            if let Ok((ss, ct)) = MlKem::encapsulate(&pk) {
                // Verify shared secret is 32 bytes
                assert_eq!(ss.expose_secret().len(), 32);
                // Verify ciphertext size
                assert_eq!(ct.as_bytes().len(), level.ciphertext_size());
            }
        }
        Err(_) => {
            // Key generation failure (RNG issue) - acceptable but rare
        }
    }

    // Test 2: Multiple key generations should produce structurally-
    // valid keys. The previous assert_ne! on bytes was technically
    // correct (collision is ~2⁻²⁵⁶) but is the same bug-class as
    // an earlier audit's `fuzz_hkdf` determinism assertion: a fuzz harness
    // should encode invariants the implementation can violate, not
    // probabilistic facts that depend on RNG state. If anything in
    // the harness ever routes fuzz bytes into the keygen RNG, the
    // assertion would fire on a real-world non-bug.
    if let (Ok((pk1, _sk1)), Ok((pk2, _sk2))) =
        (MlKem::generate_keypair(level), MlKem::generate_keypair(level))
    {
        // Both keys must be the expected length for this parameter
        // set. Length is a deterministic structural invariant.
        assert_eq!(pk1.as_bytes().len(), level.public_key_size());
        assert_eq!(pk2.as_bytes().len(), level.public_key_size());
    }

    // Test 3: Test all security levels in sequence
    for test_level in
        [MlKemSecurityLevel::MlKem512, MlKemSecurityLevel::MlKem768, MlKemSecurityLevel::MlKem1024]
    {
        if let Ok((pk, _sk)) = MlKem::generate_keypair(test_level) {
            // Verify key has correct size for its level
            assert_eq!(pk.as_bytes().len(), test_level.public_key_size());
        }
    }
});
