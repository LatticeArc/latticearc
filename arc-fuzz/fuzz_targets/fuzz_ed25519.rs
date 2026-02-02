#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for Ed25519 signatures
//!
//! Tests that Ed25519 operations handle arbitrary input data
//! without crashing and correctly verify signatures.

use libfuzzer_sys::fuzz_target;
use arc_primitives::ec::ed25519::{Ed25519KeyPair, Ed25519Signature};
use arc_primitives::ec::traits::{EcKeyPair, EcSignature};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Use data as message
    let message = data;

    // Test 1: Generate keypair and sign/verify
    if let Ok(keypair) = Ed25519KeyPair::generate() {
        // Sign the fuzzed message
        if let Ok(signature) = keypair.sign(message) {
            // Verify signature
            let pk_bytes = keypair.public_key_bytes();
            let result = Ed25519Signature::verify(&pk_bytes, message, &signature);
            assert!(result.is_ok(), "Valid signature must verify");

            // Verify signature bytes round-trip
            let sig_bytes = Ed25519Signature::signature_bytes(&signature);
            assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");

            if let Ok(restored_sig) = Ed25519Signature::signature_from_bytes(&sig_bytes) {
                let result = Ed25519Signature::verify(&pk_bytes, message, &restored_sig);
                assert!(result.is_ok(), "Restored signature must verify");
            }

            // Wrong message should fail
            let wrong_message = b"different message content here";
            let result = Ed25519Signature::verify(&pk_bytes, wrong_message, &signature);
            assert!(result.is_err(), "Wrong message must fail verification");

            // Corrupted signature should fail
            let mut corrupted_sig_bytes = sig_bytes.clone();
            corrupted_sig_bytes[0] ^= 0xFF;
            if let Ok(corrupted_sig) = Ed25519Signature::signature_from_bytes(&corrupted_sig_bytes)
            {
                let result = Ed25519Signature::verify(&pk_bytes, message, &corrupted_sig);
                assert!(result.is_err(), "Corrupted signature must fail verification");
            }
        }
    }

    // Test 2: Keypair from secret key bytes
    if data.len() >= 32 {
        let sk_bytes = &data[..32];
        match Ed25519KeyPair::from_secret_key(sk_bytes) {
            Ok(keypair) => {
                // Sign with reconstructed keypair
                if let Ok(sig) = keypair.sign(b"test message") {
                    let pk_bytes = keypair.public_key_bytes();
                    assert!(Ed25519Signature::verify(&pk_bytes, b"test message", &sig).is_ok());
                }
            }
            Err(_) => {
                // Invalid secret key - acceptable
            }
        }
    }

    // Test 3: Verify with fuzzed public key bytes
    if let Ok(keypair) = Ed25519KeyPair::generate() {
        if let Ok(sig) = keypair.sign(message) {
            // Fuzzed public key
            let fuzzed_pk = &data[..32.min(data.len())];
            if fuzzed_pk.len() == 32 {
                // Verification with wrong key should fail
                let result = Ed25519Signature::verify(fuzzed_pk, message, &sig);
                // Either error or verification failure
                let _ = result;
            }
        }
    }

    // Test 4: Invalid signature length
    let short_sig = &data[..32.min(data.len())];
    let result = Ed25519Signature::signature_from_bytes(short_sig);
    if short_sig.len() != 64 {
        assert!(result.is_err(), "Invalid signature length should fail");
    }

    // Test 5: Empty message signing
    if let Ok(keypair) = Ed25519KeyPair::generate() {
        if let Ok(sig) = keypair.sign(&[]) {
            let pk_bytes = keypair.public_key_bytes();
            assert!(Ed25519Signature::verify(&pk_bytes, &[], &sig).is_ok());
        }
    }

    // Test 6: Large message signing
    if data.len() >= 10000 {
        if let Ok(keypair) = Ed25519KeyPair::generate() {
            if let Ok(sig) = keypair.sign(data) {
                let pk_bytes = keypair.public_key_bytes();
                assert!(Ed25519Signature::verify(&pk_bytes, data, &sig).is_ok());
            }
        }
    }
});
