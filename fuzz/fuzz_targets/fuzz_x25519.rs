#![deny(unsafe_code)]
#![no_main]

//! Fuzz testing for X25519 key exchange
//!
//! Tests that X25519 ECDH operations handle arbitrary input data
//! without crashing and produce valid shared secrets.

use libfuzzer_sys::fuzz_target;
use arc_primitives::kem::ecdh::X25519KeyPair;

fuzz_target!(|data: &[u8]| {
    // Test 1: Generate keypairs and perform key agreement
    if let (Ok(alice), Ok(bob)) = (X25519KeyPair::generate(), X25519KeyPair::generate()) {
        // Clone public keys before consuming keypairs
        let alice_pk = alice.public_key_bytes().to_vec();
        let bob_pk = bob.public_key_bytes().to_vec();

        // Verify public key sizes
        assert_eq!(alice_pk.len(), 32, "X25519 public key must be 32 bytes");
        assert_eq!(bob_pk.len(), 32, "X25519 public key must be 32 bytes");

        // Perform key agreement (consume keys)
        let alice_secret = alice.agree(&bob_pk);
        let bob_secret = bob.agree(&alice_pk);

        if let (Ok(as_val), Ok(bs_val)) = (alice_secret, bob_secret) {
            // Shared secrets must match
            assert_eq!(
                as_val, bs_val,
                "Shared secrets must match for valid key exchange"
            );

            // Shared secret must be 32 bytes
            assert_eq!(as_val.len(), 32, "X25519 shared secret must be 32 bytes");
        }
    }

    // Test 2: Key agreement with fuzzed public key
    if data.len() >= 32 {
        if let Ok(keypair) = X25519KeyPair::generate() {
            let fuzzed_pk = &data[..32];

            // Attempt agreement with fuzzed public key
            let result = keypair.agree(fuzzed_pk);
            // May succeed or fail depending on whether fuzzed bytes are valid point
            let _ = result;
        }
    }

    // Test 3: Key agreement with invalid public key size
    if let Ok(keypair) = X25519KeyPair::generate() {
        // Too short
        let short_pk = &data[..16.min(data.len())];
        let result = keypair.agree(short_pk);
        if short_pk.len() != 32 {
            assert!(result.is_err(), "Invalid public key size should fail");
        }
    }

    // Test 4: Multiple key generations should produce different keys
    if let (Ok(kp1), Ok(kp2)) = (X25519KeyPair::generate(), X25519KeyPair::generate()) {
        assert_ne!(
            kp1.public_key_bytes(),
            kp2.public_key_bytes(),
            "Different key generations should produce different keys"
        );
    }

    // Test 5: Agreement with all-zero public key (should fail or produce specific result)
    if let Ok(keypair) = X25519KeyPair::generate() {
        let zero_pk = [0u8; 32];
        let _ = keypair.agree(&zero_pk);
        // Result depends on implementation - should not crash
    }

    // Test 6: Agreement with low-order point
    if let Ok(keypair) = X25519KeyPair::generate() {
        // Some implementations reject low-order points
        let low_order = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];
        let _ = keypair.agree(&low_order);
    }
});
